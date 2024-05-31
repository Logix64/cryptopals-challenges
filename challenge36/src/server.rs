use std::{collections::HashMap, sync::Arc};

use bytes::BytesMut;
use crypto_bigint::{modular::constant_mod::Residue, rand_core::CryptoRngCore, Encoding, NonZero, RandomMod, Uint, U1536};
use rand::{random, thread_rng};
use tokio::{net::TcpStream, sync::Mutex};
use tools::digest::{HashAlgorithm, Hmac};

use crate::{buffering::{Connection, Error}, crypto::{derive_key, derive_u, derive_v, SRPParam, SRPParameters}, keyexchange::KeyExchange, negotiation::{Negotiation, NegotiationError}, verification::Verification, ValidationError};

pub const LIMBS: usize = U1536::LIMBS;

/// SRP Server network implementation
pub struct Server {
    connection: Connection<TcpStream>,
    validated: bool,
}

// Databank type 
pub type Db = Arc<Mutex<HashMap<String, ([u8; 20], u64)>>>;

#[inline]
fn const_compare(u: impl AsRef<[u8]>, v: impl AsRef<[u8]>) -> bool {
    u.as_ref()
        .iter()
        .zip(v.as_ref().iter())
        .fold(true, |acc, (u, v)| acc && u.eq(v))
        && v.as_ref().len() == u.as_ref().len()
}

/// SRP Verificator of given SRPParameters 
/// allows blinding, e.g. if no user is found still performs operations to prevent any bruteforce attacks
pub struct Verificator<const LIMBS: usize, T: SRPParameters<LIMBS>> {
    public_key: Uint<LIMBS>,
    blind: bool,
    key: <T::Hashing as HashAlgorithm>::OUTPUT,
}

impl<const LIMBS: usize, H: SRPParameters<LIMBS>> Verificator<LIMBS, H>
where
    Uint<LIMBS>: Encoding,
{
    /// Generates new Verificator, depending on SRPParameters, allows const evaluation
    fn new(
        rng: &mut impl CryptoRngCore,
        v: Residue<H, LIMBS>,
        client_public_key: &Uint<LIMBS>,
        blind: bool,
    ) -> Self {
        let private_key = Uint::<LIMBS>::random_mod(rng, &NonZero::from_uint(H::MODULUS));

        let server_public_key = H::G.pow(&private_key) + H::FACTOR * v;
        let u = derive_u::<LIMBS, H>(&server_public_key.retrieve(), client_public_key);

        let key = derive_key::<LIMBS, H>(
            &(Residue::new(client_public_key) * v.pow(&u))
                .pow(&private_key)
                .retrieve(),
        );

        Self {
            public_key: server_public_key.retrieve(),
            blind,
            key,
        }
    }

    /// Returns the public key B = kv + g**b mod n of the verificator. 
    fn get_public_key(&self) -> Uint<LIMBS> {
        self.public_key
    }

    /// Validates if hmac with salt is true
    fn validate(self, mac: impl AsRef<[u8]>, salt: impl AsRef<[u8]>) -> bool {
        let mut hmac = Hmac::<H::Hashing>::new(self.key.as_ref());
        hmac.update(salt.as_ref());
        let other_hmac = hmac.finalize();
        // here const compare
        self.compare(mac, other_hmac)
    }

    /// const compare of a byte slice
    #[inline]
    fn compare(&self, hmac: impl AsRef<[u8]>, other: impl AsRef<[u8]>) -> bool {
        const_compare(hmac, other) && self.blind
    }
}

impl Server {
    /// Generates new Server Instance
    pub fn new(stream: TcpStream) -> Self {
        Self {
            connection: Connection::new(stream),
            validated: false,
        }
    }

    /// Negotiates Parameters according to the protocol and returns the negotiated Parameters
    pub async fn negotiate_params(&mut self) -> Result<SRPParam, Error<NegotiationError>> {
        loop {
            if let Negotiation::AuthInit { param } = self.connection.get_frame().await? {
                // here complicated param negotiation but for demonstration purposes just accept any possible params
                self.connection.write_frame(&Negotiation::Accept).await?;
                return Ok(param);
            } else {
                self.connection.write_frame(&Negotiation::Decline).await?;
            }
        }
    }

    /// Returns a Verificator for given SRPParameters and Databank of username
    pub async fn verify<PARAMS: SRPParameters<LIMBS>, const LIMBS: usize>(
        &mut self,
        db: &HashMap<String, ([u8; 20], u64)>,
    ) -> Result<Verificator<LIMBS, PARAMS>, ValidationError>
    where
        Uint<LIMBS>: Encoding,
    {
        if let KeyExchange::GetUsername { email, public_key } = self.connection.get_frame().await? {
            let (blind, (hash, hash_salt)) = (
                db.contains_key(&email),
                db.get(&email).copied().unwrap_or((random(), random())),
            );

            let v = derive_v::<LIMBS, PARAMS>(hash);
            let client_public_key = Uint::from_be_slice(&public_key);

            let verificator = Verificator::new(&mut thread_rng(), v, &client_public_key, blind);

            let public_key =
                BytesMut::from(verificator.get_public_key().to_be_bytes().as_ref()).freeze();
            let salt = BytesMut::from(hash_salt.to_be_bytes().as_ref()).freeze();

            self.connection
                .write_frame(&KeyExchange::GetPublicKey { salt, public_key })
                .await?;

            return Ok(verificator);
        } else {
            return Err(ValidationError::Protocol);
        }
    }

    /// Tries to handshake with given SRP Parameters
    pub async fn validate<PARAM: SRPParameters<LIMBS>>(
        mut self,
        db: &Db,
    ) -> Result<Self, ValidationError> {
        let locked = db.lock().await;
        let verify_result = self.verify::<PARAM, LIMBS>(&locked).await;

        
        if verify_result.is_err() {
            match verify_result {
                Err(ValidationError::Protocol) => {
                    return Ok(Self {
                        connection: self.connection,
                        validated: false,
                    })
                }
                Err(v) => return Err(v),
                _ => panic!("problem"),
            }
        }

        let verificator = verify_result.unwrap();

        let result =
            if let Verification::HMACRequest { hmac, salt } = self.connection.get_frame().await? {
                verificator.validate(hmac, salt)
            } else {
                false
            };
        
        // println!("received request, writing result");

        self.connection
            .write_frame(if result {
                &Verification::Accept
            } else {
                &Verification::Reject
            })
            .await?;

        Ok(Self {
            connection: self.connection,
            validated: result,
        })
    }

    /// Returns if the session is validated
    pub fn is_validated(&self) -> bool {
        self.validated
    }
}
