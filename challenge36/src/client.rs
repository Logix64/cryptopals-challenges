use bytes::BytesMut;
use crate::{
    buffering::{Connection, Error}, crypto::{
        derive_key, derive_u, generate_password, hash_to_uint,
        SRPParam, SRPParameters,
    }, keyexchange:: KeyExchange, negotiation::{Negotiation, NegotiationError}, verification::Verification, ValidationError
};
use crypto_bigint::{
    modular::constant_mod::Residue, rand_core::CryptoRngCore, Encoding, NonZero,RandomMod,
    Uint, U1536,
};
use rand::{random, thread_rng};
use tokio::net::TcpStream;
use tools::digest::{HashAlgorithm, Hmac};

pub const LIMBS: usize = U1536::LIMBS;

pub const PARAMS: [SRPParam; 2] = [
    SRPParam::NistParams,
    SRPParam::DifferentParams,
];

/// SRP Client network implementation 
pub struct Client {
    connection: Connection<TcpStream>,
    validated: bool,
}

/// SRP Authenticator only constructed with SRP Parameters
/// Essentially a Diffie-Hellmann Instance 
pub struct Authenticator<const LIMBS: usize> {
    public_key: Uint<LIMBS>,
    private_key: Uint<LIMBS> ,
}

impl<const LIMBS: usize> Authenticator<LIMBS> {
    
    /// Generates a new instance for given SRPParameters
    fn new<PARAMS : SRPParameters<LIMBS>>(rng: &mut impl CryptoRngCore) -> Self {
        let private_key = Uint::<LIMBS>::random_mod(rng, &NonZero::from_uint(PARAMS::MODULUS));
        let client_public_key = PARAMS::G.pow(&private_key);

        Self {
            public_key: client_public_key.retrieve(),
            private_key,
        }
    }

    /// Returns the public key A = g**a mod n
    fn get_public_key(&self) -> Uint<LIMBS> {
        self.public_key
    }

    /// Derives the key of a given password and returns random salt. 
    fn get_key<PARAMS : SRPParameters<LIMBS>>(
        &self,
        password: String,
        server_public_key: Uint<LIMBS>,
        salt: impl AsRef<[u8]>,
    ) -> (u64, <PARAMS::Hashing as HashAlgorithm>::OUTPUT)
    where
        Uint<LIMBS>: Encoding
    {
        let x = hash_to_uint::<LIMBS>(generate_password::<PARAMS::Hashing>(password, salt));
        let u = derive_u::<LIMBS,PARAMS>(&server_public_key, &self.get_public_key());

        let inner = Residue::new(&server_public_key) - PARAMS::FACTOR * PARAMS::G.pow(&x);
        let outer = inner.pow(&self.private_key) * inner.pow(&u).pow(&x);

        (random(), derive_key::<LIMBS, PARAMS>(&outer.retrieve()))
    }

    /// Generates HMAC from a byteslice with salt
    fn hmac<L : HashAlgorithm>(&self, salt : impl AsRef<[u8]>, key : L::OUTPUT ) -> L::OUTPUT
        where L::OUTPUT: Copy + Clone + AsRef<[u8]>,
    {
        let mut hmac = Hmac::<L>::new(key.as_ref());
        hmac.update(salt.as_ref());
        hmac.finalize()
    }
}

impl Client {

    /// Generates new Client instance
    pub fn new(stream : TcpStream) -> Self{
        Self { connection: Connection::new(stream), validated: false }
    }

    /// Negotiates SRP Parameters and returns those Parameters
    pub async fn negotiate_params(&mut self) -> Result<SRPParam, Error<NegotiationError>> {
        for param in PARAMS {
            self.connection
                .write_frame(&Negotiation::AuthInit { param })
                .await?;
            if let Negotiation::Accept = self.connection.get_frame().await? {
                return Ok(param);
            }
        }
        Err(Error::Other(NegotiationError::NoCommonParameters))
    }

    /// Generates a request from a given email 
    pub async fn generate<T: SRPParameters<LIMBS>, const LIMBS: usize>(
        &mut self,
        email: String,
    ) -> Result<Authenticator<LIMBS>, ValidationError>
    where
        Uint<LIMBS>: Encoding,
    {
        let authenticator = Authenticator::<LIMBS>::new::<T>(&mut thread_rng());
        let public_key =
            BytesMut::from(authenticator.get_public_key().to_be_bytes().as_ref()).freeze();
        self.connection
            .write_frame(&KeyExchange::GetUsername { email, public_key })
            .await?;

        Ok(authenticator)
    }

    /// Authenticates with a given Password 
    pub async fn authenticate<PARAMS : SRPParameters<LIMBS>, const LIMBS : usize>(
        mut self,
        password: String,
        authenticator : &mut Authenticator<LIMBS>
    ) -> Result<Self, ValidationError>
        where Uint<LIMBS> : Encoding
    {
        if let KeyExchange::GetPublicKey { salt, public_key } = self.connection.get_frame().await?{            
            let server_public_key = Uint::<LIMBS>::from_be_slice(&public_key);

            let (hmac_salt, key) = authenticator.get_key::<PARAMS>(password, server_public_key, salt);

            let hmac_bytes = authenticator.hmac::<PARAMS::Hashing>(&hmac_salt.to_be_bytes(), key);
            self.connection.write_frame(&Verification::HMACRequest { 
                hmac: BytesMut::from(hmac_bytes.as_ref()).freeze(),
                salt: BytesMut::from(hmac_salt.to_be_bytes().as_ref()).freeze() 
            }).await?;

            if let Verification::Accept = self.connection.get_frame().await? {
                return Ok(Self{
                    connection: self.connection,
                    validated: true,
                })
            } else {
                return Ok(Self{
                    connection: self.connection,
                    validated: false,
                })
            }
        } else {
            return Err(ValidationError::Protocol)
        }
    }

    /// Returns if the Session is validated
    pub fn is_validated(&self) -> bool {
        self.validated
    }
}
