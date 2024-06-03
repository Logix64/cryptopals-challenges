use std::io;

use bytes::BytesMut;
use challenge36::{buffering::{Connection, Error}, client::{Authenticator, LIMBS, PARAMS}, crypto::{DifferentParams, NistParams, SRPParam, SRPParameters}, negotiation::{Negotiation, NegotiationError}, verification::{Verification, VerificationError}};
use challenge38::{keyexchange::KeyExchange, ValidationError};
use crypto_bigint::{Encoding, Uint};
use rand::thread_rng;
use tokio::net::TcpStream;

pub struct Client {
    connection: Connection<TcpStream>,
    validated: bool,
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
        if let KeyExchange::GetPublicKey { salt, public_key, u : u_bytes } = self.connection.get_frame().await?{            
            let server_public_key = Uint::<LIMBS>::from_be_slice(&public_key);
            let u = Uint::<LIMBS>::from_be_slice(&u_bytes);

            let (hmac_salt, key) = authenticator.get_key::<PARAMS>(password, server_public_key, u, salt);

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


async fn run(mut client: Client) -> Result<(), ValidationError> {
    while !client.is_validated() {
        let mut email = String::new();
        println!("please enter string");
        io::stdin()
            .read_line(&mut email)
            .map_err(|v| Error::<VerificationError>::from(v))?;

        let params = client.negotiate_params().await?;
        let mut authenticator = match params {
            SRPParam::DifferentParams => {
                client
                    .generate::<DifferentParams, LIMBS>(email.trim().into())
                    .await?
            }
            SRPParam::NistParams => {
                client
                    .generate::<NistParams, LIMBS>(email.trim().into())
                    .await?
            }
        };

        let mut password = String::new();
        println!("please enter password");
        io::stdin()
            .read_line(&mut password)
            .map_err(|v| Error::<VerificationError>::from(v))?;
        client = match params {
            SRPParam::DifferentParams => {
                client
                    .authenticate::<DifferentParams, LIMBS>(
                        password.trim().into(),
                        &mut authenticator,
                    )
                    .await?
            }
            SRPParam::NistParams => {
                client
                    .authenticate::<NistParams, LIMBS>(password.trim().into(), &mut authenticator)
                    .await?
            }
        };
    }
    println!("authentication was successful !!!");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), ValidationError> {
    if let Ok(con) = TcpStream::connect("127.0.0.2:6380").await {
        // generate new Client instance
        let client = Client::new(con);
        tokio::spawn(run(client)).await.unwrap()?;
    }
    Ok(())
}
