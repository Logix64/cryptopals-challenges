use std::io;

use bytes::BytesMut;
use challenge36::{
    buffering::{Connection, Error},
    client::{Client, LIMBS},
    crypto::{derive_key, DifferentParams, NistParams, SRPParam, SRPParameters},
    keyexchange::KeyExchange,
    negotiation::Negotiation,
    verification::{Verification, VerificationError},
    ValidationError,
};
use crypto_bigint::{modular::constant_mod::ResidueParams, Encoding, Uint};
use rand::random;
use tokio::net::TcpStream;
use tools::digest::Hmac;

async fn run(mut client: Client) -> Result<(), ValidationError> {
    while !client.is_validated() {
        let mut email = String::new();
        println!("please enter email");
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

async fn inject_public_key(
    mut connection: Connection<TcpStream>,
    public_key: Uint<LIMBS>,
    server_secret: Uint<LIMBS>,
) -> Result<bool, ValidationError> {
    connection
        .write_frame(&Negotiation::AuthInit {
            param: SRPParam::NistParams,
        })
        .await?;
    if let Negotiation::Accept = connection.get_frame().await? {
        connection
            .write_frame(&KeyExchange::GetUsername {
                email: "admin".into(),
                public_key: BytesMut::from(public_key.to_be_bytes().as_ref()).freeze(),
            })
            .await?;

        if let KeyExchange::GetPublicKey { .. } = connection.get_frame().await? {
            let salt = random::<u64>();

            let mut hmac =
                Hmac::<<NistParams as SRPParameters<LIMBS>>::Hashing>::new(&derive_key::<
                    LIMBS,
                    NistParams,
                >(
                    &server_secret
                ));
            hmac.update(&salt.to_be_bytes());
            let mac = hmac.finalize();

            connection
                .write_frame(&Verification::HMACRequest {
                    hmac: BytesMut::from(mac.as_ref()).freeze(),
                    salt: BytesMut::from(salt.to_be_bytes().as_ref()).freeze(),
                })
                .await?;

            match connection.get_frame().await? {
                Verification::Accept => return Ok(true),
                Verification::Reject => return Ok(false),
                _ => return Err(ValidationError::Protocol),
            }
        } else {
            return Err(ValidationError::Protocol);
        }
    } else {
        return Err(ValidationError::Protocol);
    }
}

#[tokio::main]
async fn main() -> Result<(), ValidationError> {

    // normal login procedure
    if let Ok(con) = TcpStream::connect("127.0.0.1:6380").await {
        // generate new Client instance
        let client = Client::new(con);
        tokio::spawn(run(client)).await.unwrap()?;
    }

    // 0 as public key
    if let Ok(con) = TcpStream::connect("127.0.0.1:6380").await {
        // generate new Connection instance
        let connection = Connection::new(con);

        assert!(tokio::spawn(inject_public_key(
            connection,
            Uint::<LIMBS>::ZERO,
            Uint::<LIMBS>::ZERO,
        ))
        .await
        .unwrap()?);

        println!("0 as public key was successful");
    }

    // N as public key
    if let Ok(con) = TcpStream::connect("127.0.0.1:6380").await {
        // generate new Connection instance
        let connection = Connection::new(con);

        assert!(tokio::spawn(inject_public_key(
            connection,
            NistParams::MODULUS,
            Uint::<LIMBS>::ZERO,
        ))
        .await
        .unwrap()?);

        println!("N as public key was successful")
    }

    /*
    It is not going to work, since 2*N is not a U1536 integer anymore

    // 2*N  as public key
    if let Ok(con) = TcpStream::connect("127.0.0.1:6380").await {
        // generate new Connection instance
        let connection = Connection::new(con);

        let v = tokio::spawn(inject_public_key(connection, NistParams::MODULUS.checked_add(&NistParams::MODULUS).unwrap(), Uint::<LIMBS>::ZERO )).await.unwrap()?;

        println!("2*modulus public key successful ? : {v}");
    }
    */

    Ok(())
}
