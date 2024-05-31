use std::io;

use challenge36::{
    buffering::Error,
    client::{Client, LIMBS},
    crypto::{DifferentParams, NistParams, SRPParam},
    verification::VerificationError,
    ValidationError,
};
use tokio::net::TcpStream;

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
    if let Ok(con) = TcpStream::connect("127.0.0.1:6380").await {
        // generate new Client instance
        let client = Client::new(con);
        tokio::spawn(run(client)).await.unwrap()?;
    }
    Ok(())
}
