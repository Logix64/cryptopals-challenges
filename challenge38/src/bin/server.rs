use std::collections::HashMap;

use challenge36::crypto::{generate_password, DifferentParams, NistParams, SRPParam};
use challenge38::{server::{Db, Server}, ValidationError};
use tokio::{net::TcpListener, sync::Mutex};
use tools::digest::sha1::Sha1Core;


async fn run(mut server: Server, db: Db) -> Result<(), ValidationError> {
    while !server.is_validated() {
        server = match server.negotiate_params().await? {
            SRPParam::DifferentParams => server.validate::<DifferentParams>(&db).await?,
            SRPParam::NistParams => server.validate::<NistParams>(&db).await?,
        };
    }
    println!("validated successfully !!!");
    Ok(())
}

fn generate_entry(email: &str, password: &str, salt: u64) -> (String, ([u8; 20], u64)) {
    (
        email.into(),
        (
            generate_password::<Sha1Core>(password.into(), salt.to_be_bytes()),
            salt,
        ),
    )
}

#[tokio::main]
async fn main() -> Result<(), ValidationError> {
    let listener = TcpListener::bind("127.0.0.1:6380").await.unwrap();

    let salt = 1000u64;

    let mut hashmap = HashMap::new();
    hashmap.extend([
        generate_entry("admin", "123", salt),
        generate_entry("user", "lol123", salt),
    ]);

    let db = Db::new(Mutex::new(hashmap));

    // If we find a connection, instantiate a new Echo Server.
    while let Ok((socket, _)) = listener.accept().await {
        let server = Server::new(socket);
        tokio::spawn(run(server, db.clone())).await.unwrap()?;
    }

    return Ok(());
}
