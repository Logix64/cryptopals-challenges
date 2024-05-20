
use bytes::BytesMut;
use challenge34::{derive_key, Connection, Error, Message, CIPHER};
use rand::{thread_rng, Rng};
use tokio::{net::TcpListener, sync::mpsc::{self, Receiver, Sender}};
use tools::{
    bigint::uint_dh::{DiffieHellmannParams, DynDiffieHellmannInstance},
    encrypt::{
        aes::{Aes128, AesCbc128},
        cipher::{strip_pkcs7_padding, CipherCore, CipherMode},
    },
};

// Runtime to catch any errors 
async fn run( tx : Sender<Result<(),Error>>, server : EchoServer ) -> Result<(), mpsc::error::SendError<Result<(), Error>>>{
    tx.send(server.run().await).await
}

// Manage all threads and show any error to our command line.
async fn manage( mut rx : Receiver<Result<(),Error>> ) {
    loop {
        if let Some(Err(err)) = rx.recv().await {
            println!("error occurred in thread : {err:?}")
        }
    }
}

// Echo Server Implementation of our protocol.
struct EchoServer {
    connection: Connection,
    key: Option<[u8; Aes128::BYTES]>,
}

impl EchoServer {
    // Create a new instance for a given Connection.
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            key: None,
        }
    }

    // Receive a new frame from the connection.
    async fn receive(&mut self) -> Result<Message, Error> {
        loop {
            if let Some(msg) = self.connection.read_frame().await? {
                return Ok(msg);
            }
        }
    }

    // Write a frame into the connection. 
    async fn write(&mut self, message: &Message) -> Result<(), Error> {
        self.connection.write_frame(message).await
    }

    // For a given Request return a response message according to our protocol.
    async fn call(&mut self, message: Message) -> Result<Message, Error> {
        match message {
            // If the server receives an AuthInit, accept the Parameters and generate a new Diffie-Hellman Instance 
            // Derives a key according to our function and responds with the generated public key.
            Message::AuthInit {
                public_key,
                modulus,
                g,
            } => {
                if self.key.is_none() {
                    let params = DiffieHellmannParams::new(&modulus, g);
                    let instance = DynDiffieHellmannInstance::new(&params, &mut thread_rng());

                    let response = Message::AuthResponse {
                        public_key: instance.get_public_key(),
                    };
                    self.key = Some(derive_key(instance.generate(&public_key, params)));
                    Ok(response)
                } else {
                    Ok(Message::Error {
                        msg: "already validated".into(),
                    })
                }
            }
            // Response should not be accepted, returns an error from the server.  
            Message::AuthResponse { .. } => Ok(Message::Error {
                msg: "invalid protocol".into(),
            }),
            // Any message will be decrypted and again encrypted with a fresh new iv and sent back. 
            Message::Message { msg, iv } => {
                // In case we have no key, return Error message.
                if self.key.is_none() {
                    Ok(Message::Error {
                        msg: "not validated".into(),
                    })
                } else {
                    let mut plaintext = Vec::with_capacity(msg.len());
                    let mut cbc = AesCbc128::init(&self.key.unwrap(), &iv, CipherMode::Decrypt);
                    cbc.update(&msg, &mut plaintext);
                    cbc.end(&mut plaintext);
                    println!(">> {}", std::str::from_utf8(&strip_pkcs7_padding(&plaintext).unwrap_or(&plaintext[..]))?);

                    let mut ciphertext = Vec::with_capacity(plaintext.len());
                    let new_iv: [u8; CIPHER::BYTES] = thread_rng().gen();
                    let mut cbc = AesCbc128::init(&self.key.unwrap(), &new_iv, CipherMode::Encrypt);
                    cbc.update(&plaintext, &mut ciphertext);
                    cbc.end(&mut ciphertext);

                    Ok(Message::Message {
                        msg: BytesMut::from(&ciphertext[..]).freeze(),
                        iv: new_iv,
                    })
                }
            }
            // If we receive an error message return the message itself again. This hopefully avoids any repeating cycles.
            Message::Error { .. } => {
                println!("received error : {:?}", message);
                Ok(message)
            }
        }
    }

    // Runtime of our server. Repeatedly receives a message and responds to it. 
    async fn run( mut self ) -> Result<(),Error> {
        loop {
            let msg = self.receive().await?;
            let response = self.call(msg).await?;
            self.write(&response ).await?;
        }
    }
    
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    // Listen to a given port. 
    let listener = TcpListener::bind("127.0.0.1:6380").await?;
    let (tx, rx) = mpsc::channel(10);

    // Spawn a managing thread. 
    tokio::spawn(manage(rx));

    // If we find a connection, instantiate a new Echo Server. 
    while let Ok( (socket, _) ) = listener.accept().await {
        let server = EchoServer::new(Connection::new(socket));
        let tx1 = tx.clone();
        tokio::spawn( run(tx1, server) );
    }

    Ok(())
}
