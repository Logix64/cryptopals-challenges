use std::io;

use bytes::BytesMut;
use challenge35::{derive_key, Connection, Error, Message, CIPHER, LIMBS};
use crypto_bigint::Uint;
use rand::{random, thread_rng};
use tokio::{net::TcpStream, sync::{mpsc, oneshot}};
use tools::{
    bigint::uint_dh::{DiffieHellmannParams, DynDiffieHellmannInstance}, encrypt::{aes::AesCbc128, cipher::{strip_pkcs7_padding, CipherCore, CipherMode}}
};

const PARAMS : [DiffieHellmannParams<LIMBS>;2] = [ 
    DiffieHellmannParams::new(
        &Uint::from_be_hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"),
        Uint::from_u32(5)
    ),
    DiffieHellmannParams::new( 
    &Uint::from_be_hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"),
    Uint::from_u32(2)
), ];

/// All possible Commands given for a client, any crypto is not handled by the Client struct, therefore we need to give it to our Client
struct CmdMsg {
    msg: String,
    response: oneshot::Sender<Result<String,Error>>,
}

/// Client implementation of our protocol, 
/// communication is asynchronous, with a cmd interface 
struct Client {
    receiver: mpsc::Receiver<CmdMsg>,
    connection: Connection,
    key : Option<[u8;CIPHER::BYTES]>
}

impl Client {
    /// Creates a new Client instance.
    fn new(connection: Connection, receiver: mpsc::Receiver<CmdMsg>) -> Self {
        Self {
            connection,
            receiver,
            key : None,
        }
    }

    /// Receives a new frame from the connection
    async fn receive(&mut self) -> Result<Message, Error> {
        loop {
            if let Some(msg) = self.connection.read_frame().await? {
                return Ok(msg);
            }
        }
    }

    /// Writes the frame into the connection
    async fn request(&mut self, message: &Message) -> Result<Message, Error> {
        self.connection.write_frame(message).await?;
        self.receive().await
    }

    /// Runs through list of Diffie-Hellmann Parameters
    /// this models the negotiation of parameters in Diffie-Hellmann 
    async fn get_params(&mut self, params : &[ DiffieHellmannParams<LIMBS> ] ) -> Result<DiffieHellmannParams<LIMBS>, Error> {
        for param in params {
            match self.request(&Message::AuthInit { modulus: param.get_modulus(), g: param.get_generator() }).await? {
                Message::Accept => return Ok(param.to_owned()),
                Message::Decline => continue,
                _ => return Err(Error::from("protocol error"))
            };
        }
        Err(Error::from("not enough params"))
    }

    /// Perform handshake 
    async fn handshake(mut self, params : &[ DiffieHellmannParams<LIMBS> ] ) -> Result<Self,Error> {
        loop {
            let params = self.get_params(params).await?;
            let instance = DynDiffieHellmannInstance::new(&params, &mut thread_rng() );

            // only if auth-response was found generate secret
            // otherwise try again negotiation
            if let Message::AuthResponse { public_key } = self.request(&Message::AuthResponse { public_key: instance.get_public_key() }).await? {
                let secret = instance.generate(&public_key);                
                return Ok(Self { receiver: self.receiver, connection: self.connection, key: Some(derive_key(secret))})
            } else {
                continue;
            }
        }
    }

    /// A CmdMsg is getting called and evaluated.
    async fn call(&mut self, command: CmdMsg) -> Result<(), Error> {
        if self.key.is_none() {
            return Err(Error::from("unexpected evaluation"))
        }

        let iv : [u8;CIPHER::BYTES] = random();
        let mut ciphertext = Vec::with_capacity(1000);
        let mut cbc = AesCbc128::init(&self.key.unwrap(), &iv, CipherMode::Encrypt);
        cbc.update(command.msg.trim().as_bytes(), &mut ciphertext);
        cbc.end(&mut ciphertext);

        let msg = Message::Message { msg: BytesMut::from(&ciphertext[..]).freeze(), iv };
        let response = match self.request(&msg).await? {
            Message::Message { msg, iv } => {
                let mut plaintext = Vec::with_capacity(1000);
                let mut cbc = AesCbc128::init(&self.key.unwrap(), &iv, CipherMode::Decrypt);
                cbc.update(&msg, &mut plaintext);
                cbc.end(&mut plaintext);

                Ok(std::str::from_utf8( strip_pkcs7_padding(&plaintext).unwrap_or(&plaintext[..]) )?.into())
            },
            Message::Error { msg : _ } => Err(Error::from("received error message") ),
            _ => Err(Error::from("protocol error")),
        }; 
        command.response.send(response).unwrap();
        Ok(())
    }

    /// Runtime of our client. 
    async fn run(mut self) -> Result<(),Error>{
        loop {
            if let Some(cmd) = self.receiver.recv().await {
                self.call(cmd).await?;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    // If we can connect to our server  
    if let Ok(con) = TcpStream::connect("127.0.0.2:6380").await {

        // generate new Client instance
        let (tx, rx) = mpsc::channel(10);

        let client =  Client::new(Connection::new(con), rx);
        tokio::spawn(client.handshake(&PARAMS).await?.run() );

        loop {
            let mut input = String::new();

            io::stdin().read_line(&mut input)?;
            
            let (t1,r1) = oneshot::channel();
            tx.send(CmdMsg { msg: input, response: t1 }).await.unwrap();

            match r1.await?{
                Ok(output) => println!(">> {output}"),
                Err(e) => println!(">>! {e:?}")
            }
        }
    }

    Ok(())


}
