use std::io;

use bytes::BytesMut;
use challenge34::{derive_key, Connection, Error, Message, CIPHER, LIMBS};
use crypto_bigint::Uint;
use rand::{random, thread_rng};
use tokio::{net::TcpStream, sync::{mpsc, oneshot}};
use tools::{
    bigint::uint_dh::{DiffieHellmannParams, DynDiffieHellmannInstance}, encrypt::{aes::AesCbc128, cipher::{strip_pkcs7_padding, CipherCore, CipherMode}}
};

const PARAMS : DiffieHellmannParams<LIMBS> = DiffieHellmannParams::new( 
    &Uint::from_be_hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"),
    Uint::from_u32(2)
);

/// All possible Commands given for a client, any crypto is not handled by the Client struct, therefore we need to give it to our Client
enum CmdMsg {
    Handshake {
        params: DiffieHellmannParams<LIMBS>,
        public_key: Uint<LIMBS>,
        response: oneshot::Sender<Message>,
    },
    Message {
        msg: Message,
        response: oneshot::Sender<Message>,
    },
}

/// Client implementation of our protocol, 
/// communication is asynchronous, with a cmd interface 
struct Client {
    receiver: mpsc::Receiver<CmdMsg>,
    connection: Connection,
}

impl Client {
    /// Creates a new Client instance.
    fn new(connection: Connection, receiver: mpsc::Receiver<CmdMsg>) -> Self {
        Self {
            connection,
            receiver,
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
    async fn write(&mut self, message: &Message) -> Result<Message, Error> {
        self.connection.write_frame(message).await?;
        self.receive().await
    }

    /// A CmdMsg is getting called and evaluated.
    async fn call(&mut self, command: CmdMsg) -> Result<(), Error> {
        match command {
            CmdMsg::Handshake {
                params,
                public_key,
                response,
            } => {
                let resp: Message = self
                    .write(&Message::AuthInit {
                        modulus: params.get_modulus(),
                        g: params.get_generator(),
                        public_key,
                    })
                    .await?;
                response.send(resp).unwrap()
            }
            CmdMsg::Message { msg, response } => {
                let resp = self.write(&msg).await?;
                response.send(resp).unwrap()
            }
        }

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
        tokio::spawn(client.run() );

        // Generate our Diffie-Hellmann instance and transmit all necessary parameters
        let instance = DynDiffieHellmannInstance::new(&PARAMS, &mut thread_rng());

        let (t1,r1) = oneshot::channel();
        tx.send(CmdMsg::Handshake { params: PARAMS, public_key : instance.get_public_key(), response: t1 }).await.unwrap();
        
        // If we receive a response, derive a key. 
        if let Ok(Message::AuthResponse { public_key }) = r1.await {
            let secret = instance.generate(&public_key, PARAMS);

            let key = derive_key(secret);

            // repeatedly ask for input to communicate with the server and encrypt using our derived key. 
            // Also wait for an answer and decrypt it and show it to the user. 
            loop{
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                let iv : [u8;CIPHER::BYTES] = random();
                let mut ciphertext = Vec::with_capacity(1000);
                let mut cbc = AesCbc128::init(&key, &iv, CipherMode::Encrypt);
                cbc.update(input.trim().as_bytes(), &mut ciphertext);
                cbc.end(&mut ciphertext);

                let msg = Message::Message { msg: BytesMut::from(&ciphertext[..]).freeze(), iv };
                let (t1, r1) = oneshot::channel();
                
                tx.send(CmdMsg::Message { msg, response: t1 }).await.unwrap();
                if let Ok(Message::Message { msg : message, iv }) = r1.await {
                    let mut plaintext = Vec::with_capacity(1000);
                    let mut cbc = AesCbc128::init(&key, &iv, CipherMode::Decrypt);
                    cbc.update(&message, &mut plaintext);
                    cbc.end(&mut plaintext);


                    println!(">> {}", std::str::from_utf8( strip_pkcs7_padding(&plaintext).unwrap_or(&plaintext[..]) )? );
                }
            }
        } else {
            println!("a fatal error occurred");
        }

        todo!()
    }

    Ok(())


}
