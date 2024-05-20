use std::io::{self, Cursor};

use bytes::{Buf, BytesMut};
use challenge34::{derive_key, Error, Message, CIPHER, SIZE};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
};
use tools::encrypt::{aes::AesCbc128, cipher::{strip_pkcs7_padding, CipherCore, CipherMode}};

struct InternalMsg {
    msg: Message,
    label : String,
    response: oneshot::Sender<Option<Message>>,
}

async fn pipe(
    mut rx: OwnedReadHalf,
    wx: OwnedWriteHalf,
    sender: Sender<InternalMsg>,
    label : String
) -> Result<(), Error> {
    let mut buf = BytesMut::with_capacity(4096);
    let mut buf_writer = BufWriter::new(wx);
    loop {
        // if we reached end of stream
        if 0 == rx.read_buf(&mut buf).await? {
            return Err(Error::from(io::Error::new(
                io::ErrorKind::Other,
                "buffer is still not empty",
            )));
        }

        // else
        let mut cursor = Cursor::new(&buf[..]);

        // if whole frame found
        match Message::check(&mut cursor) {
            Ok(_) => {
                // println!("found frame");
                // current length of message
                let len = cursor.position() as usize;

                // reset cursor
                cursor.set_position(0);

                // send to manager
                let msg = Message::parse(&mut cursor)?;
                let (tx, rx) = oneshot::channel();
                
                sender
                    .send(InternalMsg { msg, label : label.clone(), response: tx })
                    .await
                    .unwrap();

                // wait for response
                // if response is some -- send that message
                if let Some(response) = rx.await.unwrap() {
                    Message::write(&mut buf_writer, &response).await?;

                // else just copy message
                } else {
                    buf_writer.write_all(&buf[0..len]).await?;
                    buf_writer.flush().await?;
                }

                // skip over message in buffer
                buf.advance(len);
            }
            Err(Error::Incomplete) => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn manage(mut receiver: Receiver<InternalMsg>) -> Result<(), Error> {
    let key: [u8;CIPHER::BYTES] = derive_key(SIZE::ZERO);
    let mut protocol_modulus: Option<SIZE> = None;

    loop {
        if let Some(InternalMsg { msg, label, response }) = receiver.recv().await {
            print!("{label} >> ");
            match msg {
                Message::AuthInit {
                    modulus,
                    g,
                    public_key: _,
                } => {
                    println!("auth-init");
                    protocol_modulus = Some(modulus);
                    response
                        .send(Some(Message::AuthInit {
                            modulus,
                            g,
                            public_key: modulus.clone(),
                        }))
                        .unwrap();
                }
                Message::AuthResponse { public_key: _ } => {
                    println!("auth-response");
                    response
                        .send(protocol_modulus.map(|modulus| Message::AuthResponse {
                            public_key: modulus,
                        }))
                        .unwrap();
                },
                Message::Message { msg, iv } => {
                    response.send(None).unwrap();
                    
                    let mut plaintext = Vec::with_capacity(msg.len());
                    let mut cbc = AesCbc128::init(&key, &iv, CipherMode::Decrypt);
                    cbc.update(&msg, &mut plaintext);
                    cbc.end(&mut plaintext);
                    println!("{}", std::str::from_utf8(&strip_pkcs7_padding(&plaintext).unwrap_or(&plaintext[..]) )?);

                }
                _ => response.send(None).unwrap(),
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.2:6380").await.unwrap();
    loop {
        if let Ok((from_client, _)) = listener.accept().await {
            if let Ok(to_server) = TcpStream::connect("127.0.0.1:6380").await {
                let (rx_from_client, wx_from_client) = from_client.into_split();
                let (rx_to_server, wx_to_server) = to_server.into_split();

                let (tx, rx) = mpsc::channel(32);

                tokio::spawn(manage(rx));

                tokio::spawn(pipe(rx_from_client, wx_to_server,tx.clone(), "client -> server".into() ));

                tokio::spawn(pipe(rx_to_server, wx_from_client, tx, "server -> client".into() ));
            }
        }
    }
}
