use std::{
    io::{self, Cursor},
    str::Utf8Error,
};

use bytes::{Buf, Bytes, BytesMut};
use crypto_bigint::{Encoding, U1536};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter},
    net::TcpStream, sync::{mpsc::error::SendError, oneshot::error::RecvError},
};
use tools::{digest::sha1::Sha1, encrypt::{aes::Aes128, cipher::CipherCore}};

pub type SIZE = U1536;
pub const LIMBS: usize = SIZE::LIMBS;
pub type CIPHER = Aes128;

/// Messages in our Protocol 
#[derive(Clone, Debug)]
pub enum Message {
    AuthInit {
        modulus: SIZE,
        g: SIZE,
    },
    AuthResponse {
        public_key: SIZE,
    },
    Message {
        msg: Bytes,
        iv: [u8; CIPHER::BYTES],
    },
    Accept,
    Decline,
    Error {
        msg: String,
    },
}

impl Message {

    /// Parses from a given Cursor into a Message, 
    pub fn parse(  src : &mut Cursor<&[u8]> ) -> Result<Self,Error> {
        match Self::get_u8(src)? {
            b'i' => {
                let modulus = SIZE::from_be_slice( Self::get_const_bytes(src, SIZE::BYTES)? );
                let g = SIZE::from_be_slice( Self::get_const_bytes(src, SIZE::BYTES)? );
                Ok(Message::AuthInit { modulus, g })
            },
            b'r' => {
                let public_key = SIZE::from_be_slice( Self::get_const_bytes(src, SIZE::BYTES)? );
                Ok(Message::AuthResponse { public_key })
            },
            b'm' => {
                let str = BytesMut::from(Self::get_bytes(src)? ).freeze();
                let mut iv = [0;CIPHER::BYTES];
                for i in 0..CIPHER::BYTES {
                    iv[i] = Self::get_u8(src)?;
                }
                Ok(Message::Message { msg: str.into(), iv })
            },
            b'a' => {
                Ok(Message::Accept)
            },
            b'd' => {
                Ok(Message::Decline)
            }
            b'e' => {
                let v = std::str::from_utf8(Self::get_bytes(src)?)?;
                Ok(Message::Error { msg: v.into() })
            },
            _ => Err(Error::from("invalid frame format")),
        }
    }

    /// Checks if from the given cursor point a Message can be parsed
    pub fn check(src: &mut Cursor<&[u8]>) -> Result<(), Error> {
        match Self::get_u8(src)? {
            b'i' => Self::skip(src, SIZE::BYTES * 2),
            b'r' => Self::skip(src, SIZE::BYTES),
            b'm' => {
                Self::get_bytes(src)?;                
                Self::skip(src, Aes128::BYTES)
            },
            b'a' => Ok(()),
            b'd' => Ok(()),
            b'e' => std::str::from_utf8(Self::get_bytes(src)?)
                .map(|_| ())
                .map_err(|v| Error::from(v)),
            _ => Err(Error::from("invalid frame format")),
        }
    }

    /// returns one u8 if there is enogh space or returns an Error::Incomplete
    fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8, Error> {
        if !src.has_remaining() {
            return Err(Error::Incomplete);
        }
        Ok(src.get_u8())
    }

    /// returns one u32 if there is enogh space or returns an Error::Incomplete
    fn get_u32(src: &mut Cursor<&[u8]>) -> Result<u32, Error> {
        if src.remaining() < 4 {
            return Err(Error::Incomplete);
        }
        Ok(src.get_u32())
    }

    /// returns one byteslice of a given prefix length if there is enough space or returns an Error::Incomplete
    fn get_bytes<'a>(src: &mut Cursor<&'a [u8]>) -> Result<&'a [u8], Error> {
        let len = Self::get_u32(src)? as u32;
        // println!("len: {len}");
        let start = src.position() as u32;
        let end = (src.get_ref().len()) as u32;
        // println!( "end: {end}, start: {start}");

        if end - start < len.into() {
            return Err(Error::Incomplete);
        }

        Self::skip(src, len as usize)?;

        Ok(&src.get_ref()[start as usize..(start + len) as usize])
    }

    /// returns one byteslice with a given length len if there is enough space or returns an Error::Incomplete
    fn get_const_bytes<'a>(src : &mut Cursor<&'a[u8]>, len : usize ) -> Result<&'a[u8], Error> {
        let start = src.position() as usize;
        let end = src.get_ref().len();

        if end - start < len {
            return Err(Error::Incomplete);
        } else {
            Self::skip(src, len as usize)?;
            Ok( &src.get_ref()[start..start+len] )
        }
    }

    /// Skips n bytes if there is enough space. Otherwise returns Error::Incomplete
    fn skip(src: &mut Cursor<&[u8]>, n: usize) -> Result<(), Error> {
        // println!("remaining: {} ", src.remaining());
        if src.remaining() < n {
            return Err(Error::Incomplete);
        }

        src.advance(n);
        Ok(())
    }

    /// Translates a message back into a buffer
    pub async fn write(drain : &mut (impl AsyncWrite + std::marker::Unpin), msg: &Message) -> Result<(),Error> {        
        match msg{
            Message::AuthInit { modulus, g } => {
                drain.write_u8(b'i').await?;
                drain.write(&modulus.to_be_bytes() ).await?;
                drain.write( &g.to_be_bytes()).await?;
            },
            Message::AuthResponse { public_key } => {
                drain.write_u8(b'r').await?;
                drain.write( &public_key.to_be_bytes()).await?;
            },
            Message::Message { msg, iv } => {
                let bytes = msg;
                drain.write_u8(b'm').await?;
                drain.write_u32( bytes.len() as u32).await?;
                drain.write(bytes ).await?;
                drain.write(iv).await?;
            },
            Message::Accept => drain.write_u8(b'a').await? ,
            Message::Decline => drain.write_u8(b'd').await?, 
            Message::Error { msg } => {
                drain.write_u8(b'e').await?;
                let bytes = msg.as_bytes();
                drain.write_u32( bytes.len() as u32).await?;
                drain.write(bytes ).await?;
            }
        }
        drain.flush().await?;
        Ok(())
    }
}

/// All possible Errors combined
#[derive(Debug)]
pub enum Error {
    Incomplete,
    IOError(io::Error),
    UTF8Error(Utf8Error),
    ParseError(&'static str),
    ReceiveError(RecvError),
    SendError,
    ProtocolError
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Error::ParseError(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::IOError(value)
    }
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Error::UTF8Error(value)
    }
}

impl From<RecvError> for Error{
    fn from(value: RecvError) -> Self {
        Error::ReceiveError(value)
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(_ : SendError<T>) -> Self {
        Error::SendError
    }
}

/// Abstract connection for our protocol
pub struct Connection {
    stream: BufWriter<TcpStream>,
    buffer: BytesMut,
}

impl Connection {

    /// Initialises a new Connection with a given TcpStream
    pub fn new(stream: TcpStream) -> Connection {
        Connection {
            stream: BufWriter::new(stream),
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Tries to read one frame from the buffer
    pub async fn read_frame(&mut self) -> Result<Option<Message>, Error> {
        loop{
            if let Some(msg) = self.parse_frame()? {
                return Ok(Some(msg));
            }
            
            if 0 == self.stream.read_buf( &mut self.buffer).await? {
                if self.buffer.is_empty() {
                    return Ok(None);
                } else {
                    return Err(Error::from( io::Error::new( io::ErrorKind::Other, "buffer is still not empty")));
                }
            } 
        }
    }

    /// Tries to parse a frame 
    fn parse_frame(&mut self) -> Result<Option<Message>, Error> {

        let mut buf = Cursor::new(&self.buffer[..]);

        match Message::check( &mut buf) {
            Ok(_) => {
                let len = buf.position() as usize;

                buf.set_position(0);

                let msgtype = Message::parse( &mut buf )?;

                self.buffer.advance(len);

                Ok(Some(msgtype))
            }
            Err(Error::Incomplete) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Writes one given frame into the buffer 
    pub async fn write_frame(&mut self, msg : &Message) -> Result<(),Error> {
        Message::write(&mut self.stream, msg).await
    }
}

/// Key derivation function for our secret 
pub fn derive_key( secret : SIZE ) -> [u8;CIPHER::BYTES] {
    let mut key = [0u8;CIPHER::BYTES];
    let mut hash = Sha1::new();
    hash.update(secret.to_be_bytes());
    key.copy_from_slice( &hash.finalize()[0..CIPHER::BYTES]);
    key
}