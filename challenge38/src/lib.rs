use std::{fmt::{Debug, Display}, io};

use challenge36::{buffering::Error, negotiation::NegotiationError, verification::VerificationError};
use keyexchange::ExchangeError;

pub mod server;

/// Catchall Error for any part of the Protocol
#[derive(Debug)]
pub enum ValidationError {
    Negotiation(Error<NegotiationError>),
    Exchange(Error<ExchangeError>),
    Verification(Error<VerificationError>),
    IOError(io::Error),
    SendReceiveError,
    Protocol,
}

impl ValidationError {
    pub fn is_protocol_error(&self) -> bool{
        match self{
            Self::Protocol => true,
            _ => false
        }
    }

    pub fn is_incomplete(&self) -> bool {
        match self{
            Self::Negotiation( Error::Incomplete ) => true,
            Self::Exchange( Error::Incomplete ) => true,
            Self::Verification( Error::Incomplete ) => true,
            _ => false
        }
    }
}

impl From<Error<NegotiationError>> for ValidationError {
    fn from(value: Error<NegotiationError>) -> Self {
        Self::Negotiation(value)
    }
}

impl From<Error<ExchangeError>> for ValidationError {
    fn from(value: Error<ExchangeError>) -> Self {
        Self::Exchange(value)
    }
}

impl From<Error<VerificationError>> for ValidationError {
    fn from(value: Error<VerificationError>) -> Self {
        Self::Verification(value)
    }
}

impl From<io::Error> for ValidationError {
    fn from(value: io::Error) -> Self{
        Self::IOError(value)
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exchange(v) => v.fmt(f),
            Self::Negotiation(v) => v.fmt(f),
            Self::Verification(v) => v.fmt(f),
            Self::IOError(v) => <io::Error as Debug>::fmt(v, f),
            Self::SendReceiveError => f.write_str("send receive error"),
            Self::Protocol => f.write_str("protocol error"),
        }
    }
}

pub mod keyexchange {
    use bytes::{Bytes, BytesMut};
    use challenge36::buffering::{self, get_bytes, get_u8, Error, Parse};


    pub enum KeyExchange{
        GetUsername{
            email : String, 
            public_key : Bytes,
        },
        GetPublicKey{
            salt : Bytes,
            public_key : Bytes,
            u : Bytes
        }
    }

    impl core::fmt::Display for KeyExchange{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("key exchange : ")?;
            match self{
                Self::GetPublicKey {..} => {
                    f.write_str("get public key")
                },
                Self::GetUsername { .. } => {
                    f.write_str("get username")
                }
            }
        }
    }

    #[derive(Debug)]
    pub enum ExchangeError{
        UTF8Error,
        UnknownMessage
    }

    impl core::fmt::Display for ExchangeError{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self{
                Self::UTF8Error => f.write_str("utf8 error"),
                Self::UnknownMessage => f.write_str("unknown message"),
            }
        }
    }

    impl Parse for KeyExchange {
        type Info =  ExchangeError;

        fn check(src : &mut std::io::Cursor<&[u8]> ) -> Result<(),buffering::Error<Self::Info>> {
            match get_u8(src)? {
                b'u' => {
                    let bytes = get_bytes(src)?;
                    std::str::from_utf8( bytes ).map_err(|_| Error::from_inner( ExchangeError::UTF8Error ) ).map(|_| ())?;
                    get_bytes(src)?;
                },
                b'p' => {
                    get_bytes(src)?;
                    get_bytes(src)?;
                    get_bytes(src)?;
                },
                _ => return Err(Error::from_inner(ExchangeError::UnknownMessage)),
            }
            Ok(())
        }

        fn parse(src : &mut std::io::Cursor<&[u8]> ) -> Result<Self,Error<Self::Info>> {
            match get_u8(src)? {
                b'u' => {
                    let bytes = get_bytes(src)?;
                    let email = std::str::from_utf8( bytes ).map_err(|_| Error::from_inner( ExchangeError::UTF8Error ) )?;
                    let public_key = BytesMut::from(get_bytes(src)?);
                    Ok(Self::GetUsername{ email : email.into(), public_key : public_key.freeze()})
                },
                b'p' => {
                    let salt = BytesMut::from(get_bytes(src)?);
                    let public_key = BytesMut::from(get_bytes(src)?);
                    let u = BytesMut::from(get_bytes(src)?);
                    
                    Ok(Self::GetPublicKey { salt:salt.freeze(), public_key: public_key.freeze(), u : u.freeze() })
                },
                _ => Err(Error::from_inner(ExchangeError::UnknownMessage))
            }
        }

        async fn write(src : &mut (impl tokio::io::AsyncWriteExt + std::marker::Unpin), msg : &Self ) -> Result<(),Error<Self::Info>> {
            match msg {
                Self::GetUsername { email, public_key } => {
                    src.write_u8(b'u').await?;
                    let bytes = email.as_bytes();
                    src.write_u32(bytes.len() as u32).await?;
                    src.write_all( email.as_bytes()).await?;
                    src.write_u32(public_key.len() as u32).await?;
                    src.write_all(public_key).await?;
                }
                Self::GetPublicKey { salt, public_key, u } => {
                    src.write_u8(b'p').await?;
                    src.write_u32(salt.len() as u32).await?;
                    src.write_all(salt).await?;
                    src.write_u32(public_key.len() as u32).await?;
                    src.write_all(public_key).await?;
                    src.write_u32(u.len() as u32).await?;
                    src.write_all(u).await?;
                }
            }
            src.flush().await?;
            Ok(())
        }

    }
}
