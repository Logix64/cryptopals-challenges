use std::fmt::{Debug, Display};

use buffering::Error;
use keyexchange::ExchangeError;
use negotiation::NegotiationError;
use verification::VerificationError;

pub mod server;
pub mod client;

pub mod buffering {
    use std::io::{self, Cursor};

    use bytes::{Buf, BytesMut};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufWriter};

    /// returns one u8 if there is enogh space or returns an Error::Incomplete
    pub fn get_u8<T>(src: &mut Cursor<&[u8]>) -> Result<u8, Error<T>> {
        if !src.has_remaining() {
            return Err(Error::Incomplete);
        }
        Ok(src.get_u8())
    }

    /// returns one u32 if there is enogh space or returns an Error::Incomplete
    pub fn get_u32<T>(src: &mut Cursor<&[u8]>) -> Result<u32, Error<T>> {
        if src.remaining() < 4 {
            return Err(Error::Incomplete);
        }
        Ok(src.get_u32())
    }

    /// returns one byteslice of a given prefix length if there is enough space or returns an Error::Incomplete
    pub fn get_bytes<'a,T>(src: &mut Cursor<&'a [u8]>) -> Result<&'a [u8], Error<T>> {
        let len = get_u32(src)? as u32;
        // println!("len: {len}");
        let start = src.position() as u32;
        let end = (src.get_ref().len()) as u32;
        // println!( "end: {end}, start: {start}");

        if end - start < len.into() {
            return Err(Error::Incomplete);
        }

        skip(src, len as usize)?;

        Ok(&src.get_ref()[start as usize..(start + len) as usize])
    }

    /// returns one byteslice with a given length len if there is enough space or returns an Error::Incomplete
    pub fn get_const_bytes<'a,T>(src : &mut Cursor<&'a[u8]>, len : usize ) -> Result<&'a[u8], Error<T>> {
        let start = src.position() as usize;
        let end = src.get_ref().len();

        if end - start < len {
            return Err(Error::Incomplete);
        } else {
            skip(src, len as usize)?;
            Ok( &src.get_ref()[start..start+len] )
        }
    }

    /// Skips n bytes if there is enough space. Otherwise returns Error::Incomplete
    pub fn skip<T>(src: &mut Cursor<&[u8]>, n: usize) -> Result<(), Error<T> > {
        // println!("remaining: {} ", src.remaining());
        if src.remaining() < n {
            return Err(Error::Incomplete);
        }

        src.advance(n);
        Ok(())
    }

    /// Error in buffering
    #[derive(Debug)]
    pub enum Error<T>{
        Incomplete,
        IOError(io::Error),
        Other(T)
    }

    impl<T> Error<T> {
        pub fn from_inner(value : T) -> Error<T> {
            Error::Other(value)
        }
    }

    impl<T> From<io::Error> for Error<T> {
        fn from(value: io::Error) -> Self {
            Error::IOError(value)
        }
    }

    pub trait Parse : Sized{
        type Info;
        fn check(src : &mut Cursor<&[u8]> ) -> Result<(),Error<Self::Info>>;
        fn parse(src : &mut Cursor<&[u8]> ) -> Result<Self,Error<Self::Info>>;
        #[allow(async_fn_in_trait)]
        async fn write(src : &mut (impl AsyncWrite + std::marker::Unpin), msg : &Self ) -> Result<(),Error<Self::Info>>;
    }

    pub struct Connection<S : AsyncWrite + AsyncRead + Unpin>{
        stream : BufWriter<S>, 
        buffer : BytesMut,
    }

    impl<S : AsyncWrite + AsyncRead + Unpin> Connection<S> {

        /// Initialises a new Connection with a given TcpStream
        pub fn new(stream : S) -> Self{
            Connection { stream : BufWriter::new(stream) , buffer: BytesMut::with_capacity(4096) }
        }

        /// Tries to parse a frame 
        fn parse_frame<M : Parse>(&mut self) -> Result<Option<M>, Error<M::Info>> {
            let mut buf = Cursor::new(&self.buffer[..]);

            match  M::check( &mut buf) {
                Ok(_) => {
                    let len = buf.position() as usize;

                    buf.set_position(0);

                    let msgtype = M::parse( &mut buf )?;

                    self.buffer.advance(len);

                    Ok(Some(msgtype))
                }
                Err(Error::Incomplete) => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// Tries to read one frame from the buffer
        async fn read_frame<M: Parse>(&mut self) -> Result<Option<M>, Error<M::Info>> {
            loop{
                if let Some(msg) = self.parse_frame()? {
                    return Ok(Some(msg));
                }
                
                if 0 == self.stream.read_buf( &mut self.buffer).await? {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    } else {
                        return Err(Error::IOError( io::Error::new( io::ErrorKind::Other, "buffer is still not empty")));
                    }
                } 
            }
        }

        /// Writes one given frame into the buffer 
        pub async fn write_frame<M : Parse>(&mut self, msg : &M) -> Result<(),Error<M::Info>> {
            M::write(&mut self.stream, msg).await
        }

        pub async fn get_frame<M : Parse>(&mut self) -> Result<M,Error<M::Info>> {
            loop {
                if let Some(msg) = self.read_frame::<M>().await? {
                    return Ok(msg);
                }
            }
        }

    } 


}

pub mod crypto{
    use crypto_bigint::{modular::constant_mod::{Residue, ResidueParams}, Encoding, Uint, U1536};
    use tools::{bigint::uint_dh::ConstDiffieHellmannParams, digest::{sha1::Sha1Core, HashAlgorithm, Hasher}, generate_params};

    use crate::{buffering::Error, negotiation::NegotiationError};

    const LIMBS : usize = U1536::LIMBS;

    /// Trait for SRP Parameters 
    pub trait SRPParameters<const LIMBS : usize> : ConstDiffieHellmannParams<LIMBS> 
        where Self::Hashing : HashAlgorithm
    {
        // Hash Algorithm for HMAC Validation and Password Hash Derivation
        type Hashing;
        const FACTOR : Residue<Self,LIMBS>;
    }

    generate_params!(NistParams, 
        Uint<LIMBS>, 
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 
        2  
    );

    impl SRPParameters<LIMBS> for NistParams {
        type Hashing = Sha1Core;
        const FACTOR : Residue<Self,LIMBS> = Residue::new(&Uint::from_u32(3));
    }

    generate_params!(DifferentParams,
        Uint<LIMBS>, 
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 
        2 
    );

    impl SRPParameters<LIMBS> for DifferentParams{
        type Hashing = Sha1Core;
        const FACTOR : Residue<Self,LIMBS> = Residue::new(&Uint::from_u32(5));
    }

    /// Standin for SRP parameters
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum SRPParam{
        DifferentParams,
        NistParams,
    }

    impl Eq for SRPParam{}

    impl SRPParam {
        pub fn from_u8(value : u8) -> Result<Self,Error<NegotiationError>>  {
            match value {
                b'a' => Ok(Self::NistParams),
                b'd' => Ok(Self::DifferentParams),
                _ => Err(Error::from_inner(NegotiationError::InvalidParameters))
            }
        }

        pub fn get_u8(&self) -> u8 {
            match &self{
                Self::NistParams => b'a',
                Self::DifferentParams => b'd',
            }
        }

        pub fn get_modulus(&self) -> Uint<LIMBS>{
            match self{
                Self::DifferentParams => DifferentParams::MODULUS,
                Self::NistParams => NistParams::MODULUS,
            }
        }

        pub fn get_factor(&self) -> Uint<LIMBS>{
            match self{
                Self::DifferentParams=> DifferentParams::FACTOR.retrieve(),
                Self::NistParams => NistParams::FACTOR.retrieve(),
            }
        }
    }

    impl core::fmt::Display for SRPParam{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NistParams => f.write_str("NIST"),
                Self::DifferentParams => f.write_str("DIFFERENT"),
            }
        }
    }

    /// Translates a hash into a Uint 
    pub fn hash_to_uint<const XLIMBS : usize>( hash : impl AsRef<[u8]> + Copy + Clone ) -> Uint<XLIMBS> {
        assert!(hash.as_ref().len() <= Uint::<XLIMBS>::BYTES );
        let mut bytes = vec![0;Uint::<XLIMBS>::BYTES];
        bytes[0..hash.as_ref().len()].copy_from_slice(hash.as_ref());
        Uint::from_be_slice(&bytes)
    }

    /// Derives the key from a given secret information
    pub fn derive_key<const LIMBS : usize, PARAM : SRPParameters<LIMBS> >(num : &Uint<LIMBS> ) -> <<PARAM as SRPParameters<LIMBS>>::Hashing as HashAlgorithm>::OUTPUT
        where Uint<LIMBS> : Encoding
    {
        let mut hasher = Hasher::<PARAM::Hashing>::new();
        hasher.update(num.to_be_bytes());
        hasher.finalize()
    }

    /// Derives u in the SRP Protocol -- can be adjusted to be robust against Replay attacks
    pub fn derive_u<const XLIMBS : usize, T : SRPParameters<XLIMBS> >(server_public_key : &Uint<XLIMBS>, client_public_key : &Uint<XLIMBS> ) -> Uint<XLIMBS> 
        where Uint<XLIMBS> : Encoding
    {
        let mut hasher = Hasher::<T::Hashing>::new();
        hasher.update(server_public_key.to_be_bytes());
        hasher.update(client_public_key.to_be_bytes());
        
        let hash = hasher.finalize();
        hash_to_uint(hash)        
    }

    /// Password Derivation function for a given HashAlgorithm
    pub fn generate_password<H : HashAlgorithm>( password : String, salt : impl AsRef<[u8]> ) -> H::OUTPUT 
        where H::OUTPUT : Copy + Clone + AsRef<[u8]>
    {
        let mut hasher = Hasher::<H>::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.finalize()
    }

    /// Derives v for given SRP Parameters
    pub fn derive_v<const XLIMBS : usize, P : SRPParameters<XLIMBS>>( hash : impl AsRef<[u8]> ) -> Residue<P,XLIMBS> {
        P::G.pow::<LIMBS>(&hash_to_uint(&hash))
    }

}

/// Catchall Error for any part of the Protocol
#[derive(Debug)]
pub enum ValidationError {
    Negotiation(Error<NegotiationError>),
    Exchange(Error<ExchangeError>),
    Verification(Error<VerificationError>),
    Protocol,
}

impl ValidationError {
    pub fn is_protocol_error(&self) -> bool{
        match self{
            Self::Protocol => true,
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

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exchange(v) => v.fmt(f),
            Self::Negotiation(v) => v.fmt(f),
            Self::Verification(v) => v.fmt(f),
            Self::Protocol => f.write_str("protocol error"),
        }
    }
}

/// Implements Negotiation part of the SRP Protocol 
pub mod negotiation{
    use std::io::Cursor;
    use crate::{buffering::{get_u8, Error, Parse}, crypto::SRPParam};

    pub enum Negotiation {
        AuthInit{
            param : SRPParam
        },
        Accept,
        Decline,
    }

    #[derive(Debug,Clone)]
    pub enum NegotiationError{
        InvalidParameters,
        UnknownMessage,
        NoCommonParameters
    }

    impl core::fmt::Display for NegotiationError{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::InvalidParameters => write!(f, "InvalidParameters"),
                Self::UnknownMessage => write!(f, "UnknownMessage"),
                Self::NoCommonParameters => write!(f, "NoCommonParameters"),
            }
        }
    }
    
    impl core::fmt::Display for Negotiation{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Negotiation :")?;
            match self {
                Self::AuthInit { param } => {
                    f.write_str("request params - ")?;
                    param.fmt(f) 
                },
                Self::Decline => f.write_str("decline request"),
                Self::Accept => f.write_str("accept request"),
            }
        }
    }

    impl Parse for Negotiation{
        type Info = NegotiationError;

        fn check(src: &mut Cursor<&[u8]> ) -> Result<(),Error<Self::Info>> {
            match get_u8(src)? {
                b'i' => {
                    SRPParam::from_u8(get_u8(src)?).map(|_| ())
                },
                b'+' => Ok(()),
                b'-' => Ok(()),
                _ => Err(Error::from_inner(NegotiationError::UnknownMessage))
            }
        }
    
        fn parse(src: &mut Cursor<&[u8]> ) -> Result<Negotiation, Error<Self::Info>> {
            match get_u8(src)? {
                b'i' => {
                    Ok(Self::AuthInit{ param : SRPParam::from_u8(get_u8(src)?)? } )
                },
                b'+' => Ok(Self::Accept),
                b'-' => Ok(Self::Decline),
                _ => Err(Error::from_inner(NegotiationError::UnknownMessage))
            }
        }
        
        async fn write(src : &mut (impl tokio::io::AsyncWriteExt + std::marker::Unpin), msg : &Self ) -> Result<(),Error<Self::Info>> {
            match msg {
                Self::AuthInit { param } => {
                    src.write_u8(b'i').await?;
                    src.write_u8(param.get_u8()).await?;
                },
                Self::Accept => { src.write_u8(b'+').await?; },
                Self::Decline =>{ src.write_u8(b'-').await?; },
            }
            src.flush().await.map_err(|v| Error::from(v) )
        }

    }

}

/// Implements KeyExchange part of the SRP Protocol 
pub mod keyexchange {
    use bytes::{Bytes, BytesMut};

    use crate::buffering::{get_bytes, get_u8, Error, Parse};

    pub enum KeyExchange{
        GetUsername{
            email : String,
            public_key : Bytes
        },
        GetPublicKey{
            salt : Bytes, 
            public_key : Bytes
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

        fn check(src : &mut std::io::Cursor<&[u8]> ) -> Result<(),crate::buffering::Error<Self::Info>> {
            match get_u8(src)? {
                b'u' => {
                    let bytes = get_bytes(src)?;
                    std::str::from_utf8( bytes ).map_err(|_| Error::from_inner( ExchangeError::UTF8Error ) ).map(|_| ())?;
                    get_bytes(src)?;
                },
                b'p' => {
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
                    Ok(Self::GetPublicKey { salt:salt.freeze(), public_key: public_key.freeze() })
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
                Self::GetPublicKey { salt, public_key } => {
                    src.write_u8(b'p').await?;
                    src.write_u32(salt.len() as u32).await?;
                    src.write_all(salt).await?;
                    src.write_u32(public_key.len() as u32).await?;
                    src.write_all(public_key).await?;
                }
            }
            src.flush().await?;
            Ok(())
        }

    }
}

/// Implements Verification part of the SRP Protocol 
pub mod verification{
    use bytes::{Bytes, BytesMut};

    use crate::buffering::{get_bytes, get_u8, Error, Parse};

    #[derive(Debug)]
    pub enum VerificationError{
        UnknownMessage
    }

    pub enum Verification {
        HMACRequest{
            hmac : Bytes, 
            salt : Bytes
        },
        Accept,
        Reject,
    }

    impl Parse for Verification{
        type Info = VerificationError;

        fn check(src : &mut std::io::Cursor<&[u8]> ) -> Result<(),crate::buffering::Error<Self::Info>> {
            match get_u8(src)?{
                b'r' => { 
                    get_bytes(src)?;
                    get_bytes(src)?;
                    Ok(())
                },
                b'x' => Ok(()),
                b'o' => Ok(()),
                _ => Err(Error::from_inner(VerificationError::UnknownMessage))
            }
        }
        
        fn parse(src : &mut std::io::Cursor<&[u8]> ) -> Result<Self,crate::buffering::Error<Self::Info>> {
            match get_u8(src)?{
                b'r' => { 
                    let hmac = BytesMut::from(get_bytes(src)?);
                    let salt = BytesMut::from(get_bytes(src)?);
                    Ok( Verification::HMACRequest { hmac : hmac.freeze(), salt : salt.freeze() })
                },
                b'x' => Ok(Verification::Reject),
                b'o' => Ok(Verification::Accept),
                _ => Err(Error::from_inner(VerificationError::UnknownMessage))
            }
        }
        
        async fn write(src : &mut (impl tokio::io::AsyncWriteExt + std::marker::Unpin), msg : &Self ) -> Result<(),crate::buffering::Error<Self::Info>> {
            match msg {
                Verification::HMACRequest { hmac, salt } => {
                    src.write_u8(b'r').await?;
                    src.write_u32(hmac.len() as u32).await?;
                    src.write_all(hmac).await?;
                    src.write_u32(salt.len() as u32).await?;
                    src.write_all(salt).await?;
                },
                Verification::Accept => {
                    src.write_u8(b'o').await?;
                },
                Verification::Reject => {
                    src.write_u8(b'x').await?;
                }
            }
            src.flush().await?;
            Ok(())
        }
    }

}
