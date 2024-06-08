use bytes::{Buf, BufMut, BytesMut};

use crate::encrypt::xor::XOREnc;

pub mod md4;
pub mod sha1;

pub struct Hasher<H : HashAlgorithm> {
    core : H, 
    buf : BytesMut
}

/// Allows translation from a given hash and block_ind to reconstruct an internal state
pub trait FromState : HashAlgorithm {
    fn from_state( hash : Self::OUTPUT, block_ind : u64 ) -> Self;
}

/// Basic pattern for a HashAlgorithm 
///  - compress for a BUFFERLEN bytes
///  - padding for less than BUFFERLEN bytes
///  - finalize for translating internal state to Hash
pub trait HashAlgorithm : Default 
    where Self::OUTPUT : Sized + Clone + Copy + AsRef<[u8]>
{
    const DIGEST_SIZE : usize;
    const BUFFERLEN : usize;
    type STATE;
    type OUTPUT;

    fn compress( &mut self, bytes : &[u8] );
    fn padding( &self, buf : &mut BytesMut );
    fn finalize(self) -> Self::OUTPUT;
}

/// Implements a basic Hasher for a given HashAlgorithm
impl<H : HashAlgorithm> Hasher<H> {
    pub fn new() -> Self {
        Self { core: H::default(), buf: BytesMut::with_capacity(2*H::BUFFERLEN) }
    }

    pub fn update(&mut self, bytes : impl AsRef<[u8]> ) {
        self.buf.put(bytes.as_ref());

        while let Some(block) = self.buf.get(0..H::BUFFERLEN) {
            self.core.compress(block);
            self.buf.advance(H::BUFFERLEN);
        }
    }

    pub fn finalize(mut self) -> H::OUTPUT {
        self.core.padding(&mut self.buf);
        while let Some(block) = self.buf.get(0..H::BUFFERLEN) {
            self.core.compress(block);
            self.buf.advance(H::BUFFERLEN);
        }
        debug_assert!(self.buf.is_empty());
        self.core.finalize()
    }
}

impl<H : FromState> Hasher<H> {
    fn from_state( hash : H::OUTPUT, block_ind : u64 ) -> Self {
        Self { core: H::from_state(hash, block_ind), buf: BytesMut::with_capacity(2*H::BUFFERLEN) }
    }
}

/// Implements Length-Extension Attack on a HashAlgorithm where the inner state can be reconstructed from the output
pub struct LengthExtender<H : FromState> {
    msg : BytesMut,
    hasher : Hasher<H>
}

impl<H : FromState> LengthExtender<H> 
{
    pub fn new( keylen : usize, msg : &[u8], hash : H::OUTPUT ) -> Self
        where H::OUTPUT : Clone + Copy
    {
        let mut bytes = BytesMut::with_capacity(2*msg.len() + keylen);
        
        // initialise dummy key to simulate padding
        bytes.put_bytes(0x00, keylen);
        bytes.put(msg);

        let inner = H::from_state(hash, 0);
        // simulate inner padding
        inner.padding( &mut bytes );
        // new block_ind 
        let block_ind = (bytes.len()/H::BUFFERLEN) as u64;
        // throw away dummy key
        bytes.advance(keylen);

        Self { msg: bytes, hasher: Hasher::from_state(hash, block_ind) }
    }

    pub fn update(&mut self, bytes : &[u8] ) {
        self.hasher.update(bytes);
        self.msg.put(bytes);
    }

    pub fn finalize(self) -> (Vec<u8>, H::OUTPUT) {
        (self.msg.into(), self.hasher.finalize())
    }
}

/// HMAC implementation of a generic HashAlgorithm
pub struct Hmac<H : HashAlgorithm> {
    inner : Hasher<H>,
    outer : Hasher<H>
}

impl<H : HashAlgorithm> Hmac<H>
{
    pub fn new( key : &[u8] ) -> Self {
        let hk = {             
            let mut hasher = Hasher::<H>::new();
            hasher.update(key);
            hasher.finalize()
        };

        let k = if key.len() >= H::BUFFERLEN {
            hk.as_ref()
        } else {
            key
        };

        let mut outer = Hasher::<H>::new();
        let mut output = Vec::with_capacity(k.chunk().len() );

        XOREnc::single_key_encrypt(k, 0x5c, &mut output);
        XOREnc::single_key_encrypt(&vec![0x00; H::BUFFERLEN - k.len()], 0x5c, &mut output);
        outer.update(&output[..]);
        output.clear();

        let mut inner = Hasher::<H>::new();
        XOREnc::single_key_encrypt(k.chunk(), 0x36, &mut output);
        XOREnc::single_key_encrypt(&vec![0x00; H::BUFFERLEN - k.len()], 0x36, &mut output);
        inner.update(&output[..]);
        output.clear();
        Self{ inner, outer }
    }

    pub fn update(&mut self, bytes : &[u8] ){
        self.inner.update(bytes);
    }

    pub fn finalize(mut self) -> H::OUTPUT {
        let h_inner = self.inner.finalize();
        self.outer.update(h_inner);
        self.outer.finalize()
    }
}

/// Calculates the MAC of a given (secret) key and message : MAC(key, message) = H( key || message )
pub fn mac<H : HashAlgorithm>( key : &[u8], message : &[u8] ) -> H::OUTPUT 
{
    let mut hasher = Hasher::<H>::new();
    hasher.update(key);
    hasher.update(message);
    hasher.finalize()
}

#[macro_export]
macro_rules! hash {
    ($algo:ty,$($x:expr),*) => {
        {
            let mut temp = <$algo>::new();
            $(
                temp.update($x);
            )*
            temp.finalize()
        }
    };
}

#[macro_export]
macro_rules! hash_by_algo {
    ($algo:ty,$($x:expr),*) => {
        {
            let mut temp = $crate::digest::Hasher::<$algo>::new();
            $(
                temp.update($x);
            )*
            temp.finalize()
        }
    };
}


#[test]
fn test_hmac_sha1() {
    // test vector for sha-1 from https://datatracker.ietf.org/doc/html/rfc2202 
    use sha1::Sha1Core;
    use crate::encode::hex::to_hex;

    let mut hmac = Hmac::<Sha1Core>::new(b"Jefe");
    hmac.update(b"what do ya want for nothing?");

    assert_eq!(to_hex(&hmac.finalize()),"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}