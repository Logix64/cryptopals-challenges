use bytes::{Buf, BufMut, BytesMut};

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
pub trait HashAlgorithm : Default {
    const BUFFERLEN : usize;
    type STATE;
    type OUTPUT;

    fn compress( &mut self, bytes : &[u8] );
    fn padding( &self, buf : &mut BytesMut );
    fn finalize(self) -> Self::OUTPUT;
}

/// Implements a basic Hasher for a given HashAlgorithm
impl<H : HashAlgorithm> Hasher<H> 
    where H::OUTPUT : Sized + Clone + Copy,
{
    pub fn new() -> Self {
        Self { core: H::default(), buf: BytesMut::with_capacity(2*H::BUFFERLEN) }
    }

    pub fn update(&mut self, bytes : &[u8] ) {
        self.buf.put(bytes);

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
    where H::OUTPUT : Sized + Clone + Copy
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

/// Calculates the MAC of a given (secret) key and message : MAC(key, message) = H( key || message )
pub fn mac<H : HashAlgorithm>( key : &[u8], message : &[u8] ) -> H::OUTPUT 
    where H::OUTPUT : Clone + Copy
{
    let mut hasher = Hasher::<H>::new();
    hasher.update(key);
    hasher.update(message);
    hasher.finalize()
}