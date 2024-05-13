use bytes::{Buf, BufMut, BytesMut};

mod md4;
pub mod sha1;

pub struct Hasher<H : HashAlgorithm> {
    core : H, 
    buf : BytesMut
}

pub trait HashAlgorithm : Default {
    const BUFFERLEN : usize;
    type STATE;
    type OUTPUT;

    fn compress( &mut self, bytes : &[u8] );
    fn padding( &self, buf : &mut BytesMut );
    fn finalize(self) -> Self::OUTPUT;
}

impl<H : HashAlgorithm> Hasher<H> 
    where H::STATE : Sized,
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

pub fn mac<H : HashAlgorithm>( key : &[u8], message : &[u8] ) -> H::OUTPUT {
    let mut hasher = Hasher::<H>::new();
    hasher.update(key);
    hasher.update(message);
    hasher.finalize()
}