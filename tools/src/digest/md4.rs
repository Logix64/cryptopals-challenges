use bytes::BufMut;

use super::{FromState, HashAlgorithm, Hasher};

pub type Md4 = Hasher<Md4Core>;

pub struct Md4Core{
    state : [u32;4],
    block_ind : u64
}

impl Default for Md4Core {
    fn default() -> Self {
        Self { state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476], block_ind: 0 }
    }
}

impl HashAlgorithm for Md4Core {
    const BUFFERLEN : usize = 64;
    type STATE = [u32;4];
    type OUTPUT = [u8;16];

    // code directly based on RustCrypto's implementation of MD4 : https://github.com/RustCrypto/hashes/tree/master/md4 
    fn compress( &mut self, bytes : &[u8] ) {
        assert_eq!(bytes.len(), Self::BUFFERLEN);

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let mut data = [0u32;16];
        for (o, chunk) in data.iter_mut().zip(bytes.chunks_exact(4)) {
            *o = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        self.block_ind = self.block_ind + 1;

        // round 1
        for &i in &[0, 4, 8, 12] {
            a = op1(a, b, c, d, data[i], 3);
            d = op1(d, a, b, c, data[i + 1], 7);
            c = op1(c, d, a, b, data[i + 2], 11);
            b = op1(b, c, d, a, data[i + 3], 19);
        }

        // round 2
        for i in 0..4 {
            a = op2(a, b, c, d, data[i], 3);
            d = op2(d, a, b, c, data[i + 4], 5);
            c = op2(c, d, a, b, data[i + 8], 9);
            b = op2(b, c, d, a, data[i + 12], 13);
        }

        // round 3
        for &i in &[0, 2, 1, 3] {
            a = op3(a, b, c, d, data[i], 3);
            d = op3(d, a, b, c, data[i + 8], 9);
            c = op3(c, d, a, b, data[i + 4], 11);
            b = op3(b, c, d, a, data[i + 12], 15);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }


    fn padding( &self, buf : &mut bytes::BytesMut ) {
        let len = ((self.block_ind * 64 + buf.len() as u64) * 8).to_le_bytes();
        let tail = buf.len() % Self::BUFFERLEN;
        let n_zeros = if tail < 56 { 55 - tail } else { 63 - tail + 55 };

        buf.put_u8(0x80);
        buf.put_bytes(0x00, n_zeros);
        buf.put(&len[..])
    }

    fn finalize(self) -> Self::OUTPUT {
        let mut bytes = [0u8; 16];
        bytes
            .iter_mut()
            .zip(self.state.map(|v| v.to_le_bytes()).concat())
            .for_each(|(u, v)| *u = v);
        bytes
    }

}

impl FromState for Md4Core{
    fn from_state( hash : Self::OUTPUT, block_ind : u64 ) -> Self {
        let mut state = [0u32; 4];
        state
            .iter_mut()
            .zip(hash.chunks_exact(4))
            .for_each(|(v, chunks)| *v = (chunks[0] as u32) << 0 | (chunks[1] as u32) << 8 | (chunks[2] as u32) << 16 | (chunks[3] as u32) << 24 );
        Self { state, block_ind }
    }
}


fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
}

fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    a.wrapping_add(g(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x5A82_7999)
        .rotate_left(s)
}

fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    a.wrapping_add(h(b, c, d))
        .wrapping_add(k)
        .wrapping_add(0x6ED9_EBA1)
        .rotate_left(s)
}

#[test]
fn  test_md4() {
    use crate::encode::hex::to_hex;

    // test vectors again from wikipedia : https://en.wikipedia.org/wiki/MD4
    let mut hasher = Md4::new();
    hasher.update(b"The quick brown fox jumps over the lazy dog");
    let state = hasher.finalize();

    assert_eq!(to_hex(&state), "1bee69a46ba811185c194762abaeae90");
    
    let mut hasher = Md4::new();
    hasher.update(b"The quick brown fox jumps over the lazy cog");
    let state = hasher.finalize();

    assert_eq!(to_hex(&state), "b86e130ce7028da59e672d56ad0113df")
    
}