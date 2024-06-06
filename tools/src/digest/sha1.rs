use bytes::BufMut;

use super::{FromState, HashAlgorithm, Hasher};

pub type Sha1 = Hasher<Sha1Core>;

pub struct Sha1Core {
    state: [u32; 5],
    block_ind: u64,
}

impl Default for Sha1Core {
    fn default() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            block_ind: 0,
        }
    }
}

impl HashAlgorithm for Sha1Core {
    const DIGEST_SIZE : usize = 20;
    const BUFFERLEN: usize = 64;
    type STATE = [u32; 5];
    type OUTPUT = [u8; 20];

    fn compress(&mut self, bytes: &[u8]) {
        assert_eq!(bytes.len(), Self::BUFFERLEN);

        let mut w = [0u32; 80];
        w.iter_mut()
            .zip(bytes.chunks_exact(4))
            .for_each(|(u, v)| *u = u32::from_be_bytes([v[0], v[1], v[2], v[3]]));

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1)
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => (f1(b, c, d), 0x5A827999),
                20..=39 => (f2(b, c, d), 0x6ED9EBA1),
                40..=59 => (f3(b, c, d), 0x8F1BBCDC),
                _ => (f2(b, c, d), 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.block_ind = self.block_ind + 1;
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    fn padding(&self, buf: &mut bytes::BytesMut) {
        let len = ((self.block_ind * 64 + buf.len() as u64) * 8).to_be_bytes();
        let tail = buf.len() % Self::BUFFERLEN;
        let n_zeros = if tail < 56 { 55 - tail } else { 63 - tail + 55 };
        buf.put_u8(0x80);
        buf.put_bytes(0x00, n_zeros);
        buf.put(&len[..])
    }

    fn finalize(self) -> Self::OUTPUT {
        let mut bytes = [0u8; 20];
        bytes
            .iter_mut()
            .zip(self.state.map(|v| v.to_be_bytes()).concat())
            .for_each(|(u, v)| *u = v);
        bytes
    }
}

impl FromState for Sha1Core {
    fn from_state(hash: Self::OUTPUT, block_ind: u64) -> Self {
        let mut state = [0u32; 5];
        state
            .iter_mut()
            .zip(hash.chunks_exact(4))
            .for_each(|(v, chunks)| *v = u32::from_be_bytes([chunks[0], chunks[1], chunks[2], chunks[3] ]));
        Self { state, block_ind }
    }
}

#[test]
fn test_sha1() {
    use crate::encode::hex::to_hex;

    // test vectors again from wikipedia : https://en.wikipedia.org/wiki/SHA-1
    let mut hasher = Sha1::new();
    hasher.update(&b"The quick brown fox jumps over the lazy dog"[..]);
    let state = hasher.finalize();

    assert_eq!(to_hex(&state), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");

    let mut hasher = Sha1::new();
    hasher.update(&b"The quick brown fox jumps over the lazy cog"[..]);
    let state = hasher.finalize();

    assert_eq!(to_hex(&state), "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
}

#[inline]
fn f1(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

#[inline]
fn f2(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn f3(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}
