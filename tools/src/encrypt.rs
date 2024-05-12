pub mod xor {

    /// Basic XOR Encryption/Decryption
    pub struct XOREnc {}

    impl XOREnc {
        /// Encrypts to byte slices with the same length.
        pub fn fixed_encrypt(bytes1: &[u8], bytes2: &[u8], output: &mut Vec<u8>) {
            assert!(bytes1.len() == bytes2.len());
            output.extend(bytes1.iter().zip(bytes2.iter()).map(|(u, v)| u ^ v));
        }

        /// Encrypts a byte slice with a single byte.
        pub fn single_key_encrypt(bytes: &[u8], key: u8, output: &mut Vec<u8>) {
            output.extend(bytes.iter().map(|&u| u ^ key))
        }

        /// Encrypts a byte slice with a repeating key. This is also called Vigenere Encryption.
        pub fn repeating_key_encrypt(bytes: &[u8], key: &[u8], output: &mut Vec<u8>) {
            output.extend(bytes.iter().zip(key.iter().cycle()).map(|(u, v)| u ^ v))
        }
    }

    #[test]
    fn test_fixed_encrypt() {
        let mut output = Vec::with_capacity(1);
        XOREnc::fixed_encrypt(&vec![0x80], &vec![0x38], &mut output);
        assert_eq!(output, vec![0x80 ^ 0x38]);
    }

    #[test]
    fn test_single_key_encrypt() {
        let mut output = Vec::with_capacity(1);
        XOREnc::single_key_encrypt(&vec![0x80], 0x38, &mut output);
        assert_eq!(output, vec![0x80 ^ 0x38]);
    }

    #[test]
    fn test_repeating_key_encrypt() {
        use crate::encode::hex::from_hex;

        let mut output = Vec::new();
        XOREnc::repeating_key_encrypt(
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            b"ICE",
            &mut output,
        );
        let res = from_hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", true).unwrap();

        assert_eq!(res, output);
    }
}

pub mod cipher {
    use std::vec::IntoIter;

    use bytes::{Buf, BufMut, BytesMut};

    use super::xor::XOREnc;

    /// Mutates the given buffer to get valid PKCS#7 padding with length len.
    pub fn pkcs7padding(buf: &mut BytesMut, len: usize) {
        let pad = (len - (buf.len() % len)) % len;
        buf.put_bytes(pad as u8, pad);
    }

    /// Checks for valid PKCS#7 padding and strips it. Returns Err if no valid padding is found.
    pub fn strip_pkcs7_padding<'a>(padded: &'a [u8]) -> Result<&'a [u8], ()> {
        let len = match u8::try_from(padded.len()) {
            Ok(a) => a,
            Err(_) => return Err(()),
        };

        for i in 1..len {
            let pad = len - i;
            if padded[(i as usize)..].iter().all(|v| *v == pad) {
                return Ok(&padded[0..(i as usize)]);
            }
        }

        Err(())
    }

    /// Basic trait for Block Ciphers like AES.
    pub trait CipherCore {
        const BYTES: usize;
        const BITS: usize;

        fn init(key: &[u8]) -> Self;
        fn encrypt(&self, text: &[u8]) -> Vec<u8>;
        fn decrypt(&self, text: &[u8]) -> Vec<u8>;
    }

    /// Modes for Encryption or Decryption.
    pub enum CipherMode {
        Encrypt,
        Decrypt,
    }

    /// ECB Implementation for a generic Cipher implementation.
    pub struct ECBMode<C: CipherCore> {
        cipher_mode: CipherMode,
        core: C,
        buf: BytesMut,
    }

    impl<C: CipherCore> ECBMode<C> {
        /// Initializes with a given key. The length of key must be the same as T::BYTES
        pub fn init(key: &[u8], cipher_mode: CipherMode) -> Self {
            Self {
                cipher_mode,
                core: C::init(key),
                buf: BytesMut::with_capacity(1024),
            }
        }

        /// Updates buffer
        pub fn update(&mut self, text: &[u8], output: &mut Vec<u8>) {
            self.buf.put(text);

            while let Some(block) = self.buf.get(0..C::BYTES) {
                match self.cipher_mode {
                    CipherMode::Decrypt => output.extend(self.core.decrypt(block)),
                    CipherMode::Encrypt => output.extend(self.core.encrypt(block)),
                }
                self.buf.advance(C::BYTES);
            }
        }

        /// Consumes self and returns the whole encrypted buffer.
        pub fn end(self, output: &mut Vec<u8>) {
            if !self.buf.is_empty() {
                let mut buf = self.buf;
                pkcs7padding(&mut buf, C::BYTES);
                let block = buf.get(0..C::BYTES).unwrap();
                match self.cipher_mode {
                    CipherMode::Decrypt => output.extend(self.core.decrypt(block)),
                    CipherMode::Encrypt => output.extend(self.core.encrypt(block)),
                }
            }
        }
    }

    /// CBC Mode for Block Cipher
    pub struct CBCMode<C: CipherCore> {
        core: C,
        buf: BytesMut,
        cipher_mode: CipherMode,
    }

    impl<C: CipherCore> CBCMode<C> {
        /// Initializes with a given key and iv. The length of key and iv must be the same as T::BYTES.
        pub fn init(key: &[u8], iv: &[u8], cipher_mode: CipherMode) -> Self {
            assert_eq!(iv.len(), C::BYTES);
            let mut buf = BytesMut::with_capacity(1024);
            buf.put(iv);
            Self {
                cipher_mode,
                core: C::init(key),
                buf,
            }
        }

        /// Updates buffer
        pub fn update(&mut self, text: &[u8], output: &mut Vec<u8>) {
            self.buf.put(text);

            while self.buf.len() >= 2 * C::BYTES {
                self.single_block(output);
                self.buf.advance(C::BYTES);
            }
        }

        /// Single block encryption. Assumes that there is enough space in the buffer.
        fn single_block(&mut self, output: &mut Vec<u8>) {
            let prev = self.buf.get(0..C::BYTES).unwrap().to_owned();
            let curr = self.buf.get_mut(C::BYTES..2 * C::BYTES).unwrap();

            let mut xor = Vec::with_capacity(C::BYTES);
            match self.cipher_mode {
                CipherMode::Encrypt => {
                    XOREnc::fixed_encrypt(&prev, curr, &mut xor);
                    let enc = self.core.encrypt(&xor);
                    curr.copy_from_slice(&enc);
                    output.extend(enc);
                }
                CipherMode::Decrypt => {
                    let dec: Vec<u8> = self.core.decrypt(&curr);
                    XOREnc::fixed_encrypt(&dec, &prev, &mut xor);
                    output.extend(xor);
                }
            }
        }

        /// Consumes self and returns the whole encrypted buffer.
        pub fn end(mut self, output: &mut Vec<u8>) {
            if self.buf.len() != C::BYTES {
                pkcs7padding(&mut self.buf, C::BYTES);
                self.single_block(output);
            }
        }
    }

    pub trait KeyStreamFormat {
        const BLOCKLEN: usize;

        fn get_block(&self, block_ctr: usize) -> Vec<u8>;
    }

    struct KeyStream<C: CipherCore, F: KeyStreamFormat> {
        core: C,
        format: F,
        block_ctr: usize,
        iter: IntoIter<u8>,
    }

    impl<C: CipherCore, F: KeyStreamFormat> KeyStream<C, F> {
        fn new(core: C, format: F) -> Self {
            assert_eq!(C::BYTES, F::BLOCKLEN);
            let block = core.encrypt(&format.get_block(0));
            Self {
                core,
                format,
                block_ctr: 0,
                iter: block.into_iter(),
            }
        }

        fn reset(&mut self) {
            self.block_ctr = 0;
            self.iter = self.format.get_block(0).into_iter();
        }
    }

    impl<C: CipherCore, F: KeyStreamFormat> Iterator for KeyStream<C, F> {
        type Item = u8;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().or_else(|| {
                self.block_ctr = self.block_ctr + 1;
                let block =  self.format.get_block( self.block_ctr );
                self.iter = self.core.encrypt(&block).into_iter();
                self.iter.next()
            })
        }
    }

    pub struct CTRMode<C: CipherCore, F: KeyStreamFormat> {
        keystream: KeyStream<C, F>,
    }

    impl<C: CipherCore, F: KeyStreamFormat> CTRMode<C, F> {
        pub fn init(key: &[u8], format: F) -> Self {
            Self {
                keystream: KeyStream::new(C::init(key), format),
            }
        }

        pub fn update(&mut self, text: &[u8], output: &mut Vec<u8>) {
            output.extend(
                text.iter()
                    .zip(self.keystream.by_ref().take(text.len()))
                    .map(|(&u, v)| u ^ v),
            )
        }

        pub fn reset(&mut self) {
            self.keystream.reset();
        }
    }

    #[test]
    fn test_pkcs7_padding() {
        let mut buf = BytesMut::with_capacity(200);
        buf.put(b"YELLOW SUBMARINE".as_slice());
        pkcs7padding(&mut buf, 20);
        assert_eq!(
            buf.get(0..),
            Some(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_slice())
        )
    }

    #[test]
    fn padding_validation() {
        assert_eq!(
            strip_pkcs7_padding(b"ICE ICE BABY\x04\x04\x04\x04".as_slice()),
            Ok(b"ICE ICE BABY".as_slice())
        );
        assert_eq!(
            strip_pkcs7_padding(b"ICE ICE BABY\x05\x05\x05\x05".as_slice()),
            Err(())
        );
        assert_eq!(
            strip_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\x04".as_slice()),
            Err(())
        );
    }
}

pub mod aes {
    use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};

    use super::cipher::{CBCMode, CTRMode, CipherCore, ECBMode, KeyStreamFormat};

    pub type AesEcb128 = ECBMode<Aes128>;
    pub type AesCbc128 = CBCMode<Aes128>;

    /// Implementation of CipherCore for AES-128
    pub struct Aes128 {
        key: Vec<u8>,
    }

    impl CipherCore for Aes128 {
        const BITS: usize = 128;
        const BYTES: usize = 16;

        fn init(key: &[u8]) -> Self {
            Self { key: key.to_vec() }
        }

        fn encrypt(&self, text: &[u8]) -> Vec<u8> {
            assert_eq!(text.len(), Self::BYTES);

            let mut cipher_ctx = CipherCtx::new().unwrap();

            cipher_ctx
                .encrypt_init(Some(Cipher::aes_128_ecb()), Some(&self.key), None)
                .unwrap();
            cipher_ctx.set_padding(false);

            let mut output = Vec::with_capacity(Self::BYTES);

            cipher_ctx.cipher_update_vec(text, &mut output).unwrap();
            cipher_ctx.cipher_final_vec(&mut output).unwrap();

            output
        }

        fn decrypt(&self, text: &[u8]) -> Vec<u8> {
            assert_eq!(text.len(), Self::BYTES);

            let mut cipher_ctx = CipherCtx::new().unwrap();

            cipher_ctx
                .decrypt_init(Some(Cipher::aes_128_ecb()), Some(&self.key), None)
                .unwrap();
            cipher_ctx.set_padding(false);

            let mut output = Vec::with_capacity(Self::BYTES);

            cipher_ctx.cipher_update_vec(text, &mut output).unwrap();
            cipher_ctx.cipher_final_vec(&mut output).unwrap();

            output
        }
    }

    /// Implementation of CTR format
    ///  64 bit unsigned little endian nonce
    ///  64 bit little endian block count
    pub struct NonceFormat {
        nonce: Vec<u8>,
    }

    impl NonceFormat {
        pub fn new(nonce: Vec<u8>) -> Self {
            assert_eq!(nonce.len(), 8);
            Self { nonce }
        }
    }

    impl KeyStreamFormat for NonceFormat {
        const BLOCKLEN: usize = 16;
        fn get_block(&self, block_ctr: usize) -> Vec<u8> {
            [
                self.nonce.clone(),
                (block_ctr as u64).to_le_bytes().to_vec(),
            ]
            .concat()
        }
    }

    pub type AesCtr128 = CTRMode<Aes128, NonceFormat>;
}
