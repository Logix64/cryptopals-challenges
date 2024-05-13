use rand::random;
use tools::encrypt::{aes::Aes128, cipher::{CBCMode, CipherCore, CipherMode}, xor::XOREnc};

const PREFIX : &str = "comment1=cooking%20MCs;userdata=";
const POSTFIX : &str = ";comment2=%20like%20a%20pound%20of%20bacon";
const BLOCKSIZE : usize = 16;

struct CbcBitflip {
    key : Vec<u8>,
    iv : Vec<u8>
}

impl CbcBitflip {

    fn new<T : CipherCore>( key : Vec<u8>, iv : Vec<u8> ) -> Self {
        assert_eq!(key.len(), T::BYTES);
        assert_eq!(key.len(), T::BYTES);
        CbcBitflip{ key, iv }
    }

    fn encrypt<T : CipherCore>( &self, input : &str, output : &mut Vec<u8> ) {
        let str = PREFIX.to_owned() + &input.to_owned().replace(";", "%3B").replace("=", "%3D") + POSTFIX;
        let mut cbc = CBCMode::<T>::init(&self.key, &self.iv, CipherMode::Encrypt);
        cbc.update(str.as_bytes(), output);
        cbc.end(output);
    }

    fn check_admin<T : CipherCore>(&self, input : &[u8] ) -> Result<bool, Vec<u8>> {
        let mut output = Vec::new();

        let mut cbc = CBCMode::<T>::init(&self.key, &self.iv, CipherMode::Decrypt);
        cbc.update(input, &mut output);
        cbc.end(&mut output);

        if output.iter().any( | u | u >= &0x80 ) {
            Err(output)
        } else {
            let string = String::from_iter(output.iter().map(|&u| (u as char) ));

            string.chars().for_each(  | u | u.escape_debug().for_each( | v | print!("{v}"))   );
            println!();
            Ok(string.contains(";admin=true;"))
        }
    }
}

fn main() {
    let key : [u8;16] =  random();

    let bitflip = CbcBitflip::new::<Aes128>(key.to_vec(), key.to_vec() );

    let message = "AAAAAAAAAAAAAAAAAAAAA";

    let mut enc = Vec::new(); 
    bitflip.encrypt::<Aes128>( message, &mut enc );

    assert!( enc.len() >= 3*BLOCKSIZE);

    let msg = vec![ &enc[0..BLOCKSIZE], &[0;BLOCKSIZE], &enc[0..BLOCKSIZE]].concat();

    match bitflip.check_admin::<Aes128>(&msg) {
        Ok(_) => panic!(),
        Err(vec) => {
            let mut out = Vec::new();
            XOREnc::fixed_encrypt(&vec[0..BLOCKSIZE], &vec[2*BLOCKSIZE..3*BLOCKSIZE], &mut out);
            assert_eq!(out, key.to_vec());
        }
    }


}
