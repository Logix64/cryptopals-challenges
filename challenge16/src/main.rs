use rand::{thread_rng, Rng};
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

    fn check_admin<T : CipherCore>(&mut self, input : &[u8] ) -> bool {
        let mut output = Vec::new();

        let mut cbc = CBCMode::<T>::init(&self.key, &self.iv, CipherMode::Decrypt);
        cbc.update(input, &mut output);
        cbc.end(&mut output);

        let string = String::from_iter(output.iter().map(|&u| (u as char) ));

        string.chars().for_each(  | u | u.escape_debug().for_each( | v | print!("{v}"))   );
        println!();
        string.contains(";admin=true;")
    }
}

fn main() {
    let key : [u8;16] = thread_rng().gen();
    let iv : [u8;16] = thread_rng().gen();
    let mut bitflip = CbcBitflip::new::<Aes128>(key.to_vec(), iv.to_vec());
    let target =  ";admin=true;";

    println!("length of prefix: {}", PREFIX.len());
    println!("length of postfix: {}", POSTFIX.len());
    println!("length of target: {}", target.len());

    let forward_padding = PREFIX.len() % BLOCKSIZE;
    let back_padding = ( BLOCKSIZE - POSTFIX.len() % BLOCKSIZE ) % BLOCKSIZE + BLOCKSIZE - target.len() ;

    println!("forward_padding: {forward_padding}");
    println!("back_padding: {back_padding}");

    let padding_bytes = u8::try_from(target.len()).expect("problem parsing"); 

    let padding = back_padding + forward_padding;

    let mut dec_input = PREFIX.as_bytes().to_owned();
    dec_input.extend_from_slice(&vec![0x9;padding]);
    dec_input.extend_from_slice(&POSTFIX.as_bytes().to_owned());
    dec_input.extend_from_slice(&vec![padding_bytes;target.len()]);

    println!("length dec_input:{}", dec_input.len());

    let mut enc_text = Vec::new();

    bitflip.encrypt::<Aes128>(&String::from_iter((0..padding).map(|_| 'A') ) , &mut enc_text);

    let num_chunks = dec_input.len() / BLOCKSIZE;
    let dec_chunks : Vec<&[u8]> = dec_input.chunks_exact(BLOCKSIZE).collect();
    let enc_chunks : Vec<&[u8]> = enc_text.chunks_exact(BLOCKSIZE).collect();

    // aes encrypted block
    let mut aes_encr = Vec::with_capacity(BLOCKSIZE);

    /*
    dec_chunks[num_chunks-2].iter().for_each( |&u| (u as char).escape_debug().for_each(|v| print!("{v}")) );
    println!();

    dec_chunks[num_chunks-1].iter().for_each( |&u| (u as char).escape_debug().for_each(|v| print!("{v}")) );
    println!();
     */
    
    // calculate next aes-enc
    XOREnc::fixed_encrypt( dec_chunks[num_chunks-1], enc_chunks[num_chunks-2], &mut aes_encr);

    let mut payload = Vec::with_capacity(BLOCKSIZE);

    XOREnc::fixed_encrypt(b"test;admin=true;", &aes_encr, &mut payload);

    let mut fake_message = enc_chunks.to_owned();
    fake_message[num_chunks-2] = &payload;

    let message = fake_message.concat();

    /* 
    enc_text.iter().for_each(|u| print!("{0:3x}", u));
    println!();
    message.iter().for_each(|u| print!("{0:3x}", u ));
    println!();    
    
    println!("len message: {}", message.len());
    */
    let is_admin = bitflip.check_admin::<Aes128>(&message);

    println!("is_admin: {is_admin}");

}