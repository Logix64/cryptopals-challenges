use rand::random;
use tools::encrypt::{
    aes::{AesCtr128, NonceFormat},
    cipher::CipherKeyStream,
    xor::XOREnc,
};

const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const POSTFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";
const BLOCKSIZE: usize = 16;

struct CtrBitflip {
    enc: AesCtr128,
}

impl CtrBitflip {
    fn new(enc: AesCtr128) -> Self {
        CtrBitflip { enc: enc }
    }

    fn encrypt(&mut self, input: &str, output: &mut Vec<u8>) {
        let str =
            PREFIX.to_owned() + &input.to_owned().replace(";", "%3B").replace("=", "%3D") + POSTFIX;
        self.enc.update(str.as_bytes(), output);
        self.enc.reset();
    }

    fn check_admin(&mut self, input: &[u8]) -> bool {
        let mut output = Vec::new();
        self.enc.update(input, &mut output);
        self.enc.reset();

        let string = String::from_iter(output.iter().map(|&u| (u as char)));

        string
            .chars()
            .for_each(|u| u.escape_debug().for_each(|v| print!("{v}")));
        println!();
        string.contains(";admin=true;")
    }
}

fn main() {
    let key: [u8; 16] = random();
    let nonce: [u8; 8] = random();

    let keystream = CipherKeyStream::new(key.as_slice(), NonceFormat::new(nonce.to_vec()));

    let enc = AesCtr128::init(keystream);
    let mut bitflip = CtrBitflip::new(enc);

    let target = ";admin=true;";

    println!("length of prefix: {}", PREFIX.len());
    println!("length of postfix: {}", POSTFIX.len());
    println!("length of target: {}", target.len());

    // we don't need to use padding anymore
    let mut dec_input = PREFIX.as_bytes().to_owned();
    dec_input.extend_from_slice(&vec![b'A'; target.len()]);
    dec_input.extend_from_slice(&POSTFIX.as_bytes().to_owned());

    println!("length dec_input:{}", dec_input.len());

    let mut enc_text = Vec::new();

    bitflip.encrypt(
        &String::from_iter((0..target.len()).map(|_| 'A')),
        &mut enc_text,
    );

    // aes encrypted block
    let mut keystream = Vec::with_capacity(BLOCKSIZE);

    XOREnc::fixed_encrypt(
        &dec_input[PREFIX.len()..PREFIX.len() + target.len()],
        &enc_text[PREFIX.len()..PREFIX.len() + target.len()],
        &mut keystream,
    );

    let mut payload = Vec::with_capacity(BLOCKSIZE);

    XOREnc::fixed_encrypt(b";admin=true;", &keystream, &mut payload);

    let fake = vec![
        &enc_text[0..PREFIX.len()],
        &payload,
        &enc_text[PREFIX.len() + payload.len()..],
    ];

    let fake_message = fake.concat();

    let is_admin = bitflip.check_admin(&fake_message);

    assert!(is_admin);
    println!("is_admin: {is_admin}");
}
