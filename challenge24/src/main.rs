use std::time::{SystemTime, UNIX_EPOCH};

use rand::{random, thread_rng, Rng};
use tools::{encrypt::{cipher::RngKeyStream, xor::XOREnc}, random::mt19937::{MersenneTwister, MersenneTwisterCipher}};

fn recover_key(ciphertext : &[u8], plaintext : &[u8] ) -> Option<u16> {
    assert_eq!(ciphertext.len(), plaintext.len() );
    let len = ciphertext.len();

    let mut target_keystream = Vec::with_capacity(len);
    XOREnc::fixed_encrypt(&ciphertext, &plaintext, &mut target_keystream);

    for key in 0..=u16::MAX{
        let keystream : RngKeyStream<MersenneTwister> = RngKeyStream::new( (key as u32).to_be_bytes() );
        
        if keystream.take(len).zip(target_keystream.iter()).all( |(u,v)| &u == v ) {
            return Some(key)
        }
    } 
    None
}

fn is_bad_token( token : u16) -> Option<u32> {
    let current_time: u32 = SystemTime::now().duration_since(UNIX_EPOCH).expect("problem reading").as_secs().try_into().expect("problem converting");

    for i in 0..1050 {
        let seed = current_time - i;
        let mut rng = MersenneTwister::seed(seed);
        if token == (rng.extract_number()) as u16 {
            return Some(seed)
        }
    }
    None
}

fn get_token() -> u16 {
    let unix_time_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("problem reading");  

    let v : u32 = unix_time_now.as_secs().try_into().expect("problem parsing"); 

    let mut twister = MersenneTwister::seed(v);

    twister.extract_number() as u16
}


fn main() {
    let known_plaintext = b"AAAAAAAAAAAAAAAA".to_vec();

    let mut prefixed_plaintext : Vec<u8>= vec![thread_rng().gen(); thread_rng().gen_range(5..40)];

    prefixed_plaintext.extend_from_slice(&known_plaintext.clone());
    
    let key : u16 = random();

    let keystream = RngKeyStream::new((key as u32).to_be_bytes() );

    let mut ciphertext = Vec::with_capacity(prefixed_plaintext.len());

    let mut cipher = MersenneTwisterCipher::init(keystream);

    cipher.update(&prefixed_plaintext, &mut ciphertext);

    let recovered_key = recover_key(&ciphertext, &prefixed_plaintext).unwrap();
    assert_eq!(recovered_key, key);
    
    let token = get_token();

    assert!( is_bad_token(token).is_some() );

}
