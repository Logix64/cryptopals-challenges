use rand::{thread_rng, Rng};
use tools::{analyze::cipher::detect_ecb, encode::{ascii::to_ascii, base64::from_base64}, encrypt::{aes::Aes128, cipher::{CipherCore, CipherMode, ECBMode}}};

struct ECBOracle {
    secret :  Vec<u8>,
    key : Vec<u8>
}

impl ECBOracle{

    fn init<T : CipherCore>( secret : Vec<u8>, key : Vec<u8> ) -> Self {
        assert_eq!(key.len(), T::BYTES);
        Self { secret, key }
    }

    fn encrypt<T : CipherCore>(&self, text : &[u8], output : &mut Vec<u8> ) {
        let mut ecb = ECBMode::<T>::init(&self.key, CipherMode::Encrypt );
        ecb.update(text, output);
        ecb.update(&self.secret, output);
        ecb.end(output);
    }
}

fn generate_random(rng: &mut impl Rng, len: usize) -> Vec<u8> {
    Vec::from_iter((0..len).map(|_| rng.gen()))
}

fn detect_len<T : CipherCore>( oracle : &ECBOracle ) -> usize {
    let mut output = Vec::new();
    
    oracle.encrypt::<T>(b"a".as_slice(), &mut output);
    let len = output.len();
    output.clear();
    oracle.encrypt::<T>(b"aa", &mut output);
    let mut start = 2;
 
    while len == output.len() {
        start =  start + 1;
        output.clear();
        oracle.encrypt::<T>(&vec![b'a';start], &mut output);       
    }

    output.len() - len
}

fn decrypt<T : CipherCore>( oracle : &ECBOracle, len : usize  ) -> Vec<u8> {

    let mut ciphertext = Vec::new();
    oracle.encrypt::<T>(&vec![0x0 as u8;len], &mut ciphertext);
    let c_len = ciphertext.len();
    ciphertext = vec![0x0; len-1];
    
    for u in 0..(c_len-len) {
        let pat = ciphertext[u..u+len-1].to_owned();
        match single_decrypt::<T>(oracle, pat, u, len) {
            Some(a) => ciphertext.push(a) ,
            None => {ciphertext.pop(); break},
        };
    }

    ciphertext[len-1..].to_owned() 
}

fn single_decrypt<T : CipherCore>(oracle : &ECBOracle, mut pat : Vec<u8>, index : usize, len : usize ) -> Option<u8> {
    assert!(pat.len() == len -1);
    // block where to compare
    let lower_b = index - index % len;
    let mut output = Vec::new();

    // how much offset 
    let offset = (len - (index+1) % len) % len;
    output.clear();

    oracle.encrypt::<T>(&vec![0x00; offset], &mut output);
    let inv = output[lower_b..lower_b+len].to_owned();

    output.clear();

    for u in 0..=u8::MAX {
        pat.push(u);
        oracle.encrypt::<T>(&pat, &mut output);
        if output[0..len].iter().zip( inv.iter() ).all( | (u,v) | u.cmp(v).is_eq() ) {
            return Some(u);
        }
        pat.pop();
        output.clear();
    }
    None
}

fn main() {
    let secret = from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    let key = generate_random(&mut thread_rng(), Aes128::BYTES);
    let oracle = ECBOracle::init::<Aes128>(secret.clone(), key);
    
    let len = detect_len::<Aes128>(&oracle);
    assert_eq!(len, Aes128::BYTES);

    let mut output = Vec::new();
    oracle.encrypt::<Aes128>(&vec![0x01;10*len], &mut output);
    assert!(detect_ecb(&output, len));
    output.clear();

    let result = decrypt::<Aes128>(&oracle, len);
    assert_eq!(secret, result);

    println!("{}", to_ascii(&result, false))
}
