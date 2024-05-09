use rand::{thread_rng, Rng};
use tools::{analyze::cipher::detect_ecb, encode::{ascii::to_ascii, base64::from_base64}, encrypt::{aes::Aes128, cipher::{CipherCore, CipherMode, ECBMode}}};

struct ECBOracle {
    prefix : Vec<u8>,
    secret :  Vec<u8>,
    key : Vec<u8>
}

impl ECBOracle{

    fn init<T : CipherCore>( prefix : Vec<u8>, secret : Vec<u8>, key : Vec<u8> ) -> Self {
        assert_eq!(key.len(), T::BYTES);
        Self { prefix, secret, key }
    }

    fn encrypt<T : CipherCore>(&self, text : &[u8], output : &mut Vec<u8> ) {
        let mut ecb = ECBMode::<T>::init(&self.key, CipherMode::Encrypt );
        ecb.update(&self.prefix, output);
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

fn decrypt<T : CipherCore>( oracle : &ECBOracle, len : usize, byte_offset : usize, block_offset : usize  ) -> Vec<u8> {

    let mut ciphertext = Vec::new();
    adjusted_encrypt::<T>(oracle, &vec![0x0 as u8;len], &mut ciphertext, byte_offset);
    let c_len = ciphertext.len();
    ciphertext = vec![0x0; len-1];
    
    for u in 0..(c_len-len-block_offset-1) {
        let pat = ciphertext[u..u+len-1].to_owned();
        match single_decrypt::<T>(oracle, pat, u, len, block_offset, byte_offset) {
            Some(a) => ciphertext.push(a) ,
            None => {ciphertext.pop(); break},
        };
    }

    ciphertext[len-1..].to_owned() 
}

fn single_decrypt<T : CipherCore>(oracle : &ECBOracle, mut pat : Vec<u8>, index : usize, len : usize, block_offset : usize, byte_offset : usize) -> Option<u8> {
    assert!(pat.len() == len -1);
    // block where to compare
    let lower_b = index - index % len;

    // how much offset 
    let offset = (len - (index+1) % len) % len;
    let mut output: Vec<u8> = Vec::new();

    adjusted_encrypt::<T>(oracle,&vec![0x00; offset], &mut output, byte_offset);
    let inv = output[lower_b+block_offset + len..block_offset + lower_b + 2*len].to_owned();

    output.clear();

    for u in 0..=u8::MAX {
        pat.push(u);
        adjusted_encrypt::<T>(oracle,&pat, &mut output, byte_offset);
        if output[block_offset+len..block_offset+len+2*len].iter().zip( inv.iter() ).all( | (u,v) | u.cmp(v).is_eq() ) {
            return Some(u);
        }
        pat.pop();
        output.clear();
    }
    None
}

fn adjusted_encrypt<T : CipherCore>( oracle : &ECBOracle, text : &[u8], output : &mut Vec<u8>, byte_offset : usize  ) {
    let mut v = vec![0; byte_offset];
    v.extend_from_slice(text);

    oracle.encrypt::<T>(&v, output);
}


fn measure_block_offset<T : CipherCore>( oracle : &ECBOracle) -> usize{
    let mut output1 = Vec::new();
    let mut output2 = Vec::new();

    oracle.encrypt::<T>(b"STIMULUS".as_slice(), &mut output1);
    oracle.encrypt::<T>(b"RESPONSE".as_slice(), &mut output2);

    output1.iter().zip(output2.iter())
        .take_while(|(u,v)| u.cmp(v).is_eq() ).count()
} 

fn measure_byte_offset<T : CipherCore>(oracle : &ECBOracle, len : usize, block_offset : usize) -> usize {
        
    let mut ind = 0;

    let mut output = Vec::new();

    oracle.encrypt::<T>(vec![0; 2*len + ind ].as_slice() , &mut output);

    while !detect_ecb(&output[block_offset..block_offset+5*len], len) {
        ind += 1;
        output.clear();
        oracle.encrypt::<T>(vec![0; 2*len + ind ].as_slice() , &mut output);
    }
    ind
}


fn main() {

    let mut rng = thread_rng();
    let secret = from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    let key = generate_random(&mut rng, Aes128::BYTES);
    let len = rng.gen_range(5..20);
    let prefix = generate_random(&mut rng, len );
    
    let oracle = ECBOracle::init::<Aes128>(prefix, secret.clone(), key);
    
    let len = detect_len::<Aes128>(&oracle);
    assert_eq!(len, Aes128::BYTES);

    let mut output = Vec::new();
    oracle.encrypt::<Aes128>(&vec![0x01;10*len], &mut output);
    assert!(detect_ecb(&output, len));
    output.clear();

    let block_offset = measure_block_offset::<Aes128>(&oracle);
    let byte_offset = measure_byte_offset::<Aes128>(&oracle, len, block_offset);

    let result = decrypt::<Aes128>(&oracle, len, byte_offset, block_offset);
    assert_eq!(secret, result);

    println!("{}", to_ascii(&result, false))
}
