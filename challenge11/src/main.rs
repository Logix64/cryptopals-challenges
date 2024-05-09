use rand::{thread_rng, Rng};
use tools::{analyze::cipher::detect_ecb, encrypt::{
    aes::Aes128,
    cipher::{CBCMode, CipherCore, CipherMode, ECBMode},
}};

fn generate_random_len(rng: &mut impl Rng, min: usize, max: usize) -> Vec<u8> {
    assert!(min <= max);
    let len = rng.gen_range(min..max);
    generate_random(rng, len)
}

fn generate_random(rng: &mut impl Rng, len: usize) -> Vec<u8> {
    Vec::from_iter((0..len).map(|_| rng.gen()))
}

fn encrypt<T: CipherCore>(text: &[u8], output: &mut Vec<u8>) -> bool {
    let mut rng = thread_rng();

    let key = generate_random(&mut rng, T::BYTES);
    let is_cbc = rng.gen();
    if is_cbc {
        let iv = generate_random(&mut rng, T::BYTES);
        let mut cbc = CBCMode::<T>::init(&key, &iv, CipherMode::Encrypt);
        cbc.update(&generate_random_len(&mut rng, 5, 10), output);
        cbc.update(text, output);
        cbc.update(&generate_random_len(&mut rng, 5, 10), output);
        cbc.end(output);
    } else {
        let mut ecb = ECBMode::<T>::init(&key, CipherMode::Encrypt);
        ecb.update(&generate_random_len(&mut rng, 5, 10), output);
        ecb.update(text, output);
        ecb.update(&generate_random_len(&mut rng, 5, 10), output);
        ecb.end(output);
    }
    is_cbc
}

fn main() {
    let text = vec![0x01u8; 10 * Aes128::BYTES];
    for _ in 0..10 {
        let mut output = Vec::with_capacity(text.len() + 2 * Aes128::BYTES);
        let result = encrypt::<Aes128>(&text, &mut output);
        assert!(!detect_ecb(&output, Aes128::BYTES) == result);
    }
}
