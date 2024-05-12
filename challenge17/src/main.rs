use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use rand::{thread_rng, Rng};
use tools::{
    encode::{ascii::to_ascii, base64::from_base64},
    encrypt::{
        aes::Aes128,
        cipher::{CBCMode, CipherCore, CipherMode},
        xor::XOREnc,
    },
};

pub fn strip_pkcs7_padding<'a>(padded : &'a[u8]) -> Result<&'a[u8], ()> {
    let len = match u8::try_from(padded.len()) {
        Ok(a) => a,
        Err(_) => return Err(())
    };

    // here it usually begins from 1..len aka to pad a text you need at least one text byte 
    // this here assumes we can have a whole pad block with 0xF0, which does not contain any information
    for i in 0..len {
        let pad = len - i;
        if padded[(i as usize)..].iter().all(|v| *v == pad ){
            return Ok(&padded[0..(i as usize)])
        }
    }

    Err(())
}
struct CbcPaddingOracle {
    key: Vec<u8>,
    plaintexts: Vec<Vec<u8>>,
}

impl CbcPaddingOracle {
    fn new<T: CipherCore>(key: Vec<u8>, plaintexts: Vec<Vec<u8>>) -> Self {
        assert_eq!(key.len(), T::BYTES);
        Self { key, plaintexts }
    }

    fn encrypt<T: CipherCore>(&self, output: &mut Vec<u8>, iv: &mut Vec<u8>) {
        assert_eq!(self.key.len(), T::BYTES);

        let mut rng = thread_rng();
        let len = self.plaintexts.len();

        let iv_s: Vec<u8> = (0..T::BYTES).map(|_| rng.gen::<u8>()).collect();
        let mut cbc = CBCMode::<T>::init(&self.key, &iv_s, CipherMode::Encrypt);
        iv.extend(iv_s);
        cbc.update(&self.plaintexts[rng.gen_range(0..len)], output);
        cbc.end(output);
    }

    fn check_padding<T: CipherCore>(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        assert_eq!(iv.len(), T::BYTES);
        assert_eq!(self.key.len(), T::BYTES);

        let mut output = Vec::with_capacity(ciphertext.len());
        let mut cbc = CBCMode::<T>::init(&self.key, iv, CipherMode::Decrypt);
        cbc.update(&ciphertext, &mut output);
        cbc.end(&mut output);

        strip_pkcs7_padding(&output).is_ok()
    }
}

fn attack_oracle<T: CipherCore>(
    oracle: CbcPaddingOracle,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let text = [iv.clone().to_vec(), ciphertext.clone()].concat();
    let n_chunks = text.len() / T::BYTES;

    let v: Vec<Vec<u8>> = (2..n_chunks+1)
        .map(|i| {
            let c_text = &text[0..i * T::BYTES.min(text.len())];
            let m = attack_single_block::<T>(&oracle, c_text);
            // m.iter().for_each( | u | (*u as char).escape_debug().for_each( | v| print!("{v}")));
            //println!();
            m
        })
        .collect();

    v.concat()
}

fn attack_single_block<T: CipherCore>(oracle: &CbcPaddingOracle, u: &[u8]) -> Vec<u8> {
    assert!(u.len() % T::BYTES == 0);
    assert!(u.len() >= 2 * T::BYTES);

    let mut working_bytes = u.to_owned();
    let mut solution = vec![0; T::BYTES];
    let len = working_bytes.len();
    // go from back to front
    for u in (0..T::BYTES).rev() {
        let pad = u8::try_from(T::BYTES - u).unwrap();
        // iterate over every byte
        for byte in 0..=u8::MAX {
            working_bytes[len - 2 * T::BYTES + u] = byte;

            if oracle.check_padding::<T>(&working_bytes[T::BYTES..], &working_bytes[0..T::BYTES]) {
                solution[u] = pad ^ byte;
                // println!("found byte {u}");
                break;
            }
        }
        // work padding
        for j in u..T::BYTES {
            working_bytes[len - 2 * T::BYTES + j] = solution[j] ^ (pad + 1);
        }
    }

    let mut output = Vec::with_capacity(T::BYTES);
    XOREnc::fixed_encrypt(
        &solution,
        &u[len - 2 * T::BYTES..len - T::BYTES],
        &mut output,
    );
    output
}



// In general this algorithm does only work if we allow whole pad blocks e.g. 0xF0 0xF0 0xF0 ... , otherwise we miss the first byte 
// since this byte will never be detected in our pad function (we only pad  at least one byte of information)
// In addition to that, this algorithm only works consistently on whole blocks of text, so we may want to cut off those.
// Overall it is one of the hairiest algorithms I have encountered (so far) and I dont want to bother with it anymore.
fn main() -> io::Result<()> {
    let file = File::open("17.txt")?;
    let mut rng = thread_rng();

    let plaintexts: Vec<Vec<u8>> = BufReader::new(file)
        .lines()
        .map(|v| {
            let line = v.unwrap();
            let u = from_base64(line.trim());
            println!("{}", to_ascii(&u, false));
            u
        })
        .collect();

    println!("----------------------------------");

    for _ in 0..100 {
        let key = Vec::from_iter((0..Aes128::BYTES).map(|_| rng.gen()));

        let oracle = CbcPaddingOracle::new::<Aes128>(key, plaintexts.clone());

        let mut ciphertext = Vec::new();
        let mut iv = Vec::new();

        oracle.encrypt::<Aes128>(&mut ciphertext, &mut iv);
        let result = attack_oracle::<Aes128>(oracle, iv, ciphertext);

        println!("{}", to_ascii(&result, true));
    }

    Ok(())
}
