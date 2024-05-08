use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use tools::{
    encode::hex::from_hex,
    encrypt::{aes::Aes128, cipher::CipherCore},
};

fn eq(slice1: &[u8], slice2: &[u8]) -> bool {
    slice1.iter().zip(slice2.iter()).all(|(u, v)| u == v) && slice1.len() == slice2.len()
}

fn detect_ecb<T: CipherCore>(ciphertext: &[u8]) -> bool {
    ciphertext
        .chunks_exact(T::BYTES)
        .enumerate()
        .any(|(i, c1)| {
            ciphertext
                .chunks_exact(T::BYTES)
                .skip(i + 1)
                .any(|c2| eq(c1, c2))
        })
}

fn main() -> io::Result<()> {
    let file = File::open("8.txt")?;

    assert!(BufReader::new(file)
        .lines()
        .enumerate()
        .any(|(index, line)| {
            let bytes = from_hex(&line.unwrap().trim(), true).unwrap();
            let detection = detect_ecb::<Aes128>(&bytes);
            if detection {
                println!("found collision in line {index}");
            }
            detection
        }));

    Ok(())
}
