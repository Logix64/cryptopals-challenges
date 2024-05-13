use std::{fs::File, io::{self, BufRead, BufReader}};

use rand::random;
use tools::{encode::base64::from_base64, encrypt::{aes::{AesCtr128, NonceFormat}, cipher::CipherKeyStream}};


fn main() -> io::Result<()> {

    let nonce: [u8;8] = random();
    let key : [u8;16] = random();

    let mut ctr = AesCtr128::init( 
        CipherKeyStream::new( key.as_slice(), NonceFormat::new(nonce.to_vec())));

    let file = File::open("25.txt")?;

    let base64 = String::from_iter( BufReader::new(file).lines().map( |v| v.unwrap()) );
    let plaintext = from_base64(&base64);

    let mut ciphertext = Vec::with_capacity(plaintext.len());

    ctr.update(&plaintext, &mut ciphertext);
    ctr.reset();

    // encrypt using edit
    let mut encrypted_text = ciphertext.to_owned();
    ctr.edit(&mut encrypted_text, 0, &ciphertext);
    ctr.reset();

    assert_eq!(encrypted_text, plaintext);

    Ok(())
}
