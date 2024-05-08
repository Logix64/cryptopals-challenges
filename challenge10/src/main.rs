use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use tools::{
    encode::base64::from_base64,
    encrypt::{aes::AesCbc128, cipher::CipherMode},
};

fn main() -> io::Result<()> {
    let file = File::open("10.txt")?;

    let ciphertext = Vec::from_iter(
        BufReader::new(file)
            .lines()
            .map(|v| {
                let line = v.unwrap();
                from_base64(line.trim())
            })
            .flatten(),
    );

    let mut cbc = AesCbc128::init(b"YELLOW SUBMARINE", &vec![0x00; 16], CipherMode::Decrypt);

    let mut decrypted = Vec::with_capacity(ciphertext.len() + 16 );
    cbc.update(&ciphertext, &mut decrypted);
    cbc.end(&mut decrypted);
    
    decrypted.iter().for_each( |v| print!("{}", *v as char));
    println!();

    Ok(())
}
