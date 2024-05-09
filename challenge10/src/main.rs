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

    let mut decrypted: Vec<u8> = Vec::new();
    let mut cbc = AesCbc128::init(b"YELLOW SUBMARINE", &vec![0x00; 16], CipherMode::Decrypt);
    
    BufReader::new(file)
        .lines()
        .for_each(|v| {
            let line = v.unwrap();
            cbc.update(&from_base64(line.trim()), &mut decrypted);
        });
    cbc.end(&mut decrypted);
    
    decrypted.iter().for_each( |v| print!("{}", *v as char));
    println!();

    Ok(())
}
