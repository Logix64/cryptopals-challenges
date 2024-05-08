use std::{fs::File, io::{self, BufRead, BufReader}};

use tools::{encode::base64::from_base64, encrypt::{aes::AesEcb128, cipher::CipherMode}};

fn main() -> io::Result<()>{
    
    let key = b"YELLOW SUBMARINE";

    let file = File::open("7.txt")?;

    let base64 = String::from_iter(
        BufReader::new(file).lines().map(|v| v.unwrap())
    );

    let bytes = from_base64(&base64);
    let mut output = Vec::with_capacity(bytes.len() + 16);

    let mut aes = AesEcb128::init(key, CipherMode::Decrypt);
    aes.update(&bytes, &mut output);
    aes.end(&mut output);

    output.iter().for_each(|v| v.escape_ascii().for_each(|v| print!("{}", v as char)));
    
    Ok(())
}
