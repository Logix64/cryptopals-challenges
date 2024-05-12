use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use attack::{attack, DefaultScorer};
use challenge6::attack;
use tools::{
    analyze::{
        multibyte::determine_keylength,
        single_byte::TaggedPlaintext,
    },
    encode::base64::from_base64,
    encrypt::xor::XOREnc,
};

 
fn main() -> io::Result<()> {
    let file = File::open("6.txt")?;

    let mut base64 = String::new();

    for line in BufReader::new(file).lines() {
        base64 = base64 + &line?;
    }

    let bytes = from_base64(&base64);

    let keylengths = determine_keylength(2, 40, &bytes).take(1);

    let keys: Vec<Vec<TaggedPlaintext<usize>>> = keylengths
        .map(|keylength| attack::<DefaultScorer>(&bytes, keylength))
        .collect();

    keys.iter()
        .map(|tagged| tagged.iter().map(|v| v.get_key()))
        .for_each(|key_iter| {
            let key = Vec::from_iter(key_iter);
            let mut decrypted = Vec::with_capacity(bytes.len());

            XOREnc::repeating_key_encrypt(&bytes, &key, &mut decrypted);

            print!("key : ");
            key.iter().for_each(|v | print!("{}", *v as char ));
            println!();
            println!("text : ");
            decrypted.iter().for_each(|v| print!("{}", *v as char));
            // decrypted.iter().for_each(|v| v.escape_ascii().for_each( |u| print!("{}", u as char)));
            println!();
        });

    Ok(())
}
