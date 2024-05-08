use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use tools::{
    analyze::{
        multibyte::determine_keylength,
        single_byte::{KeyedPlaintext, Scorer, TaggedPlaintext},
    },
    encode::base64::from_base64,
    encrypt::xor::XOREnc,
};

struct DefaultScorer {}

impl Scorer for DefaultScorer {
    fn score_fn(_: &usize, alphanumeric: &usize, whitespace: &usize, linefeed: &usize) -> f64 {
        (alphanumeric + whitespace + linefeed / 5) as f64
    }
}

fn single_byte_attack<T: Scorer>(bytes: &[u8]) -> Vec<KeyedPlaintext> {
    (0..=u8::MAX)
        .map(|key| {
            let mut encrypted = Vec::with_capacity(bytes.len());
            XOREnc::single_key_encrypt(bytes, key, &mut encrypted);
            let text = String::from_iter(encrypted.iter().map(|&v| v as char));
            KeyedPlaintext::new(key, &text)
        })
        .collect()
}

fn attack<T: Scorer>(bytes: &[u8], keylength: usize) -> Vec<TaggedPlaintext<usize>> {
    (0..keylength)
        .map(|index| {
            let filtered_bytes =
                Vec::from_iter(bytes.iter().skip(index).step_by(keylength).map(|&v| v));
            let mut scoreboard: Vec<KeyedPlaintext> = single_byte_attack::<T>(&filtered_bytes);
            scoreboard.sort_by(|a, b| a.compare::<DefaultScorer>(b));
            scoreboard.reverse();
            scoreboard[0]
        })
        .map(|plaintext| TaggedPlaintext::add_tag(plaintext, keylength))
        .collect()
}

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
