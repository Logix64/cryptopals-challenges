use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

use challenge6::attack::attack;
use tools::{ analyze::single_byte::Scorer, encode::{ascii::to_ascii, base64::from_base64}, encrypt::{aes::Aes128, cipher::CipherCore, xor::XOREnc}};

struct AdvancedScorer{}

impl Scorer for AdvancedScorer {
    fn score_fn(
        _: &usize,
        alphabetic: &usize,
        numeric : &usize,
        punctuation : &usize,
        whitespace: &usize,
        linefeed: &usize,
    ) -> f64 {
        (*alphabetic as f64) + (*numeric as f64) + (*whitespace as f64)/1.0 + (*punctuation as f64)/8.0+ (*linefeed as f64)/10.0
    }
}


fn main() -> io::Result<()> {
    let file = File::open("20.txt")?;
    let texts: Vec<Vec<u8>> = BufReader::new(file)
        .lines()
        .map(|v| {
            let line = v.unwrap();
            from_base64(&line)
        })
        .collect();

    let mut min_len = texts.iter().fold(
        usize::MAX,
        |acc, v| if acc >= v.len() { v.len() } else { acc },
    );
    min_len = min_len - (min_len % Aes128::BYTES);
    println!("min_len : {min_len}");


    let ciphertext: Vec<u8> = texts
        .iter()
        .map(|v| v[0..min_len].to_owned())
        .flatten()
        .collect();

    let keystream = Vec::from_iter(
        attack::<AdvancedScorer>(&ciphertext, min_len+1)
            .into_iter()
            .map(|v| v.get_key()),
    );

    for (index, text) in texts.into_iter().enumerate() {
        let mut output = Vec::with_capacity( min_len );

        XOREnc::repeating_key_encrypt(&text, &keystream, &mut output);

        println!("{index} : {} + {} unknown", to_ascii(&output, false), text.len() - min_len);
    }

    Ok(())
}
