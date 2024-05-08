use std::{fs::File, io::{self, BufRead, BufReader}};

use tools::{analyze::single_byte::{Scorer, TaggedPlaintext}, encode::hex::from_hex, encrypt::xor::XOREnc};

struct DefaultScorer{}

impl Scorer for DefaultScorer{
    fn score_fn( _ : &usize, alphanumeric : &usize, whitespace : &usize, linefeed : &usize ) -> f64 {
        (alphanumeric + whitespace + linefeed/5) as f64
    }
}

fn main() -> io::Result<()> {
    
    let mut scoreboard = Vec::new();

    let file = File::open("4.txt")?;

    let list_bytes : Vec<Vec<u8>> = BufReader::new(File::open("4.txt")? ).lines().map( |line| { 
        from_hex(&line.unwrap(), true).unwrap()
    }).collect();

    BufReader::new(file).lines().enumerate().for_each(|(index,line)| {
        let hexstring = line.unwrap();
        let bytes = from_hex(&hexstring.trim(), true).unwrap();
        
        scoreboard.extend( (0..=u8::MAX).map( |key| {
            let mut plain_bytes = Vec::with_capacity(bytes.len());
            XOREnc::single_key_encrypt(&bytes, key, &mut plain_bytes);

            let plaintext = String::from_iter(plain_bytes.iter().map( |&v| v as char));

            TaggedPlaintext::new(index, key, &plaintext)
        }))
    });

    scoreboard.sort_by( |a,b| a.compare::<DefaultScorer>(&b) );
    scoreboard.reverse();

    for i in 0..3 {
        print!("place {i} : ");
        let bytes = &list_bytes[*scoreboard[i].get_tag()];
        let mut plaintext = Vec::with_capacity(bytes.len());
        XOREnc::single_key_encrypt(&bytes, scoreboard[i].get_key(), &mut plaintext);
        plaintext.iter().for_each( |&v| v.escape_ascii().for_each(|u| print!("{}", u as char)));
        println!();
        println!("{}", scoreboard[i]);
    }

    Ok(())
}
