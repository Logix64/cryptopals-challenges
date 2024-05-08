use tools::{analyze::single_byte::{KeyedPlaintext, Scorer}, encode::hex::from_hex, encrypt::xor::XOREnc};


struct DefaultScorer{}

impl Scorer for DefaultScorer{
    fn score_fn( _ : &usize, alphanumeric : &usize, whitespace : &usize, linefeed : &usize ) -> f64 {
        (alphanumeric + whitespace + linefeed/5) as f64
    }
}

fn main() {

    let bytes = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", true).unwrap();

    let mut scoreboard = Vec::from_iter( (0..=u8::MAX).map( |key| {
        let mut plain_bytes = Vec::with_capacity(bytes.len());
        XOREnc::single_key_encrypt(&bytes, key, &mut plain_bytes);

        let plaintext = String::from_iter(plain_bytes.iter().map( |&v| v as char));

        KeyedPlaintext::new(key, &plaintext)
    } ) );

    scoreboard.sort_by( |a,b| a.compare::<DefaultScorer>(b) );
    scoreboard.reverse();

    for i in 0..3 {
        print!("place {i} : ");
        let mut plaintext = Vec::with_capacity(bytes.len());
        XOREnc::single_key_encrypt(&bytes, scoreboard[i].get_key(), &mut plaintext);
        plaintext.iter().for_each( |&v| v.escape_ascii().for_each(|u| print!("{}", u as char)));
        println!();
        println!("{}", scoreboard[i]);
    }

}
