pub mod attack {
    use tools::{analyze::single_byte::{KeyedPlaintext, Scorer, TaggedPlaintext}, encrypt::xor::XOREnc};

    pub struct DefaultScorer {}

    impl Scorer for DefaultScorer {
        fn score_fn(_: &usize, alphabetic: &usize, numeric : &usize, _ : &usize, whitespace: &usize, linefeed: &usize) -> f64 {
            (alphabetic + numeric + whitespace + linefeed / 5) as f64
        }
    }

    pub fn single_byte_attack<T: Scorer>(bytes: &[u8]) -> Vec<KeyedPlaintext> {
        (0..=u8::MAX)
            .map(|key| {
                let mut encrypted = Vec::with_capacity(bytes.len());
                XOREnc::single_key_encrypt(bytes, key, &mut encrypted);
                let text = String::from_iter(encrypted.iter().map(|&v| v as char));
                KeyedPlaintext::new(key, &text)
            })
            .collect()
    }

    pub fn attack<T: Scorer>(bytes: &[u8], keylength: usize) -> Vec<TaggedPlaintext<usize>> {
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
}
