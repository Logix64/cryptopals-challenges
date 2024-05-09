pub mod single_byte {
    use std::{cmp::Ordering, fmt::Display};

    /// A trait which allows to score a piece of plaintext by its human legibility.
    /// The basic function can depend on the number of chars in the text, the number of alphanumeric chars,
    /// the number of whitespace (only empty space, no tabs,linefeed,...) and the number of new line characters.
    pub trait Scorer {
        /// Mathematical function to call if there is a piece of plaintext to be scored.
        fn score_fn(
            num_chars: &usize,
            alphanumeric: &usize,
            whitespace: &usize,
            linefeed: &usize,
        ) -> f64;

        /// Scores a given plaintext. If the plaintext has not yet been scored, e.g. the parameters have not been set, returns None.
        /// Otherwise the function calls universal scoring function with the parameters of the plaintext.  
        fn score(plaintext: &Plaintext) -> Option<f64> {
            if let Plaintext::Scored {
                num_chars,
                alphanumeric,
                whitespace,
                linefeed,
            } = plaintext
            {
                Some(Self::score_fn(
                    num_chars,
                    alphanumeric,
                    whitespace,
                    linefeed,
                ))
            } else {
                None
            }
        }
    }

    /// Abstract representation of a plaintext candidate. A Plaintext can have two different states :
    ///  - Scored : the parameters, like number of alphanumeric characters, whitespace characters are stored
    ///  - Unscored : there has not yet been given a plaintext which this struct represents.
    /// A new Plaintext is always initiated as Unscored. A score can be given by calling the method eval(...).
    #[derive(Clone, Copy, Debug)]
    pub enum Plaintext {
        Scored {
            num_chars: usize,
            alphanumeric: usize,
            whitespace: usize,
            linefeed: usize,
        },
        Unscored,
    }

    impl Plaintext {
        /// Initiates the container as Unscored.
        fn new() -> Self {
            Self::Unscored
        }

        /// Assigns a text to the given Plaintext. A Plaintext struct tracks multiple components of the given text, for example :
        ///  - number of alphanumeric characters,
        ///  - number of whitespaces (or blank spaces),
        ///  - number linebreaks,
        ///  - number of characters as a whole
        fn eval(self, text: &str) -> Self {
            let alphanumeric = text.chars().filter(|v| v.is_ascii_alphanumeric()).count();
            let whitespace = text.chars().filter(|v| *v as u8 == b' ').count();
            let linefeed = text.chars().filter(|v| *v as u8 == b'\n').count();
            let num_chars = text.chars().count();
            Self::Scored {
                num_chars,
                alphanumeric,
                whitespace,
                linefeed,
            }
        }

        /// Applies a Scorer to itself and returns the given value as an Option.
        fn score<T: Scorer>(&self) -> Option<f64> {
            T::score(&self)
        }
    }

    impl Display for Plaintext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, "|  N  || abc |  _  |  lf |")?;
            match self {
                Self::Unscored => writeln!(f, "|  ?  ||  ?  |  ?  |")?,
                Self::Scored {
                    num_chars,
                    alphanumeric,
                    whitespace,
                    linefeed,
                } => writeln!(
                    f,
                    "|{:5}||{:5}|{:5}|{:5}",
                    num_chars, alphanumeric, whitespace, linefeed
                )?,
            }
            writeln!(f)
        }
    }

    /// A KeyedPlaintext decorates a Plaintext struct with a byte-sized key. This is very helpful to compare different
    /// single-byte keys in a single-byte-xor attack.
    #[derive(Clone, Copy, Debug)]
    pub struct KeyedPlaintext {
        text: Plaintext,
        key: u8,
    }

    impl KeyedPlaintext {
        /// Initiates the KeyedPlaintext with a given single-byte key and a text.
        /// This initiation asserts that every plaintext of a keyed plaintext is already scored or analyzed.
        pub fn new(key: u8, text: &str) -> Self {
            Self {
                text: Plaintext::new().eval(text),
                key,
            }
        }

        /// returns the score of the given plaintext depending on the implementation of Scorer.
        /// Since every KeyedPlaintext has a scored piece of plaintext associated with it, we don't need to return the score as an Option.  
        pub fn get_score<T: Scorer>(&self) -> f64 {
            self.text.score::<T>().unwrap()
        }

        /// returns the key of the associated KeyedPlaintext.
        pub fn get_key(&self) -> u8 {
            self.key
        }

        /// Compares two KeyedPlaintexts based on a given implementation of Scorer.
        /// This is very helpful for the statistical attack on single-byte-xor ciphers.
        pub fn compare<T: Scorer>(&self, other: &Self) -> Ordering {
            self.get_score::<T>().total_cmp(&other.get_score::<T>())
        }
    }

    impl PartialEq for KeyedPlaintext {
        fn eq(&self, other: &Self) -> bool {
            self.key.eq(&other.key)
        }
    }

    impl Eq for KeyedPlaintext {}

    impl Display for KeyedPlaintext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, " key |  N  || abc |  _  |  lf |")?;
            match self.text {
                Plaintext::Unscored => {
                    writeln!(f, "{:5}|  ?  ||  ?  |  ?  |  ?  |", self.key)
                }
                Plaintext::Scored {
                    num_chars,
                    alphanumeric,
                    whitespace,
                    linefeed,
                } => {
                    writeln!(
                        f,
                        "{:5}|{:5}||{:5}|{:5}|{:5}|",
                        self.key, num_chars, alphanumeric, whitespace, linefeed
                    )
                }
            }
        }
    }

    /// A TaggedPlaintext is a decorated KeyedPlaintext with a Tag, which allows comparison based on the given tag.
    /// This struct can be used for the extension of our single-byte-xor attack to a repeating-key-xor attack, where the
    /// tag helps to distinguish different keysizes, for example.   
    pub struct TaggedPlaintext<T>
    where
        T: Eq,
    {
        tag: T,
        plaintext: KeyedPlaintext,
    }

    impl<T: Eq> TaggedPlaintext<T> {
        /// Extends a KeyedPlaintext with a tag T
        pub fn add_tag(plaintext: KeyedPlaintext, tag: T) -> Self {
            TaggedPlaintext { tag, plaintext }
        }

        /// Builds a new TaggedPlaintext from scratch. Like KeyedPlaintext the association to a given plaintext is guaranteed, which
        /// means we can easily use scoring to achieve our goals.
        pub fn new(tag: T, key: u8, text: &str) -> Self {
            Self {
                tag,
                plaintext: KeyedPlaintext::new(key, text),
            }
        }

        /// Returns the score of the inserted plaintext. Since TaggedPlaintext guarantees, that the Plaintext is scored we don't need to return an Option.
        pub fn get_score<S: Scorer>(&self) -> f64 {
            self.plaintext.get_score::<S>()
        }

        /// Returns the key of the inherited KeyedPlaintext.
        pub fn get_key(&self) -> u8 {
            self.plaintext.get_key()
        }

        /// Returns a reference to the tag. Because we don't want to assert that T implements Copy it is only a reference.   
        pub fn get_tag<'a>(&'a self) -> &'a T {
            &self.tag
        }

        /// Compares the different inherited plaintexts with each other.
        pub fn compare<S: Scorer>(&self, other: &Self) -> Ordering {
            self.plaintext.compare::<S>(&other.plaintext)
        }
    }

    impl<T: Display + Eq> Display for TaggedPlaintext<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, " tag | key |  N  || abc |  _  |  lf |")?;
            match self.plaintext.text {
                Plaintext::Unscored => {
                    writeln!(
                        f,
                        "{:5}|{:5}|  ?  ||  ?  |  ?  |  ?  |",
                        self.tag,
                        self.get_key()
                    )
                }
                Plaintext::Scored {
                    num_chars,
                    alphanumeric,
                    whitespace,
                    linefeed,
                } => {
                    writeln!(
                        f,
                        "{:5}|{:5}|{:5}||{:5}|{:5}|{:5}|",
                        self.tag,
                        self.get_key(),
                        num_chars,
                        alphanumeric,
                        whitespace,
                        linefeed
                    )
                }
            }
        }
    }
}

pub mod multibyte {

    /// efficient hamming distance implementation for a byte
    /// This is not my algorithm, please cf. https://en.wikipedia.org/wiki/Hamming_distance .
    fn hamming(byte1: u8, byte2: u8) -> usize {
        let mut dist: usize = 0;
        let mut val: i16 = i16::from(byte1 ^ byte2);
        while val > 0 {
            val = val & (val - 1);
            dist += 1;
        }
        dist
    }

    /// Extends single byte hamming distance to multiple byte slices.
    fn hamming_bytes(bytes1: &[u8], bytes2: &[u8]) -> usize {
        bytes1
            .iter()
            .zip(bytes2.iter())
            .map(|(&u, &v)| hamming(u, v))
            .fold(0, |acc, u| acc + u)
    }

    /// Determines the most probable keylengths in a repeating-key-xor attack. The arguments min and max give us the
    /// maximum and minimum keylengths and text is a given sample of the encrypted stream. It is noted here that this algorithm 
    /// needs at least 4*max bytes of sample text to finish. 
    /// 
    /// The results are returned by a sorted iterator, where the first item is the most likely keysize and the second the second most likely keysize and so on...
    pub fn determine_keylength(min: u32, max: u32, text: &[u8]) -> impl Iterator<Item = usize> {
        assert!(min <= max);

        let mut scoreboard: Vec<(u32, f64)> = Vec::with_capacity((max - min) as usize);
        for i in min..=max {
            let first_chunks: Vec<&[u8]> = text.chunks_exact(i as usize).take(4).collect();
            let avg_dist1: f64 = hamming_bytes(first_chunks[0], first_chunks[1]) as f64;
            let avg_dist2: f64 = hamming_bytes(first_chunks[2], first_chunks[3]) as f64;
            let avg_dist3: f64 = hamming_bytes(first_chunks[1], first_chunks[3]) as f64;
            let avg_dist4: f64 = hamming_bytes(first_chunks[0], first_chunks[3]) as f64;
            let avg_dist5: f64 = hamming_bytes(first_chunks[0], first_chunks[2]) as f64;
            let avg_dist6: f64 = hamming_bytes(first_chunks[1], first_chunks[2]) as f64;

            let avg_dist: f64 =
                (avg_dist1 + avg_dist2 + avg_dist3 + avg_dist4 + avg_dist5 + avg_dist6) / 6.0;

            let score: f64 = avg_dist / f64::from(i);
            scoreboard.push((i, score));
        }

        scoreboard.sort_by(|(_, a), (_, b)| a.total_cmp(b));
        scoreboard.into_iter().map(|(u, _)| u as usize)
    }

    #[test]
    fn test_hamming_dist() {
        assert_eq!(hamming_bytes(b"this is a test", b"wokka wokka!!!"), 37);
    }
}

pub mod cipher {

    /// Allows to compare slices without panicking. The function always returns false if the slices have different lengths.   
    fn eq(slice1: &[u8], slice2: &[u8]) -> bool {
        slice1.iter().zip(slice2.iter()).all(|(u, v)| u == v) && slice1.len() == slice2.len()
    }

    /// Detects ECB mode for a Cipher of byte-length len.  
    pub fn detect_ecb(ciphertext: &[u8], len: usize) -> bool {
        ciphertext.chunks_exact(len).enumerate().any(|(i, c1)| {
            ciphertext
                .chunks_exact(len)
                .skip(i + 1)
                .any(|c2| eq(c1, c2))
        })
    }
}
