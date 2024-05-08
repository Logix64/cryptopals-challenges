pub mod single_byte {
    use std::{cmp::Ordering, fmt::Display};

    pub trait Scorer{
        fn score_fn( num_chars : &usize, alphanumeric : &usize, whitespace : &usize, linefeed : &usize ) -> f64;

        fn score( plaintext : &Plaintext ) -> Option<f64>{
            if let Plaintext::Scored { num_chars, alphanumeric, whitespace , linefeed} = plaintext{
                Some(Self::score_fn( num_chars, alphanumeric, whitespace, linefeed) )
            } else {
                None
            }
        }

    }

    #[derive(Clone, Copy, Debug)]
    pub enum Plaintext {
        Scored{
            num_chars : usize,
            alphanumeric : usize,
            whitespace : usize,
            linefeed : usize
        },
        Unscored
    }

    impl Plaintext {

        fn new() -> Self {
            Self::Unscored
        }

        fn eval(self, text : &str ) -> Self{
            let alphanumeric = text.chars().filter(|v| v.is_ascii_alphanumeric() ).count();
            let whitespace = text.chars().filter(|v| *v as u8 == b' ' ).count();
            let linefeed = text.chars().filter(|v| *v as u8 == b'\n').count();
            let num_chars = text.chars().count();
            Self::Scored { num_chars, alphanumeric, whitespace, linefeed }
        }

        fn score<T : Scorer>(&self ) -> Option<f64> {
            T::score(&self)
        }
    }

    impl Display for Plaintext{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, "|  N  || abc |  _  |  lf |")?;
            match self {
                Self::Unscored => { 
                    writeln!(f, "|  ?  ||  ?  |  ?  |")?
                },
                Self::Scored { num_chars, alphanumeric, whitespace , linefeed} => {
                    writeln!(f, "|{:5}||{:5}|{:5}|{:5}", num_chars, alphanumeric, whitespace, linefeed)?
                }
            }
            writeln!(f)
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct KeyedPlaintext{
        text : Plaintext, 
        key : u8
    }

    impl KeyedPlaintext{
        pub fn new( key : u8, text : &str) -> Self {
            Self { text: Plaintext::new().eval(text), key }
        }

        pub fn get_score<T : Scorer>(&self) -> f64 {
            self.text.score::<T>().unwrap()
        }

        pub fn get_key(&self) -> u8 {
            self.key
        }

        pub fn compare<T : Scorer>(&self, other : &Self ) -> Ordering {
            self.get_score::<T>().total_cmp(&other.get_score::<T>())
        }
    }

    impl PartialEq for KeyedPlaintext {
        fn eq(&self, other: &Self) -> bool {
            self.key.eq(&other.key)
        }
    }

    impl Eq for KeyedPlaintext {}

    impl Display for KeyedPlaintext{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, " key |  N  || abc |  _  |  lf |")?;
            match self.text {
                Plaintext::Unscored => { 
                    writeln!(f, "{:5}|  ?  ||  ?  |  ?  |  ?  |", self.key)
                },
                Plaintext::Scored { num_chars, alphanumeric, whitespace , linefeed} => {
                    writeln!(f, "{:5}|{:5}||{:5}|{:5}|{:5}|", self.key, num_chars, alphanumeric, whitespace, linefeed)
                }
            }
        }
    }

    pub struct TaggedPlaintext<T>
        where T : Eq
    {
        tag : T, 
        plaintext : KeyedPlaintext 
    }

    impl<T : Eq> TaggedPlaintext<T> {
        pub fn add_tag( plaintext : KeyedPlaintext, tag : T) -> Self {
            TaggedPlaintext { tag, plaintext }
        }

        pub fn new( tag : T, key : u8, text : &str) -> Self {
            Self { tag, plaintext : KeyedPlaintext::new(key, text) }
        }

        pub fn get_score<S : Scorer>(&self) -> f64 {
            self.plaintext.get_score::<S>()
        }

        pub fn get_key(&self) -> u8 {
            self.plaintext.get_key()
        }

        pub fn get_tag<'a>(&'a self) -> &'a T {
            &self.tag
        }

        pub fn compare<S : Scorer>(&self, other : &Self ) -> Ordering {
            self.plaintext.compare::<S>(&other.plaintext)
        }
    }

    impl<T : Display + Eq> Display for TaggedPlaintext<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f)?;
            writeln!(f, " tag | key |  N  || abc |  _  |  lf |")?;
            match self.plaintext.text{
                Plaintext::Unscored => { 
                    writeln!(f, "{:5}|{:5}|  ?  ||  ?  |  ?  |  ?  |", self.tag, self.get_key())
                },
                Plaintext::Scored { num_chars, alphanumeric, whitespace , linefeed} => {
                    writeln!(f, "{:5}|{:5}|{:5}||{:5}|{:5}|{:5}|", self.tag, self.get_key(), num_chars, alphanumeric, whitespace, linefeed)
                }
            }
        }
    }  

}

pub mod multibyte{

    fn hamming( byte1 : u8, byte2 : u8) -> usize {
        let mut dist : usize  = 0;
        let mut val : i16 = i16::from( byte1 ^ byte2 );
        while val > 0  {
            val = val & (val - 1);
            dist += 1;
        }
        dist
    }

    fn hamming_bytes( bytes1 : &[u8], bytes2 : &[u8] ) -> usize {
        bytes1.iter().zip(bytes2.iter())
            .map( |(&u,&v)| hamming(u,v) )
            .fold(0, |acc, u| acc + u )
    }

    pub fn determine_keylength( min : u32,  max : u32, text : &[u8] ) -> impl Iterator<Item = usize> {
        assert!( min <= max);

        let mut scoreboard: Vec<(u32, f64)> = Vec::with_capacity((max - min) as usize);
        for i in min..=max {
            
            let first_chunks : Vec<&[u8]> = text.chunks_exact(i as usize).take(4).collect();       
            let avg_dist1: f64 = hamming_bytes( first_chunks[0], first_chunks[1] ) as f64; 
            let avg_dist2: f64 = hamming_bytes( first_chunks[2], first_chunks[3] ) as f64; 
            let avg_dist3: f64 = hamming_bytes( first_chunks[1], first_chunks[3] ) as f64;
            let avg_dist4: f64 = hamming_bytes( first_chunks[0], first_chunks[3] ) as f64;
            let avg_dist5: f64 = hamming_bytes( first_chunks[0], first_chunks[2] ) as f64;
            let avg_dist6: f64 = hamming_bytes( first_chunks[1], first_chunks[2] ) as f64;
            
            let avg_dist: f64 = (avg_dist1 + avg_dist2 + avg_dist3 + avg_dist4 + avg_dist5 + avg_dist6) / 6.0;

            let score : f64 = avg_dist / f64::from(i);
            scoreboard.push((i, score));
        }

        scoreboard.sort_by(|(_,a),(_,b)| a.total_cmp(b) );
        scoreboard.into_iter().map(|(u,_)| u as usize)
    }

    #[test]
    fn test_hamming_dist() {
        assert_eq!(hamming_bytes(b"this is a test", b"wokka wokka!!!"), 37);
    }

}