
pub mod hex {
    fn single_u8_be( chars : [char;2] ) -> Option<u8> {
        assert!( chars.iter().all(|v| v.is_ascii_hexdigit() ), "all characters must be hex digits" );
    
        chars[0].to_digit(16)   
            .zip( chars[1].to_digit(16))
            .map( | (v1, v2)| (v1 << 4 | v2) as u8 )
    }
    
    pub fn from_hex( hex : &str, big_endian : bool  ) -> Option<Vec<u8>> {
    
        assert!( hex.chars().all(|v| v.is_ascii_hexdigit() ), "all characters must be hex digits!");
        
        let mut vec : Vec<char> = hex.chars().collect();
    
        if vec.len() % 2 == 1 {
            vec.insert(
                if big_endian { 0 } else { vec.len() },
                '0');
        }
        

        // let mut bytes = Vec::with_capacity(vec.len() / 2);
        let mut state = Some(Vec::new());

        for chunk in vec.chunks_exact(2) {
            state = single_u8_be([chunk[0], chunk[1]])
                .zip(state).map( |(v, state)| { [&state, [v].as_slice()].concat() } )
        }
        state
    }
    
    pub fn to_hex( bytes : &[u8] ) -> String {
        let mut hex = String::new();
        for i in bytes {
            hex.extend(format!("{:02x}", *i ).chars());
        }
        hex
    }

    #[test]
    fn test_from_hex() {
        assert_eq!( from_hex("ffff", true), Some(vec![0xff, 0xff]));
        assert_eq!( from_hex("fff", true), Some(vec![0x0f, 0xff]));
        assert_eq!( from_hex("fff", false), Some(vec![0xff, 0xf0]));
    }

    #[test]
    fn test_to_hex() {
        assert_eq!( to_hex( &vec![0x0f, 0xff]), "0fff" );
        assert_eq!( to_hex( &vec![0xff, 0xff]), "ffff" );
    }

}

pub mod base64 {
    use std::u32;

    pub const RANGE : &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[derive(Clone,Copy)]
    enum Sextet{ Sextet(u8) }

    impl Sextet {
        fn from( byte : u8 ) -> Option<Self> {
            if byte < 64 {
                Some(Self::Sextet(byte))
            } else {
                None
            }
        }

        fn from_char( s : char ) -> Option<Self> {
            match s as u8 {
                b'A'..=b'Z' => {
                    Some(Sextet::Sextet(s as u8 - b'A'))
                },
                b'a'..=b'z' => {
                    Some(Sextet::Sextet(s as u8 - b'a' + 26))
                },
                b'0'..=b'9' => {
                    Some(Sextet::Sextet(s as u8 - b'0' + 52))
                },
                b'+' => Some(Sextet::Sextet(62)),
                b'/' => Some(Sextet::Sextet(63)),
                _ => None
            }
        }

        fn into_inner(self) -> u8 {
            let Self::Sextet(byte) = self; 
            byte
        }

        fn into_char(self) -> char {
            let Self::Sextet(byte) = self; 
            match byte {
                0..=25 => {
                    char::from_u32((b'A' + byte) as u32).unwrap() 
                },
                26..=51 => {
                    char::from_u32( (b'a' + byte  - 26) as u32 ).unwrap()
                },
                52..=61 => {
                    char::from_u32( (b'0' + byte - 52) as u32).unwrap()
                },
                62 => '+',
                63 => '/',
                _ => panic!("invalid byte given - number is not a sextet")
            }
        }
    }

    fn single_sextet( sextets : [Sextet; 4] ) -> [u8;3] {
        
        let u1 = sextets[0].into_inner();
        let u2 = sextets[1].into_inner();
        let u3 = sextets[2].into_inner();
        let u4 = sextets[3].into_inner();
        
        [ 
            u1 << 2 | u2 >> 4,
            u2 << 4 | u3 >> 2,
            u3 << 6 | u4 
        ]

    }

    fn single_bytes( bytes : [u8;3] ) -> [Sextet;4] {
        
        let u1 = bytes[0] as u16;
        let u2 = bytes[1] as u16;
        let u3 = bytes[2] as u16;

        [
            Sextet::from( (u1 >> 2) as u8 ).unwrap(),
            Sextet::from( ( (u1 << 6) as u8 >> 2 ) | (u2 >> 4) as u8 ).unwrap(),
            Sextet::from(( (u2 << 4) as u8 >> 2) | (u3 >> 6) as u8 ).unwrap(),
            Sextet::from(  (u3 << 2) as u8 >> 2 ).unwrap()
        ]
    }

    pub fn to_base64( bytes : &[u8], pad : bool ) -> String{

        let mut string = String::new();
        for chunk in bytes.chunks(3) {
            if chunk.len() == 3 {
                string.extend( single_bytes([chunk[0], chunk[1], chunk[2]]).map(|v| v.into_char()) )
            } else {
                let mut _len = 0;
                if chunk.len() == 1 {
                    string.extend( single_bytes([chunk[0], 0, 0]).iter().map( |v| v.into_char()  ).take(2) );
                    _len = 2;
                } else {                    
                    string.extend( single_bytes([chunk[0], chunk[1], 0]).iter().map( |v| v.into_char()  ).take(3) );
                    _len = 1;
                }
                if pad {
                    string.extend(['='].repeat(_len) )
                }
            }
        }
        string
    } 

    pub fn from_base64( base64 : &str ) -> Vec<u8> {
        assert!( base64.is_ascii() );

        let mut vec = Vec::new();

        // remove '=' padding if it exists
        let mut working_str = base64;
        while let Some(string) = working_str.strip_suffix('=') {
            working_str = string;
        }
        
        for chunk in working_str.as_bytes().chunks(4) {
            if chunk.len() == 4 {
                let sextets = [ 
                    Sextet::from_char(chunk[0] as char).unwrap(), 
                    Sextet::from_char(chunk[1] as char).unwrap(), 
                    Sextet::from_char(chunk[2] as char).unwrap(), 
                    Sextet::from_char(chunk[3] as char).unwrap() ];
                vec.extend( single_sextet(sextets) );
            } else {
                let len = chunk.len();
                if len == 2 {

                    let v0 = Sextet::from_char(chunk[0] as char).unwrap();
                    let v1 = Sextet::from_char(chunk[1] as char).unwrap();

                    vec.extend( single_sextet([v0, v1, Sextet::from(0).unwrap(), Sextet::from(0).unwrap() ] ).iter().take(1)  )
                } else {
                    let v0 = Sextet::from_char(chunk[0] as char).unwrap();
                    let v1 = Sextet::from_char(chunk[1] as char).unwrap();
                    let v2 = Sextet::from_char(chunk[2] as char).unwrap();

                    vec.extend(single_sextet([v0, v1, v2, Sextet::from(0).unwrap() ]).iter().take(2) );
                }
            }
        }
        vec
    }

    #[test]
    fn test_to_base64() {
        assert_eq!(to_base64(b"Man", true),  "TWFu");
        assert_eq!(to_base64(b"Ma", true),  "TWE=");
        assert_eq!(to_base64(b"M", true),  "TQ==");

        assert_eq!(to_base64(b"Man", false),  "TWFu");
        assert_eq!(to_base64(b"Ma", false),  "TWE");
        assert_eq!(to_base64(b"M", false),  "TQ");
    }

    #[test]
    fn test_from_base64() {
        assert_eq!(from_base64("TWFu"), b"Man" );
        assert_eq!(from_base64("TWE="), b"Ma" );
        assert_eq!(from_base64("TQ=="), b"M" );

        assert_eq!(from_base64("TWFu"), b"Man" );
        assert_eq!(from_base64("TWE"), b"Ma" );
        assert_eq!(from_base64("TQ"), b"M" );    }

}