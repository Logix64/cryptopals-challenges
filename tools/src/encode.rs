pub mod hex {
    /// Converts a single pair of chars into a byte. 
    /// If there are unnatural hex chars given, returns None. 
    fn single_u8_be(chars: [char; 2]) -> Option<u8> {
        assert!(
            chars.iter().all(|v| v.is_ascii_hexdigit()),
            "all characters must be hex digits"
        );

        chars[0]
            .to_digit(16)
            .zip(chars[1].to_digit(16))
            .map(|(v1, v2)| (v1 << 4 | v2) as u8)
    }

    /// Converts from a given hex string to a byte vector. As an option one can decide between little-endian and big-endian.
    pub fn from_hex(hex: &str, big_endian: bool) -> Option<Vec<u8>> {
        assert!(
            hex.chars().all(|v| v.is_ascii_hexdigit()),
            "all characters must be hex digits!"
        );

        let mut vec: Vec<char> = hex.chars().collect();

        if vec.len() % 2 == 1 {
            vec.insert(if big_endian { 0 } else { vec.len() }, '0');
        }

        // let mut bytes = Vec::with_capacity(vec.len() / 2);
        let mut state = Some(Vec::new());

        for chunk in vec.chunks_exact(2) {
            state = single_u8_be([chunk[0], chunk[1]])
                .zip(state)
                .map(|(v, state)| [&state, [v].as_slice()].concat())
        }
        state
    }

    /// Converts bytes to a hex string. 
    pub fn to_hex(bytes: &[u8]) -> String {
        let mut hex = String::new();
        for i in bytes {
            hex.extend(format!("{:02x}", *i).chars());
        }
        hex
    }

    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("ffff", true), Some(vec![0xff, 0xff]));
        assert_eq!(from_hex("fff", true), Some(vec![0x0f, 0xff]));
        assert_eq!(from_hex("fff", false), Some(vec![0xff, 0xf0]));
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&vec![0x0f, 0xff]), "0fff");
        assert_eq!(to_hex(&vec![0xff, 0xff]), "ffff");
    }
}

pub mod base64 {
    use std::u32;

    pub const RANGE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Wrapping struct for Sextets aka numbers with at most 6 bits. 
    #[derive(Clone, Copy)]
    enum Sextet {
        Sextet(u8),
    }

    impl Sextet {
        /// Converts from byte to Sextet, the given byte must be < 2^6, otherwise returns None.
        fn from(byte: u8) -> Option<Self> {
            if byte < 64 {
                Some(Self::Sextet(byte))
            } else {
                None
            }
        }

        /// Converts from a given Base64 character to itself. 
        /// If the character is not included in the Base64 charset, returns None.
        fn from_char(s: char) -> Option<Self> {
            match s as u8 {
                b'A'..=b'Z' => Some(Sextet::Sextet(s as u8 - b'A')),
                b'a'..=b'z' => Some(Sextet::Sextet(s as u8 - b'a' + 26)),
                b'0'..=b'9' => Some(Sextet::Sextet(s as u8 - b'0' + 52)),
                b'+' => Some(Sextet::Sextet(62)),
                b'/' => Some(Sextet::Sextet(63)),
                _ => None,
            }
        }

        /// Consumes self and returns the whole byte. 
        fn into_inner(self) -> u8 {
            let Self::Sextet(byte) = self;
            byte
        }

        /// Consumes self and returns the Base64 character.
        fn into_char(self) -> char {
            let Self::Sextet(byte) = self;
            match byte {
                0..=25 => char::from_u32((b'A' + byte) as u32).unwrap(),
                26..=51 => char::from_u32((b'a' + byte - 26) as u32).unwrap(),
                52..=61 => char::from_u32((b'0' + byte - 52) as u32).unwrap(),
                62 => '+',
                63 => '/',
                _ => panic!("invalid byte given - number is not a sextet"),
            }
        }
    }

    /// Converts 4 Sextets into 3 Octets. 
    fn single_sextet(sextets: [Sextet; 4]) -> [u8; 3] {
        let u1 = sextets[0].into_inner();
        let u2 = sextets[1].into_inner();
        let u3 = sextets[2].into_inner();
        let u4 = sextets[3].into_inner();

        [u1 << 2 | u2 >> 4, u2 << 4 | u3 >> 2, u3 << 6 | u4]
    }

    // Converts 3 Octets into 4 Sextets
    fn single_bytes(bytes: [u8; 3]) -> [Sextet; 4] {
        let u1 = bytes[0] as u16;
        let u2 = bytes[1] as u16;
        let u3 = bytes[2] as u16;

        [
            Sextet::from((u1 >> 2) as u8).unwrap(),
            Sextet::from(((u1 << 6) as u8 >> 2) | (u2 >> 4) as u8).unwrap(),
            Sextet::from(((u2 << 4) as u8 >> 2) | (u3 >> 6) as u8).unwrap(),
            Sextet::from((u3 << 2) as u8 >> 2).unwrap(),
        ]
    }

    /// Encodes a given byte-slice into base64 with an option to add padding with = 
    pub fn to_base64(bytes: &[u8], pad: bool) -> String {
        let mut string = String::new();
        for chunk in bytes.chunks(3) {
            if chunk.len() == 3 {
                string.extend(single_bytes([chunk[0], chunk[1], chunk[2]]).map(|v| v.into_char()))
            } else {
                let mut _len = 0;
                if chunk.len() == 1 {
                    string.extend(
                        single_bytes([chunk[0], 0, 0])
                            .iter()
                            .map(|v| v.into_char())
                            .take(2),
                    );
                    _len = 2;
                } else {
                    string.extend(
                        single_bytes([chunk[0], chunk[1], 0])
                            .iter()
                            .map(|v| v.into_char())
                            .take(3),
                    );
                    _len = 1;
                }
                if pad {
                    string.extend(['='].repeat(_len))
                }
            }
        }
        string
    }

    /// Converts from Base64 Encoding to Byte Vector and removes padding 
    pub fn from_base64(base64: &str) -> Vec<u8> {
        assert!(base64.is_ascii());

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
                    Sextet::from_char(chunk[3] as char).unwrap(),
                ];
                vec.extend(single_sextet(sextets));
            } else {
                let len = chunk.len();
                if len == 2 {
                    let v0 = Sextet::from_char(chunk[0] as char).unwrap();
                    let v1 = Sextet::from_char(chunk[1] as char).unwrap();

                    vec.extend(
                        single_sextet([v0, v1, Sextet::from(0).unwrap(), Sextet::from(0).unwrap()])
                            .iter()
                            .take(1),
                    )
                } else {
                    let v0 = Sextet::from_char(chunk[0] as char).unwrap();
                    let v1 = Sextet::from_char(chunk[1] as char).unwrap();
                    let v2 = Sextet::from_char(chunk[2] as char).unwrap();

                    vec.extend(
                        single_sextet([v0, v1, v2, Sextet::from(0).unwrap()])
                            .iter()
                            .take(2),
                    );
                }
            }
        }
        vec
    }

    #[test]
    fn test_to_base64() {
        assert_eq!(to_base64(b"Man", true), "TWFu");
        assert_eq!(to_base64(b"Ma", true), "TWE=");
        assert_eq!(to_base64(b"M", true), "TQ==");

        assert_eq!(to_base64(b"Man", false), "TWFu");
        assert_eq!(to_base64(b"Ma", false), "TWE");
        assert_eq!(to_base64(b"M", false), "TQ");
    }

    #[test]
    fn test_from_base64() {
        assert_eq!(from_base64("TWFu"), b"Man");
        assert_eq!(from_base64("TWE="), b"Ma");
        assert_eq!(from_base64("TQ=="), b"M");

        assert_eq!(from_base64("TWFu"), b"Man");
        assert_eq!(from_base64("TWE"), b"Ma");
        assert_eq!(from_base64("TQ"), b"M");
    }
}

pub mod ascii {

    /// Converts from ASCII Encoding into Byte Vector
    pub fn from_ascii(ascii: &str) -> Vec<u8> {
        assert!(ascii.chars().all(|v| v.is_ascii()));
        Vec::from_iter(ascii.bytes())
    }

    /// Encodes a Byte Slice into ASCII Encoding with an option to escape specific characters
    pub fn to_ascii(bytes: &[u8], escape: bool) -> String {
        if escape {
            String::from_iter(
                bytes
                    .iter()
                    .map(|v| v.escape_ascii().map(|v| v as char))
                    .flatten(),
            )
        } else {
            String::from_iter(bytes.iter().map(|v| *v as char))
        }
    }

    #[test]
    fn test_ascii() {
        assert_eq!(from_ascii("abc"), vec![b'a', b'b', b'c']);
        assert_eq!(to_ascii(&vec![b'a', b'b', b'c'], false), "abc");
        assert_eq!(to_ascii(&vec![b'a', b'b', b'c', b'\n'], true), "abc\\n");
    }
}

pub mod uri {

    /// Decodes a URI paramter list into a List of Strings
    pub fn from_uri<'a>(text: &'a str) -> Option<Vec<(&'a str, &'a str)>> {
        text.trim()
            .split('&')
            .all(|v| check_single_var(v))
            .then_some(Vec::from_iter(
                text.trim().split('&').map(|v| parse_single_var(v)),
            ))
    }

    /// Checks if a single slice contains only one '=', which makes it a valid part of the URI parameter encoding.
    fn check_single_var(text: &str) -> bool {
        text.matches('=').count() == 1
    }

    /// Performs the splitting into the left and right side of the equation. 
    /// Does not check for any validation - the check must be performed before. 
    fn parse_single_var<'a>(text: &'a str) -> (&'a str, &'a str) {
        text.split_once('=').unwrap()
    }

    /// Encodes a mapping into a valid URI parameter list. Goes from the beginning to the end, unlike in HashMaps.   
    pub fn to_uri<'a>( map : &Vec<(&'a str, &'a str)> ) -> String {
        let mut res = String::new();
        if map.len() > 0 {
            let (k,v) = map.iter().next().unwrap();
            res.extend( [ k.to_string() + "=" + v ] );
            res.extend( map.iter().skip(1).map( |(k,v)| String::from('&') + k + "=" + v ) );
        }
        res
    }

    /// Converts a mapping into JSON 
    pub fn to_json<'a>( map : &Vec<(&'a str, &'a str)> ) -> String {
        let mut res = String::new();
        res.push_str("{");
        if map.len() > 0 {
            let (k,v) = map.iter().next().unwrap();
            res.push_str( &("\n\t".to_string() + k + ": \'" + v + "\'")  );
            res.extend( map.iter().skip(1).map( |(k,v)| String::from(",\n\t") + k + ": \'" + v + "\'" ) );
            res.push_str("\n");
        }
        res.push_str("}");
        res
    }

    #[test]
    fn test_from_uri() {
        let hashmap = Vec::from_iter([("foo","bar"), ("baz","qux"), ("zap","zazzle")]);
        assert_eq!(from_uri("foo=bar&baz=qux&zap=zazzle"), Some(hashmap) );
    }

    #[test]
    fn test_to_uri() {
        let hashmap = Vec::from_iter([("foo","bar"), ("baz","qux"), ("zap","zazzle")]);
        assert_eq!(to_uri(&hashmap), "foo=bar&baz=qux&zap=zazzle")
    }

    #[test]
    fn test_to_json(){
        let hashmap = Vec::from_iter([("foo","bar"), ("baz","qux"), ("zap","zazzle")]);
        assert_eq!(to_json(&hashmap), "{\n\tfoo: \'bar\',\n\tbaz: \'qux\',\n\tzap: \'zazzle\'\n}")
    }

}
