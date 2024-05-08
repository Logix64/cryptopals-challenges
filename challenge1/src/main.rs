use tools::encode::{base64::to_base64, hex::from_hex};

fn main() {
    let bytes = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", true).unwrap();
    assert_eq!( to_base64(&bytes, false), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" );
}
