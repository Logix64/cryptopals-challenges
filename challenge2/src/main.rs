use tools::{encode::hex::{from_hex, to_hex}, encrypt::xor::XOREnc};

fn main() {
    let bytes1 = from_hex("1c0111001f010100061a024b53535009181c", true).unwrap();
    let bytes2 = from_hex("686974207468652062756c6c277320657965", true).unwrap();

    let mut encrypted = Vec::with_capacity(bytes1.len());

    XOREnc::fixed_encrypt(&bytes1, &bytes2, &mut encrypted);

    assert_eq!(to_hex(&encrypted),"746865206b696420646f6e277420706c6179")
}
