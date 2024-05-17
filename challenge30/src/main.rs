use tools::{digest::{mac, md4::{Md4, Md4Core}, LengthExtender}, encode::ascii::to_ascii};

const SECRET_KEY: &[u8; 10] = b"SECRET KEY";

fn validate( msg : Vec<u8>, mac_code : [u8; 16] ) -> bool {
    mac::<Md4Core>(SECRET_KEY, &msg) == mac_code
}

fn main() {
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    let mut hash = Md4::new();
    hash.update(SECRET_KEY);
    hash.update(msg);
    let target_hash = hash.finalize();

    let mut extender = LengthExtender::<Md4Core>::new( SECRET_KEY.len(), msg, target_hash);
    extender.update(b"admin=true");
    let (tamper_msg, tamper_hash) = extender.finalize();

    println!("tampermsg : {}", to_ascii(&tamper_msg, true));

    assert!(validate(tamper_msg, tamper_hash));
}
