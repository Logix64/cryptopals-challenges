use tools::digest::{mac, sha1::Sha1Core};

fn main() {
    assert_ne!(
        mac::<Sha1Core>(b"YELLOW SUBMARINE", b"MESSAGE"),
        mac::<Sha1Core>(b"YELLOW SUBMARINE", b"MESSAG")
    );

    assert_ne!(
        mac::<Sha1Core>(b"YELLOW SUBMARINF", b"MESSAGE"),
        mac::<Sha1Core>(b"YELLOW SUBMARINE", b"MESSAGE")
    );
}
