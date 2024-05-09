use tools::encrypt::cipher::strip_pkcs7_padding;

fn main() {
    assert_eq!( strip_pkcs7_padding(b"ICE ICE BABY\x04\x04\x04\x04".as_slice()), Ok(b"ICE ICE BABY".as_slice()) );
    assert_eq!( strip_pkcs7_padding(b"ICE ICE BABY\x05\x05\x05\x05".as_slice()), Err(()) );
    assert_eq!( strip_pkcs7_padding(b"ICE ICE BABY\x01\x02\x03\x04".as_slice()), Err(()) );
}
