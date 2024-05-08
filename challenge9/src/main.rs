use bytes::{BufMut, BytesMut};
use tools::encrypt::cipher::pkcs7padding;

fn main() {
    let mut buf = BytesMut::with_capacity(200);
    buf.put(b"YELLOW SUBMARINE".as_slice());
    pkcs7padding(&mut buf,20);
    assert_eq!( buf.get(0..), Some(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_slice()))   
}