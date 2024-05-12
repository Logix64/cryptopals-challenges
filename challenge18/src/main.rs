use tools::{encode::{ascii::to_ascii, base64::from_base64}, encrypt::aes::{AesCtr128, NonceFormat} };

fn main() {
    let bytes = from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

    let format = NonceFormat::new(vec![0x00;8]);

    let mut ctr = AesCtr128::init(b"YELLOW SUBMARINE", format);
    let mut output = Vec::with_capacity(bytes.len());

    ctr.update(&bytes, &mut output);

    println!("{}", to_ascii(&output, true));
}
