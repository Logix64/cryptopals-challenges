use crypto_bigint::{modular::constant_mod::Residue, Uint, U1024, U192};
use tools::{bigint::dsa::{DSAInstance, DSAParameters, DSA}, digest::sha1::Sha1Core, encode::to_uint::string_into_uint, generate_dsa_params};

const P_LIMBS : usize = U1024::LIMBS;
const Q_LIMBS : usize = U192::LIMBS;

generate_dsa_params!(
    DefaultParams,
    U1024,
    U192,
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291",
    Sha1Core,
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
    "00000000f4f47f05794b256174bba6e9b396a7707e563c5b"
);

fn main() {
    let instance : DSAInstance<P_LIMBS,Q_LIMBS,DefaultParams> = DSA::new();
    let m = b"this is a test";
    let (r,s) = instance.sign(m, false);

    assert!( DSA::verify::<P_LIMBS, Q_LIMBS, DefaultParams>(m, &r, &s, instance.get_public_key(), false) );
    assert!(!DSA::verify::<P_LIMBS, Q_LIMBS, DefaultParams>(b"this isnt a test", &r, &s, instance.get_public_key(), false ));

    let public_key : Uint<P_LIMBS> = Uint::from_be_hex(
        "084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17"
    );

    /*
    let hash = hash!(Sha1,b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch");
    assert_eq!(to_hex(&hash), "d2d0714f014a9784047eaeccf956520045c45265");
    */

    let hash = [0xd2, 0xd0, 0x71, 0x4f, 0x01, 0x4a, 0x97, 0x84, 0x04, 0x7e, 0xae, 0xcc, 0xf9, 0x56, 0x52, 0x00, 0x45, 0xc4, 0x52, 0x65];

    let r = string_into_uint::<Q_LIMBS>("548099063082341131477253921760299949438196259240").unwrap();
    let s = string_into_uint::<Q_LIMBS>("857042759984254168557880549501802188789837994940").unwrap();
    let (r_inv,_) = Residue::new(&r).invert();

    for k  in 0..=u16::MAX {

        let nonce : Uint<P_LIMBS> = DSA::into_uint(k.to_be_bytes()).unwrap();
        let x = DSA::recover_private_key_from_nonce::<P_LIMBS,Q_LIMBS,DefaultParams>(&nonce, &s, &r_inv, hash );

        if DefaultParams::G.pow(&x).retrieve() == public_key {
            println!("found private key : {x}\nwith nonce {k:x}");
            break;
        }
    }
}
