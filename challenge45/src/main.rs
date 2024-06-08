use crypto_bigint::{modular::constant_mod::Residue, Encoding, Uint, U1024, U192};
use tools::{
    bigint::dsa::{DSAParameters, DSA},
    digest::sha1::{Sha1, Sha1Core},
    generate_dsa_params, hash,
};

generate_dsa_params!(
    DefaultParams,
    PARAMS,
    U1024,
    U192,
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291",
    Sha1Core,
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
    "00000000f4f47f05794b256174bba6e9b396a7707e563c5b"
);

generate_dsa_params!(
    ZeroGeneratorParams,
    ZERO_PARAMS,
    U1024,
    U192,
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    Sha1Core,
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
    "00000000f4f47f05794b256174bba6e9b396a7707e563c5b"
);

generate_dsa_params!(
    ModulusGeneratorParams,
    MODULUS_PARAMS,
    U1024,
    U192,
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb2",
    Sha1Core,
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
    "00000000f4f47f05794b256174bba6e9b396a7707e563c5b"
);

fn show_characteristics<
    const P_LIMBS: usize,
    const Q_LIMBS: usize,
    T: DSAParameters<P_LIMBS, Q_LIMBS>,
>(
    msg1: &impl AsRef<[u8]>,
    msg2: &impl AsRef<[u8]>,
) where
    Uint<P_LIMBS>: Encoding,
    Uint<Q_LIMBS>: Encoding,
{
    let instance = DSA::new::<P_LIMBS, Q_LIMBS, T>();

    let signature = instance.sign(msg1, false);

    println!(
        "signature with generator 0 : r = {} and s = {}",
        signature.0, signature.1
    );

    println!(
        "verification with right text : {}",
        DSA::verify::<P_LIMBS, Q_LIMBS, T>(
            msg1,
            &signature.0,
            &signature.1,
            instance.get_public_key(),
            false
        )
    );
    println!(
        "verification with false text : {}",
        DSA::verify::<P_LIMBS, Q_LIMBS, T>(
            msg2,
            &signature.0,
            &signature.1,
            instance.get_public_key(),
            false
        )
    )
}

fn sign_for_bad_params(
    public_key: &Uint<MODULUS_PARAMS_P_LIMBS>,
    msg: impl AsRef<[u8]>,
) -> (Uint<MODULUS_PARAMS_Q_LIMBS>, Uint<MODULUS_PARAMS_Q_LIMBS>) {
    let z = DSA::into_uint(hash!(Sha1, msg)).unwrap();
    let (z_inv, _) = Residue::<ModulusGeneratorParamsQ, MODULUS_PARAMS_Q_LIMBS>::new(&z).invert();
    let r = ModulusGeneratorParams::modp_to_modq(
        &Residue::<ModulusGeneratorParamsP, MODULUS_PARAMS_P_LIMBS>::new(public_key).pow(&z),
    );

    let s = r.mul(&z_inv);

    (r.retrieve(), s.retrieve())
}

fn main() {
    let message1 = b"this is a test";
    let message2 = b"this is not a test";

    println!("NORMAL PARAMETERS : ");
    show_characteristics::<PARAMS_P_LIMBS, PARAMS_Q_LIMBS, DefaultParams>(message1, message2);

    println!("ZERO GENERATOR PARAMETERS : ");
    show_characteristics::<ZERO_PARAMS_P_LIMBS, ZERO_PARAMS_Q_LIMBS, ZeroGeneratorParams>(
        message1, message2,
    );

    println!("P+1 GENERATOR PARAMETERS : ");
    show_characteristics::<MODULUS_PARAMS_P_LIMBS, MODULUS_PARAMS_Q_LIMBS, ModulusGeneratorParams>(
        message1, message2,
    );

    let instance =
        DSA::new::<MODULUS_PARAMS_P_LIMBS, MODULUS_PARAMS_Q_LIMBS, ModulusGeneratorParams>();

    let signature = sign_for_bad_params(&instance.get_public_key(), b"test test test");

    println!(
        "verification with a magic signature r = {} and s = {} : {}",
        signature.0,
        signature.1,
        DSA::verify::<MODULUS_PARAMS_P_LIMBS, MODULUS_PARAMS_Q_LIMBS, ModulusGeneratorParams>(
            b"test test test",
            &signature.0,
            &signature.1,
            instance.get_public_key(),
            false
        )
    )
}
