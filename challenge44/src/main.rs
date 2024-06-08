use std::{
    fs::File,
    io::{self, BufRead, BufReader, Error, Lines},
};

use crypto_bigint::{
    modular::constant_mod::Residue,
    subtle::{ ConstantTimeEq, CtOption},
    CtChoice, U1024, U192,
};
use tools::{
    bigint::dsa::{DSAParameters, DSA},
    digest::sha1::Sha1Core,
    encode::to_uint::string_into_uint,
    generate_dsa_params,
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

const PUBLIC_KEY : U1024 = U1024::from_be_hex("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821");

struct Entry {
    msg: String,
    s: U192,
    r: U192,
    m: U192,
}

impl Entry {
    fn get_value<'a>(s: &'a str) -> Result<String, io::Error> {
        let (_, msg) = s
            .split_once(": ")
            .ok_or(Error::other("no parameter with : found"))?;

        Ok(msg.into())
    }

    fn pad(s: &str, n : usize ) -> String {
        let len = s.chars().count();
        assert!(len <= n);
        "0".repeat(n - len) + s
    }

    fn from_str<T: BufRead>(lines: &mut Lines<T>) -> Result<Self, io::Error> {
        let msg_str = Self::get_value(&lines.next().ok_or(Error::other("not enough lines"))??)?;
        let s_str = Self::get_value(&lines.next().ok_or(Error::other("not enough lines"))??)?;
        let r_str = Self::get_value(&lines.next().ok_or(Error::other("not enough lines"))??)?;
        let m_str = Self::get_value(&lines.next().ok_or(Error::other("not enough lines"))??)?;

        Ok(Self {
            msg: msg_str.into(),
            s: string_into_uint::<PARAMS_Q_LIMBS>(&s_str)
                .ok_or(Error::other("problem parsing uint"))?,
            r: string_into_uint::<PARAMS_Q_LIMBS>(&r_str)
                .ok_or(Error::other("problem parsing uint"))?,
            m: U192::from_be_hex( &Self::pad(&m_str, U192::BYTES*2 ) ),
        })
    }
}

fn main() -> io::Result<()> {
    let file = File::open("44.txt")?;

    let mut lines = BufReader::new(file).lines();

    let mut entries = Vec::new();

    loop {
        match Entry::from_str(&mut lines) {
            Ok(v) => entries.push(v),
            Err(_) => break,
        }
    }

    for i in 0..entries.len() {
        for j in 0..i {
            let private_key = DSA::recover_nonce::<PARAMS_P_LIMBS, PARAMS_Q_LIMBS, DefaultParams>(
                &entries[i].m,
                &entries[j].m,
                &entries[i].s,
                &entries[j].s,
            )
            .and_then(|nonce| {
                let (r_inv, choice) = Residue::new(&entries[i].r).invert();

                let private_key =
                    DSA::recover_private_key_from_nonce::<
                        PARAMS_P_LIMBS,
                        PARAMS_Q_LIMBS,
                        DefaultParams,
                    >(&nonce.resize(), &entries[i].s, &r_inv, &entries[i].m);

                CtOption::new(private_key, choice.into())
            });

            if private_key
                .map(|v| DefaultParams::G.pow(&v).retrieve())
                .ct_eq(&CtOption::new(PUBLIC_KEY, CtChoice::TRUE.into()))
                .into()
            {

                println!("the messages \'{}\' and \'{}\' have the same nonce", entries[i].msg, entries[j].msg );
                println!("the private key is {private_key:?}");
                println!("the public key is : {}",  DefaultParams::G.pow(&private_key.unwrap()).retrieve() )
            }
        }
    }

    Ok(())
}
