use core::hash::Hash;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use crypto_bigint::{modular::runtime_mod::DynResidue, Encoding, Uint, U2048};
use tools::{
    bigint::rsa::{ExponentThree, Key, PrivateKey, PublicExponent, PublicKey, RSA},
    digest::{sha1::Sha1Core, HashAlgorithm, Hasher},
};

#[inline]
fn const_compare(u: impl AsRef<[u8]>, v: impl AsRef<[u8]>) -> bool {
    u.as_ref()
        .iter()
        .zip(v.as_ref().iter())
        .fold(true, |acc, (u, v)| acc && u.eq(v))
        && v.as_ref().len() == u.as_ref().len()
}

const LIMBS: usize = U2048::LIMBS;
type PubExponent = ExponentThree<LIMBS>;
// Duration 1d
const DURATION: Duration = Duration::from_secs(60 * 60 * 24);

struct MessageRecoveryOracle<const LIMBS: usize, H: HashAlgorithm>
where
    Uint<LIMBS>: Encoding,
    H::OUTPUT: Eq + PartialEq,
{
    private_key: PrivateKey<LIMBS>,
    db: HashSet<(H::OUTPUT, Instant)>,
}

impl<const LIMBS: usize, H: HashAlgorithm> MessageRecoveryOracle<LIMBS, H>
where
    Uint<LIMBS>: Encoding,
    H::OUTPUT: Eq + PartialEq + Hash,
{

    fn new<E: PublicExponent<LIMBS>>() -> (Self, PublicKey<LIMBS, E>) {
        let (public_key, private_key) = RSA::new();

        (
            Self {
                private_key,
                db: HashSet::new(),
            },
            public_key,
        )
    }

    fn decrypt(&mut self, text: &Uint<LIMBS>) -> Result<Uint<LIMBS>, &'static str> {
        let mut hasher = Hasher::<H>::new();
        hasher.update(text.to_be_bytes());
        let hash = hasher.finalize();

        let now = Instant::now();
        // only retain all entrys less than one day old
        self.db
            .retain(|(_, b)| now.duration_since(*b) <= DURATION);

        // If there is an entry which is less than a day old, where the hash matches, return an Error
        if self.db.iter().any(|(a, _)| const_compare(a, hash)) {
            return Err("message was already submitted");
        }
        self.db.insert((hash, now));

        return Ok(self.private_key.encrypt(text));
    }
}

fn main() {
    let (mut oracle, public_key) = MessageRecoveryOracle::<LIMBS, Sha1Core>::new::<PubExponent>();

    let m = RSA::into_uint(b"this is a secret message").unwrap();
    let c = public_key.encrypt(&m);

    let p = oracle.decrypt(&c).unwrap();
    assert_eq!(p, m);

    let modulus = public_key.get_modulus();
    let s = RSA::into_uint("this is a padding message").unwrap();
    let s_enc = DynResidue::new(&public_key.encrypt(&s), modulus);

    let c_other = DynResidue::new(&c, modulus).mul(&s_enc).retrieve();
    let p_other = oracle.decrypt(&c_other).unwrap();

    let p_enc = DynResidue::new(&p_other, modulus)
        .mul(
            &DynResidue::new(&s, modulus).invert().0
        ).retrieve();

    assert_eq!(p, p_enc);
}
