use crate::{digest::HashAlgorithm, encode::to_uint::bytes_into_uint, hash_by_algo};
use crypto_bigint::{
    modular::{
        constant_mod::{Residue, ResidueParams},
        runtime_mod::{DynResidue, DynResidueParams},
    },
    subtle::{ConstantTimeEq, CtOption},
    CtChoice, Encoding, Random, Uint, Zero,
};
use rand::thread_rng;

pub trait DSAParameters<const P_LIMBS: usize, const Q_LIMBS: usize>
where
    Self::HashFunction: HashAlgorithm,
    Uint<P_LIMBS>: Encoding,
{
    type HashFunction;
    type P: ResidueParams<P_LIMBS>;
    type Q: ResidueParams<Q_LIMBS>;
    const G: Residue<Self::P, P_LIMBS>;

    fn modp_to_modq(num: &Residue<Self::P, P_LIMBS>) -> Residue<Self::Q, Q_LIMBS> {
        let q: DynResidueParams<P_LIMBS> = DynResidueParams::new(&Self::Q::MODULUS.resize());
        Residue::new(&DynResidue::new(&num.retrieve(), q).retrieve().resize())
    }
}

#[macro_export]
macro_rules! generate_dsa_params {
    ($name:ident, $const_name:ident, $uint_p:ty, $uint_q:ty, $p:ty, $q:ty, $g:expr, $hash:ty) => {
        struct $name {}

        paste::paste! {
            const [<$const_name _P_LIMBS>] : usize = <$uint_p>::LIMBS;
            const [<$const_name _Q_LIMBS>] : usize = <$uint_q>::LIMBS;
        }

        impl $crate::bigint::dsa::DSAParameters<{ <$uint_p>::LIMBS }, { <$uint_q>::LIMBS }>
            for $name
        {
            type HashFunction = $hash;
            type P = $p;
            type Q = $q;
            const G: crypto_bigint::modular::constant_mod::Residue<Self::P, { <$uint_p>::LIMBS }> =
                crypto_bigint::modular::constant_mod::Residue::new(
                    &crypto_bigint::Uint::<{ <$uint_p>::LIMBS }>::from_be_hex($g),
                );
        }
    };
    ($name:ident, $const_name:ident, $uint_p:ty, $uint_q:ty, $g:expr, $hash:ty, $p_value:expr, $q_value:expr) => {
        paste::paste! {

            crypto_bigint::impl_modulus!([<$name P>], $uint_p, $p_value);
            crypto_bigint::impl_modulus!([<$name Q>], $uint_q, $q_value);
            generate_dsa_params!($name, $const_name, $uint_p, $uint_q, [<$name P>],[<$name Q>], $g, $hash);
        }
    };
}

pub struct DSAInstance<
    const P_LIMBS: usize,
    const Q_LIMBS: usize,
    PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>,
> where
    Uint<P_LIMBS>: Encoding,
    Uint<Q_LIMBS>: Encoding,
    PARAMETERS::HashFunction: HashAlgorithm,
{
    private_key: Uint<Q_LIMBS>,
    public_key: Residue<PARAMETERS::P, P_LIMBS>,
}

impl<const P_LIMBS: usize, const Q_LIMBS: usize, PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>>
    DSAInstance<P_LIMBS, Q_LIMBS, PARAMETERS>
where
    Uint<P_LIMBS>: Encoding,
    Uint<Q_LIMBS>: Encoding,
    PARAMETERS::HashFunction: HashAlgorithm,
{
    pub fn sign(&self, m: impl AsRef<[u8]>, little_endian: bool) -> (Uint<Q_LIMBS>, Uint<Q_LIMBS>) {
        loop {
            let k = Residue::<PARAMETERS::Q, Q_LIMBS>::random(&mut thread_rng());
            let (k_inv, choice) = k.invert();
            let r = PARAMETERS::modp_to_modq(&PARAMETERS::G.pow(&k.retrieve()));

            let h_m = Residue::<PARAMETERS::Q, Q_LIMBS>::new(
                &bytes_into_uint::<Q_LIMBS>(
                    hash_by_algo!(PARAMETERS::HashFunction, &m),
                    little_endian,
                    false,
                )
                .unwrap(),
            );

            let s = k_inv.mul(&(h_m.add(&Residue::new(&self.private_key).mul(&r))));

            if r.is_zero().into() || s.is_zero().into() || !<CtChoice as Into<bool>>::into(choice) {
                continue;
            } else {
                return (r.retrieve(), s.retrieve());
            }
        }
    }

    pub fn get_public_key(&self) -> Uint<P_LIMBS> {
        self.public_key.retrieve()
    }
}

/// DSA Instance Factory
pub struct DSA {}

impl DSA {
    pub fn new<
        const P_LIMBS: usize,
        const Q_LIMBS: usize,
        PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>,
    >() -> DSAInstance<P_LIMBS, Q_LIMBS, PARAMETERS>
    where
        Uint<P_LIMBS>: Encoding,
        Uint<Q_LIMBS>: Encoding,
    {
        let private_key = Residue::<PARAMETERS::Q, Q_LIMBS>::random(&mut thread_rng()).retrieve();

        DSAInstance {
            private_key,
            public_key: PARAMETERS::G.pow(&private_key),
        }
    }

    pub fn verify<
        const P_LIMBS: usize,
        const Q_LIMBS: usize,
        PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>,
    >(
        m: impl AsRef<[u8]>,
        r_uint: &Uint<Q_LIMBS>,
        s_uint: &Uint<Q_LIMBS>,
        public_key: Uint<P_LIMBS>,
        little_endian: bool,
    ) -> bool
    where
        Uint<P_LIMBS>: Encoding,
        Uint<Q_LIMBS>: Encoding,
    {
        let r = Residue::<PARAMETERS::Q, Q_LIMBS>::new(r_uint);
        let s = Residue::<PARAMETERS::Q, Q_LIMBS>::new(s_uint);
        let y = Residue::<PARAMETERS::P, P_LIMBS>::new(&public_key);

        let (w, choice) = s.invert();

        let h_m = Residue::new(
            &bytes_into_uint(
                hash_by_algo!(PARAMETERS::HashFunction, &m),
                little_endian,
                false,
            )
            .unwrap(),
        );

        let u1 = w.mul(&h_m).retrieve();
        let u2 = r.mul(&w).retrieve();

        let v = PARAMETERS::modp_to_modq(&PARAMETERS::G.pow(&u1).mul(&y.pow(&u2))).retrieve();

        v.ct_eq(&r_uint).into()
            && choice.into()
            && r.is_zero().unwrap_u8() == 0x00
            && s.is_zero().unwrap_u8() == 0x00
    }

    pub fn recover_private_key_from_nonce<
        const P_LIMBS: usize,
        const Q_LIMBS: usize,
        PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>,
    >(
        nonce: &Uint<P_LIMBS>,
        s_uint: &Uint<Q_LIMBS>,
        r_inv: &Residue<PARAMETERS::Q, Q_LIMBS>,
        m: &Uint<Q_LIMBS>,
    ) -> Uint<Q_LIMBS>
    where
        Uint<P_LIMBS>: Encoding,
        Uint<Q_LIMBS>: Encoding,
    {
        let h_m = Residue::new(m);
        let s: Residue<PARAMETERS::Q, Q_LIMBS> = Residue::new(&s_uint);
        let k = PARAMETERS::modp_to_modq(&Residue::new(&nonce));

        ((s * k - h_m) * r_inv).retrieve()
    }

    pub fn recover_nonce<
        const P_LIMBS: usize,
        const Q_LIMBS: usize,
        PARAMETERS: DSAParameters<P_LIMBS, Q_LIMBS>,
    >(
        m1_uint: &Uint<Q_LIMBS>,
        m2_uint: &Uint<Q_LIMBS>,
        s1_uint: &Uint<Q_LIMBS>,
        s2_uint: &Uint<Q_LIMBS>,
    ) -> CtOption<Uint<Q_LIMBS>>
    where
        Uint<Q_LIMBS>: Encoding,
        Uint<P_LIMBS>: Encoding,
    {
        let m1: Residue<PARAMETERS::Q, Q_LIMBS> = Residue::new(&m1_uint);
        let m2 = Residue::new(&m2_uint);
        let (diff, choice) = (Residue::new(&s1_uint) - Residue::new(&s2_uint)).invert();

        CtOption::new(diff, choice.into()).map(|v| (m1 - m2).mul(&v).retrieve())
    }

    pub fn into_uint<const LIMBS: usize>(m: impl AsRef<[u8]>) -> Option<Uint<LIMBS>>
    where
        Uint<LIMBS>: Encoding,
    {
        use crate::encode::to_uint::bytes_into_uint;

        bytes_into_uint(m, true, false)
    }
}
