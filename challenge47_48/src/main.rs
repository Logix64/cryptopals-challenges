use crypto_bigint::{
    modular::runtime_mod::DynResidue, subtle::CtOption, CheckedAdd, CheckedSub, ConcatMixed,
    Encoding, Uint, U768,
};
use tools::bigint::rsa::{ExponentThree, Key, PrivateKey, PublicExponent, PublicKey, RSA};

type Size = U768;
const LIMBS: usize = Size::LIMBS;
type PublicKeyParam = ExponentThree<LIMBS>;

struct PkcsOracle<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    private_key: PrivateKey<LIMBS>,
}

impl<const LIMBS: usize> PkcsOracle<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    /// Generates new Oracle
    fn new<EXPONENT: PublicExponent<LIMBS>>() -> (PublicKey<LIMBS, EXPONENT>, Self) {
        let (public_key, private_key) = RSA::new::<LIMBS, EXPONENT>();
        (public_key, Self { private_key })
    }

    /// Checks valid PKCS#5 padding
    fn valid_padding<const XLIMBS: usize>(&self, msg: &Uint<XLIMBS>) -> bool {
        let decrypted = self.private_key.encrypt(&msg).to_be_bytes();
        decrypted.as_ref()[0] == 0x00 && decrypted.as_ref()[1] == 0x02
    }
}

#[derive(Debug)]
struct Interval<const LIMBS: usize> {
    upper_bound: Uint<LIMBS>,
    lower_bound: Uint<LIMBS>,
}

// ceiling( a/b ) for integers 
fn ceiling_div<const LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> CtOption<Uint<LIMBS>> {
    a.checked_add(&b)
        .and_then(|sum| sum.checked_sub(&Uint::<LIMBS>::ONE))
        .and_then(|diff| diff.checked_div(b))
}

// inserts if a valid interval
fn insert<const LIMBS: usize>(m: &mut Vec<Interval<LIMBS>>, ival: Interval<LIMBS>) {
    for current in m.iter_mut() {
        if !(current.upper_bound < ival.lower_bound || current.lower_bound > ival.upper_bound) {
            current.lower_bound = current.lower_bound.min(ival.lower_bound);
            current.upper_bound = current.upper_bound.max(ival.upper_bound);
            return;
        }
    }
    if ival.lower_bound <= ival.upper_bound {
        m.push(ival);
    }
}

// Generates c0 if not PKCS#5 conform
fn blinding<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>, const XLIMBS: usize>(
    c: &Uint<LIMBS>,
    public_key: &PublicKey<LIMBS, EXPONENT>,
    oracle: &PkcsOracle<LIMBS>,
) -> Uint<LIMBS>
where
    Uint<LIMBS>: Encoding + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<XLIMBS>>,
{
    let mut s_0 = Uint::<LIMBS>::ZERO;
    let mut enc = public_key.encrypt(&s_0);
    while oracle.valid_padding(&c.mul(&enc)) {
        s_0 = s_0.wrapping_add(&Uint::<LIMBS>::ONE);
        enc = public_key.encrypt(&s_0);
    }
    s_0
}

// Search for next collision
fn search_first<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>, const XLIMBS: usize>(
    oracle: &PkcsOracle<LIMBS>,
    public_key: &PublicKey<LIMBS, EXPONENT>,
    c: &Uint<LIMBS>,
    s: &mut Uint<LIMBS>,
) where
    Uint<LIMBS>: Encoding + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<XLIMBS>>,
{
    debug_assert!(oracle.valid_padding(&c));

    let mut enc: Uint<LIMBS> = public_key.encrypt(&s);

    while !oracle.valid_padding(&c.mul(&enc)) {
        *s = s.wrapping_add(&Uint::<LIMBS>::ONE);
        enc = public_key.encrypt(&s);
    }
}

// broader search with multiple intervals for large modulus sizes
fn search<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>, const XLIMBS: usize>(
    oracle: &PkcsOracle<LIMBS>,
    public_key: &PublicKey<LIMBS, EXPONENT>,
    c: &Uint<LIMBS>,
    m: &Interval<LIMBS>,
    s: &mut Uint<LIMBS>,
) where
    Uint<LIMBS>: Encoding + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<XLIMBS>>,
{
    let modulus: Uint<XLIMBS> = public_key.get_modulus().modulus().resize();
    let two_b = Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 15);
    let three_b = two_b.wrapping_add(&Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 16));

    let mut r: Uint<LIMBS> = m
        .upper_bound
        .mul(&s)
        .checked_sub(&two_b)
        .and_then(|diff| ceiling_div::<XLIMBS>(&diff.shl(1), &modulus))
        .map(|quot| quot.resize())
        .unwrap();

    *s = r
        .mul(&modulus.resize())
        .checked_add(&two_b.resize())
        .and_then(|sum| ceiling_div(&sum, &m.upper_bound.resize() ))
        .map(|quot| quot.resize())
        .unwrap();

    loop {
        let enc = public_key.encrypt(&s);

        if oracle.valid_padding(&enc.mul(&c)) {
            break;
        }

        *s = s.wrapping_add(&Uint::<LIMBS>::ONE);

        if *s
            > r.mul(&modulus.resize())
                .checked_add(&three_b)
                .and_then(|sum| sum.checked_div(&m.lower_bound.resize()))
                .unwrap()
                .resize()
        {
            r = r.wrapping_add(&Uint::<LIMBS>::ONE);
            *s = r
                .mul(&modulus.resize())
                .checked_add(&two_b.resize())
                .and_then(|sum| ceiling_div(&sum, &m.upper_bound.resize() ))
                .map(|quot| quot.resize())
                .unwrap();
        }
    }
}

// apply solution to all Intervals
fn solutions<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>, const XLIMBS: usize>(
    public_key: &PublicKey<LIMBS, EXPONENT>,
    m: Vec<Interval<LIMBS>>,
    s: &Uint<LIMBS>,
) -> Vec<Interval<LIMBS>>
where
    Uint<LIMBS>: Encoding + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<XLIMBS>>,
{
    let modulus: Uint<XLIMBS> = public_key.get_modulus().modulus().resize();
    let two_b = Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 15);
    let three_b = two_b.wrapping_add(&Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 16));

    let mut new_vec = Vec::new();

    for ival in m {
        let mut r: Uint<LIMBS> = ceiling_div(
            &ival
                .lower_bound
                .mul(&s)
                .saturating_sub(&three_b.wrapping_sub(&Uint::<XLIMBS>::ONE)),
            &modulus,
        )
        .map(|quot| quot.resize())
        .unwrap();

        let max_r: Uint<LIMBS> = ival
            .upper_bound
            .mul(&s)
            .checked_sub(&two_b)
            .and_then(|diff| ceiling_div(&diff, &modulus))
            .map(|quot| quot.resize())
            .unwrap();

        while r <= max_r {
            let l_calc = r
                .mul(&modulus.resize())
                .checked_add(&two_b)
                .and_then(|sum| ceiling_div(&sum, &s.resize()))
                .map(|quot| quot.resize())
                .unwrap();

            let u_calc = r
                .mul(&modulus.resize())
                .checked_add(&three_b.wrapping_sub(&Uint::<XLIMBS>::ONE))
                .map(|sum| sum.wrapping_div(&s.resize()))
                .map(|quot| quot.resize())
                .unwrap();

            let l = ival.lower_bound.max(l_calc);
            let u = ival.upper_bound.min(u_calc);

            insert(
                &mut new_vec,
                Interval {
                    upper_bound: u,
                    lower_bound: l,
                },
            );

            r = r.wrapping_add(&Uint::<LIMBS>::ONE);
        }
    }

    new_vec
}

fn run<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>, const XLIMBS: usize>(
    oracle: &PkcsOracle<LIMBS>,
    public_key: &PublicKey<LIMBS, EXPONENT>,
    c: Uint<LIMBS>,
) -> Uint<LIMBS>
where
    Uint<LIMBS>: Encoding + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<XLIMBS>>,
{
    let modulus: Uint<XLIMBS> = public_key.get_modulus().modulus().resize();
    let two_b = Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 15);
    let three_b = two_b.wrapping_add(&Uint::<XLIMBS>::ONE.shl(Uint::<LIMBS>::BITS - 16));

    let s_0 = if oracle.valid_padding(&c) {
        Uint::<LIMBS>::ONE
    } else {
        blinding(&c, public_key, oracle)
    };

    let (s_0_inv, _) = DynResidue::new(&s_0, public_key.get_modulus()).invert();
    let c_0 = DynResidue::new(&c, public_key.get_modulus())
        .mul(&DynResidue::new(
            &public_key.encrypt(&s_0),
            public_key.get_modulus(),
        ))
        .retrieve();

    let mut s = ceiling_div::<LIMBS>(&modulus.resize(), &three_b.resize()).unwrap();
    let mut m: Vec<Interval<LIMBS>> = Vec::new();
    let mut i = 1;
    m.push(Interval {
        upper_bound: three_b.resize().wrapping_sub(&Uint::<LIMBS>::ONE),
        lower_bound: two_b.resize(),
    });

    loop {
        if i == 1 || m.len() != 1 {
            println!("searching for s");
            s = s.wrapping_add(&Uint::<LIMBS>::ONE);
            search_first(oracle, public_key, &c_0, &mut s);
        } else {
            if m[0].upper_bound == m[0].lower_bound {
                println!("found solution");
                return DynResidue::new(&m[0].upper_bound, public_key.get_modulus())
                    .mul(&s_0_inv)
                    .retrieve();
            }
            println!("doing fast search");
            search(oracle, public_key, &c_0, &m[0], &mut s);
        }

        m = solutions(public_key, m, &s);
        i = i + 1;
    }
}

fn main() {
    let (public_key, oracle) = PkcsOracle::new::<PublicKeyParam>();

    let byte_len = Uint::<LIMBS>::BYTES;
    let mut bytes = [0; Uint::<LIMBS>::BYTES];

    bytes[0] = 0x0;
    bytes[1] = 0x02;
    bytes[2..10].copy_from_slice(&[0xff; 8]);
    bytes[(byte_len - 10)..byte_len].copy_from_slice(b"test test ");

    let msg: Uint<LIMBS> = Uint::from_be_slice(&bytes);

    let c = public_key.encrypt(&msg);

    let decrypted = run(&oracle, &public_key, c);

    assert_eq!(decrypted, msg);
}
