use std::ops::Mul;

use crypto_bigint::{modular::runtime_mod::{DynResidue, DynResidueParams}, Concat, ConcatMixed, Encoding, Uint, U2048};
use tools::{bigint::rsa::{ExponentThree, Key, RSA}, encode::ascii::to_ascii};

const LIMBS: usize = U2048::LIMBS;
type PublicExponent =  ExponentThree<LIMBS>;

fn cube<const LIMBS: usize, const XLIMBS: usize>(
    num: &Uint<LIMBS>,
) -> <<Uint<LIMBS> as ConcatMixed>::MixedOutput as Mul<Uint<XLIMBS>>>::Output
where
    Uint<LIMBS>: ConcatMixed,
    <Uint<LIMBS> as ConcatMixed>::MixedOutput: Mul<Uint<XLIMBS>>,
{
    num.square().mul(num.resize())
}

// num ... is a cube number
// XLIMBS smallest number (origin of cube)
// YLIMBS between LIMBS and XLIMBS
fn cube_root<const CUBELIMBS: usize, const NUMLIMBS: usize, const YLIMBS: usize>(
    num: &Uint<CUBELIMBS>,
) -> Uint<NUMLIMBS>
where
    Uint<NUMLIMBS>: Concat,
    <Uint<NUMLIMBS> as Concat>::Output: Mul<Uint<YLIMBS>, Output = Uint<CUBELIMBS>>,
{
    let trailing_zeros = (Uint::<CUBELIMBS>::BITS - num.leading_zeros()) / 3 + 1;
    let mut high = Uint::<NUMLIMBS>::ONE
        .shl(trailing_zeros + 1)
        .wrapping_sub(&Uint::<NUMLIMBS>::ONE);
    let mut low = Uint::<NUMLIMBS>::ZERO;
    loop {
        let offset = high.saturating_sub(&low).shr(1);
        let mid = offset.saturating_add(&low);
        let cube = cube::<NUMLIMBS, YLIMBS>(&mid);

        match num.cmp(&cube) {
            std::cmp::Ordering::Less => {
                high = mid;
            }
            std::cmp::Ordering::Equal => {
                return mid;
            }
            std::cmp::Ordering::Greater => {
                low = mid;
            }
        }
    }
}

fn broadcast_attack<const CUBELIMBS: usize, const NUMLIMBS: usize, const YLIMBS: usize>(
    c0 : &Uint<NUMLIMBS>, c1 : &Uint<NUMLIMBS>, c2 : &Uint<NUMLIMBS>, 
    n0 : &Uint<NUMLIMBS>, n1 : &Uint<NUMLIMBS>, n2 : &Uint<NUMLIMBS>
) -> Uint<NUMLIMBS> 
where
    Uint<NUMLIMBS>: Concat<Output=Uint<YLIMBS>>,
    <Uint<NUMLIMBS> as Concat>::Output: Mul<Uint<YLIMBS>, Output = Uint<CUBELIMBS>>,
{
    let n_012 : DynResidueParams<CUBELIMBS> = DynResidueParams::new( &n0.mul(n1).mul(n2.resize()) );

    let m_s_0 = n1.mul(n2);
    let m_s_1 = n0.mul(n2);
    let m_s_2 = n0.mul(n1);

    let invmod = [
        m_s_0.inv_mod(&n0.resize()).0,
        m_s_1.inv_mod(&n1.resize()).0,
        m_s_2.inv_mod(&n2.resize()).0
    ];


    let mut result = DynResidue::new(&c0.resize(),n_012)
        .mul(&DynResidue::new(&m_s_0.resize(), n_012))
        .mul(&DynResidue::new(&invmod[0].resize(), n_012));

    result = result.add(
        &DynResidue::new(&c1.resize(),n_012)
            .mul(&DynResidue::new(&m_s_1.resize(), n_012))
            .mul(&DynResidue::new(&invmod[1].resize(), n_012))
    );

    result = result.add(
        &DynResidue::new(&c2.resize(),n_012)
            .mul(&DynResidue::new(&m_s_2.resize(), n_012))
            .mul(&DynResidue::new(&invmod[2].resize(), n_012))
    );

    println!("calculation successful");
    return cube_root(&result.retrieve())
}


#[test]
fn test_cube_root() {
    use crypto_bigint::Random;
    use rand::thread_rng;

    for _ in 0..10{
        let basis: Uint<16> = Uint::random(&mut thread_rng());

        let pot =  cube(&basis.clone());

        assert_eq!( cube_root(&pot), basis);
    }
}

#[test]
fn test_cube() {
    use crypto_bigint::{Random, Uint};
    use rand::thread_rng;

    let two = Uint::<LIMBS>::from_u32(2);
    let eight = cube(&two);

    assert_eq!(eight, Uint::<{ LIMBS * 4 }>::from_u32(8));

    for _ in 0..100 {
        let u: Uint<LIMBS> = Uint::random(&mut thread_rng());
        let cube_u: Uint<{ 4 * LIMBS }> = u.square().mul(&u.resize());

        assert_eq!(cube(&u), cube_u);
    }
}

fn main() {

    let message : Uint<LIMBS> = RSA::into_uint(b"this is a secret message").unwrap();

    let (i0,_) = RSA::new::<LIMBS,PublicExponent>();
    let (i1,_) = RSA::new::<LIMBS,PublicExponent>();
    let (i2,_) = RSA::new::<LIMBS,PublicExponent>();

    let c0 = i0.encrypt(&message);
    let c1 = i1.encrypt(&message);
    let c2 = i2.encrypt(&message);

    let decrypted = broadcast_attack(&c0, &c1, &c2, 
        i0.get_modulus().modulus(),
        i1.get_modulus().modulus(),
        i2.get_modulus().modulus() 
    );

    println!("the encrypted message is : \n {}", to_ascii(&decrypted.to_be_bytes(), true)); 
    assert_eq!(message, decrypted);
}
