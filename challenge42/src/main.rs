use std::{num::NonZeroU64, ops::Mul};

use bytes::{BufMut, BytesMut};
use crypto_bigint::{Concat, ConcatMixed, Encoding, Integer, Limb, Uint, Zero, U1024};
use tools::{
    bigint::rsa::{ExponentThree, Key, PublicExponent, PublicKey, RSA},
    digest::{sha1::{Sha1, Sha1Core}, HashAlgorithm}, hash,
};

type SIZE = U1024;
const LIMBS : usize = SIZE::LIMBS;

struct Verificator<const LIMBS: usize, E: PublicExponent<LIMBS>>
where
    Uint<LIMBS>: Encoding,
{
    public_key: PublicKey<LIMBS, E>,
}

impl<const LIMBS: usize, E: PublicExponent<LIMBS>> Verificator<LIMBS, E>
where
    Uint<LIMBS>: Encoding,
{

    fn new(public_key : PublicKey<LIMBS,E> ) -> Self {
        Self { public_key }
    }

    fn verify<H: HashAlgorithm>(&self, signed_message: &Uint<LIMBS>) -> bool {
        let text = self.public_key.encrypt(&signed_message);
        insecure_check_pkcs15::<LIMBS, H>(text.to_be_bytes().as_ref() )
    }
}

#[inline]
fn insecure_check_pkcs15<const LIMBS: usize, H: HashAlgorithm>(bytes: &[u8]) -> bool {
    assert!(bytes.len() == Uint::<LIMBS>::BYTES);

    bytes[0] == 0x00
        && bytes[1] == 0x00 // normally 0x01
        && bytes[2] == 0xff
        // ignore this as well 
        // && bytes[bytes.len() - H::DIGEST_SIZE - 2] == 0xff
        // && bytes[bytes.len() - H::DIGEST_SIZE - 1] == 0x00
}

fn pkcs15format<const LIMBS: usize>(bytes: impl AsRef<[u8]> ) -> Uint<LIMBS> {
    let len = bytes.as_ref().len();
    assert!(len <= Uint::<LIMBS>::BYTES - 3);

    let mut formatted_text = BytesMut::from(bytes.as_ref());
    formatted_text.put_u8(0x00);
    formatted_text.put_bytes(0xff, Uint::<LIMBS>::BYTES - 3 - len);
    formatted_text.put_u8(0x00); // normally 0x01
    formatted_text.put_u8(0x00);

    Uint::from_le_slice(&formatted_text)
}

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
) -> Result<Uint<NUMLIMBS>,Uint<NUMLIMBS>>
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
        let last_bit : bool =  offset.is_odd().into();

        if offset.is_zero().into() {
            return Err(mid);
        }

        match num.cmp(&cube) {
            std::cmp::Ordering::Less => {
                high = if last_bit {
                    mid.saturating_add(&Uint::<NUMLIMBS>::ONE)
                } else {
                    mid
                };
            }
            std::cmp::Ordering::Equal => {
                return Ok(mid);
            }
            std::cmp::Ordering::Greater => {
                low = if last_bit {
                    mid.saturating_sub(&Uint::<NUMLIMBS>::ONE)
                } else {
                    mid
                };
            }
        }
    }
}

fn main() {
    let msg = b"hi mom";

    let sha1 = hash!( Sha1, msg);

    let (public_key, private_key) = RSA::new::<LIMBS,ExponentThree<LIMBS>>();

    let verificator = Verificator::new(public_key);

    // sign message
    let c = private_key.encrypt::<LIMBS>(&pkcs15format(sha1) );
    assert!(verificator.verify::<Sha1Core>(&c) );

    let mut set_root = SIZE::ZERO;

    let max = SIZE::ONE.shl(1009);


    // find a third root of a certain format
    for i in 1..1008 {
        let diff = max.wrapping_sub( &SIZE::ONE.shl(1009-i) );
        let root = cube_root(&diff.resize() );
        if root.is_ok() {
            // println!("{i}");
            // println!("root: {}", root.unwrap());
            set_root = root.unwrap();
            break;
        }
    }

    let d = RSA::into_uint( &sha1 ).unwrap();
    let mut n : SIZE =  SIZE::ONE.shl(160 + 8 ).wrapping_sub(&d) ;
    n = n.shl(8);

    let (mut diff, mut v) = n.div_rem_limb( NonZeroU64::new( Limb(3).into()).unwrap().into() );    

    while v.is_zero().unwrap_u8() != 1u8 {
        n = n.wrapping_add( &Uint::<LIMBS>::ONE);
        (diff, v) =  n.div_rem_limb( NonZeroU64::new( Limb(3).into()).unwrap().into() );    
    }
    debug_assert_eq!( v.is_zero().unwrap_u8(), 1u8 );

    let m = set_root.wrapping_sub(&diff);
    
    let (lo, hi) = m.square_wide();

    debug_assert_eq!( hi.is_zero().unwrap_u8(), 1u8 );

    let (_, hi) = lo.mul_wide(&m);
    // sgn = sgn.shl(1);
    debug_assert_eq!( hi.is_zero().unwrap_u8(), 1u8 );

    assert!( verificator.verify::<Sha1Core>(&m));
}
