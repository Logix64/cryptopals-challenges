use crypto_bigint::{subtle::Choice, CheckedAdd, CheckedSub, ConcatMixed, Encoding, Integer, Uint, U1024};
use tools::{bigint::rsa::{ExponentThree, Key, PrivateKey, PublicExponent, PublicKey, RSA}, encode::{ascii::to_ascii, base64::from_base64}};


const LIMBS : usize = U1024::LIMBS;

struct ParityOracle<const LIMBS: usize> {
    private_key: PrivateKey<LIMBS>,
}

impl<const LIMBS: usize> ParityOracle<LIMBS> {
    fn new<EXPONENT: PublicExponent<LIMBS>>() -> (Self, PublicKey<LIMBS, EXPONENT>) {
        let (public_key, private_key) = RSA::new();
        return (Self { private_key }, public_key);
    }

    fn is_odd<const TWOLIMBS : usize>(&self, msg : &Uint<TWOLIMBS> ) -> Choice {
        self.private_key.encrypt(msg).is_odd()
    }
}


fn decrypt<const LIMBS : usize, const TWOLIMBS : usize, EXPONENT : PublicExponent<LIMBS>>( oracle : &ParityOracle<LIMBS>, public_key : &PublicKey<LIMBS,EXPONENT>, c : &Uint<LIMBS> ) -> Result<Uint<LIMBS>,()>
    where Uint<LIMBS> : ConcatMixed<MixedOutput = Uint<TWOLIMBS>>

{
    let modulus = *public_key.get_modulus().modulus();
    let mut upper_bound = modulus;
    let mut lower_bound = Uint::<LIMBS>::ZERO;

    // let leading_zeros = modulus.leading_zeros();

    let mut height = Uint::<LIMBS>::ONE;

    loop {
        height = height.shl(1);

        let current = public_key.encrypt(&height);
        let measure = c.mul(&current);

        let mid = upper_bound.checked_add(&lower_bound).unwrap();
        
        println!("{upper_bound}");
        if upper_bound.checked_sub(&lower_bound).unwrap_or(Uint::ONE) <= Uint::ONE {
            break;
        }

        if oracle.is_odd(&measure).into() {
            lower_bound = if mid.is_odd().into() {
                mid.shr_vartime(1).saturating_sub(&Uint::ZERO)
            } else {
                mid.shr_vartime(1)
            }
        } else {
            upper_bound = if mid.is_odd().into() {
                mid.shr_vartime(1).checked_add( &Uint::ONE ).unwrap()
            } else {
                mid.shr_vartime(1)
            }
        }
    }
    for u in 0..=u8::MAX {
        println!("checking for range {u}");
        lower_bound = lower_bound.saturating_sub(&Uint::ONE);
        if public_key.encrypt(&lower_bound).eq(c) {
            return Ok(lower_bound);
        } 
        upper_bound = upper_bound.checked_add(&Uint::ONE).unwrap();
        if public_key.encrypt(&upper_bound).eq(c) {
            return Ok(upper_bound);
        }
    }

    Err(())
}

fn main() {

    let message = from_base64("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ");

    let (oracle, public_key) = ParityOracle::new::<ExponentThree<LIMBS>>();

    let msg = RSA::into_uint::<LIMBS>(message).unwrap();
    let c = public_key.encrypt(&msg);

    let m = decrypt(&oracle, &public_key, &c);

    if m.is_ok() {
        println!(" the message is : {}", to_ascii(&m.unwrap().to_be_bytes(), true) );
    }
}
