use crypto_bigint::{NonZero, RandomMod, Uint, U1024};
use rand::thread_rng;
use tools::bigint::rsa::{ExponentThree, Key, RSA};

const LIMBS : usize = U1024::LIMBS;
type PublicExponent = ExponentThree<LIMBS>;

fn main() {
    let (public, private) = RSA::new::<LIMBS,PublicExponent>();

    let message = Uint::<LIMBS>::random_mod(&mut thread_rng(), &NonZero::from_uint(*public.get_modulus().modulus()) );
    
    assert_eq!( private.encrypt(&public.encrypt(&message)), message);
}
