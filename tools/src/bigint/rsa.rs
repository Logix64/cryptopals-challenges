use std::marker::PhantomData;

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams}, subtle::CtOption, CheckedSub, Encoding, Uint
};
use crypto_primes::generate_prime;

/// Trait for constant public exponents 
pub trait PublicExponent<const LIMBS: usize> {
    const EXPONENT: Uint<LIMBS>;
}

/// Type for constant e = 3 public key
pub struct ExponentThree<const LIMBS: usize> {}

impl<const LIMBS: usize> PublicExponent<LIMBS> for ExponentThree<LIMBS> {
    const EXPONENT: Uint<LIMBS> = Uint::from_u8(3);
}

/// Type for constant e = 65537 public key
pub struct NistExponent<const LIMBS: usize> {}

impl<const LIMBS: usize> PublicExponent<LIMBS> for NistExponent<LIMBS> {
    const EXPONENT: Uint<LIMBS> = Uint::from_u64(65537);
}

/// Trait for Public/Private keys for encryption
pub trait Key<const LIMBS: usize> {
    fn encrypt(&self, text: &Uint<LIMBS>) -> Uint<LIMBS>;
    fn get_modulus(&self) -> DynResidueParams<LIMBS>;
}

/// Public Key struct with constant public exponent.
pub struct PublicKey<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>> {
    phantom: PhantomData<EXPONENT>,
    modulus: DynResidueParams<LIMBS>,
}

impl<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>> Key<LIMBS>
    for PublicKey<LIMBS, EXPONENT>
{
    fn encrypt(&self, text: &Uint<LIMBS>) -> Uint<LIMBS> {
        DynResidue::new(text, self.modulus)
            .pow(&EXPONENT::EXPONENT)
            .retrieve()
    }

    fn get_modulus(&self) -> DynResidueParams<LIMBS> {
        self.modulus
    }
}

/// Private key struct
pub struct PrivateKey<const LIMBS: usize> {
    exponent: Uint<LIMBS>,
    modulus: DynResidueParams<LIMBS>,
}

impl<const LIMBS: usize> Key<LIMBS> for PrivateKey<LIMBS> {
    fn encrypt(&self, text: &Uint<LIMBS>) -> Uint<LIMBS> {
        DynResidue::new(text, self.modulus)
            .pow(&self.exponent)
            .retrieve()
    }

    fn get_modulus(&self) -> DynResidueParams<LIMBS> {
        self.modulus
    }
}

/// Factory for new RSA Public/Private Keypairs
pub struct RSA {}

impl RSA {
    /// Generate a new Public/Private Keypair of size Uint<LIMBS> and constant Public Exponent
    pub fn new<const LIMBS: usize, EXPONENT: PublicExponent<LIMBS>>(
    ) -> (PublicKey<LIMBS, EXPONENT>, PrivateKey<LIMBS>) {
        loop {
            let p = generate_prime(Some(Uint::<LIMBS>::BITS / 2));
            let q: Uint<LIMBS> = generate_prime(Some(Uint::<LIMBS>::BITS / 2));

            let (n, _) = p.mul_wide(&q);
            let modulus = DynResidueParams::new(&n);


            let result  = Self::totient(&p, &q).map( |totient| EXPONENT::EXPONENT.inv_mod(&totient) );

            if result.is_some().into() {
                let (exponent, choice) = result.unwrap();
                if choice.into() {
                    return (
                        PublicKey {
                            phantom: PhantomData::default(),
                            modulus,
                        },
                        PrivateKey {
                            modulus,
                            exponent: exponent,
                        },
                    );
                }
            }
           
        }
    }

    /// Generate euler totient of n = pq : phi(n) = (p-1)(q-1)
    pub fn totient<const LIMBS: usize>(p: &Uint<LIMBS>, q: &Uint<LIMBS>) -> CtOption<Uint<LIMBS>> {
        p.checked_sub(&Uint::<LIMBS>::ONE).and_then(|a| {
            q.checked_sub(&Uint::<LIMBS>::ONE).map(|b| {
                let (totient, _) = a.mul_wide(&b);
                totient
            })
        })
    }

    /// Generates Uint<LIMBS> from big endian bytes
    pub fn into_uint<const LIMBS : usize>(bytes : impl AsRef<[u8]> ) -> Option<Uint<LIMBS>> 
        where Uint<LIMBS> : Encoding
    {
        (bytes.as_ref().len() <= Uint::<LIMBS>::BYTES ).then( || {
                let bytes_len = bytes.as_ref().len();
                let mut v: Vec<u8>  = vec![0; Uint::<LIMBS>::BYTES];
                v[0..bytes_len].copy_from_slice(bytes.as_ref());
                Uint::<LIMBS>::from_be_slice(&v)
            }
        )
    }
}