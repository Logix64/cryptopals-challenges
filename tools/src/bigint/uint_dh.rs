use crypto_bigint::{
    modular::{
        constant_mod::{Residue, ResidueParams},
        runtime_mod::{DynResidue, DynResidueParams},
    },
    NonZero, RandomMod, Uint,
};
use rand_core::CryptoRngCore;

/// Dynamic Parameters for Diffie-Hellmann Key Exchange
pub struct DiffieHellmannParams<const LIMBS: usize> {
    p: DynResidueParams<LIMBS>,
    g: DynResidue<LIMBS>,
}

impl<const LIMBS: usize> DiffieHellmannParams<LIMBS> {
    /// Generates new dynamic Diffie-Hellmann Parameters from the given Bignums
    pub const fn new(p: &Uint<LIMBS>, g: Uint<LIMBS>) -> Self {
        let param = DynResidueParams::new(&p);
        let g_mod = DynResidue::new(&g, param);
        Self { p: param, g: g_mod }
    }
}

/// Generic Trait for constant Diffie-Hellmann Parameters
pub trait ConstDiffieHellmannParams<const LIMBS: usize>: ResidueParams<LIMBS> {
    const G: Residue<Self, LIMBS>;
}

/// Macro for generating const Diffie-Hellmann Parameters
#[macro_export]
macro_rules! generate_params {
    ($name:ident, $uint_type : ty, $p : expr, $g : expr) => {
        crypto_bigint::impl_modulus!($name, $uint_type, $p);

        impl $crate::bigint::uint_dh::ConstDiffieHellmannParams<{ <$uint_type>::LIMBS }> for $name {
            const G: crypto_bigint::modular::constant_mod::Residue<$name, { <$uint_type>::LIMBS }> =
                crypto_bigint::modular::constant_mod::Residue::new(&Uint::< { <$uint_type>::LIMBS } >::from_u32($g));
        }
    };
}

/// Diffie-Hellmann Instance for Const Parameters
pub struct ConstDiffieHellmanInstance<T: ConstDiffieHellmannParams<LIMBS>, const LIMBS: usize> {
    private_key: Residue<T, LIMBS>,
    public_key: Residue<T, LIMBS>,
}

impl<const LIMBS: usize, T: ConstDiffieHellmannParams<LIMBS>> ConstDiffieHellmanInstance<T, LIMBS> {
    /// From RNG output generates a new Diffie-Hellmann Instance
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let a = Uint::random_mod(rng, &NonZero::from_uint(T::MODULUS));
        let private_key = Residue::<T, LIMBS>::new(&a);

        Self {
            private_key,
            public_key: T::G.pow(&private_key.retrieve()),
        }
    }

    /// Returns the public key of the Diffie-Hellmann Instance
    pub fn get_public_key(&self) -> Uint<LIMBS> {
        self.public_key.retrieve()
    }

    /// From a received public key generates secret key material in form of a new Uint object
    /// Consumes the instance.
    pub fn generate(self, other: &Uint<LIMBS>) -> Uint<LIMBS> {
        Residue::<T, LIMBS>::new(other)
            .pow(&self.private_key.retrieve())
            .retrieve()
    }
}

/// DiffieHellman Instance for Dynamic Parameters
pub struct DynDiffieHellmannInstance<const LIMBS: usize> {
    private_key: DynResidue<LIMBS>,
    public_key: DynResidue<LIMBS>,
}

impl<const LIMBS: usize> DynDiffieHellmannInstance<LIMBS> {
    /// From RNG output generates a new Diffie-Hellmann Instance
    pub fn new(params: &DiffieHellmannParams<LIMBS>, rng: &mut impl CryptoRngCore) -> Self {
        let a = Uint::random_mod(rng, &NonZero::from_uint(*params.p.modulus()));

        Self {
            private_key: DynResidue::new(&a, params.p),
            public_key: params.g.pow(&a),
        }
    }

    /// Returns the public key of the Diffie-Hellmann Instance
    pub fn get_public_key(&self) -> Uint<LIMBS> {
        self.public_key.retrieve()
    }

    /// From a received public key generates secret key material in form of a new Uint object
    /// Consumes the instance.
    pub fn generate(self, other: &Uint<LIMBS>, params: DiffieHellmannParams<LIMBS>) -> Uint<LIMBS> {
        DynResidue::new(other, params.p)
            .pow(&self.private_key.retrieve())
            .retrieve()
    }
}
