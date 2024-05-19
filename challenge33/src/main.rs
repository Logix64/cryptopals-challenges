use crypto_bigint::{Uint, U1536};
use rand::thread_rng;
use tools::{bigint::uint_dh::{ConstDiffieHellmanInstance, DiffieHellmannParams, DynDiffieHellmannInstance}, generate_params};

const LIMBS: usize = U1536::LIMBS;
const PARAMS : DiffieHellmannParams<LIMBS> = DiffieHellmannParams::new( 
    &Uint::from_be_hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"),
    Uint::from_u32(2)
);

generate_params!(
    NISTParams, 
    Uint<LIMBS>, 
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 
    2 
);

fn main() {
    let mut rng = thread_rng();
    let instance1 = DynDiffieHellmannInstance::new(&PARAMS, &mut rng );
    let instance2 = DynDiffieHellmannInstance::new(&PARAMS, &mut rng );

    let p1 = instance1.get_public_key();
    let p2 = instance2.get_public_key();

    assert_eq!(instance1.generate(&p2, PARAMS), instance2.generate(&p1, PARAMS));

    let instance1 = ConstDiffieHellmanInstance::<NISTParams, LIMBS>::new(&mut rng);
    let instance2 = ConstDiffieHellmanInstance::<NISTParams, LIMBS>::new(&mut rng );

    let p1 = instance1.get_public_key();
    let p2 = instance2.get_public_key();

    assert_eq!(instance1.generate(&p2), instance2.generate(&p1));
}
