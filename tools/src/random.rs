pub mod mt19937 {
    use rand::{RngCore, SeedableRng};

    use crate::encrypt::cipher::{StreamCipher, RngKeyStream};

    const W: u32 = 32;
    const N: usize = 624;
    const M: usize = 397;
    const R: usize = 31;
    const A: u32 = 0x9908b0df;

    const U: usize = 11;
    const D: u32 = 0xffffffff;

    const S: usize = 7;
    const B: u32 = 0x9d2c5680;

    const T: usize = 15;
    const C: u32 = 0xefc60000;

    const L: usize = 18;
    const F: u32 = 0x6c078965;

    /// Implementation of MersenneTwister PRNG for 32bit numbers
    pub struct MersenneTwister {
        state: [u32; N],
        index: usize,
    }

    impl MersenneTwister {
        /// Constructs a MersenneTwister PRNG from a given state vector
        /// Gets constructed with index N, which means it will call twist() in the next call to extract
        pub fn from(vec: [u32; N]) -> Self {
            MersenneTwister {
                state: vec,
                index: N,
            }
        }

        /// seeds the MersenneTwister PRNG with a given value -- most likely things like time since UNIX Epoch or sth.
        pub fn seed(seed: u32) -> Self {
            let mut vec = [0; N];
            vec[0] = seed;

            for i in 1..N {
                vec[i] = ((u64::from(F)
                    .wrapping_mul(u64::from(vec[i - 1] ^ (vec[i - 1] >> W - 2))))
                    + i as u64) as u32;
            }

            MersenneTwister {
                state: vec,
                index: N,
            }
        }

        /// Extracts a 32-bit number from the PRNG
        pub fn extract_number(&mut self) -> u32 {
            // if reached end of vec -- twist again
            if self.index == N {
                self.twist();
            }

            // get index-th entry
            let mut y = self.state[self.index];
            // use some additional tempering transform
            // kind of like salting lol
            y = y ^ ((y >> U) & D);
            y = y ^ ((y << S) & B);
            y = y ^ ((y << T) & C);
            y = y ^ (y >> L);

            self.index += 1;
            y
        }

        /// One call to twist, which cycles through the state vector
        pub fn twist(&mut self) {
            // 31 1's and one 0 at the most significant bit
            let lower_mask = (1 << R) - 1;
            // only most significant bit is 1
            let upper_mask = !lower_mask;

            for i in 0..N {
                // most significant bit i-th vec and all first 31 bit of i+1-th vec
                let x = (self.state[i] & upper_mask) | (self.state[(i + 1) % N] & lower_mask);

                // most significant bit is 0, first bit in i+1 eliminated
                let mut x_a = x >> 1;

                // check on least significant bit in i+1
                // if 1 --> use xor with A on x_a
                // if 0 --> A * lsb(i+1) = 0 --> x_a xor 0 = x_a
                if (x % 2) != 0 {
                    x_a = x_a ^ A;
                }

                // xor against offset in state
                self.state[i as usize] = self.state[(i + M) % N] ^ x_a;
            }
            self.index = 0;
        }
    }

    /// Basic implementation for RNGs 
    /// We likely also need TryRngCore as recommended by rand_core
    impl RngCore for MersenneTwister {
        fn next_u32(&mut self) -> u32 {
            self.extract_number()
        }
    
        fn next_u64(&mut self) -> u64 {
            (self.extract_number() as u64) | ( (self.extract_number() as u64) << 32)
        }
    
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let block_len = dest.len()/4 +1;
            let src = Vec::from_iter( (0..block_len).map( |_| self.extract_number() ));

            rand_core::impls::fill_via_u32_chunks(&src, dest);
        }
        
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            Ok(self.fill_bytes(dest))
        }
    }

    impl SeedableRng for MersenneTwister{
        type Seed = [u8;4];
    
        fn from_seed(seed: Self::Seed) -> Self {
            Self::seed(u32::from_be_bytes(seed))
        }
    }

    pub type MersenneTwisterCipher = StreamCipher<RngKeyStream<MersenneTwister>>;

    /// Unwinds the tempering function in extract() in the MersenneTwister. By repeating calls to unwind for a stream of MersenneTwister numbers you can clone the MersenneTwister PRNG.
    pub fn unwind(u: u32) -> u32 {
        // first layer done
        let mut sol = u ^ (u >> L);

        // second layer
        sol = sol ^ ((sol << 15) & C);

        // bitmasks
        let bitmask1 = (1 << 14) - 1;
        let bitmask2 = (1 << 21) - 1;
        let bitmask3 = (1 << 28) - 1;
        let bitmask4 = !0;

        // third layer
        let z = sol;

        let z1 = z ^ ((z << S) & B);
        sol = z1 & bitmask1;

        // fill up with rest
        let mut z2 = sol | (z & !bitmask1);
        z2 = z2 ^ ((z2 << S) & B);

        sol = (sol & bitmask1) | (z2 & (!bitmask1 & bitmask2));

        z2 = sol | (z & !bitmask2);
        z2 = z2 ^ ((z2 << S) & B);

        sol = (sol & bitmask2) | (z2 & (!bitmask2 & bitmask3));

        z2 = sol | (z & !bitmask3);
        z2 = z2 ^ ((z2 << S) & B);

        sol = (sol & bitmask3) | (z2 & (!bitmask3 & bitmask4));

        // bitmasks
        let n_bitmask1 = !((1 << 21) - 1);
        let n_bitmask2 = !((1 << 10) - 1);
        let n_bitmask3 = !0;

        // fourth layer
        let z = sol;

        let z1 = z ^ ((z >> U) & D);

        let mut sol = z & n_bitmask1;

        sol = sol | ((!n_bitmask1 & n_bitmask2) & z1);

        let mut z2 = (sol & n_bitmask2) | (z & !n_bitmask2);

        z2 = z2 ^ ((z2 >> U) & D);

        sol = sol | ((!n_bitmask2 & n_bitmask3) & z2);

        sol
    }

    #[test]
    fn test_unwind() {
        use rand::random;

        // get index-th entry
        let x: u32 = random();

        // tempering function
        let mut y: u32 = x;
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        assert_eq!(x, unwind(y));
    }
}
