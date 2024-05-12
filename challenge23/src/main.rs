use rand::random;
use tools::random::mt19937::{unwind, MersenneTwister};

fn main() {
    
    let mut rng = MersenneTwister::seed( random() );

    let mut state : [u32;624] = [0;624];

    for i in 0..624 {
        state[i] = unwind( rng.extract_number() );
    }

    let mut cloned_rng = MersenneTwister::from(state);

    for _ in 0..1000 {
        assert_eq!(cloned_rng.extract_number(), rng.extract_number() );
    }
}
