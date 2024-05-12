use std::{thread::sleep, time::{Duration, SystemTime, UNIX_EPOCH}};

use rand::{thread_rng, Rng};
use tools::random::mt19937::MersenneTwister;

fn generate_random_token( simulation : bool ) -> u32 {

    if simulation {
        let v = Duration::from_secs( thread_rng().gen_range(40..1000) );
        sleep( v )
    }

    let unix_time_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("problem reading");  
    let v : u32 = unix_time_now.as_secs().try_into().expect("problem parsing"); 
    let mut twister = MersenneTwister::seed(v);

    twister.extract_number()
}

fn crack_seed( token : u32 ) -> Option<u32> {
    
    let current_time: u32 = SystemTime::now().duration_since(UNIX_EPOCH).expect("problem reading").as_secs().try_into().expect("problem converting");

    for i in 0..1050 {
        let seed = current_time - i;
        let mut rng = MersenneTwister::seed(seed);
        if token == rng.extract_number() {
            return Some(seed)
        }
    }
    None
}

fn main() {
    let token = generate_random_token(false);
    let seed = crack_seed(token);
    assert!( seed.is_some() );
    println!("the seed is {}", seed.unwrap() );
}
