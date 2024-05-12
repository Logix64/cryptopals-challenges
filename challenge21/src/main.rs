use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use tools::random::mt19937::MersenneTwister;

fn main() {
    let mut rng = MersenneTwister::seed(1131464071);

    // test vectors given by https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
    let file = File::open("test_vectors.txt").unwrap();

    BufReader::new(file)
        .lines()
        .for_each(|v| assert_eq!(v.unwrap().parse::<u32>().unwrap(), rng.extract_number()));
}
