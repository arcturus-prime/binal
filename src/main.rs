use std::{fs::File, io::Read};

mod external;
mod ir;

fn main() {
    let filepath = std::env::args()
        .next_back()
        .expect("File path required as argument");

    let mut file = File::open(filepath).expect("Could not open file");
    let mut code = vec![];

    file.read_to_end(&mut code).expect("Could not read file");
}
