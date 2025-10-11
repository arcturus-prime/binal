use std::{fs::File, io::Read};

use crate::{
    ir::print_instructions_simple,
    x86::{lift_block, lift_control_flow},
};

mod external;
mod ir;
mod x86;

fn main() {
    let filepath = std::env::args()
        .next_back()
        .expect("File path required as argument");

    let mut file = File::open(filepath).expect("Could not open file");
    let mut code = vec![];

    file.read_to_end(&mut code).expect("Could not read file");

    let out_code = lift_control_flow(&code, 0x5ce5fd8);

    match out_code {
        Ok(o) => {
            for x in o {
                let Ok(b) = lift_block(&x.1.code) else {
                    println!("Lifting failed");
                    continue;
                };

                println!("{}", print_instructions_simple(&b).unwrap());
            }
        }
        Err(e) => println!("{:x?}", e),
    }
}
