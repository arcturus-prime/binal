mod ir;
mod search;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ir::ExternalDatabase;

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Create {
        destination: PathBuf,
    },
    Merge {
        destination: PathBuf,
        source: PathBuf,
    },
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

fn main() {
    env_logger::init();
    let args = Arguments::parse();

    match args.command {
        Command::Create { destination } => {
            let db = ExternalDatabase::default();

            db.save(&destination).unwrap()
        }
        Command::Merge {
            destination,
            source,
        } => {}
    }
}
