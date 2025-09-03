mod ir;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use ir::Database;

#[derive(Subcommand, Debug, Clone)]
enum Command {
    List {
        project: PathBuf,
    },
    Merge {
        destination: PathBuf,
        source: PathBuf,
    },
    Create {
        destination: PathBuf,
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
        Command::List { project } => {
            let db = Database::open(&project).unwrap();

            for object in db.types.iter() {
                println!("{} {:?}", object.name, object)
            }
        }
        Command::Merge {
            source,
            destination,
        } => {}
        Command::Create { destination } => {
            let db = Database::default();

            db.save(&destination).unwrap()
        }
    }
}
