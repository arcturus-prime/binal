mod ir;
mod search;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ir::Database;

#[derive(Subcommand, Debug, Clone)]

enum DatabaseEdit {
    RemoveByName { name: String },
    RemoveById { id: usize },
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Create {
        destination: PathBuf,
    },
    Merge {
        destination: PathBuf,
        source: PathBuf,
    },
    Edit {
        target: PathBuf,

        #[command(subcommand)]
        command: DatabaseEdit,
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
            let db = Database::default();

            db.save(&destination).unwrap()
        }
        Command::Merge {
            destination,
            source,
        } => {}
        Command::Edit { target, command } => {}
    }
}
