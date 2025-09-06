mod ir;
mod search;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ir::Database;

#[derive(Subcommand, Debug, Clone)]
enum DatabaseCategory {
    Functions,
    Types,
    Data,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Search {
        #[command(subcommand)]
        category: DatabaseCategory,

        project: PathBuf,
        expression: String,
    },
    Merge {
        destination: PathBuf,
        source: PathBuf,
    },
    Create {
        destination: PathBuf,
    },
    Generate {
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

fn search_objects<'a, T: Default + Clone + ir::NamedObject + 'a>(
    iter: impl Iterator<Item = &'a T>,
    search: &str,
) {
    let mut tree = search::SearchTree::default();

    for item in iter {
        tree.insert(item.name(), item.clone());
    }

    println!("Done compiling");

    for item in tree.search(search) {
        println!("{}", item.name());
    }
}

fn main() {
    env_logger::init();
    let args = Arguments::parse();

    match args.command {
        Command::Search {
            project,
            expression,
            category,
        } => {
            let db = Database::open(&project).unwrap();

            match category {
                DatabaseCategory::Functions => search_objects(db.functions.iter(), &expression),
                DatabaseCategory::Types => search_objects(db.types.iter(), &expression),
                DatabaseCategory::Data => search_objects(db.data.iter(), &expression),
            }
        }
        Command::Merge {
            source,
            destination,
        } => {
            let source_db = Database::open(&source).unwrap();
            let destination_db = Database::open(&destination).unwrap();
        }
        Command::Create { destination } => {
            let db = Database::default();

            db.save(&destination).unwrap()
        }
        Command::Generate {
            destination,
            source,
        } => {}
    }
}
