mod ir;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};

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
            let objects = project::load(&project).unwrap();

            for (name, object) in objects {
                println!("{} {:?}", name, object)
            }
        }
        Command::Merge {
            source,
            destination,
        } => {
            let source = project::load(&source).unwrap();
            let mut destination_objects = project::load(&destination).unwrap();

            destination_objects.extend(source.into_iter());

            project::save(&destination, &destination_objects).unwrap();
        }
        Command::Create { destination } => bin,
    }
}
