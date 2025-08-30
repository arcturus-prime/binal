mod net;
mod project;

use std::{
    collections::HashMap,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::exit,
    sync::{mpsc::TryRecvError, Arc, Mutex},
};

use clap::{Parser, Subcommand};
use net::{Message, Object};

#[derive(Subcommand, Debug, Clone)]
enum Command {
    Serve {
        project: PathBuf,
        port: u16,
        address: IpAddr,
    },
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

fn enter_serve_terminal(
    client: net::Client,
    project_object: HashMap<String, Object>,
    project_path: PathBuf,
) -> () {
    let project_objects = Arc::new(Mutex::new(project_object));

    let project_objects_copy = project_objects.clone();
    std::thread::spawn(move || loop {
        let message = match client.rx.try_recv() {
            Ok(msg) => msg,
            Err(e) => {
                if e == TryRecvError::Empty {
                    continue;
                }

                return;
            }
        };

        println!("{:?}", message);

        match message {
            Message::Push { objects } => {
                let Ok(mut project_objects) = project_objects_copy.try_lock() else {
                    continue;
                };

                project_objects.extend(objects);
            }
        };
    });

    std::thread::spawn(move || loop {
        let mut command = String::new();

        io::stdout()
            .write(b"> ")
            .expect("Could not write to standard out");
        io::stdin()
            .read_line(&mut command)
            .expect("Failed to read command");

        match command.as_str() {
            "exit" => exit(0),
            "save" => {
                let project_objects = project_objects.lock().unwrap();

                project::save(&project_path, &project_objects).unwrap()
            }
            _ => {
                println!("Command not found");
            }
        }
    });
}

fn main() {
    let args = Arguments::parse();

    match args.command {
        Command::Serve {
            project,
            port,
            address,
        } => {
            let project_objects = project::load(&project).unwrap();
            let client = net::Client::connect(SocketAddr::new(address, port)).unwrap();

            enter_serve_terminal(client, project_objects, project)
        }
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
        Command::Create { destination } => project::save(&destination, &HashMap::new()).unwrap(),
    }
}
