use crate::net::Object;

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub fn load(path: &Path) -> Result<HashMap<String, Object>, io::Error> {
    let mut file = File::open(path)?;

    let mut text = String::new();
    file.read_to_string(&mut text)?;

    Ok(serde_json::from_str(&text)?)
}

pub fn save(path: &Path, objects: &HashMap<String, Object>) -> Result<(), io::Error> {
    let mut file = OpenOptions::new().create(true).write(true).open(path)?;

    let text = serde_json::to_vec(&objects)?;
    file.write_all(&text)?;

    Ok(())
}
