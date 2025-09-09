use std::{
    collections::HashMap,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct StructMember {
    name: String,
    field_type: usize,
    offset: usize,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct EnumValue {
    name: String,
    value: usize,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct UnionMember {
    name: String,
    field_type: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind")]
#[serde(rename_all(deserialize = "lowercase", serialize = "lowercase"))]
enum TypeInfo {
    Struct {
        name: String,
        fields: Vec<StructMember>,
    },
    Enum {
        name: String,
        values: Vec<EnumValue>,
    },
    Union {
        name: String,
        fields: Vec<UnionMember>,
    },
    TypeDef {
        name: String,
        alias_type: usize,
    },
    Function {
        arg_types: Vec<usize>,
        return_type: usize,
    },
    Int {},
    Uint {},
    Float {},
    Bool {},
    Unknown {},
    Pointer {
        depth: u8,
        value_type: usize,
    },
    Array {
        item_type: usize,
    },
}

impl Default for TypeInfo {
    fn default() -> Self {
        TypeInfo::Struct { fields: Vec::new() }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Type {
    size: usize,
    alignment: usize,
    info: TypeInfo,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct FunctionArgument {
    name: String,
    arg_type: usize,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Function {
    name: String,
    location: usize,

    return_type: usize,
    arguments: Vec<FunctionArgument>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Data {
    name: String,
    location: usize,
    data_type: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Database {
    pub functions: HashMap<usize, Function>,
    pub types: HashMap<usize, Type>,
    pub data: HashMap<usize, Data>,
}

#[derive(Debug)]
pub enum DatabaseError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl From<std::io::Error> for DatabaseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DatabaseError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

impl<'a> Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::Io(e) => e.fmt(f),
            DatabaseError::Serde(e) => e.fmt(f),
        }
    }
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        let mut project_file = File::open(&path)?;
        let mut project_data = Vec::<u8>::new();

        project_file.read_to_end(&mut project_data)?;

        let db: Database = serde_json::from_slice(&project_data)?;

        Ok(db)
    }

    pub fn save(&self, path: &Path) -> Result<(), DatabaseError> {
        let mut file;

        if !path.exists() {
            file = File::create(path)?;
        } else {
            file = OpenOptions::new().write(true).open(path)?;
        }

        let project_data = serde_json::to_vec(self)?;
        file.write_all(&project_data)?;

        Ok(())
    }
}
