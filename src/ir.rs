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
        fields: Vec<StructMember>,
    },
    Enum {
        values: Vec<EnumValue>,
    },
    Union {
        fields: Vec<UnionMember>,
    },
    TypeDef {
        alias_type: usize,
        name: String,
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
pub struct ExternalType {
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
pub struct ExternalFunction {
    name: String,
    location: usize,

    return_type: usize,
    arguments: Vec<FunctionArgument>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct ExternalData {
    name: String,
    location: usize,
    data_type: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub struct ExternalDatabase {
    pub functions: HashMap<usize, ExternalFunction>,
    pub types: HashMap<usize, ExternalType>,
    pub data: HashMap<usize, ExternalData>,
}

#[derive(Debug)]
pub enum ExternalDatabaseError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl From<std::io::Error> for ExternalDatabaseError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ExternalDatabaseError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

impl<'a> Display for ExternalDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExternalDatabaseError::Io(e) => e.fmt(f),
            ExternalDatabaseError::Serde(e) => e.fmt(f),
        }
    }
}

impl ExternalDatabase {
    pub fn open(path: &Path) -> Result<Self, ExternalDatabaseError> {
        let mut project_file = File::open(&path)?;
        let mut project_data = Vec::<u8>::new();

        project_file.read_to_end(&mut project_data)?;

        let db: ExternalDatabase = serde_json::from_slice(&project_data)?;

        Ok(db)
    }

    pub fn save(&self, path: &Path) -> Result<(), ExternalDatabaseError> {
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

pub enum ExternalCommand {
    CreateType,
}
