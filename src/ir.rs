use std::{
    collections::HashMap,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{Read, Write},
    marker::PhantomData,
    path::Path,
};

use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize,
};

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
    },
    Function {
        arg_types: Vec<usize>,
        return_type: usize,
    },
    Int {},
    Uint {},
    Float {},
    Bool {},
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
    name: String,
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

#[derive(Default)]
pub struct IdVec<T: Default> {
    array: Vec<T>,

    reverse_lookup: Vec<usize>,
    lookup: HashMap<usize, usize>,
}

impl<'a, T: Default + Deserialize<'a>> IdVec<T> {
    pub fn insert(&mut self, id: usize, item: T) {
        self.array.push(item);

        self.lookup.insert(id, self.reverse_lookup.len());

        self.reverse_lookup.push(id);
    }

    pub fn get(&self, id: usize) -> Option<&T> {
        let index;

        index = self.lookup.get(&id);
        let Some(index) = index else { return None };

        return Some(&self.array[*index]);
    }

    pub fn get_mut(&mut self, id: usize) -> Option<&mut T> {
        let index;

        index = self.lookup.get(&id);
        let Some(index) = index else { return None };

        return Some(&mut self.array[*index]);
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.array.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.array.iter_mut()
    }

    pub fn id_iter(&self) -> impl Iterator<Item = &usize> + '_ {
        self.reverse_lookup.iter()
    }

    pub fn len(&self) -> usize {
        self.array.len()
    }
}

impl<'a, T: Default + Deserialize<'a> + Serialize> Serialize for IdVec<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.array.len()))?;

        for (id, index) in self.reverse_lookup.iter().zip(0 as usize..) {
            map.serialize_entry(id, &self.array[index])?;
        }

        map.end()
    }
}

struct IdVecVisitor<T> {
    marker: PhantomData<T>,
}

impl<T> IdVecVisitor<T> {
    pub fn new() -> Self {
        IdVecVisitor {
            marker: PhantomData::default(),
        }
    }
}

impl<'de, T: Deserialize<'de> + Default> Visitor<'de> for IdVecVisitor<T> {
    type Value = IdVec<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("AAAAAAAAAAAAA")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut id_vec = IdVec::<T>::default();
        while let Some((id, value)) = map.next_entry::<usize, T>()? {
            id_vec.insert(id, value)
        }

        Ok(id_vec)
    }
}

impl<'a, T: Serialize + Deserialize<'a> + Default> Deserialize<'a> for IdVec<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_map(IdVecVisitor::new())
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct Database {
    pub functions: IdVec<Function>,
    pub types: IdVec<Type>,
    pub data: IdVec<Data>,
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
