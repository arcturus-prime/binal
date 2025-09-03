use std::{
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

#[derive(Debug, Default, Serialize, Deserialize)]
struct StructMember {
    name: String,
    r#type: TypeRef,
    offset: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EnumValue {
    name: String,
    value: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UnionMember {
    name: String,
    r#type: TypeRef,
}

#[derive(Debug, Serialize, Deserialize)]
enum TypeRef {
    Int(u16),
    Uint(u16),
    Float(u16),
    Value(usize),
    Pointer(u8, usize),
}

impl Default for TypeRef {
    fn default() -> Self {
        TypeRef::Uint(0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum TypeInfo {
    Struct(Vec<StructMember>),
    Enum(Vec<EnumValue>),
    Union(Vec<UnionMember>),
    TypeDef(TypeRef),
    Function(Vec<TypeRef>, TypeRef),
    Array(TypeRef, usize),
}

impl Default for TypeInfo {
    fn default() -> Self {
        TypeInfo::Array(TypeRef::default(), 1)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Type {
    pub name: String,

    size: usize,
    alignment: usize,
    info: TypeInfo,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Function {
    pub name: String,

    location: usize,

    return_type: TypeRef,
    argument_names: Vec<String>,
    argument_types: Vec<TypeRef>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Data {
    pub name: String,
    location: usize,
    r#type: TypeRef,
}

#[derive(Default)]
pub struct IdVec<T: Default> {
    array: Vec<T>,

    reverse_lookup: Vec<usize>,
    lookup: Vec<usize>,

    holes: Vec<usize>,
}

impl<'a, T: Default + Deserialize<'a>> IdVec<T> {
    pub fn push(&mut self, item: T) -> usize {
        let id;

        self.array.push(item);

        if let Some(hole) = self.holes.pop() {
            id = hole;
            self.lookup[id] = self.reverse_lookup.len();
            self.reverse_lookup.push(id);
        } else {
            id = self.lookup.len();
            self.lookup.push(self.reverse_lookup.len());
            self.reverse_lookup.push(id);
        }

        id
    }

    pub fn get(&self, id: usize) -> &T {
        let index = self.lookup[id];
        return &self.array[index];
    }

    pub fn get_mut(&mut self, id: usize) -> &mut T {
        let index = self.lookup[id];
        return &mut self.array[index];
    }

    pub fn delete(&mut self, id: usize) {
        let index = self.lookup[id];

        self.lookup[*self.reverse_lookup.last().unwrap()] = index;
        self.array.swap_remove(index);
        self.reverse_lookup.swap_remove(index);
        self.holes.push(id);
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.array.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.array.iter_mut()
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

        let mut holes = Vec::new();
        while let Some((id, value)) = map.next_entry::<usize, T>()? {
            id_vec.array.push(value);
            id_vec.reverse_lookup.push(id);

            id_vec.lookup.resize(id, 0);
            holes.resize(id, true);

            holes[id] = false;
            id_vec.lookup[id] = id_vec.array.len();
        }

        for (i, index) in holes.iter().zip(0..) {
            if *i {
                id_vec.holes.push(index);
            }
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
