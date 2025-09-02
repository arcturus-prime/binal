use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[derive(Default)]
struct StructMember {
    name: String,
    r#type: TypeRef,
    offset: usize,
}

#[derive(Default)]
struct EnumValue {
    name: String,
    value: usize,
}

#[derive(Default)]
struct UnionMember {
    name: String,
    r#type: TypeRef,
}

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

#[derive(Default)]
struct Type {
    pub name: String,

    size: usize,
    alignment: usize,
    info: TypeInfo,
}

#[derive(Default)]
struct Function {
    pub name: String,

    location: usize,

    return_type: TypeRef,
    argument_names: Vec<String>,
    argument_types: Vec<TypeRef>,
}

#[derive(Default)]
struct Data {
    pub name: String,
    location: usize,
    r#type: TypeRef,
}

#[derive(Default)]
struct IdVec<T> {
    array: Vec<T>,
    reverse_lookup: Vec<usize>,

    lookup: Vec<usize>,
    holes: Vec<usize>,
}

impl<T> IdVec<T> {
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

#[derive(Default)]
pub struct Database {
    pub functions: IdVec<Function>,
    pub types: IdVec<Type>,
    pub data: IdVec<Data>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        let mut project_file = File::open(&path)?;
        let mut project_data = Vec::<u8>::new();

        project_file.read_to_end(&mut project_data)?;
    }

    pub fn save(&self, path: &Path) -> Result<(), DatabaseError> {
        let mut file;

        if !path.exists() {
            file = File::create(path)?;
        } else {
            file = OpenOptions::new().write(true).open(path)?;
        }

        Ok(())
    }
}
