use std::fmt::{Debug, Write};

use num_enum::TryFromPrimitive;
use num_traits::PrimInt;

pub struct Executable {
    functions: Vec<Vec<u8>>,
}

pub struct FunctionWriter<'a>(&'a mut Vec<u8>);

impl<'a> FunctionWriter<'a> {
    pub fn new(function: &'a mut Vec<u8>) -> Self {
        Self(function)
    }

    pub fn emit_instruction(&mut self, instruction: Instruction) {
        self.0.push(instruction as u8);
    }

    pub fn emit_constant<T: PrimInt + TryFrom<u8> + TryInto<u8>>(&mut self, mut number: T) {
        loop {
            // SAFETY: number & 0x7f is always valid as u8 due to the bitmask
            let v: u8 = unsafe {
                (number & 0x7f.try_into().unwrap_unchecked())
                    .try_into()
                    .unwrap_unchecked()
            };
            number = number >> 7;

            self.0.push(v);

            if (number == T::zero() && v & 0x40 == 0) || (number == T::max_value() && v & 0x40 != 0)
            {
                break;
            }
        }
    }
}

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone, Debug, PartialEq)]
pub enum Instruction {
    Nop = 128,

    // Casts
    U64,       // value
    U32,       // value
    U16,       // value
    U8,        // value
    I64,       // value
    I32,       // value
    I16,       // value
    I8,        // value
    F32,       // value
    F64,       // value
    Boolean,   // value
    VectorF32, // value
    VectorF64, // value

    // Expressions
    Add,    // left, right
    Sub,    // left, right
    Mul,    // left, right
    Div,    // left, right
    Mod,    // left, right
    Neg,    // value
    And,    // left, right
    Or,     // left, right
    Xor,    // left, right
    Not,    // value
    LShift, // value, amount
    RShift, // value, amount
    Eq,     // left, right
    Neq,    // left, right
    Lt,     // left, right
    Lte,    // left, right
    Gt,     // left, right
    Gte,    // left, right

    Copy, // value
    Pick, // number

    Call, // destination-func
    Jump, // destination-func
    Return,

    Break,
    BreakIndex, // index
    Continue,
    ContinueIndex, // index

    Loop,
    If, // condition
    Else,
    End,

    Load,  // offset, size
    Store, // offset, value
}

impl Instruction {
    pub fn argument_count(self) -> usize {
        match self {
            Instruction::Call => 1,
            Instruction::Nop => 0,
            Instruction::Boolean => 1,
            Instruction::Add => 2,
            Instruction::Sub => 2,
            Instruction::Mul => 2,
            Instruction::Div => 2,
            Instruction::Mod => 2,
            Instruction::Neg => 1,
            Instruction::And => 2,
            Instruction::Or => 2,
            Instruction::Xor => 2,
            Instruction::Not => 1,
            Instruction::LShift => 2,
            Instruction::RShift => 2,
            Instruction::Eq => 2,
            Instruction::Neq => 2,
            Instruction::Lt => 2,
            Instruction::Lte => 2,
            Instruction::Gt => 2,
            Instruction::Gte => 2,
            Instruction::Copy => 1,
            Instruction::Pick => 1,
            Instruction::End => 0,
            Instruction::Load => 2,
            Instruction::Store => 2,
            Instruction::Loop => 0,
            Instruction::If => 1,
            Instruction::Else => 0,
            Instruction::U64 => 1,
            Instruction::U32 => 1,
            Instruction::U16 => 1,
            Instruction::U8 => 1,
            Instruction::I64 => 1,
            Instruction::I32 => 1,
            Instruction::I16 => 1,
            Instruction::I8 => 1,
            Instruction::F32 => 1,
            Instruction::F64 => 1,
            Instruction::VectorF32 => 1,
            Instruction::VectorF64 => 1,
            Instruction::Jump => 1,
            Instruction::Break => 0,
            Instruction::BreakIndex => 1,
            Instruction::Continue => 0,
            Instruction::ContinueIndex => 1,
            Instruction::Return => 0,
        }
    }

    pub fn product_count(self) -> usize {
        match self {
            Instruction::Call => 0,
            Instruction::Nop => 0,
            Instruction::Boolean => 1,
            Instruction::Add => 1,
            Instruction::Sub => 1,
            Instruction::Mul => 1,
            Instruction::Div => 1,
            Instruction::Mod => 1,
            Instruction::Neg => 1,
            Instruction::And => 1,
            Instruction::Or => 1,
            Instruction::Xor => 1,
            Instruction::Not => 1,
            Instruction::LShift => 1,
            Instruction::RShift => 1,
            Instruction::Eq => 1,
            Instruction::Neq => 1,
            Instruction::Lt => 1,
            Instruction::Lte => 1,
            Instruction::Gt => 1,
            Instruction::Gte => 1,
            Instruction::Copy => 2,
            Instruction::Pick => 1,
            Instruction::End => 0,
            Instruction::Load => 1,
            Instruction::Store => 0,
            Instruction::Loop => 0,
            Instruction::If => 0,
            Instruction::Else => 0,
            Instruction::U64 => 1,
            Instruction::U32 => 1,
            Instruction::U16 => 1,
            Instruction::U8 => 1,
            Instruction::I64 => 1,
            Instruction::I32 => 1,
            Instruction::I16 => 1,
            Instruction::I8 => 1,
            Instruction::F32 => 1,
            Instruction::F64 => 1,
            Instruction::VectorF32 => 1,
            Instruction::VectorF64 => 1,
            Instruction::Jump => 0,
            Instruction::Break => 0,
            Instruction::BreakIndex => 0,
            Instruction::Continue => 0,
            Instruction::ContinueIndex => 0,
            Instruction::Return => 0
        }
    }
}

#[derive(Debug)]
pub enum PrintError {
    InvalidByte,
    StackMismanaged,
    IOWriteError,
}

pub fn print_function_simple(code: &[u8]) -> Result<String, PrintError> {
    let mut output = String::new();

    for x in code {
        if *x < 128 {
            if write!(output, "{:02x}", *x).is_err() {
                return Err(PrintError::IOWriteError);
            }

            continue;
        }

        let Ok(x) = (*x).try_into() as Result<Instruction, _> else {
            return Err(PrintError::InvalidByte);
        };

        if write!(output, "{:?} ", x).is_err() {
            return Err(PrintError::IOWriteError);
        };
    }

    Ok(output)
}

fn pop_safe(stack: &mut Vec<String>) -> Result<String, PrintError> {
    match stack.pop() {
        None => Err(PrintError::StackMismanaged),
        Some(x) => Ok(x),
    }
}

fn parse_varint<T: PrimInt + TryFrom<u8>>(data: &[u8]) -> T
where
    <T as TryFrom<u8>>::Error: Debug,
{
    let mut result = T::zero();
    let mut last = 0;
    let mut shift = 0;

    for v in data {
        let converted: T = (*v).try_into().unwrap();

        result = result | (converted << shift);
        shift += 7;

        last = *v;
    }

    if data.len() < size_of::<T>() || last & 0x40 != 0 {
        result = result | (T::max_value() << shift);
    }

    result
}

pub fn print_function(code: &[u8]) -> Result<String, PrintError> {
    let mut stack = vec![];
    let mut const_stack = vec![];

    for x in code {
        if *x < 128 {
            const_stack.push(*x);
            continue;
        }

        let Ok(x) = (*x).try_into() else {
            return Err(PrintError::InvalidByte);
        };

        let string = match x {
            Instruction::Call => todo!(),
            Instruction::Nop => String::new(),
            Instruction::Add => todo!(),
            Instruction::Sub => todo!(),
            Instruction::Mul => todo!(),
            Instruction::Div => todo!(),
            Instruction::Mod => todo!(),
            Instruction::Neg => todo!(),
            Instruction::And => todo!(),
            Instruction::Or => todo!(),
            Instruction::Xor => todo!(),
            Instruction::Not => todo!(),
            Instruction::LShift => todo!(),
            Instruction::RShift => todo!(),
            Instruction::Eq => todo!(),
            Instruction::Neq => todo!(),
            Instruction::Lt => todo!(),
            Instruction::Lte => todo!(),
            Instruction::Gt => todo!(),
            Instruction::Gte => todo!(),
            Instruction::Copy => todo!(),
            Instruction::Pick => todo!(),
            Instruction::End => todo!(),
            Instruction::Load => todo!(),
            Instruction::Store => todo!(),
            Instruction::Loop => todo!(),
            Instruction::If => todo!(),
            Instruction::Else => todo!(),
            Instruction::Boolean => todo!(),
            Instruction::U64 => parse_varint::<u64>(&const_stack).to_string(),
            Instruction::U32 => parse_varint::<u32>(&const_stack).to_string(),
            Instruction::U16 => parse_varint::<u16>(&const_stack).to_string(),
            Instruction::U8 => parse_varint::<u8>(&const_stack).to_string(),
            Instruction::I64 => parse_varint::<i64>(&const_stack).to_string(),
            Instruction::I32 => parse_varint::<i32>(&const_stack).to_string(),
            Instruction::I16 => parse_varint::<i16>(&const_stack).to_string(),
            Instruction::I8 => parse_varint::<i8>(&const_stack).to_string(),
            Instruction::F32 => todo!(),
            Instruction::F64 => todo!(),
            Instruction::VectorF32 => todo!(),
            Instruction::VectorF64 => todo!(),
            Instruction::Jump => todo!(),
            Instruction::Break => todo!(),
            Instruction::BreakIndex => todo!(),
            Instruction::Continue => todo!(),
            Instruction::ContinueIndex => todo!(),
            Instruction::Return => todo!()
        };

        if x == Instruction::U64
            || x == Instruction::U32
            || x == Instruction::U16
            || x == Instruction::U8
            || x == Instruction::I64
            || x == Instruction::I32
            || x == Instruction::I16
            || x == Instruction::I8
        {
            const_stack.clear()
        }

        stack.push(string);
    }

    Ok(stack.pop().unwrap())
}
