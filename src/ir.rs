use std::fmt::Write;

use num_enum::TryFromPrimitive;

pub struct BitStack {
    buffer: [u8; 16],
    cursor: usize,
}

pub trait BitStackOps {
    const ZERO: Self;

    fn write_bit(&mut self, index: usize, value: bool);
    fn read_bit(&self, index: usize) -> bool;
}

macro_rules! define_bitstack_impl {
    ($a:ty, $b:ty) => {
        impl BitStackOps for $a {
            const ZERO: $a = 0;

            #[inline(always)]
            fn write_bit(&mut self, index: usize, value: bool) {
                let mut copy = <$b>::from_ne_bytes(self.to_ne_bytes());

                copy &= !(1 << index);
                copy |= (value as $b) << index;

                *self = <$a>::from_ne_bytes(copy.to_ne_bytes())
            }

            #[inline(always)]
            fn read_bit(&self, index: usize) -> bool {
                let copy = <$b>::from_ne_bytes(self.to_ne_bytes());

                (copy >> index) & 1 != 0
            }
        }
    };
}

macro_rules! define_bitstack_impl_float {
    ($a:ty, $b:ty) => {
        impl BitStackOps for $a {
            const ZERO: $a = 0.0;

            #[inline(always)]
            fn write_bit(&mut self, index: usize, value: bool) {
                let mut copy = <$b>::from_ne_bytes(self.to_ne_bytes());

                copy &= !(1 << index);
                copy |= (value as $b) << index;

                *self = <$a>::from_ne_bytes(copy.to_ne_bytes())
            }

            #[inline(always)]
            fn read_bit(&self, index: usize) -> bool {
                let copy = <$b>::from_ne_bytes(self.to_ne_bytes());

                (copy >> index) & 1 != 0
            }
        }
    };
}

define_bitstack_impl_float!(f32, u32);
define_bitstack_impl_float!(f64, u64);
define_bitstack_impl!(u8, u8);
define_bitstack_impl!(u16, u16);
define_bitstack_impl!(u32, u32);
define_bitstack_impl!(u64, u64);
define_bitstack_impl!(u128, u128);
define_bitstack_impl!(i8, u8);
define_bitstack_impl!(i16, u16);
define_bitstack_impl!(i32, u32);
define_bitstack_impl!(i64, u64);
define_bitstack_impl!(i128, u128);

impl BitStack {
    pub fn new() -> Self {
        Self {
            cursor: 0,
            buffer: [0; 16],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    pub fn all_zero(&self) -> bool {
        if self.buffer[self.cursor / 8] >> (self.cursor % 8) != 0 {
            return false;
        }

        for x in self.buffer[..self.cursor / 8].iter().rev() {
            if *x != 0 {
                return false;
            }
        }

        return true;
    }

    pub fn all_one(&self) -> bool {
        if self.buffer[self.cursor / 8] >> (self.cursor % 8) != 0xFF >> (self.cursor % 8) {
            return false;
        }

        for x in self.buffer[..self.cursor / 8].iter().rev() {
            if *x != 0xFF {
                return false;
            }
        }

        return true;
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    pub fn pop<const BITS: usize, T: BitStackOps>(&mut self) -> T {
        let mut result = T::ZERO;

        for i in 0..BITS {
            self.cursor -= 1;

            let byte_index = self.cursor / 8;
            let bit_index = self.cursor % 8;

            result.write_bit(BITS - i, self.buffer[byte_index].read_bit(bit_index));
        }

        result
    }

    pub fn push<const BITS: usize, T: BitStackOps>(&mut self, data: T) {
        const {
            assert!(
                BITS <= std::mem::size_of::<T>() * 8,
                "BITS cannot be greater than the size of T"
            );
        }

        for i in 0..BITS {
            let byte_index = self.cursor / 8;
            let bit_index = self.cursor % 8;

            self.buffer[byte_index].write_bit(bit_index, data.read_bit(i));
            self.cursor += 1;
        }
    }
}

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone, Debug)]
pub enum Instruction {
    Nop = 128,

    Const8,
    Const16,
    Const32,
    Const64,
    Const128,

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

    Load,  // offset, size
    Store, // offset, value

    // Macros
    Copy, // value
    Pick, // number

    Loop,
    If, // condition
    Else,
    End,

    Branch,
    BranchIndex, // number
    Return,
}

impl Instruction {
    pub fn argument_count(self) -> usize {
        match self {
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
            Instruction::Branch => 0,
            Instruction::BranchIndex => 1,
            Instruction::Return => 0,
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
            Instruction::Const8 => 0,
            Instruction::Const16 => 0,
            Instruction::Const32 => 0,
            Instruction::Const64 => 0,
            Instruction::Const128 => 0,
        }
    }

    pub fn product_count(self) -> usize {
        match self {
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
            Instruction::Branch => 0,
            Instruction::BranchIndex => 0,
            Instruction::Return => 0,
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
            Instruction::Const8 => 1,
            Instruction::Const16 => 1,
            Instruction::Const32 => 1,
            Instruction::Const64 => 1,
            Instruction::Const128 => 1,
        }
    }
}

#[derive(Default)]
pub struct ProgramWriter {
    instructions: Vec<u8>,
}

impl ProgramWriter {
    pub fn emit_constant<const BITS: usize, T: BitStackOps>(&mut self, constant: T) {
        let mut stack = BitStack::new();

        stack.push::<BITS, T>(constant);

        while !stack.is_empty() {
            let byte = stack.pop::<7, u8>();
            self.instructions.push(byte);
        }
    }

    pub fn emit_instruction(&mut self, instruction: Instruction) {
        self.instructions.push(0x80 | instruction as u8);
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.instructions)
    }
}

#[derive(Debug)]
pub enum PrintError {
    InvalidByte,
    StackMismanaged,
    IOWriteError,
}

fn pop_safe(stack: &mut Vec<String>) -> Result<String, PrintError> {
    match stack.pop() {
        None => Err(PrintError::StackMismanaged),
        Some(x) => Ok(x),
    }
}

pub fn print_instructions_simple(code: &[u8]) -> Result<String, PrintError> {
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

pub fn print_instructions(code: &[u8]) -> Result<(), PrintError> {
    let mut stack = vec![];
    let mut const_stack = BitStack::new();

    for x in code {
        if *x < 128 {
            const_stack.push::<7, u8>(*x);
            continue;
        }

        let Ok(x) = (*x).try_into() else {
            return Err(PrintError::InvalidByte);
        };

        let string = match x {
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
            Instruction::Branch => todo!(),
            Instruction::BranchIndex => todo!(),
            Instruction::Return => todo!(),
            Instruction::Boolean => todo!(),
            Instruction::U64 => const_stack.pop::<64, u64>().to_string(),
            Instruction::U32 => const_stack.pop::<32, u32>().to_string(),
            Instruction::U16 => const_stack.pop::<16, u16>().to_string(),
            Instruction::U8 => const_stack.pop::<8, u8>().to_string(),
            Instruction::I64 => const_stack.pop::<64, i64>().to_string(),
            Instruction::I32 => const_stack.pop::<32, i32>().to_string(),
            Instruction::I16 => const_stack.pop::<16, i16>().to_string(),
            Instruction::I8 => const_stack.pop::<8, i8>().to_string(),
            Instruction::F32 => todo!(),
            Instruction::F64 => todo!(),
            Instruction::VectorF32 => todo!(),
            Instruction::VectorF64 => todo!(),
        };

        stack.push(string);
    }

    Ok(())
}
