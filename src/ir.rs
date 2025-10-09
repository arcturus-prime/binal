use bytemuck::{Pod, bytes_of, bytes_of_mut};
use num_enum::TryFromPrimitive;

pub struct BitStack<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> BitStack<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            cursor: buffer.len() * 8,
            buffer,
        }
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }

    pub fn pop<const BITS: usize, T: Pod>(&mut self) -> T {
        let mut result = T::zeroed();
        let destination = bytes_of_mut(&mut result);

        let mut bits = BITS;
        for x in destination.iter_mut() {
            let byte_read = self.cursor / 8;
            let bit_read = self.cursor % 8;

            if self.cursor < 8 {
                *x = self.buffer[0] & (0xFF << (8 - self.cursor));
                self.cursor = 0;
                break;
            }

            if bits < 8 {
                *x = self.buffer[byte_read] & (0xFF >> (8 - bits));
                self.cursor -= bits;
                break;
            }

            self.cursor -= 8;
            bits -= 8;

            if bit_read == 0 {
                *x = self.buffer[byte_read];
            } else {
                *x = (self.buffer[byte_read] << bit_read)
                    | (self.buffer[byte_read + 1] >> (8 - bit_read));
            }
        }

        result
    }

    pub fn push<const BITS: usize, T: Pod>(&mut self, data: T) {
        const {
            assert!(
                BITS <= std::mem::size_of::<T>(),
                "BITS cannot be greater than the size of T"
            );
        }

        let mut bits = BITS;
        for x in bytes_of(&data) {
            let byte_write = self.cursor / 8;
            let bit_write = self.cursor % 8;

            if bits < 8 {
                self.buffer[byte_write] &= self.cursor += bits;
                break;
            }

            if bit_write == 0 {
                self.buffer[byte_write] = *x;
            } else {
            }

            bits -= 8;
            self.cursor += 8;
        }
    }
}

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone)]
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
            Instruction::U64 => 0,
            Instruction::U32 => 0,
            Instruction::U16 => 0,
            Instruction::U8 => 0,
            Instruction::I64 => 0,
            Instruction::I32 => 0,
            Instruction::I16 => 0,
            Instruction::I8 => 0,
            Instruction::F32 => 0,
            Instruction::F64 => 0,
            Instruction::VectorF32 => 0,
            Instruction::VectorF64 => 0,
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
        }
    }
}

#[derive(Default)]
pub struct ProgramWriter {
    instructions: Vec<u8>,
}

impl ProgramWriter {
    // NOTE: This function assumes we are working in little-endian
    pub fn emit_constant<T: Pod>(&mut self, mut constant: T) {
        let bytes = bytes_of_mut(&mut constant);

        let mut end_byte = bytes.len();
        for x in bytes.iter().rev() {
            if *x != 0 {
                break;
            }

            end_byte -= 1;
        }

        let mut stack = BitStack::new(bytes);

        for _ in 0..end_byte {
            self.instructions.push(stack.pop::<7, u8>());
        }
    }

    pub fn emit_instruction(&mut self, instruction: Instruction) {
        self.instructions.push(0x80 | instruction as u8);
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.instructions)
    }
}

pub enum PrintError {
    InvalidByte,
    StackMismanaged,
    TooLongConstant,
}

fn pop_safe(stack: &mut Vec<String>) -> Result<String, PrintError> {
    match stack.pop() {
        None => Err(PrintError::StackMismanaged),
        Some(x) => Ok(x),
    }
}

pub fn print_instructions(code: &[u8]) -> Result<(), PrintError> {
    let mut stack = vec![];
    let mut stack = BitStack::new(&mut [0_u8; 64]);

    stack.reset();

    for x in code {
        if *x < 128 {
            stack.push::<7, u8>(*x);
            continue;
        }

        let Ok(x) = (*x).try_into() else {
            return Err(PrintError::InvalidByte);
        };

        let string = match x {
            Instruction::Nop => String::new(),
            Instruction::Boolean => todo!(),
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
            Instruction::U64 => todo!(),
            Instruction::U32 => todo!(),
            Instruction::U16 => todo!(),
            Instruction::U8 => todo!(),
            Instruction::I64 => todo!(),
            Instruction::I32 => todo!(),
            Instruction::I16 => todo!(),
            Instruction::I8 => todo!(),
            Instruction::F32 => todo!(),
            Instruction::F64 => todo!(),
            Instruction::VectorF32 => todo!(),
            Instruction::VectorF64 => todo!(),
        };

        stack.push(string);
    }

    Ok(())
}
