use std::collections::HashMap;

use bytemuck::{bytes_of, Pod};
use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone)]
pub enum Instruction {
    Nop = 128,

    // Casts
    String,       // value
    Unsigned,     // value
    Signed,       // value
    Float,        // value
    Double,       // value
    Boolean,      // value
    VectorFloat,  // value
    VectorDouble, // value

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

    Register, // size, offset
    Name,     // value, string

    // Macros
    Copy, // value
    Pick, // number

    // Statements
    LifterError, // body, code
    Comment,     // body, string
    Assign,      // body, register, value

    IfCreate,    // condition
    ElseCreate,  // if-body
    WhileCreate, // condition
    BlockCreate, // label
    End,         // body, body

    Goto,     // body, label
    Continue, // body
    Break,    // body
}

impl Instruction {
    pub fn argument_count(self) -> usize {
        match self {
            Instruction::Nop => 0,
            Instruction::String => 1,
            Instruction::Unsigned => 1,
            Instruction::Signed => 1,
            Instruction::Float => 1,
            Instruction::Double => 1,
            Instruction::Boolean => 1,
            Instruction::VectorFloat => 1,
            Instruction::VectorDouble => 1,
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
            Instruction::Register => 2,
            Instruction::Name => 2,
            Instruction::Copy => 1,
            Instruction::Pick => 1,
            Instruction::Comment => 2,
            Instruction::Assign => 2,
            Instruction::IfCreate => 1,
            Instruction::ElseCreate => 1,
            Instruction::WhileCreate => 1,
            Instruction::BlockCreate => 1,
            Instruction::End => 2,
            Instruction::Goto => 2,
            Instruction::Continue => 1,
            Instruction::Break => 1,
            Instruction::LifterError => 2,
        }
    }

    pub fn product_count(self) -> usize {
        match self {
            Instruction::Nop => 0,
            Instruction::String => 1,
            Instruction::Unsigned => 1,
            Instruction::Signed => 1,
            Instruction::Float => 1,
            Instruction::Double => 1,
            Instruction::Boolean => 1,
            Instruction::VectorFloat => 1,
            Instruction::VectorDouble => 1,
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
            Instruction::Register => 1,
            Instruction::Name => 1,
            Instruction::Copy => 2,
            Instruction::Pick => 1,
            Instruction::Comment => 1,
            Instruction::Assign => 1,
            Instruction::Goto => 1,
            Instruction::Continue => 1,
            Instruction::Break => 1,
            Instruction::IfCreate => 1,
            Instruction::ElseCreate => 1,
            Instruction::WhileCreate => 1,
            Instruction::BlockCreate => 1,
            Instruction::End => 2,
            Instruction::LifterError => 1,
        }
    }
}

pub enum LifterErrors {
    CouldNotResolveJump,
}

#[derive(Default)]
pub struct ProgramWriter {
    instructions: Vec<u8>,
}

impl ProgramWriter {
    // NOTE: This function assumes we are working in little-endian
    pub fn emit_constant<T: Pod>(&mut self, constant: T) {
        let bytes = bytes_of(&constant);
        let mut carry = 0;

        let mut end = bytes.len();
        for x in bytes.iter().rev() {
            if *x != 0 {
                break;
            }

            end -= 1;
        }

        for x in &bytes[..end] {
            self.instructions.push((x + carry) & 0x7F);
            carry = if x + carry > 127 { 1 } else { 0 };
        }
    }

    pub fn emit_string(&mut self, string: &str) {
        if !string.is_ascii() {
            panic!("Strings must be contain only ASCII-compatible characters");
        }

        for x in string.as_bytes() {
            self.instructions.push(*x);
        }
    }

    pub fn emit_instruction(&mut self, instruction: Instruction) {
        self.instructions.push(instruction as u8);
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.instructions)
    }
}

pub fn print_program(code: &[u8]) {}
