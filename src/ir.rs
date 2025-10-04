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
    Swap, // value, value
    Pick, // number
    Pop,  // value

    // Statements
    Comment, // string
    Assign,  // register, value

    IfEnter, // condition
    ElseEnter,
    WhileEnter, // condition
    BlockEnter, // label

    Goto, // label
    Continue,
    Break,

    Exit,
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
