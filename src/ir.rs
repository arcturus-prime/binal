use std::{fmt::Debug, io::Cursor};

use num_enum::TryFromPrimitive;

enum IrIOError {
    InvalidByte,
    OutOfBounds,
    Leb128Error,
}

pub struct InstructionStream {
    buffer: Vec<u8>,
    gap_start: usize,
    gap_end: usize,
}

impl InstructionStream {
    pub fn new() -> Self {
        Self::with_capacity(64)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: vec![0; capacity],
            gap_start: 0,
            gap_end: capacity,
        }
    }

    pub fn seek(&mut self, pos: usize) {
        let len = self.len();
        if pos > len {
            panic!("seek position {} out of bounds (length: {})", pos, len);
        }

        if pos < self.gap_start {
            let distance = self.gap_start - pos;
            let new_gap_end = self.gap_end;
            let new_gap_start = pos;

            for i in 0..distance {
                self.buffer[new_gap_end - distance + i] = self.buffer[pos + i];
            }

            self.gap_start = new_gap_start;
            self.gap_end = new_gap_end;
        } else if pos > self.gap_start {
            let distance = pos - self.gap_start;
            let old_gap_end = self.gap_end;

            for i in 0..distance {
                self.buffer[self.gap_start + i] = self.buffer[old_gap_end + i];
            }

            self.gap_start = pos;
            self.gap_end = old_gap_end + distance;
        }
    }

    fn ensure_gap(&mut self, needed: usize) {
        let gap_size = self.gap_end - self.gap_start;
        if gap_size < needed {
            let new_gap_size = (needed + 64).max(self.buffer.len());
            let old_len = self.buffer.len();

            self.buffer.resize(old_len + new_gap_size, 0);

            let after_gap_len = old_len - self.gap_end;

            if after_gap_len > 0 {
                let src_start = self.gap_end;
                let dst_start = self.buffer.len() - after_gap_len;
                for i in (0..after_gap_len).rev() {
                    self.buffer[dst_start + i] = self.buffer[src_start + i];
                }
            }

            self.gap_end = self.buffer.len() - after_gap_len;
        }
    }

    pub fn emit_block(&mut self, block: InstructionStream) {
        self.ensure_gap(block.len());
        self.buffer[self.gap_start..self.gap_start + block.len()].copy_from_slice(&block.to_vec());
        self.gap_start += block.len();
    }

    pub fn emit_instruction(&mut self, instruction: Instruction) {
        self.ensure_gap(1);
        self.buffer[self.gap_start] = instruction as u8;
        self.gap_start += 1;
    }

    pub fn emit_constant(&mut self, number: i64) -> Result<(), IrIOError> {
        // Reserve space for instruction + max LEB128 size (10 bytes for i64)
        self.ensure_gap(11);

        self.buffer[self.gap_start] = Instruction::Constant as u8;
        self.gap_start += 1;

        let mut buf = &mut self.buffer[self.gap_start..self.gap_end];
        let Ok(bytes_written) = leb128::write::signed(&mut buf, number) else {
            return Err(IrIOError::Leb128Error);
        };

        self.gap_start += bytes_written;

        Ok(())
    }

    fn read_byte(&mut self) -> Option<u8> {
        if self.gap_start >= self.len() {
            return None;
        }

        let byte = self.buffer[self.gap_end];
        self.gap_end += 1;

        Some(byte)
    }

    pub fn consume_instruction(&mut self) -> Result<Instruction, IrIOError> {
        Instruction::try_from(self.read_byte().ok_or(IrIOError::OutOfBounds)?)
            .ok()
            .ok_or(IrIOError::InvalidByte)
    }

    pub fn consume_constant(&mut self) -> Result<i64, IrIOError> {
        let mut cursor = Cursor::new(&self.buffer[self.gap_end..]);
        let Ok(value) = leb128::read::signed(&mut cursor) else {
            return Err(IrIOError::Leb128Error);
        };

        self.gap_end += cursor.position() as usize;

        Ok(value)
    }

    pub fn position(&self) -> usize {
        self.gap_start
    }

    pub fn len(&self) -> usize {
        self.buffer.len() - (self.gap_end - self.gap_start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.len());
        result.extend_from_slice(&self.buffer[..self.gap_start]);
        result.extend_from_slice(&self.buffer[self.gap_end..]);
        result
    }

    pub fn clear(&mut self) {
        self.gap_start = 0;
        self.gap_end = self.buffer.len();
    }
}

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone, Debug, PartialEq)]
pub enum Instruction {
    Constant,

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

    Recall,
    Jump, // address

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
