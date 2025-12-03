use crate::ir::{Instruction, InstructionStream};

#[derive(PartialEq)]
pub enum GeneratorError {
    InvalidInstruction,
    OutOfBounds,
}

pub trait SemanticGenerator {
    fn disassemble(
        &self,
        address: u64,
        semantics: &mut InstructionStream,
    ) -> Result<(), GeneratorError>;
}

#[derive(Debug)]
pub enum LifterError {
    InvalidByte,
    StackMismanaged,
}

enum Literal {
    I64(i64),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    I32(i32),
    I16(i16),
    I8(i8),
}

fn cast_literal(value: Literal, target_type: Instruction) -> Result<Literal, LifterError> {
    match target_type {
        Instruction::I32 => match value {
            Literal::U16(x) => Ok(Literal::I32(x as i32)),
            Literal::U8(x) => Ok(Literal::I32(x as i32)),
            Literal::I8(x) => Ok(Literal::I32(x as i32)),
            Literal::I16(x) => Ok(Literal::I32(x as i32)),
            Literal::I32(x) => Ok(Literal::I32(x)),
            Literal::U32(x) => Ok(Literal::I32(x as i32)),
            Literal::U64(x) => Ok(Literal::I32(x as i32)),
            Literal::I64(x) => Ok(Literal::I32(x as i32)),
        },
        Instruction::I64 => match value {
            Literal::U16(x) => Ok(Literal::I64(x as i64)),
            Literal::U8(x) => Ok(Literal::I64(x as i64)),
            Literal::I8(x) => Ok(Literal::I64(x as i64)),
            Literal::I16(x) => Ok(Literal::I64(x as i64)),
            Literal::I32(x) => Ok(Literal::I64(x as i64)),
            Literal::U32(x) => Ok(Literal::I64(x as i64)),
            Literal::U64(x) => Ok(Literal::I64(x as i64)),
            Literal::I64(x) => Ok(Literal::I64(x)),
        },
        Instruction::U32 => match value {
            Literal::U16(x) => Ok(Literal::U32(x as u32)),
            Literal::U8(x) => Ok(Literal::U32(x as u32)),
            Literal::I8(x) => Ok(Literal::U32(x as u32)),
            Literal::I16(x) => Ok(Literal::U32(x as u32)),
            Literal::I32(x) => Ok(Literal::U32(x as u32)),
            Literal::U32(x) => Ok(Literal::U32(x)),
            Literal::U64(x) => Ok(Literal::U32(x as u32)),
            Literal::I64(x) => Ok(Literal::U32(x as u32)),
        },
        Instruction::U64 => match value {
            Literal::U16(x) => Ok(Literal::U64(x as u64)),
            Literal::U8(x) => Ok(Literal::U64(x as u64)),
            Literal::I8(x) => Ok(Literal::U64(x as u64)),
            Literal::I16(x) => Ok(Literal::U64(x as u64)),
            Literal::I32(x) => Ok(Literal::U64(x as u64)),
            Literal::U32(x) => Ok(Literal::U64(x as u64)),
            Literal::U64(x) => Ok(Literal::U64(x)),
            Literal::I64(x) => Ok(Literal::U64(x as u64)),
        },
        Instruction::I16 => match value {
            Literal::U16(x) => Ok(Literal::I16(x as i16)),
            Literal::U8(x) => Ok(Literal::I16(x as i16)),
            Literal::I8(x) => Ok(Literal::I16(x as i16)),
            Literal::I16(x) => Ok(Literal::I16(x)),
            Literal::I32(x) => Ok(Literal::I16(x as i16)),
            Literal::U32(x) => Ok(Literal::I16(x as i16)),
            Literal::U64(x) => Ok(Literal::I16(x as i16)),
            Literal::I64(x) => Ok(Literal::I16(x as i16)),
        },
        Instruction::I8 => match value {
            Literal::U16(x) => Ok(Literal::I8(x as i8)),
            Literal::U8(x) => Ok(Literal::I8(x as i8)),
            Literal::I8(x) => Ok(Literal::I8(x)),
            Literal::I16(x) => Ok(Literal::I8(x as i8)),
            Literal::I32(x) => Ok(Literal::I8(x as i8)),
            Literal::U32(x) => Ok(Literal::I8(x as i8)),
            Literal::U64(x) => Ok(Literal::I8(x as i8)),
            Literal::I64(x) => Ok(Literal::I8(x as i8)),
        },
        Instruction::U16 => match value {
            Literal::U16(x) => Ok(Literal::U16(x)),
            Literal::U8(x) => Ok(Literal::U16(x as u16)),
            Literal::I8(x) => Ok(Literal::U16(x as u16)),
            Literal::I16(x) => Ok(Literal::U16(x as u16)),
            Literal::I32(x) => Ok(Literal::U16(x as u16)),
            Literal::U32(x) => Ok(Literal::U16(x as u16)),
            Literal::U64(x) => Ok(Literal::U16(x as u16)),
            Literal::I64(x) => Ok(Literal::U16(x as u16)),
        },
        Instruction::U8 => match value {
            Literal::U8(x) => Ok(Literal::U8(x)),
            Literal::U16(x) => Ok(Literal::U8(x as u8)),
            Literal::I8(x) => Ok(Literal::U8(x as u8)),
            Literal::I16(x) => Ok(Literal::U8(x as u8)),
            Literal::I32(x) => Ok(Literal::U8(x as u8)),
            Literal::U32(x) => Ok(Literal::U8(x as u8)),
            Literal::U64(x) => Ok(Literal::U8(x as u8)),
            Literal::I64(x) => Ok(Literal::U8(x as u8)),
        },
        _ => {
            panic!("Unsupported instruction type")
        }
    }
}

enum LifterData {
    Literal(Literal),
}

enum LifterControl {
    Jump(u64, u64),
}

fn pop_data_safe(stack: &mut Vec<LifterData>) -> Result<LifterData, LifterError> {
    match stack.pop() {
        None => Err(LifterError::StackMismanaged),
        Some(x) => Ok(x),
    }
}

pub fn lift<T: SemanticGenerator>(generator: &T, mut address: u64) -> Result<Vec<u8>, LifterError> {
    let mut code_out = InstructionStream::new();
    let mut current_block = InstructionStream::new();

    let mut code_in = InstructionStream::new();
    let mut data_stack = Vec::new();
    let mut control_stack = Vec::new();

    loop {
        if let Err(e) = generator.disassemble(address, &mut code_in) {
            continue;
        }

        while !code_in.is_empty() {
            let Ok(instruction) = code_in.consume_instruction() else {
                return Err(LifterError::InvalidByte);
            };

            match instruction {
                Instruction::Constant => {
                    let Ok(value) = code_in.consume_constant() else {
                        return Err(LifterError::InvalidByte);
                    };
                    data_stack.push(LifterData::Literal(Literal::I64(value)));
                }
                Instruction::F32
                | Instruction::F64
                | Instruction::VectorF32
                | Instruction::VectorF64
                | Instruction::U64
                | Instruction::U32
                | Instruction::U16
                | Instruction::U8
                | Instruction::I64
                | Instruction::I32
                | Instruction::I16
                | Instruction::I8 => {
                    let value = pop_data_safe(&mut data_stack)?;

                    if let LifterData::Literal(l) = value {
                        data_stack.push(LifterData::Literal(cast_literal(l, instruction)?));
                    }
                }
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
                Instruction::Recall => todo!(),
                Instruction::Jump => todo!(),
                Instruction::Break => todo!(),
                Instruction::BreakIndex => todo!(),
                Instruction::Continue => todo!(),
                Instruction::ContinueIndex => todo!(),
                Instruction::Loop => todo!(),
                Instruction::If => todo!(),
                Instruction::Else => todo!(),
                Instruction::End => todo!(),
                Instruction::Load => todo!(),
                Instruction::Store => todo!(),
            };
        }
    }
}
