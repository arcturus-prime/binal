use std::{
    collections::{HashMap, VecDeque},
};

use crate::ir::{Instruction, FunctionWriter};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register, RflagsBits};

fn emit_memory_offset(inst: iced_x86::Instruction, code: &mut FunctionWriter) {
    let mut to_add = 0;

    if inst.memory_base() != Register::None {
        emit_register_read(inst.memory_base(), code);
        to_add += 1;
    }

    if inst.memory_index() != Register::None {
        emit_register_read(inst.memory_index(), code);

        if inst.memory_index_scale() != 1 {
            code.emit_constant(inst.memory_index_scale());
            code.emit_instruction(Instruction::Mul);
        }

        to_add += 1;
    }

    if inst.memory_displacement64() != 0 {
        code.emit_constant(inst.memory_displacement64());
        to_add += 1;
    }

    for _ in 1..to_add {
        code.emit_instruction(Instruction::Add);
    }
}

fn emit_register_read(register: Register, code: &mut FunctionWriter) {
    code.emit_constant(register.size() as u8);
    code.emit_instruction(Instruction::U8);
    code.emit_constant(register.full_register() as u8);
    code.emit_instruction(Instruction::U64);
    code.emit_instruction(Instruction::Load)
}

fn emit_register_write(register: Register, code: &mut FunctionWriter) {
    code.emit_constant(register.full_register() as u8);
    code.emit_instruction(Instruction::U64);
    code.emit_instruction(Instruction::Store);
}

fn emit_operand_read(
    instruction: iced_x86::Instruction,
    operand_number: u32,
    code: &mut FunctionWriter,
) {
    match instruction.op_kind(operand_number) {
        OpKind::Register => emit_register_read(instruction.op_register(operand_number), code),
        OpKind::NearBranch16
        | OpKind::NearBranch32
        | OpKind::NearBranch64
        | OpKind::FarBranch16
        | OpKind::FarBranch32 => panic!("Cannot read branch"),
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => code.emit_constant(instruction.immediate64()),
        OpKind::MemorySegSI => todo!(),
        OpKind::MemorySegESI => todo!(),
        OpKind::MemorySegRSI => todo!(),
        OpKind::MemorySegDI => todo!(),
        OpKind::MemorySegEDI => todo!(),
        OpKind::MemorySegRDI => todo!(),
        OpKind::MemoryESDI => todo!(),
        OpKind::MemoryESEDI => todo!(),
        OpKind::MemoryESRDI => todo!(),
        OpKind::Memory => {
            code.emit_constant(instruction.memory_size() as u32);
            code.emit_instruction(Instruction::U8);
            emit_memory_offset(instruction, code);
            code.emit_instruction(Instruction::Load)
        }
    }
}

fn emit_operand_write(
    instruction: iced_x86::Instruction,
    operand_number: u32,
    code: &mut FunctionWriter,
) {
    match instruction.op_kind(operand_number) {
        OpKind::Register => emit_register_write(instruction.op_register(operand_number), code),
        OpKind::NearBranch16
        | OpKind::NearBranch32
        | OpKind::NearBranch64
        | OpKind::FarBranch16
        | OpKind::FarBranch32 => panic!("Cannot write to branch"),
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => panic!("Cannot write to immediate"),
        OpKind::MemorySegSI => todo!(),
        OpKind::MemorySegESI => todo!(),
        OpKind::MemorySegRSI => todo!(),
        OpKind::MemorySegDI => todo!(),
        OpKind::MemorySegEDI => todo!(),
        OpKind::MemorySegRDI => todo!(),
        OpKind::MemoryESDI => todo!(),
        OpKind::MemoryESEDI => todo!(),
        OpKind::MemoryESRDI => todo!(),
        OpKind::Memory => {
            emit_memory_offset(instruction, code);
            code.emit_instruction(Instruction::Store)
        }
    }
}

fn emit_binary_operation(
    operation: Instruction,
    instruction: iced_x86::Instruction,
    writer: &mut FunctionWriter,
) {
    emit_operand_read(instruction, 0, writer);
    emit_operand_read(instruction, 1, writer);
    writer.emit_instruction(operation);
    emit_operand_write(instruction, 0, writer);
}

fn emit_flag_condition(flags: u32, writer: &mut FunctionWriter) {
    writer.emit_constant(4);
    writer.emit_instruction(Instruction::U8);
    writer.emit_constant(512 * 512); // address of choice
    writer.emit_instruction(Instruction::U64);
    writer.emit_instruction(Instruction::Load);
    writer.emit_constant(flags);
    writer.emit_instruction(Instruction::Or);
    writer.emit_constant(flags);
    writer.emit_instruction(Instruction::Eq);
}

pub fn set_decoder_position(decoder: &mut Decoder, position: u64) -> Result<(), X86LiftError> {
    let Ok(_) = decoder.set_position(position as usize) else {
        return Err(X86LiftError::DecodeOutOfBounds(position));
    };

    decoder.set_ip(position);

    Ok(())
}

#[derive(Debug)]
pub enum X86LiftError {
    DecodeOutOfBounds(u64),
}

fn resolve_jump_target(
    instruction: iced_x86::Instruction,
    length: u64,
) -> Option<(u64, bool, bool)> {
    if instruction.is_call_near_indirect() {
        // TODO: attempt to resolve
        Some((0, true, false))
    } else if instruction.is_jmp_near_indirect() {
        // TODO: attempt to resolve
        Some((0, false, false))
    } else if (instruction.is_jcc_short_or_near() || instruction.is_call_near())
        && instruction.near_branch_target() < length
    {
        Some((instruction.near_branch_target(), true, true))
    } else if (instruction.is_jcc_short_or_near() || instruction.is_call_near())
        && instruction.near_branch_target() >= length
    {
        Some((0, true, false))
    } else if instruction.is_jmp_short_or_near() && instruction.near_branch_target() < length {
        Some((instruction.near_branch_target(), false, true))
    } else if instruction.is_jmp_short_or_near() && instruction.near_branch_target() >= length {
        Some((0, false, false))
    } else if instruction.mnemonic() == Mnemonic::Ret || instruction.mnemonic() == Mnemonic::Int3 {
        Some((0, false, false))
    } else {
        None
    }
}

pub fn lift_control_flow(
    code: &[u8],
    position: u64,
) -> Result<Vec<Vec<iced_x86::Instruction>>, X86LiftError> {
    let mut queue = VecDeque::new();
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);

    queue.push_back(position);

    set_decoder_position(&mut decoder, position)?;

    let mut blocks = HashMap::new();
    let mut block_start = position;
    let mut block = vec![];
    while !queue.is_empty() {
        if blocks.contains_key(&block_start) {
            block_start = queue.pop_front().unwrap();
            set_decoder_position(&mut decoder, block_start)?;

            continue;
        }

        let instruction = decoder.decode();
        let jump_target = resolve_jump_target(instruction, code.len() as u64);

        block.push(instruction);

        if let Some((target, should_return, should_use_target)) = jump_target {
            if should_return {
                queue.push_back(decoder.ip());
            }

            if should_use_target {
                queue.push_back(target);
            }

            blocks.insert(
                block_start,
                std::mem::take(&mut block),
            );
        }
    }

    Ok(blocks)
}

pub fn lift_block(block: &[iced_x86::Instruction]) -> Result<Vec<u8>, X86LiftError> {
    let mut writer = FunctionWriter::default();

    for x in block {
        match x.mnemonic() {
            Mnemonic::Mov => {
                emit_operand_read(*x, 1, &mut writer);
                emit_operand_write(*x, 0, &mut writer);
            }
            Mnemonic::Sub => emit_binary_operation(Instruction::Sub, *x, &mut writer),
            Mnemonic::Add => emit_binary_operation(Instruction::Add, *x, &mut writer),
            Mnemonic::Xor => emit_binary_operation(Instruction::Xor, *x, &mut writer),
            Mnemonic::And => emit_binary_operation(Instruction::And, *x, &mut writer),
            Mnemonic::Or => emit_binary_operation(Instruction::Or, *x, &mut writer),
            Mnemonic::Shr => emit_binary_operation(Instruction::LShift, *x, &mut writer),
            Mnemonic::Shl => emit_binary_operation(Instruction::RShift, *x, &mut writer),
            Mnemonic::Ret => {
                //TODO: read stack address
            }
            _ => {}
        }
    }

    Ok(writer.finish())
}
