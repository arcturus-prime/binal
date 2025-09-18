use crate::ir::{emit_constant, Instruction};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register, RflagsBits};

pub fn emit_memory_operand(inst: iced_x86::Instruction, code: &mut Vec<u8>) {
    let mut to_add = 0;

    emit_constant(0, code);
    emit_constant(inst.memory_size() as u64 * 8, code);

    if inst.memory_base() != Register::None {
        emit_register_operand(inst.memory_base(), code);
        to_add += 1;
    }

    if inst.memory_index() != Register::None {
        emit_register_operand(inst.memory_index(), code);
        if inst.memory_index_scale() != 1 {
            emit_constant(inst.memory_index_scale(), code);
            code.push(Instruction::Mul as u8);
        }
        to_add += 1;
    }

    if inst.memory_displacement64() != 0 {
        emit_constant(inst.memory_displacement64() * 8, code);
        to_add += 1;
    }

    for _ in 1..to_add {
        code.push(Instruction::Add as u8);
    }

    code.push(Instruction::Register as u8)
}

pub fn emit_register_operand(operand: Register, code: &mut Vec<u8>) {
    emit_constant(1, code);
    emit_constant(operand.size() as i128 * 8, code);
    emit_constant(operand as u8, code);
    code.push(Instruction::Register as u8);
}

pub fn emit_set_eflags(flags: u32, code: &mut Vec<u8>) {
    emit_constant(2, code);
    emit_constant(32, code);
    emit_constant(0, code);
    code.push(Instruction::Register as u8);

    emit_constant(2, code);
    emit_constant(32, code);
    emit_constant(0, code);
    code.push(Instruction::Register as u8);

    emit_constant(flags, code);
    code.push(Instruction::Or as u8);
    code.push(Instruction::Assign as u8);
    code.push(Instruction::BodyAppend as u8);
}

pub fn emit_clear_eflags(flags: u32, code: &mut Vec<u8>) {
    emit_constant(2, code);
    emit_constant(32, code);
    emit_constant(0, code);
    code.push(Instruction::Register as u8);

    emit_constant(2, code);
    emit_constant(32, code);
    emit_constant(0, code);
    code.push(Instruction::Register as u8);

    emit_constant(!flags, code);
    code.push(Instruction::And as u8);
    code.push(Instruction::Assign as u8);
    code.push(Instruction::BodyAppend as u8);
}

pub fn emit_check_flags(flags: u32, code: &mut Vec<u8>) {
    emit_constant(2, code);
    emit_constant(32, code);
    emit_constant(0, code);
    code.push(Instruction::Register as u8);
    emit_constant(flags, code);

    code.push(Instruction::And as u8);

    emit_constant(flags, code);
    code.push(Instruction::Eq as u8);
}

pub fn emit_operand(inst: iced_x86::Instruction, operand_number: u32, code: &mut Vec<u8>) {
    let kind = match operand_number {
        0 => inst.op0_kind(),
        1 => inst.op1_kind(),
        2 => inst.op2_kind(),
        3 => inst.op3_kind(),
        4 => inst.op4_kind(),
        _ => panic!("Invalid operand number"),
    };

    match kind {
        iced_x86::OpKind::Register => emit_register_operand(inst.op_register(operand_number), code),
        iced_x86::OpKind::NearBranch16
        | iced_x86::OpKind::NearBranch32
        | iced_x86::OpKind::NearBranch64 => emit_constant(inst.near_branch_target() as i128, code),
        iced_x86::OpKind::FarBranch16 => emit_constant(inst.far_branch16() as i128, code),
        // TODO: make this actually function
        iced_x86::OpKind::FarBranch32 => emit_constant(inst.far_branch32() as i128, code),
        iced_x86::OpKind::Immediate8
        | iced_x86::OpKind::Immediate8_2nd
        | iced_x86::OpKind::Immediate16
        | iced_x86::OpKind::Immediate32
        | iced_x86::OpKind::Immediate64
        | iced_x86::OpKind::Immediate8to16
        | iced_x86::OpKind::Immediate8to32
        | iced_x86::OpKind::Immediate8to64
        | iced_x86::OpKind::Immediate32to64 => {
            emit_constant(inst.immediate(operand_number) as i128, code)
        }
        iced_x86::OpKind::MemorySegSI => todo!(),
        iced_x86::OpKind::MemorySegESI => todo!(),
        iced_x86::OpKind::MemorySegRSI => todo!(),
        iced_x86::OpKind::MemorySegDI => todo!(),
        iced_x86::OpKind::MemorySegEDI => todo!(),
        iced_x86::OpKind::MemorySegRDI => todo!(),
        iced_x86::OpKind::MemoryESDI => todo!(),
        iced_x86::OpKind::MemoryESEDI => todo!(),
        iced_x86::OpKind::MemoryESRDI => todo!(),
        iced_x86::OpKind::Memory => emit_memory_operand(inst, code),
    }
}

pub fn lift_block(code: &[u8], ip: u64) -> Vec<u8> {
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);
    decoder.set_ip(ip);

    let mut out_code = vec![Instruction::BodyCreate as u8];

    while decoder.can_decode() {
        let inst = decoder.decode();

        match inst.mnemonic() {
            Mnemonic::Mov => {
                emit_operand(inst, 1, &mut out_code);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Assign as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Sub => {
                emit_operand(inst, 1, &mut out_code);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Sub as u8);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Assign as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Add => {
                emit_operand(inst, 1, &mut out_code);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Add as u8);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Assign as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Call => {
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::FunctionCall as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Jmp => {
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::FunctionCall as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Xor => {
                emit_operand(inst, 1, &mut out_code);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Xor as u8);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::Assign as u8);
                out_code.push(Instruction::BodyAppend as u8);

                out_code.push(Instruction::BodyCreate as u8);
                emit_set_eflags(RflagsBits::ZF, &mut out_code);
                emit_operand(inst, 0, &mut out_code);
                emit_constant(0, &mut out_code);
                out_code.push(Instruction::Eq as u8);
                out_code.push(Instruction::IfCreate as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            Mnemonic::Je => {
                out_code.push(Instruction::BodyCreate as u8);
                emit_operand(inst, 0, &mut out_code);
                out_code.push(Instruction::FunctionCall as u8);
                out_code.push(Instruction::BodyAppend as u8);
                emit_check_flags(RflagsBits::ZF, &mut out_code);
                out_code.push(Instruction::IfCreate as u8);
                out_code.push(Instruction::BodyAppend as u8);
            }
            _ => {}
        }
    }

    out_code
}
