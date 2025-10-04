use crate::ir::{Instruction, LifterErrors, ProgramWriter};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register, RflagsBits};

fn emit_memory_operand(inst: iced_x86::Instruction, code: &mut ProgramWriter) {
    let mut to_add = 0;

    if inst.memory_base() != Register::None {
        emit_register_operand(inst.memory_base(), code);
        to_add += 1;
    }

    if inst.memory_index() != Register::None {
        emit_register_operand(inst.memory_index(), code);

        if inst.memory_index_scale() != 1 {
            code.emit_constant(inst.memory_index_scale());
            code.emit_instruction(Instruction::Mul);
        }

        to_add += 1;
    }

    if inst.memory_displacement64() != 0 {
        code.emit_constant(inst.memory_displacement64() * 8);
        to_add += 1;
    }

    for _ in 1..to_add {
        code.emit_instruction(Instruction::Add);
    }
}

fn emit_register_operand(register: Register, code: &mut ProgramWriter) {
    code.emit_constant(register.full_register() as usize * 8);
    code.emit_constant(register.size());
    code.emit_instruction(Instruction::Register)
}

fn lift_operand(instruction: iced_x86::Instruction, operand_number: u32, code: &mut ProgramWriter) {
    match instruction.op_kind(operand_number) {
        OpKind::Register => emit_register_operand(instruction.op_register(operand_number), code),
        OpKind::NearBranch16
        | OpKind::NearBranch32
        | OpKind::NearBranch64
        | OpKind::FarBranch16
        | OpKind::FarBranch32 => panic!("Cannot lift branch operand"),
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
        OpKind::Memory => emit_memory_operand(instruction, code),
    }
}

fn lift_conditional_jump(
    decoder: &mut Decoder,
    inst: iced_x86::Instruction,
    return_to_address: &mut Vec<u64>,
    writer: &mut ProgramWriter,
    flags: u32,
) {
    return_to_address.pop().unwrap();
    return_to_address.push(inst.near_branch64());
    return_to_address.push(decoder.ip());

    writer.emit_constant(flags);
    writer.emit_constant(0);
    writer.emit_constant(32);
    writer.emit_instruction(Instruction::Register);
    writer.emit_instruction(Instruction::Or);
    writer.emit_constant(flags);
    writer.emit_instruction(Instruction::Eq);

    writer.emit_instruction(Instruction::IfCreate);
    writer.emit_constant(inst.near_branch64());
    writer.emit_instruction(Instruction::Goto);
    writer.emit_instruction(Instruction::ElseCreate);
    writer.emit_constant(decoder.ip());
    writer.emit_instruction(Instruction::Goto);
    writer.emit_instruction(Instruction::End);
    writer.emit_instruction(Instruction::End);

    writer.emit_constant(decoder.ip());
    writer.emit_instruction(Instruction::BlockCreate);
}

fn lift_always_jump(
    decoder: &mut Decoder,
    inst: iced_x86::Instruction,
    return_to_address: &mut Vec<u64>,
    writer: &mut ProgramWriter,
) {
    return_to_address.pop().unwrap();
    return_to_address.push(decoder.ip());

    let mut destination = None;
    if inst.op0_kind() == OpKind::NearBranch64 {
        destination = Some(inst.near_branch64());
    } else {
        //TODO: solve for destination
    }

    if let Some(destination) = destination {
        writer.emit_constant(destination);
        writer.emit_instruction(Instruction::Goto);

        return_to_address.push(destination);
    } else {
        writer.emit_constant(LifterErrors::CouldNotResolveJump as u8);
        writer.emit_instruction(Instruction::LifterError);
    }

    writer.emit_instruction(Instruction::End);
    writer.emit_constant(decoder.ip());
    writer.emit_instruction(Instruction::BlockCreate);
}

fn lift_simple_binary_op(
    iced_instruction: iced_x86::Instruction,
    writer: &mut ProgramWriter,
    instruction: Instruction,
) {
    lift_operand(iced_instruction, 0, writer);
    lift_operand(iced_instruction, 1, writer);
    writer.emit_instruction(instruction);
    lift_operand(iced_instruction, 0, writer);
    writer.emit_instruction(Instruction::Assign);
}

pub fn lift_program(code: &[u8], ip: u64) -> Vec<u8> {
    let mut decoder = Decoder::new(64, code, DecoderOptions::NONE);

    decoder.set_ip(ip);

    let mut return_to_address = vec![ip];
    let mut writer = ProgramWriter::default();

    while decoder.can_decode() {
        let inst = decoder.decode();

        match inst.mnemonic() {
            Mnemonic::Mov => {
                lift_operand(inst, 0, &mut writer);
                lift_operand(inst, 1, &mut writer);
                writer.emit_instruction(Instruction::Assign);
            }
            Mnemonic::Sub => lift_simple_binary_op(inst, &mut writer, Instruction::Sub),
            Mnemonic::Add => lift_simple_binary_op(inst, &mut writer, Instruction::Add),
            Mnemonic::Call => {
                lift_always_jump(&mut decoder, inst, &mut return_to_address, &mut writer)
            }
            Mnemonic::Jmp => {
                lift_always_jump(&mut decoder, inst, &mut return_to_address, &mut writer)
            }
            Mnemonic::Je => lift_conditional_jump(
                &mut decoder,
                inst,
                &mut return_to_address,
                &mut writer,
                RflagsBits::ZF,
            ),
            Mnemonic::Xor => lift_simple_binary_op(inst, &mut writer, Instruction::Xor),
            Mnemonic::And => lift_simple_binary_op(inst, &mut writer, Instruction::And),
            Mnemonic::Or => lift_simple_binary_op(inst, &mut writer, Instruction::Or),
            Mnemonic::Shr => lift_simple_binary_op(inst, &mut writer, Instruction::RShift),
            Mnemonic::Shl => lift_simple_binary_op(inst, &mut writer, Instruction::LShift),
            Mnemonic::Ret => {
                return_to_address.pop().unwrap();
                let ip = return_to_address.last().unwrap();

                decoder.set_ip(*ip);
                writer.emit_instruction(Instruction::End);

                // TODO: handle return
            }
            _ => {}
        }
    }

    writer.finish()
}
