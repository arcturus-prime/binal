#[repr(u8)]
pub enum Instruction {
    Register = 0, // number
    Assign,       // left, right
    Deref,        // size, address

    Add, // left right
    Sub, // left right
    Mul, // left right
    Div, // left right
    Mod, // left right
    Neg, // operand

    And, // left right
    Or,  // left right
    Xor, // left right
    Not, // operand

    FAdd, // left right
    FSub, // left right
    FMul, // left right
    FDiv, // left right
    FMod, // left right
    FNeg, // operand

    ConstSeparator,
    Const = 128,
}

pub fn print_instructions(code: &[u8]) {
    let mut stack = Vec::new();

    let in_constant = false;
    for x in code {
        let Ok(inst) = (*x).try_into() else {
            continue;
        };
        match inst {
            Instruction::Register => todo!(),
            Instruction::Assign => todo!(),
            Instruction::Deref => todo!(),
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
            Instruction::FAdd => todo!(),
            Instruction::FSub => todo!(),
            Instruction::FMul => todo!(),
            Instruction::FDiv => todo!(),
            Instruction::FMod => todo!(),
            Instruction::FNeg => todo!(),
            Instruction::ConstSeparator => todo!(),
            Instruction::Const => todo!(),
        }
    }
}
