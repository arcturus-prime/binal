use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(TryFromPrimitive)]
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

    ConstSeparator = 127,
}

enum PrintInstructionError {
    TooLongConstant,
    MalformedProgram,
}

fn pop_safe(stack: &mut Vec<String>) -> Result<String, PrintInstructionError> {
    let Some(string) = stack.pop() else {
        return Err(PrintInstructionError::MalformedProgram);
    };

    return Ok(string);
}

pub fn print_instructions(code: &[u8]) -> Result<(), PrintInstructionError> {
    let mut stack = Vec::<String>::new();
    let mut constant = Vec::new();

    for x in code {
        let Ok(inst) = (*x).try_into() else {
            constant.push(*x & 0b0111_1111);
            continue;
        };

        if constant.len() > 0 {
            let mut literal: u128 = 0;
            for (byte, i) in constant.iter().zip(0..) {
                literal += (*byte as u128) << i * 7;
            }

            constant.clear();
            stack.push(literal.to_string());
        }

        let new_string = match inst {
            Instruction::Register => format!("reg({})", pop_safe(&mut stack)?),
            Instruction::Assign => format!("{} = {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Deref => format!("[{}]", pop_safe(&mut stack)?),
            Instruction::Add => format!("{} + {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Sub => format!("{} - {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Mul => format!("{} * {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Div => format!("{} / {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Mod => format!("{} % {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Neg => format!("-{}", pop_safe(&mut stack)?),
            Instruction::And => format!("{} & {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Or => format!("{} | {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Xor => format!("{} ^ {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::Not => format!("~{}", pop_safe(&mut stack)?),
            Instruction::FAdd => format!("{} f+ {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::FSub => format!("{} f- {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::FMul => format!("{} f* {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::FDiv => format!("{} f/ {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::FMod => format!("{} f% {}", pop_safe(&mut stack)?, pop_safe(&mut stack)?),
            Instruction::FNeg => format!("f-{}", pop_safe(&mut stack)?),
            Instruction::ConstSeparator => continue,
        };

        stack.push(new_string)
    }

    Ok(())
}
