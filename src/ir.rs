use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone)]
pub enum Instruction {
    String,
    Unsigned,
    Signed,
    Float,
    Double,

    Register, // name, space, offset, size
    Copy,     // offset

    Add,  // left right
    Sub,  // left right
    Mul,  // left right
    Div,  // left right
    Mod,  // left right
    Neg,  // operand
    And,  // left right
    Or,   // left right
    Xor,  // left right
    Not,  // operand
    FAdd, // left right
    FSub, // left right
    FMul, // left right
    FDiv, // left right
    FMod, // left right
    FNeg, // operand
    Eq,   // left right
    Neq,  // left right
    Lt,   // left right
    Lte,  // left right
    Gt,   // left right
    Gte,  // left right
    Flt,  // left right
    Flte, // left right
    Fgt,  // left right
    Fgte, // left right

    ArgumentsCreate,
    ArgumentsAppend,

    Assign,       // left, right
    FunctionCall, // function, arguments

    BodyCreate,
    BodyAppend,

    FunctionCreate, // name, body
    IfCreate,       // condition, body
}

impl Instruction {
    pub fn argument_count(self) -> usize {
        match self {
            Instruction::String => 0,
            Instruction::Unsigned => 0,
            Instruction::Signed => 0,
            Instruction::Float => 0,
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
            Instruction::FAdd => 2,
            Instruction::FSub => 2,
            Instruction::FMul => 2,
            Instruction::FDiv => 2,
            Instruction::FMod => 2,
            Instruction::FNeg => 1,
            Instruction::FunctionCreate => 2,
            Instruction::FunctionCall => 1,
            Instruction::Eq => 2,
            Instruction::Neq => 2,
            Instruction::Lt => 2,
            Instruction::Lte => 2,
            Instruction::Gt => 2,
            Instruction::Gte => 2,
            Instruction::Flt => 2,
            Instruction::Flte => 2,
            Instruction::Fgt => 2,
            Instruction::Fgte => 2,
            Instruction::IfCreate => 2,
            Instruction::Register => 4,
            Instruction::Copy => 1,
            Instruction::Assign => 2,
            Instruction::Double => 0,
            Instruction::BodyCreate => 0,
            Instruction::BodyAppend => 2,
            Instruction::ArgumentsCreate => 0,
            Instruction::ArgumentsAppend => 2,
        }
    }
}

#[derive(Debug)]
pub enum PrintInstructionError {
    MalformedProgram(usize),
    IncorrectlySizedConstant,
}

fn pop_safe(
    instruction_number: usize,
    stack: &mut Vec<String>,
) -> Result<String, PrintInstructionError> {
    let Some(string) = stack.pop() else {
        return Err(PrintInstructionError::MalformedProgram(instruction_number));
    };

    Ok(string)
}

fn print_float(constant: &[u8]) -> Result<String, PrintInstructionError> {
    if constant.len() > 5 {
        return Err(PrintInstructionError::IncorrectlySizedConstant);
    }

    let mut raw_number: u32 = 0;
    for v in constant {
        raw_number += *v as u32 & 0x7F;
    }

    Ok(f32::from_ne_bytes(raw_number.to_ne_bytes()).to_string())
}

fn print_double(constant: &[u8]) -> Result<String, PrintInstructionError> {
    if constant.len() > 9 {
        return Err(PrintInstructionError::IncorrectlySizedConstant);
    }

    let mut raw_number: u64 = 0;
    for v in constant {
        raw_number += *v as u64 & 0x7F;
    }

    Ok(f64::from_ne_bytes(raw_number.to_ne_bytes()).to_string())
}

fn print_unsigned(constant: &[u8]) -> Result<String, PrintInstructionError> {
    if constant.len() > 18 {
        return Err(PrintInstructionError::IncorrectlySizedConstant);
    }

    let mut raw_number: u128 = 0;

    for v in constant {
        raw_number += *v as u128 & 0x7F;
    }

    Ok(raw_number.to_string())
}

fn print_signed(constant: &[u8]) -> Result<String, PrintInstructionError> {
    if constant.len() > 18 {
        return Err(PrintInstructionError::IncorrectlySizedConstant);
    }

    let mut raw_number: i128 = 0;
    for v in constant {
        raw_number += *v as i128;
    }

    Ok(raw_number.to_string())
}

fn print_string(constant: &[u8]) -> String {
    let mut string = String::new();

    for v in constant {
        string.push((*v & 0x7F) as char)
    }

    string
}

pub fn print_instructions(code: &[u8]) -> Result<String, PrintInstructionError> {
    let mut stack = Vec::<String>::new();
    let mut constant = Vec::new();

    let i = 0;
    while i < code.len() {
        let byte = code[i];

        if byte >= 128 {
            constant.push(0x7F & byte);
            continue;
        }

        let Ok(inst) = byte.try_into() else {
            return Err(PrintInstructionError::MalformedProgram(i));
        };

        let new_string = match inst {
            Instruction::Unsigned => print_unsigned(&constant)?,
            Instruction::Signed => print_signed(&constant)?,
            Instruction::Float => print_float(&constant)?,
            Instruction::Double => print_double(&constant)?,
            Instruction::String => print_string(&constant),
            Instruction::Assign => format!(
                "{} = {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Add => format!(
                "{} + {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Sub => format!(
                "{} - {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Mul => format!(
                "{} * {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Div => format!(
                "{} / {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Mod => format!(
                "{} % {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Neg => format!("-{}", pop_safe(i, &mut stack)?),
            Instruction::And => format!(
                "{} & {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Or => format!(
                "{} | {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Xor => format!(
                "{} ^ {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Not => format!("~{}", pop_safe(i, &mut stack)?),
            Instruction::BodyCreate => String::new(),
            Instruction::BodyAppend => {
                format!("{}\n{}", pop_safe(i, &mut stack)?, pop_safe(i, &mut stack)?)
            }
            Instruction::FAdd => format!(
                "{} f+ {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FSub => format!(
                "{} f- {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FMul => format!(
                "{} f* {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FDiv => format!(
                "{} f/ {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FMod => format!(
                "{} f% {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FNeg => format!("f-{}", pop_safe(i, &mut stack)?),
            Instruction::Eq => format!(
                "{} f% {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Neq => format!(
                "{} f% {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Lt => format!(
                "{} > {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Lte => format!(
                "{} >= {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Gt => format!(
                "{} < {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Gte => format!(
                "{} <= {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Flt => format!(
                "{} f< {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Flte => format!(
                "{} f<= {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Fgt => format!(
                "{} f> {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::Fgte => format!(
                "{} f>= {}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?
            ),
            Instruction::FunctionCreate => format!(
                "{}: {{\n{}}}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?.replace("\n", "\n\t")
            ),
            Instruction::FunctionCall => format!("{}()", pop_safe(i, &mut stack)?),
            Instruction::IfCreate => format!(
                "if ({}) {{\n{}}}",
                pop_safe(i, &mut stack)?,
                pop_safe(i, &mut stack)?.replace("\n", "\n\t")
            ),
            Instruction::Register => todo!(),
            Instruction::Copy => todo!(),
            Instruction::ArgumentsCreate => todo!(),
            Instruction::ArgumentsAppend => todo!(),
        };

        stack.push(new_string)
    }

    let Some(final_output) = stack.pop() else {
        return Err(PrintInstructionError::MalformedProgram(code.len() - 1));
    };

    Ok(final_output)
}

pub fn emit_signed(code: &mut Vec<u8>, number: i128) {
    let mut number_unsigned: u128 = unsafe { std::mem::transmute(number) };

    let mut number_bytes: Vec<u8> = vec![(number_unsigned & 0x7F) as u8];
    number_unsigned >>= 7;

    while number_unsigned != 0 {
        number_bytes.push((number_unsigned & 0x7F) as u8);
        number_unsigned >>= 7;
    }

    if *number_bytes.last().unwrap() & 0x80 != 0 {
        let mut carry = 1;
        for v in number_bytes.iter_mut() {
            *v = !*v;
            *v += carry;

            carry = (*v == 0) as u8;
        }
    }

    code.append(&mut number_bytes);
}
