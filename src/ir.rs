use num_enum::TryFromPrimitive;
use num_traits::PrimInt;

#[repr(u8)]
#[derive(TryFromPrimitive, Copy, Clone)]
pub enum Instruction {
    Register = 0, // space, address, size
    Constant,
    Assign,         // left, right
    Add,            // left right
    Sub,            // left right
    Mul,            // left right
    Div,            // left right
    Mod,            // left right
    Neg,            // operand
    And,            // left right
    Or,             // left right
    Xor,            // left right
    Not,            // operand
    FAdd,           // left right
    FSub,           // left right
    FMul,           // left right
    FDiv,           // left right
    FMod,           // left right
    FNeg,           // operand
    Eq,             // left right
    Neq,            // left right
    Lt,             // left right
    Lte,            // left right
    Gt,             // left right
    Gte,            // left right
    Flt,            // left right
    Flte,           // left right
    Fgt,            // left right
    Fgte,           // left right
    BodyCreate,     //
    BodyAppend,     // body, statement
    FunctionCreate, // body, id
    FunctionCall,   // id
    IfCreate,       // body, condition
}

impl Instruction {
    pub fn argument_count(self) -> usize {
        match self {
            Instruction::Register => 3,
            Instruction::Assign => 2,
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
            Instruction::BodyCreate => 0,
            Instruction::BodyAppend => 2,
            Instruction::FunctionCreate => 2,
            Instruction::FunctionCall => 1,
            Instruction::Constant => 0,
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
        }
    }
}

#[derive(Debug)]
pub enum PrintInstructionError {
    MalformedProgram(usize),
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

pub fn print_instructions(code: &[u8]) -> Result<String, PrintInstructionError> {
    let mut stack = Vec::<String>::new();

    let i = 0;
    while i < code.len() {
        let byte = code[i];

        let Ok(inst) = byte.try_into() else {
            return Err(PrintInstructionError::MalformedProgram(i));
        };

        let new_string = match inst {
            Instruction::Register => format!(),
            Instruction::Constant => format!(),
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
        };

        stack.push(new_string)
    }

    let Some(final_output) = stack.pop() else {
        return Err(PrintInstructionError::MalformedProgram(code.len() - 1));
    };

    Ok(final_output)
}

pub fn emit_constant<T: PrimInt>(value: T, code: &mut Vec<u8>) {
    let mut value = value.to_u128().unwrap_or(unsafe {
        std::mem::transmute::<i128, u128>(value.to_i128().unwrap_unchecked())
    });

    code.push(Instruction::BeginConstant as u8);
    loop {
        let piece = value & 0xFF;
        value >>= 8;

        code.push(piece as u8);

        if value == 0 {
            break;
        }
    }
    code.push(Instruction::EndConstant as u8);
}
