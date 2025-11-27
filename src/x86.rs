use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register, RflagsBits};

use crate::{ir::InstructionStream, lifter::SemanticGenerator};

pub struct X86Lifter<'a> {
    code: &'a [u8],
    sections: Vec<(u64, usize)>,
}

impl<'a> SemanticGenerator for X86Lifter<'a> {
    fn disassemble(
        &self,
        address: u64,
        semantics: &mut InstructionStream,
    ) -> Result<(), crate::lifter::GeneratorError> {
        todo!()
    }
}

impl<'a> X86Lifter<'a> {
    pub fn from_pe(binary: &'a [u8]) -> Self {
        let decoder = Decoder::new(64, code, DecoderOptions::NONE);
        X86Lifter { code }
    }
}
