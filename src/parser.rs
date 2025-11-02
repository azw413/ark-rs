//! Parsing utilities for Ark textual disassembly back into bytecode structures.

use crate::constant_pool::{ConstantPool, StringRecord};
use crate::functions::{BasicBlock, Function, FunctionParameter, InstructionBlock};
use crate::instructions::{
    IdentifierOperand, ImmediateOperand, Instruction, InstructionIndex, Opcode, Operand, Register,
    RegisterOperand,
};
use crate::instructions_generated::MNEMONIC_TO_OPCODE;
use crate::types::{FieldType, FunctionSignature, PrimitiveType, StringId, TypeDescriptor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        ParseError {
            line,
            message: message.into(),
        }
    }
}

/// Parse a textual Ark function definition into the in-memory representation.
pub fn parse_function(input: &str, pool: &mut ConstantPool) -> Result<Function, ParseError> {
    Parser::new(input, pool).parse_function()
}

struct Parser<'a> {
    pool: &'a mut ConstantPool,
    lines: Vec<&'a str>,
    index: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str, pool: &'a mut ConstantPool) -> Self {
        Parser {
            pool,
            lines: input.lines().collect(),
            index: 0,
        }
    }

    fn parse_function(&mut self) -> Result<Function, ParseError> {
        let header_line = self.next_non_empty_line()?;
        let header = header_line.trim_end_matches('{').trim();
        if !header.starts_with(".function ") {
            return Err(ParseError::new(
                self.current_line(),
                "expected .function header",
            ));
        }
        let header_body = header[10..].trim();
        let (ret_ty_str, rest) = split_once(header_body, ' ')
            .ok_or_else(|| ParseError::new(self.current_line(), "missing return type"))?;
        let (name_and_params, _) = split_once(rest, ')')
            .ok_or_else(|| ParseError::new(self.current_line(), "unterminated parameter list"))?;
        let (name_part, params_part) = split_once(name_and_params, '(')
            .ok_or_else(|| ParseError::new(self.current_line(), "missing parameter list"))?;

        let function_name = name_part.trim();
        let return_type = self.parse_type(ret_ty_str)?;
        let name_id = self.intern_string(function_name);

        let parameters = self.parse_parameters(params_part.trim())?;
        let signature = FunctionSignature {
            this_type: None,
            parameters: parameters.iter().map(|p| p.type_info.clone()).collect(),
            return_type: return_type.clone(),
            flags: Default::default(),
        };

        let mut function = Function::new(crate::types::FunctionId::new(0), signature);
        function.name = Some(name_id);
        function.parameters = parameters;
        function.signature.return_type = return_type;

        let mut block = BasicBlock::new(0);
        let mut instruction_index = 0;
        let mut highest_register = 0u16;

        while let Some(line) = self.peek_line() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                self.index += 1;
                continue;
            }
            if trimmed == "}" {
                self.index += 1;
                break;
            }

            let current = self.current_line();
            let (mnemonic, operands_str) = match split_once(trimmed, ' ') {
                Some((m, rest)) => (m, rest.trim()),
                None => (trimmed, ""),
            };
            let opcode = parse_opcode(mnemonic)
                .ok_or_else(|| ParseError::new(current, format!("unknown opcode {mnemonic}")))?;

            let mut operands = Vec::new();
            if !operands_str.is_empty() {
                for operand_piece in operands_str.split(',') {
                    let operand_piece = operand_piece.trim();
                    if operand_piece.is_empty() {
                        continue;
                    }
                    let operand = self.parse_operand(operand_piece, &mut highest_register)?;
                    operands.push(operand);
                }
            }

            let mut instruction =
                Instruction::new(InstructionIndex::new(instruction_index), opcode);
            instruction.operands = operands;
            instruction_index += 1;
            block.instructions.push(instruction);
            self.index += 1;
        }

        function.instruction_block = InstructionBlock {
            blocks: vec![block],
        };
        function.register_count = highest_register.saturating_add(1);
        Ok(function)
    }

    fn parse_parameters(&mut self, params: &str) -> Result<Vec<FunctionParameter>, ParseError> {
        if params.is_empty() {
            return Ok(Vec::new());
        }
        params
            .split(',')
            .map(|segment| {
                let segment = segment.trim();
                let (ty_str, name_str) = split_once(segment, ' ')
                    .ok_or_else(|| ParseError::new(self.current_line(), "malformed parameter"))?;
                let ty = self.parse_type(ty_str)?;
                let name_id = self.intern_string(name_str.trim());
                Ok(FunctionParameter {
                    name: Some(name_id),
                    type_info: ty,
                    default_literal: None,
                    is_optional: false,
                })
            })
            .collect()
    }

    fn parse_type(&mut self, token: &str) -> Result<FieldType, ParseError> {
        let descriptor = match token {
            "void" => TypeDescriptor::Primitive(PrimitiveType::Void),
            "boolean" => TypeDescriptor::Primitive(PrimitiveType::Boolean),
            "i8" => TypeDescriptor::Primitive(PrimitiveType::I8),
            "i16" => TypeDescriptor::Primitive(PrimitiveType::I16),
            "i32" => TypeDescriptor::Primitive(PrimitiveType::I32),
            "i64" => TypeDescriptor::Primitive(PrimitiveType::I64),
            "u8" => TypeDescriptor::Primitive(PrimitiveType::U8),
            "u16" => TypeDescriptor::Primitive(PrimitiveType::U16),
            "u32" => TypeDescriptor::Primitive(PrimitiveType::U32),
            "u64" => TypeDescriptor::Primitive(PrimitiveType::U64),
            "f32" => TypeDescriptor::Primitive(PrimitiveType::F32),
            "f64" => TypeDescriptor::Primitive(PrimitiveType::F64),
            "string" => TypeDescriptor::Primitive(PrimitiveType::String),
            "any" => TypeDescriptor::Primitive(PrimitiveType::Any),
            "undefined" => TypeDescriptor::Primitive(PrimitiveType::Undefined),
            "object" => TypeDescriptor::Primitive(PrimitiveType::Object),
            other => {
                return Err(ParseError::new(
                    self.current_line(),
                    format!("unknown type {other}"),
                ));
            }
        };
        Ok(FieldType::new(descriptor))
    }

    fn parse_operand(
        &mut self,
        text: &str,
        highest_register: &mut u16,
    ) -> Result<Operand, ParseError> {
        if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
            let inner = &text[1..text.len() - 1];
            let value = unescape_string(inner)?;
            let id = self.intern_string(&value);
            return Ok(Operand::String(id));
        }
        if text.starts_with("@0x") {
            let value = parse_hex(text.trim_start_matches('@'))?;
            return Ok(Operand::Identifier(IdentifierOperand::Id16(value as u16)));
        }
        if let Some(rest) = text.strip_prefix("literal#") {
            let value = rest.parse::<u32>().map_err(|_| {
                ParseError::new(self.current_line(), format!("invalid literal index {text}"))
            })?;
            return Ok(Operand::LiteralIndex(value));
        }
        if let Some(rest) = text.strip_prefix("func#") {
            let value = rest.parse::<u32>().map_err(|_| {
                ParseError::new(self.current_line(), format!("invalid function id {text}"))
            })?;
            return Ok(Operand::Function(crate::types::FunctionId(value)));
        }
        if let Some(rest) = text.strip_prefix("field#") {
            let value = rest.parse::<u32>().map_err(|_| {
                ParseError::new(self.current_line(), format!("invalid field id {text}"))
            })?;
            return Ok(Operand::Field(crate::types::FieldId(value)));
        }
        if let Some(rest) = text.strip_prefix("methodhandle#") {
            let value = rest.parse::<u32>().map_err(|_| {
                ParseError::new(self.current_line(), format!("invalid method handle {text}"))
            })?;
            return Ok(Operand::MethodHandle(value));
        }
        if let Some(rest) = text.strip_prefix("+0x") {
            let value = parse_hex(&format!("0x{rest}"))?;
            return Ok(Operand::Label(value as u32));
        }
        if let Some(rest) = text.strip_prefix('v') {
            if let Ok(index) = rest.parse::<u16>() {
                *highest_register = (*highest_register).max(index);
                return Ok(Operand::Register(RegisterOperand::V8(Register(index))));
            }
        }
        if let Some(rest) = text.strip_prefix('a') {
            if let Ok(index) = rest.parse::<u16>() {
                *highest_register = (*highest_register).max(index);
                return Ok(Operand::Register(RegisterOperand::Argument(Register(
                    index,
                ))));
            }
        }
        if text.starts_with("0x") {
            let value = parse_hex(text)?;
            return Ok(Operand::Immediate(match value {
                v if v <= 0xF => ImmediateOperand::Imm4(v as u8),
                v if v <= 0xFF => ImmediateOperand::Imm8(v as u8),
                v if v <= 0xFFFF => ImmediateOperand::Imm16(v as u16),
                v if v <= 0xFFFF_FFFF => ImmediateOperand::Imm32(v as u32),
                v => ImmediateOperand::Imm64(v),
            }));
        }

        let string_id = self.intern_string(text);
        Ok(Operand::String(string_id))
    }

    fn intern_string(&mut self, value: &str) -> StringId {
        if let Some(existing) = self
            .pool
            .strings
            .iter()
            .find(|record| record.value == value)
            .map(|record| record.id)
        {
            return existing;
        }
        let id = StringId::new(self.pool.strings.len() as u32);
        self.pool.strings.push(StringRecord {
            id,
            value: value.to_owned(),
        });
        id
    }

    fn next_non_empty_line(&mut self) -> Result<&'a str, ParseError> {
        while let Some(line) = self.lines.get(self.index).copied() {
            self.index += 1;
            if !line.trim().is_empty() {
                return Ok(line);
            }
        }
        Err(ParseError::new(
            self.current_line(),
            "unexpected end of input",
        ))
    }

    fn peek_line(&self) -> Option<&'a str> {
        self.lines.get(self.index).copied()
    }

    fn current_line(&self) -> usize {
        self.index.saturating_add(1)
    }
}

fn parse_opcode(mnemonic: &str) -> Option<Opcode> {
    // First check the generated MNEMONIC_TO_OPCODE table
    for (name, opcode_byte) in MNEMONIC_TO_OPCODE {
        if name == &mnemonic {
            return Some(byte_to_opcode(*opcode_byte, mnemonic));
        }
    }

    // Fall back to hardcoded special cases for mnemonics that map to multiple opcode variants
    // (e.g., "mov" can be mov.v4 or mov.v8)
    match mnemonic {
        "mov" => Some(Opcode::MovV8), // Default to v8 variant
        _ => Some(Opcode::Extended(mnemonic.to_owned())),
    }
}

/// Convert an opcode byte to the corresponding Opcode enum variant
fn byte_to_opcode(opcode_byte: u8, mnemonic: &str) -> Opcode {
    match opcode_byte {
        0x00 => Opcode::LdUndefined,
        0x01 => Opcode::LdNull,
        0x02 => Opcode::LdTrue,
        0x03 => Opcode::LdFalse,
        0x04 => Opcode::CreateEmptyObject,
        0x05 => Opcode::CreateEmptyArray,
        0x06 => Opcode::CreateArrayWithBuffer,
        0x07 => Opcode::CreateObjectWithBuffer,
        0x08 => Opcode::NewObjRange,
        0x09 => Opcode::NewLexEnv,
        0x0a => Opcode::Add2,
        0x0b => Opcode::Sub2,
        0x0c => Opcode::Mul2,
        0x0d => Opcode::Div2,
        0x0e => Opcode::Mod2,
        0x0f => Opcode::Eq,
        0x10 => Opcode::NotEq,
        0x11 => Opcode::Less,
        0x12 => Opcode::LessEq,
        0x13 => Opcode::Greater,
        0x14 => Opcode::GreaterEq,
        0x15 => Opcode::Shl2,
        0x16 => Opcode::Shr2,
        0x17 => Opcode::Ashr2,
        0x18 => Opcode::And2,
        0x19 => Opcode::Or2,
        0x1a => Opcode::Xor2,
        0x1b => Opcode::Exp,
        0x1c => Opcode::TypeOf,
        0x1d => Opcode::ToNumber,
        0x1e => Opcode::ToNumeric,
        0x1f => Opcode::Neg,
        0x20 => Opcode::Not,
        0x21 => Opcode::Inc,
        0x22 => Opcode::Dec,
        0x23 => Opcode::IsTrue,
        0x24 => Opcode::IsFalse,
        0x25 => Opcode::IsIn,
        0x26 => Opcode::InstanceOf,
        0x27 => Opcode::StrictNotEq,
        0x28 => Opcode::StrictEq,
        0x29 => Opcode::CallArg0,
        0x2a => Opcode::CallArg1,
        0x2b => Opcode::CallArgs2,
        0x2c => Opcode::CallArgs3,
        0x2d => Opcode::CallThis0,
        0x2e => Opcode::CallThis1,
        0x2f => Opcode::CallThis2,
        0x30 => Opcode::CallThis3,
        0x31 => Opcode::CallThisRange,
        0x32 => Opcode::SuperCallThisRange,
        0x33 => Opcode::DefineFunc,
        0x34 => Opcode::DefineMethod,
        0x35 => Opcode::DefineClassWithBuffer,
        0x36 => Opcode::GetNextPropName,
        0x37 => Opcode::LdObjByValue,
        0x38 => Opcode::StObjByValue,
        0x39 => Opcode::LdSuperByValue,
        0x3a => Opcode::LdObjByIndex,
        0x3b => Opcode::StObjByIndex,
        0x3c => Opcode::LdLexVar,
        0x3d => Opcode::StLexVar,
        0x3e => Opcode::LdaStr,
        0x3f => Opcode::TryLdGlobalByName,
        0x40 => Opcode::TryStGlobalByName,
        0x41 => Opcode::LdGlobalVar,
        0x42 => Opcode::LdObjByName,
        0x43 => Opcode::StObjByName,
        0x44 => Opcode::MovV4, // or v8 or v16, using v4 as default
        0x46 => Opcode::LdSuperByName,
        0x47 => Opcode::StConstToGlobalRecord,
        0x48 => Opcode::StToGlobalRecord,
        0x49 => Opcode::LdThisByName,
        0x4a => Opcode::StThisByName,
        0x4b => Opcode::LdThisByValue,
        0x4c => Opcode::StThisByValue,
        0x4d => Opcode::JmpImm8,
        0x4e => Opcode::JmpImm16,
        0x4f => Opcode::JEqzImm8,
        0x50 => Opcode::JEqzImm16,
        0x51 => Opcode::JNezImm8,
        0x52 => Opcode::JStrictEqzImm8,
        0x53 => Opcode::JNStrictEqzImm8,
        0x54 => Opcode::JEqNullImm8,
        0x55 => Opcode::JNeNullImm8,
        0x56 => Opcode::JStrictEqNullImm8,
        0x57 => Opcode::JNStrictEqNullImm8,
        0x58 => Opcode::JEqUndefinedImm8,
        0x59 => Opcode::JNeUndefinedImm8,
        0x5a => Opcode::JStrictEqUndefinedImm8,
        0x5b => Opcode::JNStrictEqUndefinedImm8,
        0x5c => Opcode::JEqRegImm8,
        0x5d => Opcode::JNeRegImm8,
        0x5e => Opcode::JStrictEqRegImm8,
        0x5f => Opcode::JNStrictEqRegImm8,
        0x60 => Opcode::Lda,
        0x61 => Opcode::Sta,
        0x62 => Opcode::Ldai,
        0x63 => Opcode::FLdai,
        0x64 => Opcode::Return,
        0x65 => Opcode::ReturnUndefined,
        0x66 => Opcode::GetPropIterator,
        0x67 => Opcode::GetIterator,
        0x68 => Opcode::CloseIterator,
        0x69 => Opcode::PopLexEnv,
        0x6a => Opcode::LdNan,
        0x6b => Opcode::LdInfinity,
        0x6c => Opcode::GetUnmappedArgs,
        0x6d => Opcode::LdGlobal,
        0x6e => Opcode::LdNewTarget,
        0x6f => Opcode::LdThis,
        0x70 => Opcode::LdHole,
        0x71 => Opcode::CreateRegExpWithLiteral,
        0x72 => Opcode::CreateRegExpWithLiteralWide,
        0x73 => Opcode::CallRange,
        0x74 => Opcode::DefineFuncWide,
        0x75 => Opcode::DefineClassWithBufferWide,
        0x76 => Opcode::GetTemplateObject,
        0x77 => Opcode::SetObjectWithProto,
        0x78 => Opcode::StOwnByValue,
        0x79 => Opcode::StOwnByIndex,
        0x7a => Opcode::StOwnByName,
        0x7b => Opcode::GetModuleNamespace,
        0x7c => Opcode::StModuleVar,
        0x7d => Opcode::LdLocalModuleVar,
        0x7e => Opcode::LdExternalModuleVar,
        0x7f => Opcode::StGlobalVar,
        0x80 => Opcode::CreateEmptyArrayWide,
        0x81 => Opcode::CreateArrayWithBufferWide,
        0x82 => Opcode::CreateObjectWithBufferWide,
        0x83 => Opcode::NewObjRangeWide,
        0x84 => Opcode::TypeOfWide,
        0x85 => Opcode::LdObjByValueWide,
        0x86 => Opcode::StObjByValueWide,
        0x87 => Opcode::LdSuperByValueWide,
        0x88 => Opcode::LdObjByIndexWide,
        0x89 => Opcode::StObjByIndexWide,
        0x8a => Opcode::LdLexVarImm8,
        0x8b => Opcode::StLexVarImm8,
        0x8c => Opcode::TryLdGlobalByNameWide,
        0x8d => Opcode::TryStGlobalByNameWide,
        0x8e => Opcode::StOwnByNameWithNameSet,
        0x8f => Opcode::MovV8,
        0x90 => Opcode::LdObjByNameWide,
        0x91 => Opcode::StObjByNameWide,
        0x92 => Opcode::LdSuperByNameWide,
        0x93 => Opcode::LdThisByNameWide,
        0x94 => Opcode::StThisByNameWide,
        0x95 => Opcode::LdThisByValueWide,
        0x96 => Opcode::StThisByValueWide,
        0x97 => Opcode::AsyncGeneratorReject,
        0x98 => Opcode::JmpImm32,
        0x99 => Opcode::StOwnByValueWithNameSet,
        0x9a => Opcode::JEqzImm32,
        0x9b => Opcode::JNezImm16,
        0x9c => Opcode::JNezImm32,
        0x9d => Opcode::JStrictEqzImm16,
        0x9e => Opcode::JNStrictEqzImm16,
        0x9f => Opcode::JEqNullImm16,
        0xa0 => Opcode::JNeNullImm16,
        0xa1 => Opcode::JStrictEqNullImm16,
        0xa2 => Opcode::JNStrictEqNullImm16,
        0xa3 => Opcode::JEqUndefinedImm16,
        0xa4 => Opcode::JNeUndefinedImm16,
        0xa5 => Opcode::JStrictEqUndefinedImm16,
        0xa6 => Opcode::JNStrictEqUndefinedImm16,
        0xa7 => Opcode::JEqRegImm16,
        0xa8 => Opcode::JNeRegImm16,
        0xa9 => Opcode::JStrictEqRegImm16,
        0xaa => Opcode::JNStrictEqRegImm16,
        0xab => Opcode::GetIteratorWide,
        0xac => Opcode::CloseIteratorWide,
        0xad => Opcode::LdSymbol,
        0xae => Opcode::AsyncFunctionEnter,
        0xaf => Opcode::LdFunction,
        0xb0 => Opcode::Debugger,
        0xb1 => Opcode::CreateGeneratorObj,
        0xb2 => Opcode::CreateIterResultObj,
        0xb3 => Opcode::CreateObjectWithExcludedKeys,
        0xb4 => Opcode::NewObjApply,
        0xb5 => Opcode::NewObjApplyWide,
        0xb6 => Opcode::NewLexEnvWithName,
        0xb7 => Opcode::CreateAsyncGeneratorObj,
        0xb8 => Opcode::AsyncGeneratorResolve,
        0xb9 => Opcode::SuperCallSpread,
        0xba => Opcode::Apply,
        0xbb => Opcode::SuperCallArrowRange,
        0xbc => Opcode::DefineGetterSetterByValue,
        0xbd => Opcode::DynamicImport,
        0xbe => Opcode::DefineMethodWide,
        0xbf => Opcode::ResumeGenerator,
        0xc0 => Opcode::GetResumeMode,
        0xc1 => Opcode::GetTemplateObjectWide,
        0xc2 => Opcode::DelObjProp,
        0xc3 => Opcode::SuspendGenerator,
        0xc4 => Opcode::AsyncFunctionAwaitUncaught,
        0xc5 => Opcode::CopyDataProperties,
        0xc6 => Opcode::StArraySpread,
        _ => Opcode::Extended(mnemonic.to_owned()),
    }
}

fn parse_hex(text: &str) -> Result<u64, ParseError> {
    let trimmed = text.trim_start_matches('+');
    let without_prefix = trimmed.trim_start_matches("0x");
    u64::from_str_radix(without_prefix, 16)
        .map_err(|_| ParseError::new(0, format!("invalid hex {text}")))
}

fn unescape_string(input: &str) -> Result<String, ParseError> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let next = chars
                .next()
                .ok_or_else(|| ParseError::new(0, "unterminated escape"))?;
            match next {
                '\\' => result.push('\\'),
                '"' => result.push('"'),
                'n' => result.push('\n'),
                't' => result.push('\t'),
                other => result.push(other),
            }
        } else {
            result.push(ch);
        }
    }
    Ok(result)
}

fn split_once(input: &str, needle: char) -> Option<(&str, &str)> {
    let pos = input.find(needle)?;
    Some((&input[..pos], &input[pos + needle.len_utf8()..]))
}

pub(crate) fn normalize_function_text(original: &str) -> String {
    let mut lines: Vec<String> = original
        .lines()
        .map(|line| line.replace('\t', "    "))
        .collect();

    if let Some(first) = lines.first_mut() {
        if let Some(brace_pos) = first.find('{') {
            let (prefix, _suffix) = first.split_at(brace_pos);
            let mut prefix = prefix.trim_end();
            if let Some(angle_pos) = prefix.find('<') {
                prefix = prefix[..angle_pos].trim_end();
            }
            *first = format!("{} {{", prefix);
        }
    }

    if let Some(pos) = lines.iter().rposition(|line| line.trim() == "}") {
        if pos > 0 && !lines[pos - 1].trim().is_empty() {
            lines.insert(pos, String::new());
        }
    }

    let mut normalized = lines.join("\n");
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant_pool::ConstantPool;
    use crate::disassembly::format_function;

    fn seed_pool() -> ConstantPool {
        let mut pool = ConstantPool::default();
        for (id, value) in [
            (0, ".func_main_0"),
            (1, "a0"),
            (2, "a1"),
            (3, "a2"),
            (4, "a"),
            (5, "b"),
            (6, "d"),
            (7, "hilog"),
            (8, "info"),
            (9, "DOMAIN"),
            (10, "testTag"),
            (11, "%{public}s"),
            (12, "Ability onBackground"),
        ] {
            pool.strings.push(StringRecord {
                id: StringId::new(id),
                value: value.to_owned(),
            });
        }
        pool
    }

    fn sample_text() -> &'static str {
        ".function any .func_main_0(any a0, any a1, any a2) {\n    getmodulenamespace 0x1\n    ldai 0x3\n    stmodulevar 0x0\n    ldexternalmodulevar 0x0\n    sta v0\n    throw.undefinedifholewithname \"a\"\n    ldexternalmodulevar 0x1\n    sta v1\n    throw.undefinedifholewithname \"b\"\n    lda v1\n    add2 0x0, v0\n    sta v0\n    ldlocalmodulevar 0x0\n    sta v1\n    throw.undefinedifholewithname \"d\"\n    lda v1\n    add2 0x1, v0\n\n}\n"
    }

    fn complex_text() -> &'static str {
        ".function any Example.func(any a0, any a1, any a2, any a3) {\n    mov v0, a0\n    mov v1, a1\n    mov v2, a2\n    mov v3, a3\n    lda v0\n    sta v5\n    callruntime.supercallforwardallargs v5\n    sta v5\n    lda v2\n    throw.ifsupernotcorrectcall 0x1\n    lda v5\n    sta v2\n    lda v2\n    throw.ifsupernotcorrectcall 0x0\n    ldexternalmodulevar 0x2\n    throw.undefinedifholewithname \"hilog\"\n    sta v5\n    lda v5\n    ldobjbyname 0x0, \"info\"\n    sta v4\n    ldlexvar 0x0, 0x0\n    throw.undefinedifholewithname \"DOMAIN\"\n    sta v6\n    lda.str \"testTag\"\n    sta v7\n    lda.str \"%{public}s\"\n    sta v8\n    lda.str \"Ability onBackground\"\n    sta v9\n    return\n\n}\n"
    }

    #[test]
    fn parse_sample_function() {
        let mut pool = seed_pool();
        let function = parse_function(sample_text(), &mut pool).expect("parse failed");
        let formatted = format_function(&function, &pool).expect("formatting failed");
        assert_eq!(formatted, sample_text());
    }

    #[test]
    fn parse_complex_function() {
        let mut pool = seed_pool();
        let function = parse_function(complex_text(), &mut pool).expect("parse failed");
        let formatted = format_function(&function, &pool).expect("formatting failed");
        assert_eq!(formatted, complex_text());
    }

    #[test]
    fn parse_real_module_functions() {
        let data =
            std::fs::read_to_string("test-data/modules.txt").expect("failed to read modules.txt");
        let abc = crate::abc::parse_abc_file(&data).expect("abc parse failed");
        assert!(
            !abc.functions.is_empty(),
            "expected at least one function in fixtures"
        );
        let parsed_count = abc
            .functions
            .iter()
            .filter(|entry| entry.parsed.is_some())
            .count();
        assert!(parsed_count > 0, "no functions successfully parsed");
    }
}
