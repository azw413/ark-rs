//! Parsing utilities for Ark textual disassembly back into bytecode structures.

use crate::constant_pool::{ConstantPool, StringRecord};
use crate::functions::{BasicBlock, Function, FunctionParameter, InstructionBlock};
use crate::instructions::{
    IdentifierOperand, ImmediateOperand, Instruction, InstructionIndex, Opcode, Operand, Register,
    RegisterOperand,
};
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
    match mnemonic {
        "getmodulenamespace" => Some(Opcode::GetModuleNamespace),
        "ldai" => Some(Opcode::Ldai),
        "stmodulevar" => Some(Opcode::StModuleVar),
        "ldexternalmodulevar" => Some(Opcode::LdExternalModuleVar),
        "sta" => Some(Opcode::Sta),
        "throw.undefinedifholewithname" => Some(Opcode::ThrowUndefinedIfHoleWithName),
        "throw.ifsupernotcorrectcall" => Some(Opcode::ThrowIfSuperNotCorrectCallImm8),
        "lda" => Some(Opcode::Lda),
        "lda.str" => Some(Opcode::LdaStr),
        "add2" => Some(Opcode::Add2),
        "mov" => Some(Opcode::MovV8),
        "return" => Some(Opcode::Return),
        "ldobjbyname" => Some(Opcode::LdObjByName),
        "ldlexvar" => Some(Opcode::LdLexVar),
        "ldlocalmodulevar" => Some(Opcode::LdLocalModuleVar),
        _ => Some(Opcode::Extended(mnemonic.to_owned())),
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
