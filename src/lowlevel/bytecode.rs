//! Bytecode decoder and encoder for ABC modules.
//!
//! This module handles the conversion between binary bytecode and high-level
//! representations like Instructions, BasicBlocks, and InstructionBlocks.

use super::metadata::AbcReader;
use crate::error::{ArkError, ArkResult};
use crate::highlevel::functions::{
    BasicBlock, ExceptionHandler, FunctionParameter, FunctionSignature, InstructionBlock,
};
use crate::highlevel::instructions::{
    IdentifierOperand, ImmediateOperand, Instruction, InstructionFlags, InstructionFormat,
    InstructionIndex, Opcode, Operand, Register, RegisterOperand, RegisterWidth,
};
use crate::lowlevel::isa_generated::{INSTRUCTION_TABLE, PREFIXED_INSTRUCTION_TABLE};
use crate::lowlevel::{FunctionId, StringId, TypeId};

/// Metadata viewed directly from the bytecode section (offsets, register counts, etc.).
#[derive(Debug, Clone)]
pub struct BytecodeSection {
    pub code_offset: u32,
    pub code_length: u32,
    pub register_count: u16,
    pub parameter_count: u16,
    pub local_count: u16,
    pub exception_handler_count: u16,
    pub traits_count: u16,
}

/// Result of decoding a function body, including instructions and exception handlers.
#[derive(Debug, Clone)]
pub struct DecodedFunction {
    pub id: FunctionId,
    pub name: Option<StringId>,
    pub signature: FunctionSignature,
    pub register_count: u16,
    pub parameters: Vec<FunctionParameter>,
    pub locals: Vec<String>,
    pub instruction_block: InstructionBlock,
    pub exception_handlers: Vec<ExceptionHandler>,
}

/// Decodes a function body from binary bytecode using the default string resolver.
pub fn decode_function_body(
    bytecode: &[u8],
    offset: u32,
    function_id: FunctionId,
    name: Option<StringId>,
    signature: FunctionSignature,
) -> ArkResult<DecodedFunction> {
    decode_function_body_with_resolver(
        bytecode,
        offset,
        function_id,
        name,
        signature,
        None::<fn(u32) -> Option<String>>,
    )
}

/// Decodes a function body from binary bytecode using a custom string resolver.
pub fn decode_function_body_with_resolver<F>(
    bytecode: &[u8],
    offset: u32,
    function_id: FunctionId,
    name: Option<StringId>,
    mut signature: FunctionSignature,
    string_resolver: Option<F>,
) -> ArkResult<DecodedFunction>
where
    F: Fn(u32) -> Option<String>,
{
    let mut reader = AbcReader::new(bytecode);
    reader.seek(offset as usize)?;

    // Function prologue begins with unsigned LEB128 counts.
    let register_count = reader.read_uleb128()? as u16;
    let parameter_count = reader.read_uleb128()? as u16;
    let code_size = reader.read_uleb128()? as usize;
    let exception_handler_count = reader.read_uleb128()? as usize;

    let code_bytes = reader.read_bytes(code_size)?;
    let mut code_reader = AbcReader::new(code_bytes);
    let code_size_u32 = code_size as u32;

    let mut signature_parameters = Vec::with_capacity(parameter_count as usize);
    let mut parameters = Vec::with_capacity(parameter_count as usize);
    for _ in 0..parameter_count {
        signature_parameters.push("any".to_owned());
        parameters.push(FunctionParameter {
            name: None,
            type_name: "any".to_owned(),
            default_literal: None,
            is_optional: false,
        });
    }
    signature.parameters = signature_parameters;

    let resolver_ref: Option<&dyn Fn(u32) -> Option<String>> = string_resolver
        .as_ref()
        .map(|r| r as &dyn Fn(u32) -> Option<String>);
    let instruction_block = decode_instructions(&mut code_reader, register_count, resolver_ref)?;

    let mut exception_handlers = Vec::with_capacity(exception_handler_count);
    for try_index in 0..exception_handler_count {
        let try_start = reader.read_uleb128()?;
        let try_length = reader.read_uleb128()?;
        let catch_count = reader.read_uleb128()? as usize;
        if try_start > code_size_u32 {
            // Skip invalid entry that points beyond the function body
            for _ in 0..catch_count {
                let _ = reader.read_uleb128()?; // type index + 1
                let _ = reader.read_uleb128()?; // handler start
                let _ = reader.read_uleb128()?; // handler size
            }
            continue;
        }

        let try_end = try_start.saturating_add(try_length);
        if try_end > code_size_u32 {
            for _ in 0..catch_count {
                let _ = reader.read_uleb128()?;
                let _ = reader.read_uleb128()?;
                let _ = reader.read_uleb128()?;
            }
            continue;
        }

        for catch_index in 0..catch_count {
            let type_plus_one = reader.read_uleb128()?;
            let handler_start = reader.read_uleb128()?;
            let handler_size = reader.read_uleb128()?;
            let handler_end = handler_start.saturating_add(handler_size);

            if handler_start > code_size_u32 || handler_end > code_size_u32 {
                continue;
            }

            let exception_type = if type_plus_one == 0 {
                None
            } else {
                Some(TypeId::new(type_plus_one - 1))
            };

            exception_handlers.push(ExceptionHandler {
                try_index: try_index as u32,
                catch_index: catch_index as u32,
                try_start,
                try_end,
                handler_start,
                handler_end,
                exception_type,
            });
        }
    }

    Ok(DecodedFunction {
        id: function_id,
        name,
        signature,
        register_count,
        parameters,
        locals: Vec::new(), // TODO: decode from function body
        instruction_block,
        exception_handlers,
    })
}

/// Decodes instructions from a bytecode reader
fn decode_instructions(
    reader: &mut AbcReader,
    register_count: u16,
    string_resolver: Option<&dyn Fn(u32) -> Option<String>>,
) -> ArkResult<InstructionBlock> {
    let mut blocks = Vec::new();
    let mut current_block = BasicBlock::new(0);
    let mut instruction_index = 0u32;

    while reader.remaining() > 0 {
        // Check if we need to start a new basic block
        // This happens after control flow instructions (jumps, returns, throws)
        if should_start_new_block(&current_block.instructions) {
            if !current_block.instructions.is_empty() {
                blocks.push(current_block);
                current_block = BasicBlock::new(blocks.len() as u32);
            }
        }

        // Decode single instruction
        let instruction = decode_instruction(
            reader,
            InstructionIndex(instruction_index),
            register_count,
            string_resolver,
        )?;
        current_block.instructions.push(instruction);
        instruction_index += 1;

        // Check if this instruction terminates the block
        if is_terminating_instruction(&current_block.instructions.last().unwrap()) {
            blocks.push(current_block);
            current_block = BasicBlock::new(blocks.len() as u32);
        }
    }

    // Add the last block if it has instructions
    if !current_block.instructions.is_empty() {
        blocks.push(current_block);
    }

    Ok(InstructionBlock { blocks })
}

/// Decodes a single instruction from the bytecode stream
fn decode_instruction(
    reader: &mut AbcReader,
    index: InstructionIndex,
    register_count: u16,
    string_resolver: Option<&dyn Fn(u32) -> Option<String>>,
) -> ArkResult<Instruction> {
    let offset = reader.position() as u32;
    let first_byte = reader.read_u8()?;

    let format;
    let opcode = if let Some(entry) = INSTRUCTION_TABLE
        .get(first_byte as usize)
        .and_then(|opt| opt.as_ref())
    {
        format = entry.format;
        let mnemonic = signature_to_mnemonic(entry.signature);
        opcode_from_signature(mnemonic, first_byte, format)
    } else if let Some(prefix_byte) = prefix_kind(first_byte) {
        let secondary = reader.read_u8()?;
        let entry = PREFIXED_INSTRUCTION_TABLE
            .get(prefix_index(prefix_byte, secondary))
            .and_then(|opt| opt.as_ref())
            .ok_or_else(|| {
                ArkError::format(format!(
                    "unknown prefixed opcode 0x{:02x} 0x{:02x}",
                    prefix_byte, secondary
                ))
            })?;

        format = entry.format;
        let mnemonic = signature_to_mnemonic(entry.signature);
        opcode_from_prefixed_mnemonic(mnemonic, prefix_byte, secondary)
    } else {
        // Unknown opcode, treat as raw extended instruction
        format = InstructionFormat::NONE;
        Opcode::Extended(format!("unknown_0x{:02x}", first_byte))
    };
    let operands = decode_operands(reader, &format, register_count, string_resolver)?;

    let mut instruction = Instruction {
        index,
        opcode,
        format,
        operands,
        flags: InstructionFlags::NONE,
        comment: None,
        bytecode_offset: offset,
        byte_length: 0,
    };

    let end = reader.position() as u32;
    instruction.byte_length = end.saturating_sub(offset).try_into().unwrap_or(u16::MAX);

    if let Some(target_offset) = branch_target_offset(&instruction, offset) {
        if let Some((operand_index, _)) = instruction
            .operands
            .iter()
            .enumerate()
            .find(|(_, operand)| matches!(operand, Operand::Immediate(_)))
        {
            instruction.operands[operand_index] = Operand::Label(target_offset);
        }
    }

    Ok(instruction)
}

/// Decodes operands for an instruction based on its format
fn decode_operands(
    reader: &mut AbcReader,
    format: &InstructionFormat,
    register_count: u16,
    string_resolver: Option<&dyn Fn(u32) -> Option<String>>,
) -> ArkResult<Vec<Operand>> {
    use IdentifierOperand::Id16;
    use ImmediateOperand::{Imm4, Imm8, Imm16, Imm32, Imm64};
    let mut operands = Vec::new();

    let normalized = match *format {
        InstructionFormat::PREF_NONE => InstructionFormat::NONE,
        InstructionFormat::PREF_IMM8 => InstructionFormat::IMM8,
        InstructionFormat::PREF_IMM8_V8 => InstructionFormat::IMM8_V8,
        InstructionFormat::PREF_IMM8_V8_V8 => InstructionFormat::IMM8_V8_V8,
        InstructionFormat::PREF_IMM8_IMM8 => InstructionFormat::IMM8_IMM8,
        InstructionFormat::PREF_IMM8_IMM8_V8 => InstructionFormat::IMM8_IMM8_V8,
        InstructionFormat::PREF_IMM8_IMM16_IMM16_V8 => InstructionFormat::IMM8_IMM16_IMM16_V8,
        InstructionFormat::PREF_IMM4_IMM4 => InstructionFormat::IMM4_IMM4,
        InstructionFormat::PREF_IMM16 => InstructionFormat::IMM16,
        InstructionFormat::PREF_IMM16_V8 => InstructionFormat::IMM16_V8,
        InstructionFormat::PREF_IMM16_V8_V8 => InstructionFormat::IMM16_V8_V8,
        InstructionFormat::PREF_IMM16_ID16 => InstructionFormat::IMM16_ID16,
        InstructionFormat::PREF_IMM16_ID16_ID16_IMM16_V8 => {
            InstructionFormat::IMM16_ID16_ID16_IMM16_V8
        }
        InstructionFormat::PREF_IMM16_IMM16 => InstructionFormat::IMM16_IMM16,
        InstructionFormat::PREF_IMM16_IMM16_V8 => InstructionFormat::IMM16_IMM16_V8,
        InstructionFormat::PREF_V8 => InstructionFormat::V8,
        InstructionFormat::PREF_V8_V8 => InstructionFormat::V8_V8,
        InstructionFormat::PREF_V8_V8_V8 => InstructionFormat::V8_V8_V8,
        InstructionFormat::PREF_V8_V8_V8_V8 => InstructionFormat::V8_V8_V8_V8,
        InstructionFormat::PREF_ID16 => InstructionFormat::ID16,
        other => other,
    };

    match normalized {
        InstructionFormat::NONE => {}
        InstructionFormat::ID16 => {
            let id = reader.read_u16()?;
            let operand = if let Some(resolver) = string_resolver {
                if let Some(value) = resolver(id as u32) {
                    Operand::String(value)
                } else {
                    Operand::Identifier(Id16(id))
                }
            } else {
                Operand::Identifier(Id16(id))
            };
            operands.push(operand);
        }
        InstructionFormat::IMM4_IMM4 => {
            let packed = reader.read_u8()?;
            let imm1 = packed & 0x0f;
            let imm2 = (packed >> 4) & 0x0f;
            operands.push(Operand::Immediate(Imm4(imm1)));
            operands.push(Operand::Immediate(Imm4(imm2)));
        }
        InstructionFormat::IMM8 => {
            let imm = reader.read_u8()?;
            operands.push(Operand::Immediate(Imm8(imm)));
        }
        InstructionFormat::IMM8_ID16 => {
            let imm = reader.read_u8()?;
            let id = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Identifier(Id16(id)));
        }
        InstructionFormat::IMM8_ID16_IMM8 => {
            let imm1 = reader.read_u8()?;
            let id = reader.read_u16()?;
            let imm2 = reader.read_u8()?;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm8(imm2)));
        }
        InstructionFormat::IMM8_ID16_IMM16 => {
            let imm1 = reader.read_u8()?;
            let id = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm16(imm2)));
        }
        InstructionFormat::IMM8_ID16_V8 => {
            let imm = reader.read_u8()?;
            let id = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM8_ID16_ID16_IMM16_V8 => {
            let imm = reader.read_u8()?;
            let id1 = reader.read_u16()?;
            let id2 = reader.read_u16()?;
            let trailing = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Identifier(Id16(id1)));
            operands.push(Operand::Identifier(Id16(id2)));
            operands.push(Operand::Immediate(Imm16(trailing)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM8_IMM8 => {
            let imm1 = reader.read_u8()?;
            let imm2 = reader.read_u8()?;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Immediate(Imm8(imm2)));
        }
        InstructionFormat::IMM8_IMM8_V8 => {
            let imm1 = reader.read_u8()?;
            let imm2 = reader.read_u8()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Immediate(Imm8(imm2)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM8_IMM16 => {
            let imm1 = reader.read_u8()?;
            let imm2 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
        }
        InstructionFormat::IMM8_IMM16_IMM16 => {
            let imm1 = reader.read_u8()?;
            let imm2 = reader.read_u16()?;
            let imm3 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
            operands.push(Operand::Immediate(Imm16(imm3)));
        }
        InstructionFormat::IMM8_IMM16_IMM16_V8 => {
            let imm1 = reader.read_u8()?;
            let imm2 = reader.read_u16()?;
            let imm3 = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
            operands.push(Operand::Immediate(Imm16(imm3)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM8_V8 => {
            let imm = reader.read_u8()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM8_V8_IMM16 => {
            let imm = reader.read_u8()?;
            let reg = reader.read_u8()? as u16;
            let trailing = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm16(trailing)));
        }
        InstructionFormat::IMM8_V8_V8 => {
            let imm = reader.read_u8()?;
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
        }
        InstructionFormat::IMM8_V8_V8_V8 => {
            let imm = reader.read_u8()?;
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            let reg3 = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg3,
                register_count,
            )));
        }
        InstructionFormat::IMM8_V8_V8_V8_V8 => {
            let imm = reader.read_u8()?;
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            let reg3 = reader.read_u8()? as u16;
            let reg4 = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg3,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg4,
                register_count,
            )));
        }
        InstructionFormat::IMM16 => {
            let imm = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm16(imm)));
        }
        InstructionFormat::IMM16_ID16 => {
            let imm = reader.read_u16()?;
            let id = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Identifier(Id16(id)));
        }
        InstructionFormat::IMM16_ID16_IMM8 => {
            let imm = reader.read_u16()?;
            let id = reader.read_u16()?;
            let trailing = reader.read_u8()?;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm8(trailing)));
        }
        InstructionFormat::IMM16_ID16_IMM16 => {
            let imm1 = reader.read_u16()?;
            let id = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm16(imm2)));
        }
        InstructionFormat::IMM16_ID16_IMM16_V8 => {
            let imm1 = reader.read_u16()?;
            let id = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm16(imm2)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_ID16_V8 => {
            let imm = reader.read_u16()?;
            let id = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_ID16_ID16_IMM16_V8 => {
            let imm = reader.read_u16()?;
            let id1 = reader.read_u16()?;
            let id2 = reader.read_u16()?;
            let trailing = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Identifier(Id16(id1)));
            operands.push(Operand::Identifier(Id16(id2)));
            operands.push(Operand::Immediate(Imm16(trailing)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_IMM16 => {
            let imm1 = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
        }
        InstructionFormat::IMM16_IMM8_V8 => {
            let imm16 = reader.read_u16()?;
            let imm8 = reader.read_u8()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm16)));
            operands.push(Operand::Immediate(Imm8(imm8)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_IMM16_V8 => {
            let imm1 = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_V8 => {
            let imm = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::IMM16_V8_IMM16 => {
            let imm1 = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            let imm2 = reader.read_u16()?;
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm16(imm2)));
        }
        InstructionFormat::IMM16_V8_IMM32 => {
            let imm16 = reader.read_u16()?;
            let reg = reader.read_u8()? as u16;
            let imm32 = reader.read_u32()?;
            operands.push(Operand::Immediate(Imm16(imm16)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm32(imm32)));
        }
        InstructionFormat::IMM16_V8_V8 => {
            let imm = reader.read_u16()?;
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm16(imm)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
        }
        InstructionFormat::IMM32 => {
            let imm = reader.read_u32()?;
            operands.push(Operand::Immediate(Imm32(imm)));
        }
        InstructionFormat::IMM64 => {
            let imm = reader.read_u64()?;
            operands.push(Operand::Immediate(Imm64(imm)));
        }
        InstructionFormat::V4_V4 => {
            let packed = reader.read_u8()?;
            let dest = (packed & 0x0f) as u16;
            let src = (packed >> 4) as u16;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V4,
                dest,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V4,
                src,
                register_count,
            )));
        }
        InstructionFormat::V8 => {
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::V8_IMM8 => {
            let reg = reader.read_u8()? as u16;
            let imm = reader.read_u8()?;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm8(imm)));
        }
        InstructionFormat::V8_IMM16 => {
            let reg = reader.read_u8()? as u16;
            let imm = reader.read_u16()?;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm16(imm)));
        }
        InstructionFormat::V8_V8 => {
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
        }
        InstructionFormat::V8_V8_V8 => {
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            let reg3 = reader.read_u8()? as u16;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg3,
                register_count,
            )));
        }
        InstructionFormat::V8_V8_V8_V8 => {
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            let reg3 = reader.read_u8()? as u16;
            let reg4 = reader.read_u8()? as u16;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg3,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg4,
                register_count,
            )));
        }
        InstructionFormat::V16_V16 => {
            let reg1 = reader.read_u16()?;
            let reg2 = reader.read_u16()?;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V16,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V16,
                reg2,
                register_count,
            )));
        }
        InstructionFormat::PREF_IMM4_IMM4_V8 => {
            let first = reader.read_u8()?;
            let reg = reader.read_u8()? as u16;
            let imm1 = first & 0x0f;
            let imm2 = (first >> 4) & 0x0f;
            operands.push(Operand::Immediate(Imm4(imm1)));
            operands.push(Operand::Immediate(Imm4(imm2)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::PREF_IMM8_IMM32_V8 => {
            let imm8 = reader.read_u8()?;
            let imm32 = reader.read_u32()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm8(imm8)));
            operands.push(Operand::Immediate(Imm32(imm32)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        InstructionFormat::PREF_V8_ID16 => {
            let reg = reader.read_u8()? as u16;
            let id = reader.read_u16()?;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Identifier(Id16(id)));
        }
        InstructionFormat::PREF_V8_IMM32 => {
            let reg = reader.read_u8()? as u16;
            let imm = reader.read_u32()?;
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
            operands.push(Operand::Immediate(Imm32(imm)));
        }
        InstructionFormat::PREF_ID16_IMM16_IMM16_V8_V8 => {
            let id = reader.read_u16()?;
            let imm1 = reader.read_u16()?;
            let imm2 = reader.read_u16()?;
            let reg1 = reader.read_u8()? as u16;
            let reg2 = reader.read_u8()? as u16;
            operands.push(Operand::Identifier(Id16(id)));
            operands.push(Operand::Immediate(Imm16(imm1)));
            operands.push(Operand::Immediate(Imm16(imm2)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg1,
                register_count,
            )));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg2,
                register_count,
            )));
        }
        InstructionFormat::PREF_ID32 => {
            let value = reader.read_u32()?;
            operands.push(Operand::Immediate(Imm32(value)));
        }
        InstructionFormat::PREF_ID32_IMM8 => {
            let value = reader.read_u32()?;
            let imm = reader.read_u8()?;
            operands.push(Operand::Immediate(Imm32(value)));
            operands.push(Operand::Immediate(Imm8(imm)));
        }
        InstructionFormat::PREF_ID32_V8 => {
            let value = reader.read_u32()?;
            let reg = reader.read_u8()? as u16;
            operands.push(Operand::Immediate(Imm32(value)));
            operands.push(Operand::Register(make_register(
                RegisterWidth::V8,
                reg,
                register_count,
            )));
        }
        other => {
            eprintln!("Warning: Unhandled instruction format: {:?}", other);
        }
    }

    Ok(operands)
}

fn branch_target_offset(instruction: &Instruction, current_offset: u32) -> Option<u32> {
    use Opcode::*;

    let immediate = match instruction.opcode {
        JmpImm8 | JEqzImm8 | JNezImm8 | JStrictEqzImm8 | JNStrictEqzImm8 | JmpImm16 | JEqzImm16
        | JNezImm16 | JStrictEqzImm16 | JNStrictEqzImm16 | JmpImm32 | JEqzImm32 | JNezImm32 => {
            extract_first_immediate(&instruction.operands)?
        }
        _ => return None,
    };

    let target = current_offset as i64 + immediate;
    if target < 0 {
        None
    } else {
        Some(target as u32)
    }
}

fn extract_first_immediate(operands: &[Operand]) -> Option<i64> {
    operands.iter().find_map(|operand| match operand {
        Operand::Immediate(ImmediateOperand::Imm8(value)) => Some((*value as i8) as i64),
        Operand::Immediate(ImmediateOperand::Imm16(value)) => Some((*value as i16) as i64),
        Operand::Immediate(ImmediateOperand::Imm32(value)) => Some((*value as i32) as i64),
        Operand::Immediate(ImmediateOperand::Imm64(value)) => Some(*value as i64),
        _ => None,
    })
}

fn signature_to_mnemonic(signature: &'static str) -> &'static str {
    signature.split_whitespace().next().unwrap_or(signature)
}

fn prefix_kind(byte: u8) -> Option<u8> {
    match byte {
        0xfb | 0xfc | 0xfd | 0xfe => Some(byte),
        _ => None,
    }
}

fn prefix_index(prefix: u8, opcode: u8) -> usize {
    (prefix as usize) * 256 + opcode as usize
}

fn opcode_from_prefixed_mnemonic(mnemonic: &'static str, prefix: u8, opcode_byte: u8) -> Opcode {
    match mnemonic {
        "throw" => Opcode::Throw,
        "throw.notexists" => Opcode::ThrowNotExists,
        "throw.patternnoncoercible" => Opcode::ThrowPatternNonCoercible,
        "throw.deletesuperproperty" => Opcode::ThrowDeleteSuperProperty,
        "throw.constassignment" => Opcode::ThrowConstAssignment,
        "throw.ifnotobject" => Opcode::ThrowIfNotObject,
        "throw.undefinedifhole" => Opcode::ThrowUndefinedIfHole,
        "throw.ifsupernotcorrectcall" => match opcode_byte {
            0x07 => Opcode::ThrowIfSuperNotCorrectCallImm8,
            0x08 => Opcode::ThrowIfSuperNotCorrectCallImm16,
            _ => Opcode::Extended(mnemonic.to_owned()),
        },
        "throw.undefinedifholewithname" => Opcode::ThrowUndefinedIfHoleWithName,

        "callruntime.notifyconcurrentresult" => Opcode::CallRuntimeNotifyConcurrentResult,
        "callruntime.definefieldbyvalue" => Opcode::CallRuntimeDefineFieldByValue,
        "callruntime.definefieldbyindex" => Opcode::CallRuntimeDefineFieldByIndex,
        "callruntime.topropertykey" => Opcode::CallRuntimeToPropertyKey,
        "callruntime.createprivateproperty" => Opcode::CallRuntimeCreatePrivateProperty,
        "callruntime.defineprivateproperty" => Opcode::CallRuntimeDefinePrivateProperty,
        "callruntime.callinit" => Opcode::CallRuntimeCallInit,
        "callruntime.definesendableclass" => Opcode::CallRuntimeDefineSendableClass,
        "callruntime.ldsendableclass" => Opcode::CallRuntimeLdSendableClass,
        "callruntime.ldsendableexternalmodulevar" => Opcode::CallRuntimeLdSendableExternalModuleVar,
        "callruntime.wideldsendableexternalmodulevar" => {
            Opcode::CallRuntimeWideLdSendableExternalModuleVar
        }
        "callruntime.newsendableenv" => Opcode::CallRuntimeNewSendableEnv,
        "callruntime.widenewsendableenv" => Opcode::CallRuntimeWideNewSendableEnv,
        "callruntime.stsendablevar" => match opcode_byte {
            0x0d => Opcode::CallRuntimeStSendableVarImm4,
            0x0e => Opcode::CallRuntimeStSendableVarImm8,
            _ => Opcode::Extended(mnemonic.to_owned()),
        },
        "callruntime.widestsendablevar" => Opcode::CallRuntimeWideStSendableVar,
        "callruntime.ldsendablevar" => match opcode_byte {
            0x10 => Opcode::CallRuntimeLdSendableVarImm4,
            0x11 => Opcode::CallRuntimeLdSendableVarImm8,
            _ => Opcode::Extended(mnemonic.to_owned()),
        },
        "callruntime.wideldsendablevar" => Opcode::CallRuntimeWideLdSendableVar,
        "callruntime.istrue" => Opcode::CallRuntimeIsTrue,
        "callruntime.isfalse" => Opcode::CallRuntimeIsFalse,
        "callruntime.ldlazymodulevar" => Opcode::CallRuntimeLdLazyModuleVar,
        "callruntime.wideldlazymodulevar" => Opcode::CallRuntimeWideLdLazyModuleVar,
        "callruntime.ldlazysendablemodulevar" => Opcode::CallRuntimeLdLazySendableModuleVar,
        "callruntime.wideldlazysendablemodulevar" => Opcode::CallRuntimeWideLdLazySendableModuleVar,

        "wide.createobjectwithexcludedkeys" => Opcode::WideCreateObjectWithExcludedKeys,
        "wide.newobjrange" => Opcode::WideNewObjRange,
        "wide.newlexenv" => Opcode::WideNewLexEnv,
        "wide.newlexenvwithname" => Opcode::WideNewLexEnvWithName,
        "wide.callrange" => Opcode::WideCallRange,
        "wide.callthisrange" => Opcode::WideCallThisRange,
        "wide.supercallthisrange" => Opcode::WideSuperCallThisRange,
        "wide.supercallarrowrange" => Opcode::WideSuperCallArrowRange,
        "wide.ldobjbyindex" => Opcode::WideLdObjByIndex,
        "wide.stobjbyindex" => Opcode::WideStObjByIndex,
        "wide.stownbyindex" => Opcode::WideStOwnByIndex,
        "wide.copyrestargs" => Opcode::WideCopyRestArgs,
        "wide.ldlexvar" => Opcode::WideLdLexVar,
        "wide.stlexvar" => Opcode::WideStLexVar,
        "wide.getmodulenamespace" => Opcode::WideGetModuleNamespace,
        "wide.stmodulevar" => Opcode::WideStModuleVar,
        "wide.ldlocalmodulevar" => Opcode::WideLdLocalModuleVar,
        "wide.ldexternalmodulevar" => Opcode::WideLdExternalModuleVar,
        "wide.ldpatchvar" => Opcode::WideLdPatchVar,
        "wide.stpatchvar" => Opcode::WideStPatchVar,

        mnemonic if prefix == 0xfc => Opcode::Extended(mnemonic.to_owned()),

        _ => Opcode::Extended(mnemonic.to_owned()),
    }
}

fn make_register(width: RegisterWidth, raw: u16, register_count: u16) -> RegisterOperand {
    if raw < register_count as u16 {
        match width {
            RegisterWidth::V4 => RegisterOperand::V4(Register::new(raw)),
            RegisterWidth::V8 => RegisterOperand::V8(Register::new(raw)),
            RegisterWidth::V16 => RegisterOperand::V16(Register::new(raw)),
        }
    } else {
        let argument_index = raw.saturating_sub(register_count as u16);
        RegisterOperand::Argument(Register::new(argument_index))
    }
}

/// Converts an opcode byte to an Opcode enum variant
/// Converts an opcode byte to an Opcode enum variant using the generated lookup table
#[allow(dead_code)]
fn byte_to_opcode(opcode_byte: u8) -> ArkResult<Opcode> {
    // Get the mnemonic from the generated lookup table
    if let Some(entry) = INSTRUCTION_TABLE
        .get(opcode_byte as usize)
        .and_then(|opt| opt.as_ref())
    {
        let mnemonic = signature_to_mnemonic(entry.signature);
        Ok(opcode_from_signature(mnemonic, opcode_byte, entry.format))
    } else {
        Ok(Opcode::Extended(format!("unknown_0x{:02x}", opcode_byte)))
    }
}

fn opcode_from_signature(mnemonic: &str, opcode_byte: u8, format: InstructionFormat) -> Opcode {
    match mnemonic {
        // 0x00 - 0x0f
        "ldundefined" => Opcode::LdUndefined,
        "ldnull" => Opcode::LdNull,
        "ldtrue" => Opcode::LdTrue,
        "ldfalse" => Opcode::LdFalse,
        "createemptyobject" => Opcode::CreateEmptyObject,
        "createemptyarray" => Opcode::CreateEmptyArray,
        "createarraywithbuffer" => Opcode::CreateArrayWithBuffer,
        "createobjectwithbuffer" => Opcode::CreateObjectWithBuffer,
        "newobjrange" => Opcode::NewObjRange,
        "newlexenv" => Opcode::NewLexEnv,
        "add2" => Opcode::Add2,
        "sub2" => Opcode::Sub2,
        "mul2" => Opcode::Mul2,
        "div2" => Opcode::Div2,
        "mod2" => Opcode::Mod2,
        "eq" => Opcode::Eq,

        // 0x10 - 0x1f
        "noteq" => Opcode::NotEq,
        "less" => Opcode::Less,
        "lesseq" => Opcode::LessEq,
        "greater" => Opcode::Greater,
        "greatereq" => Opcode::GreaterEq,
        "shl2" => Opcode::Shl2,
        "shr2" => Opcode::Shr2,
        "ashr2" => Opcode::Ashr2,
        "and2" => Opcode::And2,
        "or2" => Opcode::Or2,
        "xor2" => Opcode::Xor2,
        "exp" => Opcode::Exp,
        "typeof" => Opcode::TypeOf,
        "tonumber" => Opcode::ToNumber,
        "tonumeric" => Opcode::ToNumeric,
        "neg" => Opcode::Neg,
        "not" => Opcode::Not,
        "inc" => Opcode::Inc,
        "dec" => Opcode::Dec,
        "istrue" => Opcode::IsTrue,
        "isfalse" => Opcode::IsFalse,

        // 0x20 - 0x2f
        "isin" => Opcode::IsIn,
        "instanceof" => Opcode::InstanceOf,
        "strictitempty" => Opcode::StrictNotEq,
        "stricteq" => Opcode::StrictEq,
        "callarg0" => Opcode::CallArg0,
        "callarg1" => Opcode::CallArg1,
        "callargs2" => Opcode::CallArgs2,
        "callargs3" => Opcode::CallArgs3,
        "callthis0" => Opcode::CallThis0,
        "callthis1" => Opcode::CallThis1,
        "callthis2" => Opcode::CallThis2,
        "callthis3" => Opcode::CallThis3,
        "callthisrange" => Opcode::CallThisRange,
        "supercallthisrange" => Opcode::SuperCallThisRange,
        "definefunc" => Opcode::DefineFunc,
        "definemethod" => Opcode::DefineMethod,
        "defineclasswithbuffer" => Opcode::DefineClassWithBuffer,
        "getnextpropname" => Opcode::GetNextPropName,

        // 0x30 - 0x3f
        "ldobjbyvalue" => Opcode::LdObjByValue,
        "stobjbyvalue" => Opcode::StObjByValue,
        "ldsuperbyvalue" => Opcode::LdSuperByValue,
        "ldobjbyindex" => Opcode::LdObjByIndex,
        "stobjbyindex" => Opcode::StObjByIndex,
        "ldlexvar" => Opcode::LdLexVar,
        "stlexvar" => Opcode::StLexVar,
        "lda.str" => Opcode::LdaStr,
        "tryldglobalbyname" => Opcode::TryLdGlobalByName,
        "trystglobalbyname" => Opcode::TryStGlobalByName,
        "ldglobalvar" => Opcode::LdGlobalVar,
        "ldobjbyname" => Opcode::LdObjByName,
        "stobjbyname" => Opcode::StObjByName,
        "mov" => match format {
            InstructionFormat::V4_V4 => Opcode::MovV4,
            InstructionFormat::V16_V16 => Opcode::MovV16,
            _ => Opcode::MovV8,
        },

        // 0x40 - 0x4f
        "ldsuperbyname" => Opcode::LdSuperByName,
        "stconsttoglobalrecord" => Opcode::StConstToGlobalRecord,
        "sttoglobalrecord" => Opcode::StToGlobalRecord,
        "ldthisbyname" => Opcode::LdThisByName,
        "stthisbyname" => Opcode::StThisByName,
        "ldthisbyvalue" => Opcode::LdThisByValue,
        "stthisbyvalue" => Opcode::StThisByValue,
        "jmp" => {
            // 0x4d is imm32, 0x4e is imm16, 0x98 is imm32
            match opcode_byte {
                0x4e => Opcode::JmpImm16,
                _ => Opcode::JmpImm32,
            }
        }
        "jeqz" => {
            // 0x4f is imm8, 0x50 is imm16, 0x9a is imm32
            match opcode_byte {
                0x4f => Opcode::JEqzImm8,
                0x50 => Opcode::JEqzImm16,
                _ => Opcode::JEqzImm32,
            }
        }
        "jnez" => {
            // 0x51 is imm8, 0x9b is imm16, 0x9c is imm32
            match opcode_byte {
                0x51 => Opcode::JNezImm8,
                0x9b => Opcode::JNezImm16,
                _ => Opcode::JNezImm32,
            }
        }
        "jstricteqz" => {
            // 0x52 is imm8, 0x9d is imm16
            if opcode_byte == 0x52 {
                Opcode::JStrictEqzImm8
            } else {
                Opcode::JStrictEqzImm16
            }
        }
        "jnstricteqz" => {
            // 0x53 is imm8, 0x9e is imm16
            if opcode_byte == 0x53 {
                Opcode::JNStrictEqzImm8
            } else {
                Opcode::JNStrictEqzImm16
            }
        }
        "jeqnull" => {
            // 0x54 is imm8, 0x9f is imm16
            if opcode_byte == 0x54 {
                Opcode::JEqNullImm8
            } else {
                Opcode::JEqNullImm16
            }
        }
        "jnenull" => {
            // 0x55 is imm8, 0xa0 is imm16
            if opcode_byte == 0x55 {
                Opcode::JNeNullImm8
            } else {
                Opcode::JNeNullImm16
            }
        }
        "jstricteqnull" => {
            // 0x56 is imm8, 0xa1 is imm16
            if opcode_byte == 0x56 {
                Opcode::JStrictEqNullImm8
            } else {
                Opcode::JStrictEqNullImm16
            }
        }
        "jnstricteqnull" => {
            // 0x57 is imm8, 0xa2 is imm16
            if opcode_byte == 0x57 {
                Opcode::JNStrictEqNullImm8
            } else {
                Opcode::JNStrictEqNullImm16
            }
        }
        "jequndefined" => {
            // 0x58 is imm8, 0xa3 is imm16
            if opcode_byte == 0x58 {
                Opcode::JEqUndefinedImm8
            } else {
                Opcode::JEqUndefinedImm16
            }
        }
        "jneundefined" => {
            // 0x59 is imm8, 0xa4 is imm16
            if opcode_byte == 0x59 {
                Opcode::JNeUndefinedImm8
            } else {
                Opcode::JNeUndefinedImm16
            }
        }
        "jstrictequndefined" => {
            // 0x5a is imm8, 0xa5 is imm16
            if opcode_byte == 0x5a {
                Opcode::JStrictEqUndefinedImm8
            } else {
                Opcode::JStrictEqUndefinedImm16
            }
        }
        "jnstrictequndefined" => {
            // 0x5b is imm8, 0xa6 is imm16
            if opcode_byte == 0x5b {
                Opcode::JNStrictEqUndefinedImm8
            } else {
                Opcode::JNStrictEqUndefinedImm16
            }
        }

        // 0x50 - 0x5f continued
        "jeq" => {
            // 0x5c is reg, imm8; 0xa7 is reg, imm16
            if opcode_byte == 0x5c {
                Opcode::JEqRegImm8
            } else {
                Opcode::JEqRegImm16
            }
        }
        "jne" => {
            // 0x5d is reg, imm8; 0xa8 is reg, imm16
            if opcode_byte == 0x5d {
                Opcode::JNeRegImm8
            } else {
                Opcode::JNeRegImm16
            }
        }
        "jstricteq" => {
            // 0x5e is reg, imm8; 0xa9 is reg, imm16
            if opcode_byte == 0x5e {
                Opcode::JStrictEqRegImm8
            } else {
                Opcode::JStrictEqRegImm16
            }
        }
        "jnstricteq" => {
            // 0x5f is reg, imm8; 0xaa is reg, imm16
            if opcode_byte == 0x5f {
                Opcode::JNStrictEqRegImm8
            } else {
                Opcode::JNStrictEqRegImm16
            }
        }

        // 0x60 - 0x6f
        "lda" => Opcode::Lda,
        "sta" => Opcode::Sta,
        "ldai" => Opcode::Ldai,
        "fldai" => Opcode::FLdai,
        "return" => Opcode::Return,
        "returnundefined" => Opcode::ReturnUndefined,
        "getpropiterator" => Opcode::GetPropIterator,
        "getiterator" => Opcode::GetIterator,
        "closeiterator" => Opcode::CloseIterator,
        "poplexenv" => Opcode::PopLexEnv,
        "ldnan" => Opcode::LdNan,
        "ldinfinity" => Opcode::LdInfinity,
        "getunmappedargs" => Opcode::GetUnmappedArgs,
        "ldglobal" => Opcode::LdGlobal,
        "ldnewtarget" => Opcode::LdNewTarget,
        "ldthis" => Opcode::LdThis,
        "ldhole" => Opcode::LdHole,

        // 0x70 - 0x7f
        "createregexpwithliteral" => Opcode::CreateRegExpWithLiteral,
        "createregexpwithliteralwide" => Opcode::CreateRegExpWithLiteralWide,
        "callrange" => Opcode::CallRange,
        "definefuncwide" => Opcode::DefineFuncWide,
        "defineclasswithbufferwide" => Opcode::DefineClassWithBufferWide,
        "gettemplaterobject" => Opcode::GetTemplateObject,
        "setobjectwithproto" => Opcode::SetObjectWithProto,
        "stownbyvalue" => Opcode::StOwnByValue,
        "stownbyindex" => Opcode::StOwnByIndex,
        "stownbyname" => Opcode::StOwnByName,
        "getmodulenamespace" => Opcode::GetModuleNamespace,
        "stmodulevar" => Opcode::StModuleVar,
        "ldlocalmodulevar" => Opcode::LdLocalModuleVar,
        "ldexternalmodulevar" => Opcode::LdExternalModuleVar,
        "stglobalvar" => Opcode::StGlobalVar,

        // 0x80 - 0x8f
        "createemptyarraywide" => Opcode::CreateEmptyArrayWide,
        "createarraywithbufferwide" => Opcode::CreateArrayWithBufferWide,
        "createobjectwithbufferwide" => Opcode::CreateObjectWithBufferWide,
        "newobjrangewide" => Opcode::NewObjRangeWide,
        "typeofwide" => Opcode::TypeOfWide,
        "ldobjbyvaluewide" => Opcode::LdObjByValueWide,
        "stobjbyvaluewide" => Opcode::StObjByValueWide,
        "ldsuperbyvaluewide" => Opcode::LdSuperByValueWide,
        "ldobjbyindexwide" => Opcode::LdObjByIndexWide,
        "stobjbyindexwide" => Opcode::StObjByIndexWide,
        "ldlexvarimm8" => Opcode::LdLexVarImm8,
        "stlexvarimm8" => Opcode::StLexVarImm8,
        "tryldglobalbynamewide" => Opcode::TryLdGlobalByNameWide,
        "trystglobalbynamewide" => Opcode::TryStGlobalByNameWide,
        "stownbynamewithnameset" => Opcode::StOwnByNameWithNameSet,

        // 0x90 - 0x9f
        "ldobjbynamewide" => Opcode::LdObjByNameWide,
        "stobjbynamewide" => Opcode::StObjByNameWide,
        "ldsuperbynamewide" => Opcode::LdSuperByNameWide,
        "ldthisbynamewide" => Opcode::LdThisByNameWide,
        "stthisbynamewide" => Opcode::StThisByNameWide,
        "ldthisbyvaluewide" => Opcode::LdThisByValueWide,
        "stthisbyvaluewide" => Opcode::StThisByValueWide,
        "asyncgeneratorreject" => Opcode::AsyncGeneratorReject,

        // 0xa0 - 0xaf
        "stownbyvaluewithnameset" => Opcode::StOwnByValueWithNameSet,
        "getiteratorwide" => Opcode::GetIteratorWide,
        "closeiteratorwide" => Opcode::CloseIteratorWide,
        "ldsymbol" => Opcode::LdSymbol,
        "asyncfunctionenter" => Opcode::AsyncFunctionEnter,
        "ldfunction" => Opcode::LdFunction,
        "debugger" => Opcode::Debugger,
        "creategeneratorobj" => Opcode::CreateGeneratorObj,
        "createiterresultobj" => Opcode::CreateIterResultObj,
        "createobjectwithexcludedkeys" => Opcode::CreateObjectWithExcludedKeys,
        "newobjapply" => Opcode::NewObjApply,
        "newobjapplywide" => Opcode::NewObjApplyWide,
        "newlexenvwithname" => Opcode::NewLexEnvWithName,

        // 0xb0 - 0xbf
        "createasyncgeneratorobj" => Opcode::CreateAsyncGeneratorObj,
        "asyncgeneratorresolve" => Opcode::AsyncGeneratorResolve,
        "supercallspread" => Opcode::SuperCallSpread,
        "apply" => Opcode::Apply,
        "supercallarrowrange" => Opcode::SuperCallArrowRange,
        "definegettersetterbyvalue" => Opcode::DefineGetterSetterByValue,
        "dynamicimport" => Opcode::DynamicImport,
        "definemethodwide" => Opcode::DefineMethodWide,
        "resumegenerator" => Opcode::ResumeGenerator,
        "getresumemode" => Opcode::GetResumeMode,
        "gettemplaterobjectwide" => Opcode::GetTemplateObjectWide,
        "delobjprop" => Opcode::DelObjProp,
        "suspendgenerator" => Opcode::SuspendGenerator,
        "asyncfunctionawaituncaught" => Opcode::AsyncFunctionAwaitUncaught,
        "copydataproperties" => Opcode::CopyDataProperties,
        "starrayspread" => Opcode::StArraySpread,

        // Fallback for any unknown mnemonics
        unknown => Opcode::Extended(format!("unknown_0x{:02x}_{}", opcode_byte, unknown)),
    }
}

/// Checks if a new basic block should be started based on the last instruction
fn should_start_new_block(instructions: &[Instruction]) -> bool {
    if let Some(last) = instructions.last() {
        is_terminating_instruction(last)
    } else {
        false
    }
}

/// Checks if an instruction terminates a basic block
fn is_terminating_instruction(instruction: &Instruction) -> bool {
    matches!(
        instruction.opcode,
        Opcode::JmpImm8
            | Opcode::JmpImm16
            | Opcode::JmpImm32
            | Opcode::JEqzImm8
            | Opcode::JEqzImm16
            | Opcode::JEqzImm32
            | Opcode::JNezImm8
            | Opcode::JNezImm16
            | Opcode::JNezImm32
            | Opcode::Return
            | Opcode::ReturnUndefined
    )
}

#[cfg(test)]
mod opcode_tests {
    use super::*;

    #[test]
    fn test_opcode_mappings() {
        // Test that key opcodes are correctly mapped
        assert_eq!(byte_to_opcode(0x00).unwrap(), Opcode::LdUndefined);
        assert_eq!(byte_to_opcode(0x09).unwrap(), Opcode::NewLexEnv);
        assert_eq!(byte_to_opcode(0x0a).unwrap(), Opcode::Add2);
        assert_eq!(byte_to_opcode(0x10).unwrap(), Opcode::NotEq);
        assert_eq!(byte_to_opcode(0x2f).unwrap(), Opcode::CallThis2);
        assert_eq!(byte_to_opcode(0x37).unwrap(), Opcode::LdObjByValue);
        assert_eq!(byte_to_opcode(0x44).unwrap(), Opcode::MovV4);
        assert_eq!(byte_to_opcode(0x4d).unwrap(), Opcode::JmpImm32);
        assert_eq!(byte_to_opcode(0x60).unwrap(), Opcode::Lda);
        assert_eq!(byte_to_opcode(0x64).unwrap(), Opcode::Return);
        assert_eq!(byte_to_opcode(0x6e).unwrap(), Opcode::LdNewTarget);
        assert_eq!(byte_to_opcode(0x70).unwrap(), Opcode::LdHole);
        assert_eq!(byte_to_opcode(0x73).unwrap(), Opcode::CallRange);
        assert_eq!(byte_to_opcode(0x7e).unwrap(), Opcode::LdExternalModuleVar);
        assert_eq!(byte_to_opcode(0xb6).unwrap(), Opcode::NewLexEnvWithName);

        // Verify mnemonics are correct
        assert_eq!(byte_to_opcode(0x6e).unwrap().mnemonic(), "ldnewtarget");
        assert_eq!(byte_to_opcode(0x2f).unwrap().mnemonic(), "callthis2");
        assert_eq!(byte_to_opcode(0x70).unwrap().mnemonic(), "ldhole");
        assert_eq!(byte_to_opcode(0x73).unwrap().mnemonic(), "callrange");
        assert_eq!(byte_to_opcode(0x78).unwrap().mnemonic(), "stownbyvalue");
        assert_eq!(byte_to_opcode(0x30).unwrap().mnemonic(), "callthis3");
        assert_eq!(byte_to_opcode(0x5e).unwrap().mnemonic(), "jstricteq");
        assert_eq!(
            byte_to_opcode(0x5b).unwrap().mnemonic(),
            "jnstrictequndefined"
        );
    }
}
