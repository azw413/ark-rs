//! Helpers for formatting Ark bytecode structures into the textual disassembly form.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{self, Write};

use super::functions::Function;
use super::instructions::{IdentifierOperand, ImmediateOperand, Operand, RegisterOperand};
use crate::lowlevel::TypeDescriptor;

/// Render a single [`Function`] into the Ark textual disassembly representation.
pub fn format_function(function: &Function) -> Result<String, fmt::Error> {
    let mut output = String::new();
    write_function(&mut output, function)?;
    Ok(output)
}

/// Internal formatter that writes directly into a [`fmt::Write`] instance.
pub fn write_function<W: Write>(mut w: W, function: &Function) -> fmt::Result {
    let return_ty = &function.signature.return_type;
    let name = function.name.as_deref().unwrap_or("<unnamed>");

    write!(w, ".function {} {}(", return_ty, name)?;

    for (index, param) in function.parameters.iter().enumerate() {
        if index > 0 {
            write!(w, ", ")?;
        }
        let param_type = &param.type_name;
        let param_name = param
            .name
            .as_deref()
            .unwrap_or_else(|| fallback_param_name(index));
        write!(w, "{} {}", param_type, param_name)?;
    }

    writeln!(w, ") {{")?;

    let mut flat_instructions = Vec::new();
    for block in &function.instruction_block.blocks {
        for instruction in &block.instructions {
            flat_instructions.push(instruction);
        }
    }

    let mut label_map: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut branch_lookup: HashMap<u32, String> = HashMap::new();
    let mut branch_order: Vec<(u32, String)> = Vec::new();

    for instruction in &flat_instructions {
        for operand in &instruction.operands {
            if let Operand::Label(offset) = operand {
                if !branch_lookup.contains_key(offset) {
                    let name = format!("jump_label_{}", branch_order.len());
                    branch_lookup.insert(*offset, name.clone());
                    branch_order.push((*offset, name));
                }
            }
        }
    }

    for (offset, name) in &branch_order {
        add_label(&mut label_map, *offset, name.clone());
    }

    for handler in &function.exception_handlers {
        add_label(
            &mut label_map,
            handler.try_start,
            format!("try_begin_label_{}", handler.try_index),
        );
        add_label(
            &mut label_map,
            handler.try_end,
            format!("try_end_label_{}", handler.try_index),
        );
        add_label(
            &mut label_map,
            handler.handler_end,
            format!(
                "handler_end_label_{}_{}",
                handler.try_index, handler.catch_index
            ),
        );
    }

    let mut printed_label_offsets = BTreeSet::new();

    for block in &function.instruction_block.blocks {
        for instruction in &block.instructions {
            if let Some(labels) = label_map.get(&instruction.bytecode_offset) {
                for label in labels {
                    writeln!(w, "{}:", label)?;
                }
                printed_label_offsets.insert(instruction.bytecode_offset);
            }

            let mnemonic = instruction.opcode.mnemonic();
            write!(w, "    {}", mnemonic)?;
            let operands = format_operands(&instruction.operands, &branch_lookup);
            if !operands.is_empty() {
                write!(w, " ")?;
                for (index, operand) in operands.iter().enumerate() {
                    if index > 0 {
                        write!(w, ", ")?;
                    }
                    write!(w, "{}", operand)?;
                }
            }
            writeln!(w)?;
        }
    }

    for (offset, labels) in &label_map {
        if printed_label_offsets.contains(offset) {
            continue;
        }
        for label in labels {
            writeln!(w, "{}:", label)?;
        }
        printed_label_offsets.insert(*offset);
    }

    writeln!(w)?;

    if !function.exception_handlers.is_empty() {
        for handler in &function.exception_handlers {
            if let Some(type_id) = handler.exception_type {
                writeln!(
                    w,
                    ".catch type#{}, try_begin_label_{}, try_end_label_{}, try_end_label_{}, handler_end_label_{}_{}",
                    type_id.0,
                    handler.try_index,
                    handler.try_index,
                    handler.try_index,
                    handler.try_index,
                    handler.catch_index
                )?;
            } else {
                writeln!(
                    w,
                    ".catchall try_begin_label_{}, try_end_label_{}, try_end_label_{}, handler_end_label_{}_{}",
                    handler.try_index,
                    handler.try_index,
                    handler.try_index,
                    handler.try_index,
                    handler.catch_index
                )?;
            }
        }
    }

    writeln!(w, "}}")?;
    Ok(())
}

fn add_label(labels: &mut BTreeMap<u32, Vec<String>>, offset: u32, label: String) {
    let entry = labels.entry(offset).or_default();
    if !entry.iter().any(|existing| existing == &label) {
        entry.push(label);
    }
}

fn format_operands(operands: &[Operand], label_lookup: &HashMap<u32, String>) -> Vec<String> {
    operands
        .iter()
        .map(|operand| match operand {
            Operand::Register(register) => format_register_operand(*register),
            Operand::Immediate(immediate) => format_immediate_operand(*immediate),
            Operand::Identifier(identifier) => format_identifier_operand(*identifier),
            Operand::String(value) => escape_string(value),
            Operand::Type(descriptor) => format_type_descriptor(descriptor),
            Operand::TypeId(type_id) => format!("type#{}", type_id.0),
            Operand::Field(field_id) => format!("field#{}", field_id.0),
            Operand::Function(function_id) => format!("func#{}", function_id.0),
            Operand::MethodHandle(handle_id) => format!("methodhandle#{}", handle_id),
            Operand::LiteralIndex(index) => format!("literal#{}", index),
            Operand::Label(label) => label_lookup
                .get(label)
                .cloned()
                .unwrap_or_else(|| format!("+0x{:x}", label)),
            Operand::ConditionCode(code) => format!("{:?}", code).to_ascii_lowercase(),
            Operand::Comparison(kind) => format!("{:?}", kind).to_ascii_lowercase(),
        })
        .collect()
}

fn format_register_operand(register: RegisterOperand) -> String {
    match register {
        RegisterOperand::V4(reg) | RegisterOperand::V8(reg) | RegisterOperand::V16(reg) => {
            format!("v{}", reg.0)
        }
        RegisterOperand::Argument(reg) => format!("a{}", reg.0),
        RegisterOperand::Span(span) => {
            let start = span.start.0 as u32;
            let count = u32::from(span.count.saturating_sub(1));
            let end = start + count;
            format!("v{}-v{}", start, end)
        }
    }
}

fn format_immediate_operand(immediate: ImmediateOperand) -> String {
    match immediate {
        ImmediateOperand::Imm4(value) => format!("0x{:x}", value),
        ImmediateOperand::Imm8(value) => format!("0x{:x}", value),
        ImmediateOperand::Imm16(value) => format!("0x{:x}", value),
        ImmediateOperand::Imm32(value) => format!("0x{:x}", value),
        ImmediateOperand::Imm64(value) => format!("0x{:x}", value),
    }
}

fn format_identifier_operand(identifier: IdentifierOperand) -> String {
    match identifier {
        IdentifierOperand::Id16(id) => format!("@0x{:x}", id),
    }
}

fn escape_string(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\t' => result.push_str("\\t"),
            other => result.push(other),
        }
    }
    result.push('"');
    result
}

fn format_type_descriptor(descriptor: &TypeDescriptor) -> String {
    match descriptor {
        TypeDescriptor::Primitive(primitive) => format!("{:?}", primitive).to_ascii_lowercase(),
        TypeDescriptor::Type(type_id) => format!("type#{}", type_id.0),
        TypeDescriptor::Function(function_id) => format!("func#{}", function_id.0),
        TypeDescriptor::Array {
            element,
            dimensions,
        } => {
            let element_str = format_type_descriptor(element);
            format!("{}[{}]", element_str, dimensions)
        }
        TypeDescriptor::Generic { base, arguments } => {
            let base_str = format!("type#{}", base.0);
            let args: Vec<String> = arguments.iter().map(format_type_descriptor).collect();
            format!("{}<{}>", base_str, args.join(", "))
        }
        TypeDescriptor::TypeParameter { owner, index } => format!("tparam#{}_{}", owner.0, index),
        TypeDescriptor::Union(types) => {
            let parts: Vec<String> = types.iter().map(format_type_descriptor).collect();
            parts.join(" | ")
        }
        TypeDescriptor::Intersection(types) => {
            let parts: Vec<String> = types.iter().map(format_type_descriptor).collect();
            parts.join(" & ")
        }
        TypeDescriptor::Unknown(id) => format!("unknown#{}", id),
    }
}

fn fallback_param_name(index: usize) -> &'static str {
    match index {
        0 => "a0",
        1 => "a1",
        2 => "a2",
        3 => "a3",
        4 => "a4",
        5 => "a5",
        _ => "a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::highlevel::functions::{BasicBlock, Function, FunctionParameter, FunctionSignature};
    use crate::highlevel::instructions::{
        IdentifierOperand, ImmediateOperand, Instruction, InstructionFormat, InstructionIndex,
        Opcode, Operand, Register, RegisterOperand,
    };
    use crate::lowlevel::FunctionId;

    #[test]
    fn format_sample_function() {
        let mut signature = FunctionSignature::new("any");
        signature.parameters = vec!["any".to_owned(), "any".to_owned(), "any".to_owned()];

        let mut function = Function::new(FunctionId::new(0), signature);
        function.name = Some(".func_main_0".to_owned());
        function.parameters = vec![
            FunctionParameter {
                name: Some("a0".to_owned()),
                type_name: "any".to_owned(),
                default_literal: None,
                is_optional: false,
            },
            FunctionParameter {
                name: Some("a1".to_owned()),
                type_name: "any".to_owned(),
                default_literal: None,
                is_optional: false,
            },
            FunctionParameter {
                name: Some("a2".to_owned()),
                type_name: "any".to_owned(),
                default_literal: None,
                is_optional: false,
            },
        ];
        function.register_count = 2;

        let mut block = BasicBlock::new(0);
        let mut index = 0;

        block.instructions.push(make_instruction(
            &mut index,
            Opcode::GetModuleNamespace,
            InstructionFormat::IMM8,
            vec![Operand::Immediate(ImmediateOperand::Imm8(1))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Ldai,
            InstructionFormat::IMM32,
            vec![Operand::Immediate(ImmediateOperand::Imm32(3))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::StModuleVar,
            InstructionFormat::IMM8,
            vec![Operand::Immediate(ImmediateOperand::Imm8(0))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::LdExternalModuleVar,
            InstructionFormat::IMM8,
            vec![Operand::Immediate(ImmediateOperand::Imm8(0))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Sta,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(0)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::ThrowUndefinedIfHoleWithName,
            InstructionFormat::PREF_ID16,
            vec![Operand::String("a".to_owned())],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::LdExternalModuleVar,
            InstructionFormat::IMM8,
            vec![Operand::Immediate(ImmediateOperand::Imm8(1))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Sta,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(1)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::ThrowUndefinedIfHoleWithName,
            InstructionFormat::PREF_ID16,
            vec![Operand::String("b".to_owned())],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Lda,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(1)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Add2,
            InstructionFormat::IMM8_V8,
            vec![
                Operand::Immediate(ImmediateOperand::Imm8(0)),
                Operand::Register(RegisterOperand::V8(Register(0))),
            ],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Sta,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(0)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::LdLocalModuleVar,
            InstructionFormat::IMM8,
            vec![Operand::Immediate(ImmediateOperand::Imm8(0))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Sta,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(1)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::ThrowUndefinedIfHoleWithName,
            InstructionFormat::PREF_ID16,
            vec![Operand::String("d".to_owned())],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Lda,
            InstructionFormat::V8,
            vec![Operand::Register(RegisterOperand::V8(Register(1)))],
        ));
        block.instructions.push(make_instruction(
            &mut index,
            Opcode::Add2,
            InstructionFormat::IMM8_V8,
            vec![
                Operand::Immediate(ImmediateOperand::Imm8(1)),
                Operand::Register(RegisterOperand::V8(Register(0))),
            ],
        ));

        function.instruction_block.blocks.push(block);

        let disassembled = format_function(&function).expect("format failed");

        let expected = concat!(
            ".function any .func_main_0(any a0, any a1, any a2) {\n",
            "    getmodulenamespace 0x1\n",
            "    ldai 0x3\n",
            "    stmodulevar 0x0\n",
            "    ldexternalmodulevar 0x0\n",
            "    sta v0\n",
            "    throw.undefinedifholewithname \"a\"\n",
            "    ldexternalmodulevar 0x1\n",
            "    sta v1\n",
            "    throw.undefinedifholewithname \"b\"\n",
            "    lda v1\n",
            "    add2 0x0, v0\n",
            "    sta v0\n",
            "    ldlocalmodulevar 0x0\n",
            "    sta v1\n",
            "    throw.undefinedifholewithname \"d\"\n",
            "    lda v1\n",
            "    add2 0x1, v0\n",
            "\n",
            "}\n",
        );

        assert_eq!(disassembled, expected);
    }

    fn make_instruction(
        index: &mut u32,
        opcode: Opcode,
        format: InstructionFormat,
        operands: Vec<Operand>,
    ) -> Instruction {
        let mut instruction =
            Instruction::with_format(InstructionIndex::new(*index), opcode, format);
        instruction.operands = operands;
        *index += 1;
        instruction
    }

    #[test]
    fn operand_rendering_covers_all_formats() {
        use InstructionFormat::*;

        let imm4 = |v: u8| Operand::Immediate(ImmediateOperand::Imm4(v));
        let imm8 = |v: u8| Operand::Immediate(ImmediateOperand::Imm8(v));
        let imm16 = |v: u16| Operand::Immediate(ImmediateOperand::Imm16(v));
        let imm32 = |v: u32| Operand::Immediate(ImmediateOperand::Imm32(v));
        let imm64 = |v: u64| Operand::Immediate(ImmediateOperand::Imm64(v));
        let id16 = |v: u16| Operand::Identifier(IdentifierOperand::Id16(v));
        let reg_v4 = |v: u16| Operand::Register(RegisterOperand::V4(Register(v)));
        let reg_v8 = |v: u16| Operand::Register(RegisterOperand::V8(Register(v)));
        let reg_v16 = |v: u16| Operand::Register(RegisterOperand::V16(Register(v)));

        let cases: Vec<(InstructionFormat, Vec<Operand>, &str)> = vec![
            (NONE, vec![], ""),
            (ID16, vec![id16(0x1234)], "@0x1234"),
            (IMM4_IMM4, vec![imm4(0x1), imm4(0x2)], "0x1, 0x2"),
            (IMM8, vec![imm8(0x12)], "0x12"),
            (IMM8_ID16, vec![imm8(0x12), id16(0x1234)], "0x12, @0x1234"),
            (
                IMM8_ID16_IMM8,
                vec![imm8(0x12), id16(0x1234), imm8(0x34)],
                "0x12, @0x1234, 0x34",
            ),
            (
                IMM8_ID16_ID16_IMM16_V8,
                vec![
                    imm8(0x12),
                    id16(0x1234),
                    id16(0x5678),
                    imm16(0x9abc),
                    reg_v8(0),
                ],
                "0x12, @0x1234, @0x5678, 0x9abc, v0",
            ),
            (
                IMM8_ID16_V8,
                vec![imm8(0x12), id16(0x1234), reg_v8(0)],
                "0x12, @0x1234, v0",
            ),
            (IMM8_IMM8, vec![imm8(0x12), imm8(0x34)], "0x12, 0x34"),
            (
                IMM8_IMM8_V8,
                vec![imm8(0x12), imm8(0x34), reg_v8(0)],
                "0x12, 0x34, v0",
            ),
            (IMM8_IMM16, vec![imm8(0x12), imm16(0x9abc)], "0x12, 0x9abc"),
            (
                IMM8_IMM16_IMM16,
                vec![imm8(0x12), imm16(0x9abc), imm16(0xdef0)],
                "0x12, 0x9abc, 0xdef0",
            ),
            (
                IMM8_IMM16_IMM16_V8,
                vec![imm8(0x12), imm16(0x9abc), imm16(0xdef0), reg_v8(0)],
                "0x12, 0x9abc, 0xdef0, v0",
            ),
            (IMM8_V8, vec![imm8(0x12), reg_v8(0)], "0x12, v0"),
            (
                IMM8_V8_IMM16,
                vec![imm8(0x12), reg_v8(0), imm16(0x9abc)],
                "0x12, v0, 0x9abc",
            ),
            (
                IMM8_V8_V8,
                vec![imm8(0x12), reg_v8(0), reg_v8(1)],
                "0x12, v0, v1",
            ),
            (
                IMM8_V8_V8_V8,
                vec![imm8(0x12), reg_v8(0), reg_v8(1), reg_v8(2)],
                "0x12, v0, v1, v2",
            ),
            (
                IMM8_V8_V8_V8_V8,
                vec![imm8(0x12), reg_v8(0), reg_v8(1), reg_v8(2), reg_v8(3)],
                "0x12, v0, v1, v2, v3",
            ),
            (IMM16, vec![imm16(0x9abc)], "0x9abc"),
            (
                IMM16_ID16,
                vec![imm16(0x9abc), id16(0x1234)],
                "0x9abc, @0x1234",
            ),
            (
                IMM16_ID16_IMM8,
                vec![imm16(0x9abc), id16(0x1234), imm8(0x12)],
                "0x9abc, @0x1234, 0x12",
            ),
            (
                IMM16_ID16_V8,
                vec![imm16(0x9abc), id16(0x1234), reg_v8(0)],
                "0x9abc, @0x1234, v0",
            ),
            (
                IMM16_ID16_ID16_IMM16_V8,
                vec![
                    imm16(0x9abc),
                    id16(0x1234),
                    id16(0x5678),
                    imm16(0xdef0),
                    reg_v8(0),
                ],
                "0x9abc, @0x1234, @0x5678, 0xdef0, v0",
            ),
            (
                IMM16_IMM16,
                vec![imm16(0x9abc), imm16(0xdef0)],
                "0x9abc, 0xdef0",
            ),
            (
                IMM16_IMM8_V8,
                vec![imm16(0x9abc), imm8(0x12), reg_v8(0)],
                "0x9abc, 0x12, v0",
            ),
            (IMM16_V8, vec![imm16(0x9abc), reg_v8(0)], "0x9abc, v0"),
            (
                IMM16_V8_IMM16,
                vec![imm16(0x9abc), reg_v8(0), imm16(0xdef0)],
                "0x9abc, v0, 0xdef0",
            ),
            (
                IMM16_V8_V8,
                vec![imm16(0x9abc), reg_v8(0), reg_v8(1)],
                "0x9abc, v0, v1",
            ),
            (IMM32, vec![imm32(0x12345678)], "0x12345678"),
            (IMM64, vec![imm64(0x123456789abcdef0)], "0x123456789abcdef0"),
            (PREF_NONE, vec![], ""),
            (PREF_IMM8, vec![imm8(0x12)], "0x12"),
            (PREF_IMM8_V8, vec![imm8(0x12), reg_v8(0)], "0x12, v0"),
            (
                PREF_IMM8_V8_V8,
                vec![imm8(0x12), reg_v8(0), reg_v8(1)],
                "0x12, v0, v1",
            ),
            (PREF_IMM8_IMM8, vec![imm8(0x12), imm8(0x34)], "0x12, 0x34"),
            (
                PREF_IMM8_IMM32_V8,
                vec![imm8(0x12), imm32(0x12345678), reg_v8(0)],
                "0x12, 0x12345678, v0",
            ),
            (
                PREF_IMM8_IMM16_IMM16_V8,
                vec![imm8(0x12), imm16(0x9abc), imm16(0xdef0), reg_v8(0)],
                "0x12, 0x9abc, 0xdef0, v0",
            ),
            (PREF_IMM4_IMM4, vec![imm4(0x1), imm4(0x2)], "0x1, 0x2"),
            (PREF_IMM16, vec![imm16(0x9abc)], "0x9abc"),
            (PREF_IMM16_V8, vec![imm16(0x9abc), reg_v8(0)], "0x9abc, v0"),
            (
                PREF_IMM16_V8_V8,
                vec![imm16(0x9abc), reg_v8(0), reg_v8(1)],
                "0x9abc, v0, v1",
            ),
            (
                PREF_IMM16_ID16,
                vec![imm16(0x9abc), id16(0x1234)],
                "0x9abc, @0x1234",
            ),
            (
                PREF_IMM16_ID16_ID16_IMM16_V8,
                vec![
                    imm16(0x9abc),
                    id16(0x1234),
                    id16(0x5678),
                    imm16(0xdef0),
                    reg_v8(0),
                ],
                "0x9abc, @0x1234, @0x5678, 0xdef0, v0",
            ),
            (
                PREF_IMM16_IMM16,
                vec![imm16(0x9abc), imm16(0xdef0)],
                "0x9abc, 0xdef0",
            ),
            (PREF_IMM32, vec![imm32(0x12345678)], "0x12345678"),
            (PREF_V8, vec![reg_v8(0)], "v0"),
            (PREF_V8_V8, vec![reg_v8(0), reg_v8(1)], "v0, v1"),
            (PREF_V8_ID16, vec![reg_v8(0), id16(0x1234)], "v0, @0x1234"),
            (
                PREF_V8_IMM32,
                vec![reg_v8(0), imm32(0x12345678)],
                "v0, 0x12345678",
            ),
            (PREF_ID16, vec![id16(0x1234)], "@0x1234"),
            (V4_V4, vec![reg_v4(0), reg_v4(1)], "v0, v1"),
            (V8, vec![reg_v8(0)], "v0"),
            (V8_IMM8, vec![reg_v8(0), imm8(0x12)], "v0, 0x12"),
            (V8_IMM16, vec![reg_v8(0), imm16(0x9abc)], "v0, 0x9abc"),
            (V8_V8, vec![reg_v8(0), reg_v8(1)], "v0, v1"),
            (
                V8_V8_V8,
                vec![reg_v8(0), reg_v8(1), reg_v8(2)],
                "v0, v1, v2",
            ),
            (
                V8_V8_V8_V8,
                vec![reg_v8(0), reg_v8(1), reg_v8(2), reg_v8(3)],
                "v0, v1, v2, v3",
            ),
            (V16_V16, vec![reg_v16(0), reg_v16(1)], "v0, v1"),
        ];

        assert_eq!(cases.len(), 58);

        for (format, operands, expected) in cases {
            let rendered = format_operands(&operands, &HashMap::new()).join(", ");
            assert_eq!(rendered, expected, "format {:?}", format);
        }
    }

    #[test]
    fn identifier_operands_render_with_hex_prefix() {
        let rendered = format_operands(
            &[Operand::Identifier(IdentifierOperand::Id16(0x2a))],
            &HashMap::new(),
        );

        assert_eq!(rendered, vec!["@0x2a".to_owned()]);
    }
}
