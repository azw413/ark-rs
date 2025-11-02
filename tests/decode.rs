use ark_rs::abc_bytecode::decode_function_body;
use ark_rs::instructions::{Operand, RegisterOperand};
use ark_rs::types::{FieldType, FunctionId, FunctionSignature, PrimitiveType, TypeDescriptor};
use ark_rs::{abc_binary::BinaryAbcFile, abc_types::AbcMethodItem};

fn find_method<'a>(methods: &'a [AbcMethodItem], name: &str) -> &'a AbcMethodItem {
    methods
        .iter()
        .find(|method| method.name.value == name)
        .unwrap_or_else(|| panic!("missing method {name}"))
}

#[test]
fn decode_on_create_matches_reference() {
    let data = std::fs::read("test-data/modules.abc").expect("read modules.abc");

    let signature = FunctionSignature::new(
        Vec::new(),
        FieldType::new(TypeDescriptor::Primitive(PrimitiveType::Any)),
    );

    let function = decode_function_body(&data, 0x1aac, FunctionId::new(0), None, signature)
        .expect("decode onCreate body");

    let opcodes: Vec<String> = function
        .instruction_block
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .take(12)
        .map(|instr| instr.opcode.mnemonic().to_string())
        .collect();

    let expected = vec![
        "mov",
        "mov",
        "mov",
        "mov",
        "mov",
        "lda",
        "sta",
        "lda",
        "ldobjbyname",
        "sta",
        "lda",
        "ldobjbyname",
    ];
    assert_eq!(opcodes, expected);

    assert_eq!(function.parameters.len(), 5);

    let first = &function.instruction_block.blocks[0].instructions[0];
    match first.operands.as_slice() {
        [
            Operand::Register(RegisterOperand::V4(dest)),
            Operand::Register(RegisterOperand::Argument(arg)),
        ] => {
            assert_eq!(dest.0, 0);
            assert_eq!(arg.0, 0);
        }
        other => panic!("unexpected operands for first instruction: {:?}", other),
    }
}

#[test]
fn binary_method_index_resolves_code_offsets() {
    let data = std::fs::read("test-data/modules.abc").expect("read modules.abc");
    let binary = BinaryAbcFile::parse(&data).expect("parse binary abc");
    let code_map = binary.method_code_map();

    let entry_on_create = find_method(&binary.methods, "#~@0>#onCreate");
    assert_eq!(code_map.get(&entry_on_create.name.offset), Some(&0x1aac));

    let entry_func_main = find_method(&binary.methods, "func_main_0");
    assert_eq!(code_map.get(&entry_func_main.name.offset), Some(&0x1cc6));
}

#[test]
fn inspect_on_backup_exception_ranges() {
    let data = std::fs::read("test-data/modules.abc").expect("read modules.abc");
    let signature = FunctionSignature::new(
        Vec::new(),
        FieldType::new(TypeDescriptor::Primitive(PrimitiveType::Any)),
    );

    let function = decode_function_body(&data, 0x1d26, FunctionId::new(0), None, signature)
        .expect("decode onBackup");

    assert!(!function.exception_handlers.is_empty());
    let handler = &function.exception_handlers[0];
    assert!(handler.try_start < handler.try_end);
    assert!(handler.handler_start >= handler.try_end);
    assert!(handler.handler_end > handler.handler_start);
    assert!(handler.exception_type.is_none());
}
