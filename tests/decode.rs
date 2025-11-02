use ark_rs::abc_bytecode::decode_function_body;
use ark_rs::instructions::{Operand, RegisterOperand};
use ark_rs::types::{FieldType, FunctionId, FunctionSignature, PrimitiveType, TypeDescriptor};

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
