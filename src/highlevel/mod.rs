pub mod attributes;
pub mod classes;
pub mod disassembly;
pub mod functions;
pub mod instructions;
pub mod module;
pub mod parser;

pub use module::{
    ArkModule, ArkParseError, ArkSegment, FunctionEntry as ArkFunctionEntry,
    LiteralEntry as ArkLiteralEntry, RecordEntry as ArkRecordEntry, parse_ark_module,
};

pub use functions::{
    BasicBlock as ArkBasicBlock, ExceptionHandler as ArkExceptionHandler, Function as ArkFunction,
    FunctionFlag as ArkFunctionFlag, FunctionKind as ArkFunctionKind,
    FunctionParameter as ArkFunctionParameter, FunctionSignature as ArkFunctionSignature,
    InstructionBlock as ArkInstructionBlock,
};

pub use instructions::{
    ComparisonKind, ConditionCode, IdentifierOperand, IdentifierWidth, ImmediateOperand,
    ImmediateWidth, Instruction, InstructionFlags, InstructionFormat, InstructionIndex, Opcode,
    Operand, OperandKind, Register, RegisterOperand, RegisterSpan, RegisterWidth,
};

pub use disassembly::{format_function, write_function};
pub use parser::{ParseError, parse_function};

pub use classes::{
    ClassDefinition as ArkClassDefinition, ClassField as ArkClassField, ClassFlag as ArkClassFlag,
    ClassMetadata as ArkClassMetadata, ClassMethod as ArkClassMethod,
    ClassMethodBody as ArkClassMethodBody, MethodId, TypeParameter as ArkTypeParameter,
};

pub use attributes::{
    Attribute as ArkAttribute, AttributeKind as ArkAttributeKind, DebugInfo as ArkDebugInfo,
    LineNumberEntry as ArkLineNumberEntry, LocalVariableEntry as ArkLocalVariableEntry,
    RuntimeAnnotation as ArkRuntimeAnnotation, SourceMapEntry as ArkSourceMapEntry,
};
