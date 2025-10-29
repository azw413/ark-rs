//! Core data structures for representing Ark bytecode in memory.

pub mod abc;
pub mod abc_binary;
pub mod abc_types;
pub mod attributes;
pub mod classes;
pub mod constant_pool;
pub mod disassembly;
pub mod error;
pub mod file;
pub mod functions;
pub mod header;
pub mod instructions;
pub mod parser;
pub mod types;

pub use abc::{
    AbcFile, AbcParseError, AbcSegment, FunctionEntry as AbcFunctionEntry,
    LiteralEntry as AbcLiteralEntry, RecordEntry as AbcRecordEntry, parse_abc_file,
};
pub use abc_binary::BinaryAbcFile;
pub use abc_types::{
    AbcEntityId, AbcHeader as AbcBinaryHeader, AbcIndexHeader as AbcBinaryIndexHeader, AbcReader,
    AbcSectionRange, AbcVersion as AbcBinaryVersion, AbcWriter,
};
pub use attributes::{
    Attribute, AttributeKind, DebugInfo, LineNumberEntry, LocalVariableEntry, RuntimeAnnotation,
    SourceMapEntry,
};
pub use classes::{
    ClassDefinition, ClassField, ClassFlag, ClassMetadata, ClassMethod, ClassMethodBody, MethodId,
    TypeParameter,
};
pub use constant_pool::{
    ConstantPool, ConstantPoolEntry, FieldDescriptor, LiteralArray, LiteralValue, MethodHandle,
    MethodHandleKind, MethodPrototype, StringRecord,
};
pub use disassembly::{format_function, write_function};
pub use error::{ArkError, ArkResult};
pub use file::{ArkBytecodeFile, SectionInfo, SectionOffsets, SourceFileRecord};
pub use functions::{
    BasicBlock, ExceptionHandler, Function, FunctionFlag, FunctionKind, FunctionParameter,
    InstructionBlock,
};
pub use header::{Endianness, FileFlags, FileHeader, FileVersion, ModuleKind};
pub use instructions::{
    ComparisonKind, ConditionCode, IdentifierOperand, IdentifierWidth, ImmediateOperand,
    ImmediateWidth, Instruction, InstructionFlags, InstructionFormat, InstructionIndex, Opcode,
    Operand, OperandKind, Register, RegisterOperand, RegisterSpan, RegisterWidth,
};
pub use parser::{ParseError, parse_function};
pub use types::{
    FieldId, FieldType, FunctionId, FunctionSignature, PrimitiveType, StringId, TypeDescriptor,
    TypeFlag, TypeId,
};
