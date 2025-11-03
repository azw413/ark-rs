//! Core data structures for representing Ark bytecode in memory.

pub mod error;
pub mod highlevel;
pub mod lowlevel;

pub use error::{ArkError, ArkResult};

// High-level API
pub use highlevel::{
    ArkAttribute, ArkAttributeKind, ArkBasicBlock, ArkClassDefinition, ArkClassField, ArkClassFlag,
    ArkClassMetadata, ArkClassMethod, ArkClassMethodBody, ArkDebugInfo, ArkFunction,
    ArkFunctionEntry, ArkFunctionFlag, ArkFunctionKind, ArkFunctionParameter, ArkFunctionSignature,
    ArkInstructionBlock, ArkLineNumberEntry, ArkLiteralEntry, ArkModule, ArkParseError,
    ArkRecordEntry, ArkRuntimeAnnotation, ArkSegment, ArkSourceMapEntry, ArkTypeParameter,
    ComparisonKind, ConditionCode, IdentifierOperand, IdentifierWidth, ImmediateOperand,
    ImmediateWidth, Instruction, InstructionFlags, InstructionFormat, InstructionIndex, MethodId,
    Opcode, Operand, OperandKind, Register, RegisterOperand, RegisterSpan, RegisterWidth,
    format_function, parse_ark_module, parse_function, write_function,
};

// Low-level API
pub use lowlevel::{
    AbcClassDefinition, AbcFile, AbcHeader as AbcBinaryHeader,
    AbcIndexHeader as AbcBinaryIndexHeader, AbcMethodItem, AbcReader, AbcSectionRange,
    AbcStringEntry, AbcVersion as AbcBinaryVersion, AbcWriter, ArkBytecodeFile, ConstantPool,
    ConstantPoolEntry, DecodedFunction, Endianness, FieldDescriptor, FieldId, FieldType, FileFlags,
    FileHeader, FileVersion, FunctionId, FunctionSignature, LiteralArray, LiteralArrayEntry,
    LiteralValue, MethodHandle, MethodHandleKind, MethodIndexEntry, MethodPrototype, ModuleKind,
    PrimitiveType, SectionInfo, SectionOffsets, SourceFileRecord, StringId, TypeDescriptor,
    TypeFlag, TypeId, decode_function_body_with_resolver,
};
