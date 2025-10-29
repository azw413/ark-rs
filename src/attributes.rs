//! Attribute and debug information structures used across Ark bytecode.

use crate::instructions::InstructionIndex;
use crate::types::{StringId, TypeDescriptor};

/// High-level attribute container referencing specific attribute payloads.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub name: StringId,
    pub kind: AttributeKind,
}

/// Kinds of attribute payloads included in Ark bytecode sections.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeKind {
    Annotation(RuntimeAnnotation),
    Debug(DebugInfo),
    LineNumbers(Vec<LineNumberEntry>),
    Locals(Vec<LocalVariableEntry>),
    SourceMap(Vec<SourceMapEntry>),
    Custom(Vec<u8>),
}

/// Describes a runtime visible annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAnnotation {
    pub type_descriptor: TypeDescriptor,
    pub elements: Vec<AnnotationElement>,
}

/// Single key/value pair inside an annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationElement {
    pub name: StringId,
    pub value: AnnotationValue,
}

/// Values supported inside annotation elements.
#[derive(Debug, Clone, PartialEq)]
pub enum AnnotationValue {
    Boolean(bool),
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    String(StringId),
    Type(TypeDescriptor),
    Array(Vec<AnnotationValue>),
    Nested(RuntimeAnnotation),
    Null,
}

/// Debug information captured for a function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfo {
    pub line_numbers: Vec<LineNumberEntry>,
    pub locals: Vec<LocalVariableEntry>,
    pub source_map: Vec<SourceMapEntry>,
}

/// Associates program counters with source code line numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineNumberEntry {
    pub instruction: InstructionIndex,
    pub line: u32,
}

/// Information about active local variables within a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableEntry {
    pub name: StringId,
    pub type_descriptor: TypeDescriptor,
    pub start: InstructionIndex,
    pub end: InstructionIndex,
}

/// Source map entries linking bytecode offsets to original source spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapEntry {
    pub instruction: InstructionIndex,
    pub column: u32,
    pub length: u32,
}
