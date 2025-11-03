//! Attribute and debug information structures used across Ark bytecode.

use super::instructions::InstructionIndex;
use crate::lowlevel::TypeDescriptor;

/// High-level attribute container capturing the attribute name and concrete payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub name: String,
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

/// Runtime-visible annotation and its key/value elements.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAnnotation {
    pub type_descriptor: TypeDescriptor,
    pub elements: Vec<AnnotationElement>,
}

/// Single key/value pair within an annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationElement {
    pub name: String,
    pub value: AnnotationValue,
}

/// Supported value kinds inside annotation elements.
#[derive(Debug, Clone, PartialEq)]
pub enum AnnotationValue {
    Boolean(bool),
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    String(String),
    Type(TypeDescriptor),
    Array(Vec<AnnotationValue>),
    Nested(RuntimeAnnotation),
    Null,
}

/// Debug information captured for a function body (line numbers, locals, source map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfo {
    pub line_numbers: Vec<LineNumberEntry>,
    pub locals: Vec<LocalVariableEntry>,
    pub source_map: Vec<SourceMapEntry>,
}

/// Associates instruction positions with source line numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineNumberEntry {
    pub instruction: InstructionIndex,
    pub line: u32,
}

/// Describes a local variable that is active within a bytecode range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVariableEntry {
    pub name: String,
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
