//! Constant pool definitions covering strings, literal arrays, and member descriptors.

use crate::types::{
    FieldId, FieldType, FunctionId, FunctionSignature, StringId, TypeDescriptor, TypeId,
};

/// Collection of all constant pool sections present in a bytecode file.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ConstantPool {
    pub strings: Vec<StringRecord>,
    pub literals: Vec<LiteralArray>,
    pub types: Vec<TypeDescriptor>,
    pub fields: Vec<FieldDescriptor>,
    pub methods: Vec<MethodPrototype>,
    pub method_handles: Vec<MethodHandle>,
    pub metadata: Vec<ConstantPoolEntry>,
}

/// Individual constant pool entry variants that do not belong to the typed tables.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantPoolEntry {
    Integer(i64),
    Float(f64),
    String(StringId),
    Type(TypeId),
    Field(FieldId),
    Method(FunctionId),
    LiteralArray(u32),
    Annotation(u32),
    Unknown(u32),
}

/// A UTF-8 encoded string record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRecord {
    pub id: StringId,
    pub value: String,
}

/// A literal array as represented in the bytecode literal section.
#[derive(Debug, Clone, PartialEq)]
pub struct LiteralArray {
    pub id: u32,
    pub values: Vec<LiteralValue>,
}

/// Literal values supported in Ark bytecode constant pool.
#[derive(Debug, Clone, PartialEq)]
pub enum LiteralValue {
    Boolean(bool),
    Integer(i64),
    Float(f32),
    Double(f64),
    String(StringId),
    Type(TypeId),
    Method(FunctionId),
    Field(FieldId),
    LiteralArray(u32),
    MethodAffiliate(u16),
    Builtin(u8),
    Accessor(u8),
    BigInt(Vec<u8>),
    Any { type_index: TypeId, data: Vec<u8> },
    Null,
    Undefined,
    Raw { tag: u8, bytes: Vec<u8> },
}

/// Describes a field entry exposed in the constant pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescriptor {
    pub id: FieldId,
    pub name: StringId,
    pub type_info: FieldType,
}

/// Signature and metadata for method entries stored in the constant pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodPrototype {
    pub id: FunctionId,
    pub name: StringId,
    pub signature: FunctionSignature,
    pub flags: u32,
}

/// Kinds of method handles supported by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodHandleKind {
    DirectCall,
    VirtualCall,
    SuperCall,
    InterfaceCall,
    Constructor,
    Getter,
    Setter,
    Unknown(u8),
}

/// Represents a method handle entry within the constant pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodHandle {
    pub kind: MethodHandleKind,
    pub target: FunctionId,
    pub receiver: Option<TypeId>,
}
