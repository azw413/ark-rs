//! Shared type system definitions used across Ark bytecode sections.

/// Primitive value kinds supported by the Ark runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveType {
    Void,
    Boolean,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    String,
    Any,
    Undefined,
    Object,
}

/// Unique identifier referencing a type entry in the constant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId(pub u32);

impl TypeId {
    pub const fn new(index: u32) -> Self {
        TypeId(index)
    }
}

/// Unique identifier referencing a string stored in the string table section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringId(pub u32);

impl StringId {
    pub const fn new(index: u32) -> Self {
        StringId(index)
    }
}

/// Unique identifier referencing a field declaration in the constant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldId(pub u32);

impl FieldId {
    pub const fn new(index: u32) -> Self {
        FieldId(index)
    }
}

/// Unique identifier referencing a function declaration in the constant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionId(pub u32);

impl FunctionId {
    pub const fn new(index: u32) -> Self {
        FunctionId(index)
    }
}

/// Qualifiers used for values and references inside the Ark bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeFlag(pub u32);

impl TypeFlag {
    pub const NONE: TypeFlag = TypeFlag(0);
    pub const NULLABLE: TypeFlag = TypeFlag(1 << 0);
    pub const MUTABLE: TypeFlag = TypeFlag(1 << 1);
    pub const OPTIONAL: TypeFlag = TypeFlag(1 << 2);

    pub const fn contains(self, other: TypeFlag) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: TypeFlag) -> TypeFlag {
        TypeFlag(self.0 | other.0)
    }
}

impl Default for TypeFlag {
    fn default() -> Self {
        TypeFlag::NONE
    }
}

/// Describes the type of a field, including mutability information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldType {
    pub descriptor: TypeDescriptor,
    pub flags: TypeFlag,
}

impl FieldType {
    pub fn new(descriptor: TypeDescriptor) -> Self {
        FieldType {
            descriptor,
            flags: TypeFlag::NONE,
        }
    }
}

/// Representation of function signatures, including generic receivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    pub this_type: Option<TypeDescriptor>,
    pub parameters: Vec<FieldType>,
    pub return_type: FieldType,
    pub flags: TypeFlag,
}

impl FunctionSignature {
    pub fn new(parameters: Vec<FieldType>, return_type: FieldType) -> Self {
        FunctionSignature {
            this_type: None,
            parameters,
            return_type,
            flags: TypeFlag::NONE,
        }
    }
}

/// Type descriptors as they appear in the Ark bytecode metadata tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDescriptor {
    Primitive(PrimitiveType),
    Type(TypeId),
    Function(FunctionId),
    Array {
        element: Box<TypeDescriptor>,
        dimensions: u8,
    },
    Generic {
        base: TypeId,
        arguments: Vec<TypeDescriptor>,
    },
    TypeParameter {
        owner: FunctionId,
        index: u16,
    },
    Union(Vec<TypeDescriptor>),
    Intersection(Vec<TypeDescriptor>),
    Unknown(u32),
}
