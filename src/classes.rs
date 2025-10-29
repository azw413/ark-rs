//! Class, field, and annotation metadata tables.

use crate::attributes::RuntimeAnnotation;
use crate::constant_pool::FieldDescriptor;
use crate::functions::Function;
use crate::types::{FieldId, FieldType, FunctionId, StringId, TypeDescriptor, TypeFlag, TypeId};

/// Unique identifier for class methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodId(pub u32);

impl MethodId {
    pub const fn new(index: u32) -> Self {
        MethodId(index)
    }
}

/// Bit flags describing the behaviour of a class definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassFlag(pub u32);

impl ClassFlag {
    pub const NONE: ClassFlag = ClassFlag(0);
    pub const EXPORTED: ClassFlag = ClassFlag(1 << 0);
    pub const ABSTRACT: ClassFlag = ClassFlag(1 << 1);
    pub const FINAL: ClassFlag = ClassFlag(1 << 2);
    pub const INTERFACE: ClassFlag = ClassFlag(1 << 3);
    pub const ENUM: ClassFlag = ClassFlag(1 << 4);
    pub const ANNOTATION: ClassFlag = ClassFlag(1 << 5);
    pub const GENERIC: ClassFlag = ClassFlag(1 << 6);

    pub const fn contains(self, other: ClassFlag) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: ClassFlag) -> ClassFlag {
        ClassFlag(self.0 | other.0)
    }
}

impl Default for ClassFlag {
    fn default() -> Self {
        ClassFlag::NONE
    }
}

/// Field metadata contained in a class definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassField {
    pub id: FieldId,
    pub name: StringId,
    pub descriptor: FieldType,
    pub is_static: bool,
    pub is_readonly: bool,
    pub initial_literal: Option<u32>,
    pub annotations: Vec<RuntimeAnnotation>,
}

/// Methods defined within a class body.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassMethod {
    pub id: MethodId,
    pub function: FunctionId,
    pub name: StringId,
    pub type_params: Vec<TypeId>,
    pub annotations: Vec<RuntimeAnnotation>,
    pub overrides: Option<FunctionId>,
    pub is_static: bool,
    pub is_constructor: bool,
}

/// Full representation of a class definition section.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassDefinition {
    pub name: TypeId,
    pub language: StringId,
    pub super_class: Option<TypeId>,
    pub interfaces: Vec<TypeId>,
    pub flags: ClassFlag,
    pub type_parameters: Vec<TypeParameter>,
    pub fields: Vec<ClassField>,
    pub methods: Vec<ClassMethod>,
    pub runtime_annotations: Vec<RuntimeAnnotation>,
    pub metadata: Vec<ClassMetadata>,
}

/// Type parameter metadata for generic classes and methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeParameter {
    pub name: StringId,
    pub constraint: Option<TypeDescriptor>,
    pub default_type: Option<TypeDescriptor>,
    pub flags: TypeFlag,
}

/// Arbitrary metadata associated with a class definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassMetadata {
    Slots(u16),
    SourceFile(StringId),
    LineRange { start: u32, end: u32 },
    FieldDescriptors(Vec<FieldDescriptor>),
    Extra(Vec<u8>),
}

/// Associates class-level methods with their bodies for convenience.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassMethodBody {
    pub method: ClassMethod,
    pub body: Option<Function>,
}
