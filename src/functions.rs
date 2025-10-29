//! Function bodies, metadata, and control flow constructs.

use crate::attributes::DebugInfo;
use crate::instructions::{Instruction, InstructionIndex};
use crate::types::{FieldType, FunctionId, FunctionSignature, StringId, TypeId};

/// Categorises functions within an Ark module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionKind {
    TopLevel,
    Method,
    Constructor,
    Lambda,
    Async,
    Generator,
    Getter,
    Setter,
    Imported,
    Intrinsic,
    Native,
    Unknown(u8),
}

/// Additional function-level flags present in metadata tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionFlag(pub u32);

impl FunctionFlag {
    pub const NONE: FunctionFlag = FunctionFlag(0);
    pub const ASYNC: FunctionFlag = FunctionFlag(1 << 0);
    pub const GENERATOR: FunctionFlag = FunctionFlag(1 << 1);
    pub const LAMBDA: FunctionFlag = FunctionFlag(1 << 2);
    pub const NATIVE: FunctionFlag = FunctionFlag(1 << 3);
    pub const EXPORTED: FunctionFlag = FunctionFlag(1 << 4);
    pub const IMPORTED: FunctionFlag = FunctionFlag(1 << 5);
    pub const VARIADIC: FunctionFlag = FunctionFlag(1 << 6);

    pub const fn contains(self, other: FunctionFlag) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: FunctionFlag) -> FunctionFlag {
        FunctionFlag(self.0 | other.0)
    }
}

impl Default for FunctionFlag {
    fn default() -> Self {
        FunctionFlag::NONE
    }
}

/// Function parameter metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionParameter {
    pub name: Option<StringId>,
    pub type_info: FieldType,
    pub default_literal: Option<u32>,
    pub is_optional: bool,
}

/// A single basic block containing a linear sequence of instructions with a terminating control transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub label: u32,
    pub instructions: Vec<Instruction>,
}

impl BasicBlock {
    pub fn new(label: u32) -> Self {
        BasicBlock {
            label,
            instructions: Vec::new(),
        }
    }
}

/// A convenience wrapper for a list of instruction blocks.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InstructionBlock {
    pub blocks: Vec<BasicBlock>,
}

/// Exception handler metadata describing try/catch/finally ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub start: InstructionIndex,
    pub end: InstructionIndex,
    pub handler: InstructionIndex,
    pub exception_type: Option<TypeId>,
    pub is_finally: bool,
}

/// Core representation of a function body in Ark bytecode.
#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    pub id: FunctionId,
    pub name: Option<StringId>,
    pub signature: FunctionSignature,
    pub kind: FunctionKind,
    pub flags: FunctionFlag,
    pub register_count: u16,
    pub parameters: Vec<FunctionParameter>,
    pub locals: Vec<FieldType>,
    pub instruction_block: InstructionBlock,
    pub exception_handlers: Vec<ExceptionHandler>,
    pub debug_info: Option<DebugInfo>,
}

impl Function {
    pub fn new(id: FunctionId, signature: FunctionSignature) -> Self {
        Function {
            id,
            name: None,
            signature,
            kind: FunctionKind::TopLevel,
            flags: FunctionFlag::NONE,
            register_count: 0,
            parameters: Vec::new(),
            locals: Vec::new(),
            instruction_block: InstructionBlock::default(),
            exception_handlers: Vec::new(),
            debug_info: None,
        }
    }
}
