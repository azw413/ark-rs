//! Function bodies, metadata, and control flow constructs.

use crate::attributes::DebugInfo;
use crate::constant_pool::ConstantPool;
use crate::disassembly::format_function;
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

    pub fn to_string(&self, annotations: &[String], pool: &ConstantPool) -> String {
        let mut output = String::new();
        for annotation in annotations {
            output.push_str(annotation);
            if !annotation.ends_with('\n') {
                output.push('\n');
            }
        }

        let formatted = match format_function(self, pool) {
            Ok(text) => text,
            Err(err) => format!("# Failed to format function: {err}"),
        };

        let lines: Vec<String> = formatted.lines().map(|line| line.to_owned()).collect();
        let mut normalized = Vec::with_capacity(lines.len());
        let mut index = 0usize;
        while index < lines.len() {
            let line = &lines[index];
            if line.trim().is_empty() {
                if matches!(lines.get(index + 1), Some(next) if next.trim() == "}") {
                    index += 1;
                    continue;
                }
            }

            let mut space_count = 0usize;
            for ch in line.chars() {
                if ch == ' ' {
                    space_count += 1;
                } else {
                    break;
                }
            }
            let tabs = space_count / 4;
            let spaces = space_count % 4;
            let mut rebuilt = String::new();
            if tabs > 0 {
                rebuilt.push_str(&"\t".repeat(tabs));
            }
            if spaces > 0 {
                rebuilt.push_str(&" ".repeat(spaces));
            }
            rebuilt.push_str(&line[space_count..]);
            normalized.push(rebuilt);
            index += 1;
        }

        if !normalized.is_empty() && !normalized.last().unwrap().is_empty() {
            normalized.push(String::new());
        }

        output.push_str(&normalized.join("\n"));
        output
    }
}
