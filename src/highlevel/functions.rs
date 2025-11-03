//! Function bodies, metadata, and control flow constructs.

use super::attributes::DebugInfo;
use super::disassembly::format_function;
use super::instructions::Instruction;
use crate::lowlevel::{FunctionId, TypeId};

/// Categorises the role a function plays within an Ark module.
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

/// Additional function-level flags present in Ark metadata tables.
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

/// Describes a single function parameter, including its name, type, and optional default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionParameter {
    pub name: Option<String>,
    pub type_name: String,
    pub default_literal: Option<u32>,
    pub is_optional: bool,
}

/// A linear sequence of instructions that executes without branching until the end of the block.
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

/// A container for the basic blocks that make up a function body.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InstructionBlock {
    pub blocks: Vec<BasicBlock>,
}

/// Metadata describing the range covered by a `try` block and its associated handler.
/// Signature information shared by textual disassembly and the high-level model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub try_index: u32,
    pub catch_index: u32,
    pub try_start: u32,
    pub try_end: u32,
    pub handler_start: u32,
    pub handler_end: u32,
    pub exception_type: Option<TypeId>,
}

/// Core representation of a function body in Ark bytecode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    pub this_type: Option<String>,
    pub parameters: Vec<String>,
    pub return_type: String,
}

impl FunctionSignature {
    pub fn new(return_type: impl Into<String>) -> Self {
        FunctionSignature {
            this_type: None,
            parameters: Vec::new(),
            return_type: return_type.into(),
        }
    }
}

/// In-memory representation of an Ark function body together with decoded metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    pub id: FunctionId,
    pub name: Option<String>,
    pub signature: FunctionSignature,
    pub kind: FunctionKind,
    pub flags: FunctionFlag,
    pub register_count: u16,
    pub parameters: Vec<FunctionParameter>,
    pub locals: Vec<String>,
    pub instruction_block: InstructionBlock,
    pub exception_handlers: Vec<ExceptionHandler>,
    pub debug_info: Option<DebugInfo>,
}

impl Function {
    /// Creates an empty function with the supplied identifier and signature.
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

    /// Formats the function into Ark textual disassembly, optionally prefixing annotations.
    pub fn to_string(&self, annotations: &[String]) -> String {
        let mut output = String::new();
        for annotation in annotations {
            output.push_str(annotation);
            if !annotation.ends_with('\n') {
                output.push('\n');
            }
        }

        let formatted = match format_function(self) {
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
