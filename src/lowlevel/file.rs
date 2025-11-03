//! Top-level representation of an Ark bytecode artifact.

use super::constant_pool::ConstantPool;
use super::header::FileHeader;
use super::types::StringId;
use crate::highlevel::attributes::Attribute;
use crate::highlevel::classes::ClassDefinition;
use crate::highlevel::functions::Function;

/// Stores the offsets and sizes of bytecode sections in the binary file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionOffsets {
    pub string_table: Option<SectionInfo>,
    pub literal_arrays: Option<SectionInfo>,
    pub type_table: Option<SectionInfo>,
    pub field_table: Option<SectionInfo>,
    pub method_table: Option<SectionInfo>,
    pub method_handles: Option<SectionInfo>,
    pub classes: Option<SectionInfo>,
    pub functions: Option<SectionInfo>,
    pub debug: Option<SectionInfo>,
    pub attributes: Option<SectionInfo>,
}

/// Offset and length for a single section, expressed in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    pub offset: u32,
    pub size: u32,
}

impl SectionInfo {
    pub const fn new(offset: u32, size: u32) -> Self {
        SectionInfo { offset, size }
    }
}

/// Full in-memory representation of an Ark bytecode file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ArkBytecodeFile {
    pub header: FileHeader,
    pub constant_pool: ConstantPool,
    pub classes: Vec<ClassDefinition>,
    pub functions: Vec<Function>,
    pub module_attributes: Vec<Attribute>,
    pub source_files: Vec<SourceFileRecord>,
    pub sections: SectionOffsets,
}

/// Source file metadata for mapping code back to human readable files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileRecord {
    pub name: StringId,
    pub checksum: Option<[u8; 16]>,
}
