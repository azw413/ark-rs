use crate::abc_types::{
    AbcClassDefinition, AbcHeader, AbcLiteralArray, AbcLiteralValue, AbcReader,
};
use crate::classes::{ClassDefinition, ClassFlag};
use crate::constant_pool::{ConstantPool, LiteralArray, LiteralValue, StringRecord};
use crate::error::{ArkError, ArkResult};
use crate::file::{ArkBytecodeFile, SectionOffsets};
use crate::header::{Endianness, FileFlags, FileHeader, FileVersion, ModuleKind};
use crate::types::{FunctionId, StringId, TypeDescriptor, TypeId};
use std::collections::HashMap;

/// In-memory representation of a decoded binary ABC module focusing on class metadata.
#[derive(Debug, Clone)]
pub struct BinaryAbcFile {
    pub header: AbcHeader,
    pub class_offsets: Vec<u32>,
    pub classes: Vec<AbcClassDefinition>,
    pub literal_offsets: Vec<u32>,
    pub literal_arrays: Vec<Option<AbcLiteralArray>>,
}

impl BinaryAbcFile {
    /// Parses a raw `.abc` binary buffer into a [`BinaryAbcFile`].
    pub fn parse(bytes: &[u8]) -> ArkResult<Self> {
        let mut reader = AbcReader::new(bytes);
        let header = AbcHeader::read(&mut reader)?;

        if header.class_index_offset as usize + (header.class_count as usize * 4) > bytes.len() {
            return Err(ArkError::format("class index table exceeds file length"));
        }

        let mut index_reader = AbcReader::new(bytes);
        index_reader.seek(header.class_index_offset as usize)?;
        let mut class_offsets = Vec::with_capacity(header.class_count as usize);
        for _ in 0..header.class_count {
            class_offsets.push(index_reader.read_u32()?);
        }

        let mut classes = Vec::with_capacity(class_offsets.len());
        for offset in &class_offsets {
            if *offset == 0 {
                continue;
            }
            let class = AbcClassDefinition::read_at(&mut reader, *offset)?;
            classes.push(class);
        }

        let (literal_offsets, literal_arrays) =
            if header.literal_array_count == 0 || header.literal_array_index_offset == u32::MAX {
                (Vec::new(), Vec::new())
            } else {
                let literal_index_offset = header.literal_array_index_offset as usize;
                let literal_count = header.literal_array_count as usize;
                if literal_index_offset > bytes.len()
                    || literal_index_offset + literal_count.saturating_mul(4) > bytes.len()
                {
                    return Err(ArkError::format("literal index table exceeds file length"));
                }

                let mut literal_index_reader = AbcReader::new(bytes);
                literal_index_reader.seek(literal_index_offset)?;
                let mut literal_offsets = Vec::with_capacity(literal_count);
                for _ in 0..literal_count {
                    literal_offsets.push(literal_index_reader.read_u32()?);
                }

                let mut literal_arrays = Vec::with_capacity(literal_offsets.len());
                for offset in &literal_offsets {
                    if *offset == 0 {
                        literal_arrays.push(None);
                        continue;
                    }
                    let array = AbcLiteralArray::read_at(&mut reader, *offset)?;
                    literal_arrays.push(Some(array));
                }

                (literal_offsets, literal_arrays)
            };

        Ok(BinaryAbcFile {
            header,
            class_offsets,
            classes,
            literal_offsets,
            literal_arrays,
        })
    }

    /// Converts the binary representation into the existing high level [`ArkBytecodeFile`]
    /// structure. The translation currently focuses on recreating class declarations and
    /// populating the constant pool with their descriptors.
    pub fn to_ark_file(&self) -> ArkBytecodeFile {
        let mut header = FileHeader::default();
        header.magic = FileHeader::MAGIC;
        header.version = FileVersion::new(
            self.header.version.major() as u16,
            self.header.version.minor() as u16,
            self.header.version.patch() as u16,
        );
        header.module_kind = ModuleKind::ArkTs;
        header.endianness = Endianness::Little;
        header.flags = FileFlags::NONE;
        header.checksum = self.header.checksum;
        header.file_size = self.header.file_size;
        header.section_count = self.header.index_count as u16;

        let mut constant_pool = ConstantPool::default();
        let mut string_records: Vec<StringRecord> = Vec::new();
        let mut string_ids: HashMap<String, StringId> = HashMap::new();

        // Reserve a placeholder language id.
        let language_string = "unknown".to_string();
        string_records.push(StringRecord {
            id: StringId::new(0),
            value: language_string.clone(),
        });
        string_ids.insert(language_string, StringId::new(0));

        let mut type_descriptors: Vec<TypeDescriptor> = Vec::new();
        let mut classes: Vec<ClassDefinition> = Vec::new();

        for class in &self.classes {
            string_ids
                .entry(class.name.value.clone())
                .or_insert_with(|| {
                    let id = StringId::new(string_records.len() as u32);
                    string_records.push(StringRecord {
                        id,
                        value: class.name.value.clone(),
                    });
                    id
                });

            let type_id = TypeId::new(type_descriptors.len() as u32);
            type_descriptors.push(TypeDescriptor::Unknown(class.offset));

            classes.push(ClassDefinition {
                name: type_id,
                language: StringId::new(0),
                super_class: None,
                interfaces: Vec::new(),
                flags: ClassFlag::NONE,
                type_parameters: Vec::new(),
                fields: Vec::new(),
                methods: Vec::new(),
                runtime_annotations: Vec::new(),
                metadata: Vec::new(),
            });
        }

        constant_pool.strings = string_records;
        constant_pool.types = type_descriptors;
        constant_pool.literals = self
            .literal_arrays
            .iter()
            .enumerate()
            .filter_map(|(index, maybe_array)| {
                maybe_array.as_ref().map(|array| LiteralArray {
                    id: index as u32,
                    values: array.entries.iter().map(convert_literal_value).collect(),
                })
            })
            .collect();

        ArkBytecodeFile {
            header,
            constant_pool,
            classes,
            functions: Vec::new(),
            module_attributes: Vec::new(),
            source_files: Vec::new(),
            sections: SectionOffsets::default(),
        }
    }
}

fn convert_literal_value(value: &AbcLiteralValue) -> LiteralValue {
    match value {
        AbcLiteralValue::Boolean(v) => LiteralValue::Boolean(*v),
        AbcLiteralValue::Integer(v) => LiteralValue::Integer(*v),
        AbcLiteralValue::Float(v) => LiteralValue::Float(*v),
        AbcLiteralValue::Double(v) => LiteralValue::Double(*v),
        AbcLiteralValue::String(index) => LiteralValue::String(StringId::new(*index)),
        AbcLiteralValue::Type(index) => LiteralValue::Type(TypeId::new(*index)),
        AbcLiteralValue::Method(index) => LiteralValue::Method(FunctionId::new(*index)),
        AbcLiteralValue::MethodAffiliate(idx) => LiteralValue::MethodAffiliate(*idx),
        AbcLiteralValue::Builtin(code) => LiteralValue::Builtin(*code),
        AbcLiteralValue::Accessor(code) => LiteralValue::Accessor(*code),
        AbcLiteralValue::LiteralArray(index) => LiteralValue::LiteralArray(*index),
        AbcLiteralValue::BigInt(bytes) => LiteralValue::BigInt(bytes.clone()),
        AbcLiteralValue::BigIntExternal { length } => {
            LiteralValue::BigIntExternal { length: *length }
        }
        AbcLiteralValue::Any { type_index, data } => LiteralValue::Any {
            type_index: TypeId::new(*type_index),
            data: data.clone(),
        },
        AbcLiteralValue::AnyExternal { type_index, length } => LiteralValue::AnyExternal {
            type_index: TypeId::new(*type_index),
            length: *length,
        },
        AbcLiteralValue::Null => LiteralValue::Null,
        AbcLiteralValue::Undefined => LiteralValue::Undefined,
        AbcLiteralValue::Raw { tag, bytes } => LiteralValue::Raw {
            tag: *tag,
            bytes: bytes.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryAbcFile;
    use crate::abc_types::AbcLiteralValue;

    #[test]
    fn parse_module_classes() {
        let bytes = std::fs::read("test-data/modules.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        assert_eq!(abc.class_offsets.len(), 13);
        assert!(
            abc.classes
                .iter()
                .any(|cls| cls.name.value.contains("EntryAbility"))
        );
    }

    #[test]
    fn convert_to_high_level_file() {
        let bytes = std::fs::read("test-data/wechat.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        let ark = abc.to_ark_file();
        assert_eq!(ark.classes.len(), abc.classes.len());
        assert!(ark.constant_pool.strings.len() >= abc.classes.len());
        let populated = abc
            .literal_arrays
            .iter()
            .filter(|entry| entry.is_some())
            .count();
        assert_eq!(ark.constant_pool.literals.len(), populated);
    }

    #[test]
    fn decode_first_literal_array_entries() {
        let bytes = std::fs::read("test-data/wechat.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        assert!(abc.literal_arrays.iter().any(|entry| entry.is_some()));
        let first = abc
            .literal_arrays
            .iter()
            .flatten()
            .next()
            .expect("at least one literal array");
        assert!(!first.entries.is_empty());

        assert!(
            abc.literal_arrays
                .iter()
                .flatten()
                .flat_map(|array| &array.entries)
                .any(|entry| matches!(
                    entry,
                    AbcLiteralValue::Any { .. }
                        | AbcLiteralValue::AnyExternal { .. }
                        | AbcLiteralValue::BigInt { .. }
                        | AbcLiteralValue::BigIntExternal { .. }
                ))
        );

        let ark = abc.to_ark_file();
        assert!(!ark.constant_pool.literals.is_empty());
    }

    #[test]
    fn parse_wechat_literal_index() {
        let bytes = std::fs::read("test-data/wechat.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        assert_eq!(abc.literal_offsets.len(), abc.literal_arrays.len());
        assert!(
            abc.literal_offsets
                .iter()
                .zip(abc.literal_arrays.iter())
                .all(|(offset, maybe)| (*offset == 0) == maybe.is_none())
        );
    }
}
