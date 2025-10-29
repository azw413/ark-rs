use crate::abc::{AbcFile, AbcSegment, LiteralEntry, RecordEntry};
use crate::abc_types::{
    AbcClassDefinition, AbcHeader, AbcIndexHeader, AbcLiteralArray, AbcLiteralValue, AbcReader,
    AbcStringEntry,
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
    pub record_offsets: Vec<u32>,
    pub method_index: Vec<MethodIndexEntry>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodIndexEntry {
    pub name_offset: u32,
    pub code_offset: u32,
}

impl BinaryAbcFile {
    /// Parses a raw `.abc` binary buffer into a [`BinaryAbcFile`].
    pub fn parse(bytes: &[u8]) -> ArkResult<Self> {
        let data = bytes.to_vec();
        let mut reader = AbcReader::new(&data);
        let header = AbcHeader::read(&mut reader)?;

        if header.class_index_offset as usize + (header.class_count as usize * 4) > data.len() {
            return Err(ArkError::format("class index table exceeds file length"));
        }

        let mut index_reader = AbcReader::new(&data);
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

        let index_header = if header.index_count > 0 && header.index_section_offset != u32::MAX {
            let mut idx_reader = AbcReader::new(&data);
            idx_reader.seek(header.index_section_offset as usize)?;
            Some(AbcIndexHeader::read(&mut idx_reader)?)
        } else {
            None
        };

        let (literal_offsets, literal_arrays) =
            if header.literal_array_count == 0 || header.literal_array_index_offset == u32::MAX {
                (Vec::new(), Vec::new())
            } else {
                let literal_index_offset = header.literal_array_index_offset as usize;
                let literal_count = header.literal_array_count as usize;
                if literal_index_offset > data.len()
                    || literal_index_offset + literal_count.saturating_mul(4) > data.len()
                {
                    return Err(ArkError::format("literal index table exceeds file length"));
                }

                let mut literal_index_reader = AbcReader::new(&data);
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

        let method_index = if let Some(index_header) = &index_header {
            if index_header.method_index_offset == u32::MAX {
                Vec::new()
            } else {
                let count = index_header.method_index_size as usize;
                let mut entries = Vec::with_capacity(count);
                let base = header.index_section_offset as usize
                    + index_header.method_index_offset as usize;
                if base > data.len() || base + count.saturating_mul(8) > data.len() {
                    return Err(ArkError::format("method index table exceeds file length"));
                }
                for i in 0..count {
                    let pos = base + i * 8;
                    let name_offset = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let code_offset =
                        u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
                    entries.push(MethodIndexEntry {
                        name_offset,
                        code_offset,
                    });
                }
                entries
            }
        } else {
            Vec::new()
        };

        Ok(BinaryAbcFile {
            header,
            class_offsets,
            classes,
            literal_offsets,
            literal_arrays,
            record_offsets: vec![],
            method_index,
            data,
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

    /// Returns a best-effort textual [`AbcFile`] representation of this binary module.
    ///
    /// The result is intentionally lossy while we continue to reverse engineer the
    /// binary format, but it allows the existing textual tooling to render
    /// intermediate progress via [`AbcFile::to_string`].
    pub fn to_abc_file(&self) -> AbcFile {
        let mut file = AbcFile::default();
        file.language = Some("ArkTS (binary preview)".to_owned());

        file.segments.push(AbcSegment::Raw(format!(
            "# generated from binary module ({} classes, {} literal arrays)",
            self.classes.len(),
            self.literal_offsets.len()
        )));
        file.segments.push(AbcSegment::Raw(String::new()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# LITERALS (binary)".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));

        for (index, (offset, entry)) in self
            .literal_offsets
            .iter()
            .zip(self.literal_arrays.iter())
            .enumerate()
        {
            let mut lines = Vec::new();

            match entry {
                Some(array) => {
                    lines.push(format!(
                        "{index} 0x{offset:04x} {{ {} [",
                        array.entries.len()
                    ));
                    for literal in &array.entries {
                        lines.push(format!("\t{},", self.render_literal_value(literal)));
                    }
                    lines.push("]}".to_owned());
                }
                None => {
                    lines.push(format!("{index} 0x{offset:04x} {{ <unresolved> }}"));
                }
            }

            let body = lines.join("\n");
            file.literals.push(LiteralEntry {
                index: index as u32,
                offset: *offset,
                body,
                lines,
            });
            let lit_idx = file.literals.len() - 1;
            file.segments.push(AbcSegment::Literal(lit_idx));
            file.segments.push(AbcSegment::Raw(String::new()));
        }

        file.segments.push(AbcSegment::Raw(String::new()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# RECORDS (binary)".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));

        for class in &self.classes {
            let record_name = normalize_record_name(&class.name.value);
            let mut lines = Vec::new();
            lines.push(format!(".record {} {{", record_name));
            lines.push("\t# TODO: decode record body from binary".to_owned());
            lines.push(format!("\tu32 field_count = {};", class.field_count));
            lines.push(format!("\tu32 method_count = {};", class.method_count));
            lines.push("}".to_owned());

            let body = lines.join("\n");
            file.records.push(RecordEntry {
                name: record_name,
                body,
                lines: lines.clone(),
            });
            let rec_idx = file.records.len() - 1;
            file.segments.push(AbcSegment::Record(rec_idx));
            file.segments.push(AbcSegment::Raw(String::new()));
        }

        if !self.method_index.is_empty() {
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# FUNCTIONS (binary)".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));

            for entry in &self.method_index {
                let method_name = self
                    .resolve_string(entry.name_offset)
                    .map(|s| normalize_method_name(&s))
                    .unwrap_or_else(|| format!("method@0x{:x}", entry.name_offset));
                file.segments
                    .push(AbcSegment::Raw(format!(".function any {} {{", method_name)));
                file.segments
                    .push(AbcSegment::Raw("\t# TODO: decode function body".to_owned()));
                file.segments.push(AbcSegment::Raw("}".to_owned()));
                file.segments.push(AbcSegment::Raw(String::new()));
            }
        }

        file
    }

    fn resolve_string(&self, offset: u32) -> Option<String> {
        if offset == 0 || (offset as usize) >= self.data.len() {
            return None;
        }
        let mut reader = AbcReader::new(&self.data);
        AbcStringEntry::read_at(&mut reader, offset)
            .ok()
            .map(|entry| entry.value)
    }

    fn render_literal_value(&self, value: &AbcLiteralValue) -> String {
        match value {
            AbcLiteralValue::Boolean(v) => {
                format!("bool:{}", if *v { "true" } else { "false" })
            }
            AbcLiteralValue::Integer(v) => format!("i64:{v}"),
            AbcLiteralValue::Float(v) => format!("f32:{v}"),
            AbcLiteralValue::Double(v) => format!("f64:{v}"),
            AbcLiteralValue::String(index) => {
                if let Some(value) = self.resolve_string(*index) {
                    format!("string:\"{}\"", escape_string(&value))
                } else {
                    format!("string_id:{}", index)
                }
            }
            AbcLiteralValue::Type(index) => format!("type_id:{}", index),
            AbcLiteralValue::Method(index) => format!("method_id:{}", index),
            AbcLiteralValue::MethodAffiliate(idx) => {
                format!("method_affiliate:{}", idx)
            }
            AbcLiteralValue::Builtin(code) => format!("builtin:{}", code),
            AbcLiteralValue::Accessor(code) => format!("accessor:{}", code),
            AbcLiteralValue::LiteralArray(index) => format!("literal_ref:{}", index),
            AbcLiteralValue::BigInt(bytes) => format!("bigint({} bytes)", bytes.len()),
            AbcLiteralValue::BigIntExternal { length } => {
                format!("bigint_external({length} bytes)")
            }
            AbcLiteralValue::Any { type_index, data } => {
                format!("any(type={}, {} bytes)", type_index, data.len())
            }
            AbcLiteralValue::AnyExternal { type_index, length } => {
                format!("any_external(type={}, {length} bytes)", type_index)
            }
            AbcLiteralValue::Null => "null".to_owned(),
            AbcLiteralValue::Undefined => "undefined".to_owned(),
            AbcLiteralValue::Raw { tag, bytes } => {
                format!("raw(tag=0x{tag:02x}, {} bytes)", bytes.len())
            }
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

fn escape_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn normalize_record_name(raw: &str) -> String {
    if raw.is_empty() {
        return raw.to_owned();
    }

    let mut name = raw;
    if let Some(stripped) = name.strip_prefix('L') {
        name = stripped;
    }
    if let Some(stripped) = name.strip_suffix(';') {
        name = stripped;
    }

    name.replace('/', ".")
}

fn normalize_method_name(raw: &str) -> String {
    if raw.is_empty() {
        return raw.to_owned();
    }

    let mut name = raw;
    if let Some(stripped) = name.strip_prefix('L') {
        name = stripped;
    }
    if let Some(stripped) = name.strip_suffix(';') {
        name = stripped;
    }
    name.replace('/', ".")
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

    #[test]
    fn dump_modules_disassembly() {
        use std::path::Path;

        let bytes = std::fs::read("test-data/modules.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        let textual = abc.to_abc_file();
        let report = textual.to_string();
        assert!(!report.trim().is_empty());
        assert!(report.contains(".record"));
        assert!(report.contains(".function"));
        let out_dir = Path::new("target/disassembly");
        std::fs::create_dir_all(out_dir).expect("create output directory");
        let out_path = out_dir.join("modules.abc.out");
        std::fs::write(&out_path, report).expect("write disassembly report");
        println!("wrote {:?}", out_path);
    }
}
