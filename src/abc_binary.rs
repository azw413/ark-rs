use crate::abc::{AbcFile, AbcSegment, LiteralEntry, RecordEntry};
use crate::abc_types::{
    AbcClassDefinition, AbcHeader, AbcIndexHeader, AbcLiteralArray, AbcLiteralValue, AbcMethodItem,
    AbcReader, AbcStringEntry,
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
    pub class_ranges: Vec<(u32, u32)>,
    pub literal_offsets: Vec<u32>,
    pub literal_arrays: Vec<Option<AbcLiteralArray>>,
    pub record_offsets: Vec<u32>,
    pub method_index: Vec<MethodIndexEntry>,
    pub methods: Vec<AbcMethodItem>,
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
        let (mut literal_offsets, mut literal_arrays) = {
            let region_start = index_header
                .as_ref()
                .map(|idx| idx.start as usize)
                .unwrap_or(0);
            let region_end = index_header
                .as_ref()
                .map(|idx| idx.end as usize)
                .unwrap_or(data.len());
            let mut offsets = Vec::new();
            let mut arrays = Vec::new();
            let mut cursor = region_start;
            while cursor < region_end {
                if cursor + 4 > data.len() {
                    break;
                }
                let count = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
                if count == 0 || count > 0x100 {
                    cursor += 1;
                    continue;
                }
                match AbcLiteralArray::read_at(&mut reader, cursor as u32) {
                    Ok(array) => {
                        let size = array.byte_len;
                        if size == 0 || cursor + size > region_end || cursor + size > data.len() {
                            cursor += 1;
                            continue;
                        }
                        offsets.push(cursor as u32);
                        if array.entries.is_empty() {
                            arrays.push(None);
                        } else {
                            arrays.push(Some(array));
                        }
                        cursor += size;
                    }
                    Err(_) => {
                        cursor += 1;
                    }
                }
            }
            (offsets, arrays)
        };
        let mut known_offsets: std::collections::HashSet<u32> =
            literal_offsets.iter().copied().collect();
        let mut queue = std::collections::VecDeque::new();
        for maybe_array in &literal_arrays {
            if let Some(array) = maybe_array {
                for entry in &array.entries {
                    if let AbcLiteralValue::LiteralArray(target) = entry {
                        if known_offsets.insert(*target) {
                            queue.push_back(*target);
                        }
                    }
                }
            }
        }
        let mut pairs: Vec<(u32, Option<AbcLiteralArray>)> = literal_offsets
            .iter()
            .cloned()
            .zip(literal_arrays.into_iter())
            .collect();
        process_literal_queue(&data, &mut queue, &mut known_offsets, &mut pairs);
        let region_start_u32 = index_header.as_ref().map(|idx| idx.start).unwrap_or(0);
        let region_end_u32 = index_header
            .as_ref()
            .map(|idx| idx.end)
            .unwrap_or(data.len() as u32);
        for pos in 0..data.len().saturating_sub(4) {
            let candidate = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            if candidate < region_start_u32 || candidate >= region_end_u32 {
                continue;
            }
            if known_offsets.insert(candidate) {
                queue.push_back(candidate);
            }
        }
        process_literal_queue(&data, &mut queue, &mut known_offsets, &mut pairs);
        pairs.sort_by_key(|(offset, _)| *offset);
        literal_offsets = pairs.iter().map(|(offset, _)| *offset).collect();
        literal_arrays = pairs.into_iter().map(|(_, array)| array).collect();
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
        let mut methods = Vec::new();
        let mut seen_method_offsets = std::collections::HashSet::new();
        let class_region_end = index_header
            .as_ref()
            .map(|idx| idx.start)
            .unwrap_or(data.len() as u32);
        let mut boundaries: Vec<(u32, usize)> = class_offsets
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, offset)| *offset > 0)
            .map(|(index, offset)| (offset, index))
            .collect();
        boundaries.sort_by_key(|(offset, _)| *offset);
        let mut class_ranges = vec![(0u32, class_region_end); classes.len()];
        for (position, &(start_offset, class_idx)) in boundaries.iter().enumerate() {
            let class = &classes[class_idx];
            let expected = class.method_count as usize;
            if expected == 0 {
                class_ranges[class_idx] = (
                    start_offset,
                    boundaries
                        .get(position + 1)
                        .map(|(offset, _)| *offset)
                        .unwrap_or(class_region_end),
                );
                continue;
            }
            let next_start = boundaries
                .get(position + 1)
                .map(|(offset, _)| *offset)
                .unwrap_or(class_region_end);
            class_ranges[class_idx] = (start_offset, next_start);
            let mut cursor = start_offset as usize;
            let limit = next_start.max(start_offset) as usize;
            while cursor < limit {
                match AbcMethodItem::read_at(&data, cursor as u32) {
                    Ok((mut item, size)) if size > 0 => {
                        if seen_method_offsets.insert(item.offset) {
                            item.declaring_class_offset = Some(start_offset);
                            methods.push(item);
                        }
                        cursor = cursor.saturating_add(size as usize);
                    }
                    _ => {
                        cursor = cursor.saturating_add(1);
                    }
                }
            }
        }
        methods.sort_by_key(|item| item.offset);
        Ok(BinaryAbcFile {
            header,
            class_offsets,
            classes,
            class_ranges,
            literal_offsets,
            literal_arrays,
            record_offsets: vec![],
            method_index,
            methods,
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
        file.segments.push(AbcSegment::Raw("# LITERALS".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));
        let mut display_index = 0usize;
        for (offset, entry) in self.literal_offsets.iter().zip(self.literal_arrays.iter()) {
            let (body, lines) = match entry {
                Some(array) if self.should_render_literal(&array.entries) => {
                    let items = array
                        .entries
                        .iter()
                        .map(|value| format!("{}{}", self.render_literal_value(value), ","))
                        .collect::<Vec<_>>();
                    let rendered = if items.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", items.join(" "))
                    };
                    let line = format!(
                        "{} 0x{offset:04x} {{ {} [{} ]}}",
                        display_index,
                        array.entries.len(),
                        rendered
                    );
                    (line.clone(), vec![line])
                }
                Some(_) => continue,
                None => match self.render_module_literal(display_index, *offset) {
                    Some(result) => result,
                    None => {
                        let line = format!("{} 0x{offset:04x} {{ <unresolved> }}", display_index);
                        (line.clone(), vec![line])
                    }
                },
            };
            file.literals.push(LiteralEntry {
                index: display_index as u32,
                offset: *offset,
                body: body.clone(),
                lines,
            });
            let lit_idx = file.literals.len() - 1;
            file.segments.push(AbcSegment::Literal(lit_idx));
            file.segments.push(AbcSegment::Raw(String::new()));
            display_index += 1;
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
            for line in self.render_record_body(class, &record_name) {
                lines.push(line);
            }
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
        if !self.methods.is_empty() {
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# FUNCTIONS (binary)".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));
            for method in &self.methods {
                let method_name = self.display_method_name(method);
                let qualified_name = method
                    .declaring_class_offset
                    .and_then(|offset| self.class_name_for_offset(offset))
                    .filter(|name| !name.is_empty())
                    .map(|class_name| format!("{}.{}", class_name, method_name))
                    .unwrap_or_else(|| method_name.clone());
                file.segments.push(AbcSegment::Raw(format!(
                    ".function any {} {{",
                    qualified_name
                )));
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
    fn should_render_literal(&self, entries: &[AbcLiteralValue]) -> bool {
        entries.iter().any(|entry| {
            !matches!(
                entry,
                AbcLiteralValue::Raw { .. } | AbcLiteralValue::TagValue(_)
            )
        })
    }

    fn render_module_literal(&self, index: usize, offset: u32) -> Option<(String, Vec<String>)> {
        let module = self.parse_module_literal(offset)?;
        let mut lines = Vec::new();
        lines.push(format!(
            "{} 0x{offset:04x} {{ {} [",
            index,
            module.records.len()
        ));
        lines.push("\tMODULE_REQUEST_ARRAY: {".to_owned());
        for (idx, request) in module.requests.iter().enumerate() {
            lines.push(format!("\t\t{} : {},", idx, request));
        }
        lines.push("\t};".to_owned());
        for record in module.records {
            let mut parts = Vec::new();
            parts.push(format!("ModuleTag: {}", record.tag));
            if let Some(local) = record.local_name {
                parts.push(format!("local_name: {}", local));
            }
            if let Some(export) = record.export_name {
                parts.push(format!("export_name: {}", export));
            }
            if let Some(import) = record.import_name {
                parts.push(format!("import_name: {}", import));
            }
            if let Some(request) = record.module_request {
                parts.push(format!("module_request: {}", request));
            }
            lines.push(format!("\t{};", parts.join(", ")));
        }
        lines.push("]}".to_owned());
        let body = lines.join("\n");
        Some((body, lines))
    }

    fn parse_module_literal(&self, offset: u32) -> Option<ModuleLiteralDisplay> {
        let mut reader = AbcReader::new(&self.data);
        reader.seek(offset as usize).ok()?;
        let _literal_count = reader.read_u32().ok()?;

        let request_count = reader.read_u32().ok()? as usize;
        let mut requests = Vec::with_capacity(request_count);
        for _ in 0..request_count {
            let str_offset = reader.read_u32().ok()?;
            let value = self
                .resolve_string(str_offset)
                .unwrap_or_else(|| format!("@0x{str_offset:04x}"));
            requests.push(value);
        }

        let mut records = Vec::new();

        let regular_imports = reader.read_u32().ok()? as usize;
        for _ in 0..regular_imports {
            let local_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<local>".to_owned());
            let import_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<import>".to_owned());
            let module_idx = reader.read_u16().ok()? as usize;
            records.push(ModuleRecordDisplay {
                tag: "REGULAR_IMPORT",
                local_name: Some(local_name),
                export_name: None,
                import_name: Some(import_name),
                module_request: requests.get(module_idx).cloned(),
            });
        }

        let namespace_imports = reader.read_u32().ok()? as usize;
        for _ in 0..namespace_imports {
            let local_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<local>".to_owned());
            let module_idx = reader.read_u16().ok()? as usize;
            records.push(ModuleRecordDisplay {
                tag: "NAMESPACE_IMPORT",
                local_name: Some(local_name),
                export_name: None,
                import_name: None,
                module_request: requests.get(module_idx).cloned(),
            });
        }

        let local_exports = reader.read_u32().ok()? as usize;
        for _ in 0..local_exports {
            let local_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<local>".to_owned());
            let export_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<export>".to_owned());
            records.push(ModuleRecordDisplay {
                tag: "LOCAL_EXPORT",
                local_name: Some(local_name),
                export_name: Some(export_name),
                import_name: None,
                module_request: None,
            });
        }

        let indirect_exports = reader.read_u32().ok()? as usize;
        for _ in 0..indirect_exports {
            let export_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<export>".to_owned());
            let import_name = self
                .resolve_string(reader.read_u32().ok()?)
                .unwrap_or_else(|| "<import>".to_owned());
            let module_idx = reader.read_u16().ok()? as usize;
            records.push(ModuleRecordDisplay {
                tag: "INDIRECT_EXPORT",
                local_name: None,
                export_name: Some(export_name),
                import_name: Some(import_name),
                module_request: requests.get(module_idx).cloned(),
            });
        }

        let star_exports = reader.read_u32().ok()? as usize;
        for _ in 0..star_exports {
            let module_idx = reader.read_u16().ok()? as usize;
            records.push(ModuleRecordDisplay {
                tag: "STAR_EXPORT",
                local_name: None,
                export_name: None,
                import_name: None,
                module_request: requests.get(module_idx).cloned(),
            });
        }

        Some(ModuleLiteralDisplay { requests, records })
    }
    fn render_literal_value(&self, value: &AbcLiteralValue) -> String {
        match value {
            AbcLiteralValue::Boolean(v) => {
                format!("bool:{}", if *v { "true" } else { "false" })
            }
            AbcLiteralValue::Integer(v) => format!("i32:{v}"),
            AbcLiteralValue::Float(v) => format!("f32:{v}"),
            AbcLiteralValue::Double(v) => format!("f64:{v}"),
            AbcLiteralValue::String(index) | AbcLiteralValue::EtsImplements(index) => {
                if let Some(value) = self.resolve_string(*index) {
                    let normalized = if value.starts_with('L') && value.ends_with(';') {
                        normalize_record_name(&value)
                    } else {
                        value
                    };
                    format!("string:\"{}\"", escape_string(&normalized))
                } else {
                    format!("string_id:{}", index)
                }
            }
            AbcLiteralValue::Type(index) => format!("type_id:{}", index),
            AbcLiteralValue::Method(index) => self.render_method_literal("method", *index),
            AbcLiteralValue::GeneratorMethod(index) => {
                self.render_method_literal("generator_method", *index)
            }
            AbcLiteralValue::AsyncGeneratorMethod(index) => {
                self.render_method_literal("async_generator_method", *index)
            }
            AbcLiteralValue::MethodAffiliate(idx) => {
                format!("method_affiliate:{}", idx)
            }
            AbcLiteralValue::Builtin(code) => format!("builtin:{}", code),
            AbcLiteralValue::BuiltinTypeIndex(code) => format!("builtin_type:{}", code),
            AbcLiteralValue::Accessor(code) => format!("accessor:{}", code),
            AbcLiteralValue::Getter(index) => self.render_method_literal("getter", *index),
            AbcLiteralValue::Setter(index) => self.render_method_literal("setter", *index),
            AbcLiteralValue::LiteralArray(index) => format!("literal_array:0x{index:04x}"),
            AbcLiteralValue::LiteralBufferIndex(index) => {
                format!("literal_buffer:0x{index:04x}")
            }
            AbcLiteralValue::BigInt(bytes) => format!("bigint(len={})", bytes.len()),
            AbcLiteralValue::BigIntExternal { length } => {
                format!("bigint_external(len={length})")
            }
            AbcLiteralValue::Any { type_index, data } => {
                format!("any(type={}, len={})", type_index, data.len())
            }
            AbcLiteralValue::AnyExternal { type_index, length } => {
                format!("any_external(type={}, len={length})", type_index)
            }
            AbcLiteralValue::Null => "null_value:0".to_owned(),
            AbcLiteralValue::Undefined => "undefined".to_owned(),
            AbcLiteralValue::TagValue(tag) => format!("tag:0x{tag:02x}"),
            AbcLiteralValue::Raw { tag, bytes } => {
                format!("raw(tag=0x{tag:02x}, len={})", bytes.len())
            }
        }
    }

    fn render_method_literal(&self, kind: &str, method_offset: u32) -> String {
        if let Some(name) = self.format_method_ref(method_offset) {
            format!("{kind}:{name}")
        } else {
            format!("{kind}:0x{method_offset:04x}")
        }
    }

    fn format_method_ref(&self, method_offset: u32) -> Option<String> {
        self.get_method_by_offset(method_offset)
            .map(|method| self.display_method_name(method))
    }

    fn get_method_by_offset(&self, offset: u32) -> Option<&AbcMethodItem> {
        self.methods
            .binary_search_by_key(&offset, |item| item.offset)
            .ok()
            .map(|index| &self.methods[index])
    }

    fn class_name_for_offset(&self, offset: u32) -> Option<String> {
        self.classes
            .iter()
            .find(|class| class.offset == offset)
            .map(|class| normalize_record_name(&class.name.value))
    }

    fn display_method_name(&self, method: &AbcMethodItem) -> String {
        let raw = &method.name.value;
        if raw.is_empty() || raw.chars().any(|ch| ch.is_control()) {
            format!("method@0x{:x}", method.offset)
        } else if raw.starts_with('#') || raw.starts_with('@') {
            raw.clone()
        } else {
            normalize_method_name(raw)
        }
    }

    fn class_byte_range(&self, class: &AbcClassDefinition) -> (usize, usize) {
        self.class_ranges
            .iter()
            .zip(self.classes.iter())
            .find_map(|(&(start, end), candidate)| {
                if candidate.offset == class.offset {
                    Some((start as usize, end as usize))
                } else {
                    None
                }
            })
            .unwrap_or((class.offset as usize, self.data.len()))
    }

    fn render_record_body(&self, _class: &AbcClassDefinition, record_name: &str) -> Vec<String> {
        if record_name.starts_with('&') {
            let simple_name = simple_class_name(record_name);
            let scope_literal = self
                .find_scope_names_literal(_class, simple_name)
                .unwrap_or_default();
            let module_literal = self
                .find_module_record_literal(_class, simple_name)
                .unwrap_or_default();
            let mut body = Vec::new();
            body.push("\tu8 pkgName@entry = 0x0".to_owned());
            body.push("\tu8 isCommonjs = 0x0".to_owned());
            body.push("\tu8 hasTopLevelAwait = 0x0".to_owned());
            body.push("\tu8 isSharedModule = 0x0".to_owned());
            body.push(format!("\tu32 scopeNames = 0x{scope_literal:04x}"));
            body.push(format!("\tu32 moduleRecordIdx = 0x{module_literal:04x}"));
            body
        } else if record_name.starts_with('@') {
            let native_name = format!("@native.{}", record_name.trim_start_matches('@'));
            vec![format!("\tu8 {} = 0x0", native_name)]
        } else {
            Vec::new()
        }
    }

    fn find_scope_names_literal(
        &self,
        class: &AbcClassDefinition,
        simple_name: &str,
    ) -> Option<u32> {
        let (start, end) = self.class_byte_range(class);
        let mut cursor = start;
        while cursor + 4 <= end {
            let raw = u32::from_le_bytes(
                self.data[cursor..cursor + 4]
                    .try_into()
                    .expect("slice to array"),
            );
            let candidate = raw >> 8;
            if candidate != 0 {
                let mut reader = AbcReader::new(&self.data);
                if let Ok(array) = AbcLiteralArray::read_at(&mut reader, candidate) {
                    if let Some(AbcLiteralValue::String(index)) = array.entries.first() {
                        if self
                            .resolve_string(*index)
                            .map(|value| value == simple_name)
                            .unwrap_or(false)
                        {
                            return Some(candidate);
                        }
                    }
                }
            }
            cursor += 1;
        }
        None
    }

    fn find_module_record_literal(
        &self,
        class: &AbcClassDefinition,
        simple_name: &str,
    ) -> Option<u32> {
        let (start, end) = self.class_byte_range(class);
        let mut cursor = start;
        let mut fallback = None;
        while cursor + 4 <= end {
            let raw = u32::from_le_bytes(
                self.data[cursor..cursor + 4]
                    .try_into()
                    .expect("slice to array"),
            );
            let candidate = raw >> 8;
            if candidate != 0 {
                if let Some(module) = self.parse_module_literal(candidate) {
                    if module.records.iter().any(|record| {
                        record.tag == "LOCAL_EXPORT"
                            && record
                                .local_name
                                .as_deref()
                                .map(|name| name == simple_name)
                                .unwrap_or(false)
                    }) {
                        return Some(candidate);
                    }
                    if fallback.is_none() {
                        fallback = Some(candidate);
                    }
                }
            }
            cursor += 1;
        }
        if fallback.is_some() {
            return fallback;
        }
        self.literal_offsets.iter().copied().find(|offset| {
            self.parse_module_literal(*offset)
                .map(|module| {
                    module.records.iter().any(|record| {
                        record.tag == "LOCAL_EXPORT"
                            && record
                                .local_name
                                .as_deref()
                                .map(|name| name == simple_name)
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
    }
}

fn simple_class_name(record_name: &str) -> &str {
    let trimmed = record_name.trim_matches('&');
    trimmed.rsplit('.').next().unwrap_or(trimmed)
}

#[derive(Debug, Clone)]
struct ModuleLiteralDisplay {
    requests: Vec<String>,
    records: Vec<ModuleRecordDisplay>,
}

#[derive(Debug, Clone)]
struct ModuleRecordDisplay {
    tag: &'static str,
    local_name: Option<String>,
    export_name: Option<String>,
    import_name: Option<String>,
    module_request: Option<String>,
}

fn process_literal_queue(
    data: &[u8],
    queue: &mut std::collections::VecDeque<u32>,
    known_offsets: &mut std::collections::HashSet<u32>,
    pairs: &mut Vec<(u32, Option<AbcLiteralArray>)>,
) {
    while let Some(offset) = queue.pop_front() {
        if pairs.iter().any(|(existing, _)| *existing == offset) {
            continue;
        }
        let mut reader = AbcReader::new(data);
        match AbcLiteralArray::read_at(&mut reader, offset) {
            Ok(array) => {
                if array.entries.is_empty() {
                    pairs.push((offset, None));
                } else {
                    for entry in &array.entries {
                        if let AbcLiteralValue::LiteralArray(inner) = entry {
                            if known_offsets.insert(*inner) {
                                queue.push_back(*inner);
                            }
                        }
                    }
                    pairs.push((offset, Some(array)));
                }
            }
            Err(_) => {
                known_offsets.remove(&offset);
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
        AbcLiteralValue::Method(index)
        | AbcLiteralValue::GeneratorMethod(index)
        | AbcLiteralValue::AsyncGeneratorMethod(index)
        | AbcLiteralValue::Getter(index)
        | AbcLiteralValue::Setter(index) => LiteralValue::Method(FunctionId::new(*index)),
        AbcLiteralValue::MethodAffiliate(idx) => LiteralValue::MethodAffiliate(*idx),
        AbcLiteralValue::Builtin(code) | AbcLiteralValue::BuiltinTypeIndex(code) => {
            LiteralValue::Builtin(*code)
        }
        AbcLiteralValue::Accessor(code) => LiteralValue::Accessor(*code),
        AbcLiteralValue::LiteralArray(index) | AbcLiteralValue::LiteralBufferIndex(index) => {
            LiteralValue::LiteralArray(*index)
        }
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
        AbcLiteralValue::EtsImplements(index) => LiteralValue::String(StringId::new(*index)),
        AbcLiteralValue::Null => LiteralValue::Null,
        AbcLiteralValue::Undefined => LiteralValue::Undefined,
        AbcLiteralValue::TagValue(tag) => LiteralValue::Raw {
            tag: 0x00,
            bytes: vec![*tag],
        },
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
    use super::{BinaryAbcFile, normalize_record_name, simple_class_name};
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
        assert!(abc.literal_arrays.iter().any(|maybe| maybe.is_some()));
    }

    #[test]
    fn list_modules_literal_offsets() {
        let bytes = std::fs::read("test-data/modules.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        let collected: Vec<u32> = abc
            .literal_offsets
            .iter()
            .copied()
            .filter(|offset| *offset != 0)
            .collect();
        assert!(!collected.is_empty());
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

    #[test]
    fn locate_module_literal_for_entryability() {
        let bytes = std::fs::read("test-data/modules.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        let module = abc
            .parse_module_literal(0x16d1)
            .expect("module literal 0x16d1");
        assert!(module.records.iter().any(|record| {
            record.tag == "LOCAL_EXPORT"
                && record
                    .local_name
                    .as_deref()
                    .map(|name| name == "EntryAbility")
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn record_module_index_lookup() {
        let bytes = std::fs::read("test-data/modules.abc").expect("fixture");
        let abc = BinaryAbcFile::parse(&bytes).expect("parse binary abc");
        let entry_record = abc
            .classes
            .iter()
            .find(|class| {
                normalize_record_name(&class.name.value)
                    == "&entry.src.main.ets.entryability.EntryAbility&"
            })
            .expect("entry ability class");
        let normalized = normalize_record_name(&entry_record.name.value);
        let simple = simple_class_name(&normalized);
        let offset = abc
            .find_module_record_literal(entry_record, simple)
            .expect("module literal for EntryAbility");
        assert_eq!(offset, 0x16d1);

        let index_record = abc
            .classes
            .iter()
            .find(|class| {
                normalize_record_name(&class.name.value)
                    == "&entry.src.main.ets.pages.Index&"
            })
            .expect("index class");
        let normalized_index = normalize_record_name(&index_record.name.value);
        let simple_index = simple_class_name(&normalized_index);
        let index_offset = abc
            .find_module_record_literal(index_record, simple_index)
            .expect("module literal for Index");
        assert_eq!(index_offset, 0x1833);
    }
}
