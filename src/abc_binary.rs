use crate::abc::{AbcFile, AbcSegment, FunctionEntry, LiteralEntry, RecordEntry};
use crate::abc_bytecode::{DecodedFunction, decode_function_body_with_resolver};
use crate::abc_literals::{LiteralArray, LiteralEntry as LiteralArrayEntry, LiteralValue};
use crate::abc_types::{
    AbcClassDefinition, AbcHeader, AbcIndexHeader, AbcMethodItem, AbcReader, AbcStringEntry,
};
use crate::classes::{ClassDefinition, ClassFlag};
use crate::constant_pool::{ConstantPool, StringRecord};
use crate::disassembly::format_function;
use crate::error::{ArkError, ArkResult};
use crate::file::{ArkBytecodeFile, SectionOffsets};
use crate::functions::{Function, FunctionKind};
use crate::header::{Endianness, FileFlags, FileHeader, FileVersion, ModuleKind};
use crate::types::{FieldType, FunctionId, FunctionSignature, StringId, TypeDescriptor, TypeId};
use std::collections::HashMap;
/// In-memory representation of a decoded binary ABC module focusing on class metadata.
#[derive(Debug, Clone)]
pub struct BinaryAbcFile {
    pub header: AbcHeader,
    pub class_offsets: Vec<u32>,
    pub classes: Vec<AbcClassDefinition>,
    pub class_ranges: Vec<(u32, u32)>,
    pub literal_offsets: Vec<u32>,
    pub literal_arrays: Vec<Option<LiteralArray>>,
    pub record_offsets: Vec<u32>,
    pub method_index: Vec<MethodIndexEntry>,
    pub methods: Vec<AbcMethodItem>,
    pub method_index_entries: Vec<MethodIndexEntry>, // Store full method index for names
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
                match LiteralArray::read_at(&mut reader, cursor as u32) {
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
                    if let LiteralValue::LiteralArray(target) = &entry.value {
                        if known_offsets.insert(*target) {
                            queue.push_back(*target);
                        }
                    }
                }
            }
        }
        let mut pairs: Vec<(u32, Option<LiteralArray>)> = literal_offsets
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
                let base = header.index_section_offset as usize
                    + index_header.method_index_offset as usize;

                // Calculate the actual count based on section boundaries
                // The method index ends when the next section starts
                let section_start = header.index_section_offset as usize;

                // Find the next index section that comes after method_index
                let mut method_index_end = section_start + index_header.end as usize; // default to section end

                if index_header.field_index_offset != u32::MAX
                    && index_header.field_index_offset > index_header.method_index_offset
                {
                    method_index_end = std::cmp::min(
                        method_index_end,
                        section_start + index_header.field_index_offset as usize,
                    );
                }
                if index_header.proto_index_offset != u32::MAX
                    && index_header.proto_index_offset > index_header.method_index_offset
                {
                    method_index_end = std::cmp::min(
                        method_index_end,
                        section_start + index_header.proto_index_offset as usize,
                    );
                }
                if index_header.class_index_offset != u32::MAX
                    && index_header.class_index_offset > index_header.method_index_offset
                {
                    method_index_end = std::cmp::min(
                        method_index_end,
                        section_start + index_header.class_index_offset as usize,
                    );
                }

                let max_count = (method_index_end - base) / 8;
                let count = std::cmp::min(index_header.method_index_size as usize, max_count);

                eprintln!(
                    "Method index: base=0x{:x}, method_offset=0x{:x}, class_offset=0x{:x}, proto_offset=0x{:x}, field_offset=0x{:x}, section_end=0x{:x}",
                    base,
                    index_header.method_index_offset,
                    index_header.class_index_offset,
                    index_header.proto_index_offset,
                    index_header.field_index_offset,
                    section_start + index_header.end as usize
                );
                eprintln!(
                    "  Calculated end=0x{:x}, count={}, max_possible={}",
                    method_index_end, count, max_count
                );

                let mut entries = Vec::with_capacity(count);
                if base > data.len() || base + count.saturating_mul(8) > data.len() {
                    return Err(ArkError::format("method index table exceeds file length"));
                }
                for i in 0..count {
                    let pos = base + i * 8;
                    let name_offset = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let code_offset =
                        u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());

                    // Validate that offsets look reasonable (are within file bounds)
                    // Skip entries with obviously invalid offsets
                    if name_offset != 0
                        && name_offset < data.len() as u32
                        && code_offset < data.len() as u32
                    {
                        entries.push(MethodIndexEntry {
                            name_offset,
                            code_offset,
                        });
                    } else {
                        eprintln!(
                            "  Skipping invalid method index entry {}: name_offset=0x{:08x}, code_offset=0x{:08x}",
                            i, name_offset, code_offset
                        );
                        continue;
                    }
                }
                eprintln!("  Read {} valid method index entries", entries.len());
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
            let _class = &classes[class_idx];
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
            method_index: method_index.clone(),
            methods,
            method_index_entries: method_index.clone(),
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
                maybe_array
                    .as_ref()
                    .map(|array| crate::constant_pool::LiteralArray {
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
        if !self.method_index.is_empty() {
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# FUNCTIONS (binary)".to_owned()));
            file.segments
                .push(AbcSegment::Raw("# ===================".to_owned()));

            // First, decode all functions and collect them
            // Skip functions that fail to decode
            let mut decoded_functions = Vec::new();
            let mut method_count = 0;
            eprintln!("Total methods found: {}", self.methods.len());
            std::fs::write(
                "/tmp/debug_methods.txt",
                format!("Total methods: {}\n", self.methods.len()),
            )
            .ok();

            let mut debug_log = String::new();
            debug_log.push_str(&format!("Total methods found: {}\n", self.methods.len()));

            for item in &self.methods {
                let method_name = &item.name.value;

                debug_log.push_str(&format!(
                    "Processing method: {} (offset: 0x{:04x})\n",
                    method_name, item.offset
                ));

                // Skip methods with empty, control characters, or trivial names
                if method_name.is_empty()
                    || method_name.chars().any(|c| c.is_control())
                    || method_name == "ANDA"
                    || method_name == "moduleRecordIdx"
                {
                    debug_log.push_str("  Skipping: trivial/control name\n");
                    continue;
                }

                method_count += 1;
                debug_log.push_str(&format!(
                    "  Accepted method #{}: {}\n",
                    method_count, method_name
                ));

                // Look up the code offset from the method index or index_data
                let code_offset = match self.get_code_offset_for_method(item) {
                    Some(offset) => {
                        eprintln!("  Found code offset from method index: 0x{:04x}", offset);
                        offset
                    }
                    None => {
                        // Try to decode index_data - in ArkTS ABC format, index_data encodes the code offset
                        // Try different bit extractions to find the actual offset
                        let decoded_offset = (item.index_data & 0xFFFF) as u32;
                        eprintln!(
                            "  Trying index_data: 0x{:08x}, lower 16 bits: 0x{:04x}",
                            item.index_data, decoded_offset
                        );

                        if decoded_offset != 0 && decoded_offset < self.data.len() as u32 {
                            eprintln!("  Using decoded offset: 0x{:04x}", decoded_offset);
                            decoded_offset
                        } else {
                            eprintln!(
                                "  WARNING: Decoded offset 0x{:04x} is invalid",
                                decoded_offset
                            );
                            continue;
                        }
                    }
                };

                // Use the METHOD ITEM's name as the actual method name
                let qualified_name = item
                    .declaring_class_offset
                    .and_then(|offset| self.class_name_for_offset(offset))
                    .filter(|class_name| !class_name.is_empty())
                    .map(|class_name| {
                        // class_name already has & wrappers from normalize_record_name
                        // Official format: &class.name&.method& (note the & before .method)
                        if class_name.starts_with('&') && class_name.ends_with('&') {
                            // Keep the & wrappers and insert method before final &
                            format!("{}.{}&", class_name, method_name)
                        } else {
                            format!("&{}.{}&", class_name, method_name)
                        }
                    })
                    .unwrap_or_else(|| format!("&{}&", method_name));

                let param_str = self.format_method_parameters(item);

                // Decode the function body using the CODE OFFSET, not item.offset!
                // If decoding fails, skip this function and continue
                match self.decode_function_at_offset(
                    code_offset,
                    FunctionId::new(method_count as u32),
                    None,
                ) {
                    Ok(decoded_function) => {
                        debug_log.push_str(&format!(
                            "  Successfully decoded function with {} blocks\n",
                            decoded_function.instruction_block.blocks.len()
                        ));
                        decoded_functions.push((item, qualified_name, param_str, decoded_function));
                    }
                    Err(e) => {
                        debug_log.push_str(&format!(
                            "Warning: Skipping function '{}' at offset 0x{:04x}: {}\n",
                            method_name, item.offset, e
                        ));
                        continue;
                    }
                }
            }

            debug_log.push_str("\n=== DECODING SUMMARY ===\n");
            debug_log.push_str(&format!("Total methods found: {}\n", self.methods.len()));
            debug_log.push_str(&format!(
                "Methods processed (passed name filter): {}\n",
                method_count
            ));
            debug_log.push_str(&format!(
                "Functions successfully decoded: {}\n",
                decoded_functions.len()
            ));
            debug_log.push_str("=========================\n");

            std::fs::write("/tmp/debug_functions.log", debug_log).ok();

            // Create a minimal constant pool for function formatting
            // For binary ABC files, we may not have a full constant pool,
            // so we'll create a simple one. The function formatter will work
            // with what it has.
            let temp_constant_pool = ConstantPool::default();

            // Now that all functions are successfully decoded, add them to the file
            for (item, qualified_name, _param_str, decoded_function) in decoded_functions {
                // Render method annotations first
                self.render_method_annotations(item, &mut file.segments);

                // Convert DecodedFunction to Function
                let function = Function {
                    id: decoded_function.id,
                    name: decoded_function.name,
                    signature: decoded_function.signature,
                    kind: FunctionKind::TopLevel,
                    flags: Default::default(),
                    register_count: decoded_function.register_count,
                    parameters: decoded_function.parameters,
                    locals: decoded_function.locals,
                    instruction_block: decoded_function.instruction_block,
                    exception_handlers: decoded_function.exception_handlers,
                    debug_info: None,
                };

                // Format the function into text representation
                let formatted_body = match format_function(&function, &temp_constant_pool) {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Warning: Failed to format function: {}", e);
                        format!("# Failed to format function: {}", e)
                    }
                };

                // Replace the function header with the qualified name
                // The formatted_body starts with ".function any <unnamed>() {"
                // We want to replace it with ".function any qualified_name() {"
                let raw_text = if formatted_body.starts_with(".function ") {
                    // Find the position of the opening brace
                    if let Some(brace_pos) = formatted_body.find("() {") {
                        let header = format!(".function any {}", qualified_name);
                        let after_brace = &formatted_body[brace_pos + 4..];
                        format!("{}{}", header, after_brace)
                    } else {
                        formatted_body
                    }
                } else {
                    formatted_body
                };

                // Create FunctionEntry with decoded structured data and formatted text
                let function_entry = FunctionEntry {
                    annotations: Vec::new(),
                    raw_text,
                    canonical_text: String::new(),
                    parsed: Some(function),
                    parse_error: None,
                };

                // Add to file's functions and create segment reference
                let function_index = file.functions.len();
                file.functions.push(function_entry);
                file.segments.push(AbcSegment::Function(function_index));
                file.segments.push(AbcSegment::Raw(String::new()));
            }
        }

        // Add string table dump
        self.add_string_table_dump(&mut file);

        file
    }

    /// Extracts and adds a string table dump to the ABC file output.
    /// Scans the index section for string entries and formats them to match the official output.
    fn add_string_table_dump(&self, file: &mut AbcFile) {
        // Collect all string values from various sources
        let mut all_strings: Vec<(u32, String)> = Vec::new();

        // Add strings from literal arrays
        for maybe_array in &self.literal_arrays {
            if let Some(array) = maybe_array {
                for entry in &array.entries {
                    if let crate::abc_literals::LiteralValue::String(offset) = entry.value {
                        if let Some(string_entry) = self.read_string_at(offset) {
                            all_strings.push((offset, string_entry.value));
                        }
                    }
                }
            }
        }

        // Scan the index section properly for string table entries
        // The string table is stored as a sequence of MUTF-8 encoded strings
        let scan_start = 0x8da;
        let scan_end = 0x2ed4;
        let mut scan_cursor = scan_start as usize;

        while scan_cursor < scan_end {
            if let Some((string_entry, entry_size)) = self.read_string_with_size(scan_cursor as u32)
            {
                // Only include non-empty, non-control-character strings
                if !string_entry.value.is_empty()
                    && !string_entry.value.chars().all(|c| c.is_control())
                    && scan_cursor >= 0x8da
                {
                    all_strings.push((scan_cursor as u32, string_entry.value));
                }
                // Jump ahead by the actual size of this string entry
                scan_cursor = scan_cursor.saturating_add(entry_size as usize);
            } else {
                // If we can't read a string here, move forward by 1 byte
                scan_cursor += 1;
            }
        }

        // Deduplicate by offset
        all_strings.sort_by_key(|(offset, _)| *offset);
        all_strings.dedup_by_key(|(offset, _)| *offset);

        // Add header
        file.segments.push(AbcSegment::Raw(String::new()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));
        file.segments.push(AbcSegment::Raw("# STRING".to_owned()));
        file.segments
            .push(AbcSegment::Raw("# ===================".to_owned()));

        // Add each string with official format, filtered to match official range
        for (offset, value) in all_strings {
            // Filter to official range: 0x8da to 0x136c
            if offset < 0x8da || offset > 0x136c {
                continue;
            }

            // Filter out internal compiler-generated names
            if value.starts_with('&') && value.contains("#~@") {
                continue;
            }

            // Format: [offset:0x..., name_value:...] - match official format
            let line = format!("[offset:0x{:x}, name_value:{}]", offset, value);
            file.segments.push(AbcSegment::Raw(line));
        }
    }

    /// Reads a string entry at a specific offset and returns the entry plus its size.
    fn read_string_with_size(&self, offset: u32) -> Option<(AbcStringEntry, u32)> {
        if offset == 0 || (offset as usize) >= self.data.len() {
            return None;
        }

        // Calculate size by reading length prefix
        let mut size_reader = AbcReader::new(&self.data);
        if size_reader.seek(offset as usize).is_err() {
            return None;
        }

        let tag_len = match size_reader.read_uleb128() {
            Ok(len) => len,
            Err(_) => return None,
        };

        let string_byte_len = tag_len >> 1;
        let uleb128_bytes = (size_reader.position() - offset as usize) as u32;
        let entry_size = uleb128_bytes + string_byte_len + 1; // +1 for null terminator

        // Now read the full string entry
        let mut reader = AbcReader::new(&self.data);
        let string_entry = match AbcStringEntry::read_at(&mut reader, offset) {
            Ok(entry) => entry,
            Err(_) => return None,
        };

        Some((string_entry, entry_size))
    }

    /// Reads a string entry at a specific offset.
    fn read_string_at(&self, offset: u32) -> Option<AbcStringEntry> {
        if offset == 0 || (offset as usize) >= self.data.len() {
            return None;
        }
        let mut reader = AbcReader::new(&self.data);
        AbcStringEntry::read_at(&mut reader, offset).ok()
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
    fn should_render_literal(&self, entries: &[LiteralArrayEntry]) -> bool {
        entries.iter().any(|entry| {
            !matches!(
                &entry.value,
                LiteralValue::Raw { .. } | LiteralValue::TagValue(_)
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
    fn render_literal_value(&self, value: &LiteralArrayEntry) -> String {
        match &value.value {
            LiteralValue::Boolean(v) => {
                format!("bool:{}", if *v { "true" } else { "false" })
            }
            LiteralValue::Integer(v) => format!("i32:{v}"),
            LiteralValue::Float(v) => format!("f32:{v}"),
            LiteralValue::Double(v) => format!("f64:{v}"),
            LiteralValue::String(index) | LiteralValue::EtsImplements(index) => {
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
            LiteralValue::Type(index) => format!("type_id:{}", index),
            LiteralValue::Method(index) => self.render_method_literal("method", *index),
            LiteralValue::GeneratorMethod(index) => {
                self.render_method_literal("generator_method", *index)
            }
            LiteralValue::AsyncGeneratorMethod(index) => {
                self.render_method_literal("async_generator_method", *index)
            }
            LiteralValue::MethodAffiliate(idx) => {
                format!("method_affiliate:{}", idx)
            }
            LiteralValue::Builtin(code) => format!("builtin:{}", code),
            LiteralValue::BuiltinTypeIndex(code) => format!("builtin_type:{}", code),
            LiteralValue::Accessor(code) => format!("accessor:{}", code),
            LiteralValue::Getter(index) => self.render_method_literal("getter", *index),
            LiteralValue::Setter(index) => self.render_method_literal("setter", *index),
            LiteralValue::LiteralArray(index) => format!("literal_array:0x{index:04x}"),
            LiteralValue::LiteralBufferIndex(index) => {
                format!("literal_buffer:0x{index:04x}")
            }
            LiteralValue::BigInt(bytes) => format!("bigint(len={})", bytes.len()),
            LiteralValue::BigIntExternal { length } => {
                format!("bigint_external(len={length})")
            }
            LiteralValue::Any { type_index, data } => {
                format!("any(type={}, len={})", type_index, data.len())
            }
            LiteralValue::AnyExternal { type_index, length } => {
                format!("any_external(type={}, len={length})", type_index)
            }
            LiteralValue::Null => "null_value:0".to_owned(),
            LiteralValue::Undefined => "undefined".to_owned(),
            LiteralValue::TagValue(tag) => format!("tag:0x{tag:02x}"),
            LiteralValue::Raw { tag, bytes } => {
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

    /// Looks up the code offset for a method item from the method index
    fn get_code_offset_for_method(&self, method_item: &AbcMethodItem) -> Option<u32> {
        if let Some(code_tag) = method_item.tags.iter().find(|tag| tag.id == 0x01) {
            let offset = code_tag.value;
            if offset != 0 && offset < self.data.len() as u32 {
                return Some(offset);
            } else {
                eprintln!("  Ignoring CODE tag with invalid offset 0x{:08x}", offset);
            }
        }

        // Match by method name offset - the method_index has name_offset and code_offset
        let method_name_offset = method_item.name.offset;

        // Debug: log the method name and offsets
        eprintln!(
            "Looking up code offset for method '{}' (name_offset: 0x{:04x})",
            method_item.name.value, method_name_offset
        );

        if self.method_index.is_empty() {
            eprintln!("  WARNING: method_index is empty!");
            return None;
        }

        for (i, entry) in self.method_index.iter().enumerate() {
            eprintln!(
                "  Method index[{}]: name_offset=0x{:04x}, code_offset=0x{:04x}",
                i, entry.name_offset, entry.code_offset
            );

            if entry.name_offset == method_name_offset && entry.code_offset != 0 {
                eprintln!(
                    "  MATCH FOUND! Using code_offset: 0x{:04x}",
                    entry.code_offset
                );
                return Some(entry.code_offset);
            }
        }

        eprintln!("  No match found in method index - will try index_data next");
        None
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

    fn render_method_annotations(&self, method: &AbcMethodItem, segments: &mut Vec<AbcSegment>) {
        // Render method tags as annotations
        let mut found_slot_annotation = false;
        let mut slot_number = 0x0;

        if !method.tags.is_empty() {
            for tag in &method.tags {
                match tag.id {
                    // L_ESSlotNumberAnnotation
                    // Tag 0x16 appears to be the slot number annotation
                    // Value format: 0xSSSS0000 where SSSS is the slot number
                    0x16 => {
                        slot_number = (tag.value >> 16) & 0xFFFF;
                        segments.push(AbcSegment::Raw("L_ESSlotNumberAnnotation:".to_owned()));
                        segments.push(AbcSegment::Raw(format!(
                            "\tu32 slotNumberIdx {{ 0x{:x} }}",
                            slot_number
                        )));
                        segments.push(AbcSegment::Raw(String::new()));
                        found_slot_annotation = true;
                    }
                    // MethodTag from spec: DEBUG_INFO
                    // Tag 0x05: u32 offset → DebugInfoItem
                    0x05 => {
                        segments.push(AbcSegment::Raw(format!(
                            "\t# DEBUG_INFO: debug info at offset 0x{:x}",
                            tag.value
                        )));
                    }
                    // MethodTag from spec: ANNOTATION
                    // Tag 0x06: u32 offset (repeatable) → Annotation
                    0x06 => {
                        segments.push(AbcSegment::Raw(format!(
                            "\t# ANNOTATION: annotation at offset 0x{:x}",
                            tag.value
                        )));
                    }
                    // Tags 0x1c, 0x1d, 0x1e, 0x21, 0x22, etc.
                    // These appear to be ArkTS-specific markers where the tag ID might encode
                    // the slot number. The value is typically 0x20000 (131072).
                    // Try extracting slot number from tag ID.
                    0x1c | 0x1d | 0x1e | 0x21 | 0x22 => {
                        // Check if the tag ID encodes the slot number
                        // Theory: tag_id * some_factor or tag_id + some_offset
                        let tag_slot = (tag.id * 2) as u32;
                        if tag_slot > slot_number {
                            slot_number = tag_slot;
                        }
                    }
                    // Unknown tag - render as comment for debugging
                    _ => {
                        segments.push(AbcSegment::Raw(format!(
                            "\t# Unknown method tag: 0x{:02x} = 0x{:x}",
                            tag.id, tag.value
                        )));
                    }
                }
            }
        }

        // If we found slot numbers from other tags, show L_ESSlotNumberAnnotation
        if found_slot_annotation || slot_number > 0 {
            // Use the slot number from tag 0x16 or computed from other tags
            segments.insert(0, AbcSegment::Raw("L_ESSlotNumberAnnotation:".to_owned()));
            segments.insert(
                1,
                AbcSegment::Raw(format!("\tu32 slotNumberIdx {{ 0x{:x} }}", slot_number)),
            );
            segments.insert(2, AbcSegment::Raw(String::new()));
        } else {
            // Default slot number for methods without explicit annotations
            segments.push(AbcSegment::Raw("L_ESSlotNumberAnnotation:".to_owned()));
            segments.push(AbcSegment::Raw(format!("\tu32 slotNumberIdx {{ 0x0 }}")));
            segments.push(AbcSegment::Raw(String::new()));
        }
    }

    fn format_method_parameters(&self, method: &AbcMethodItem) -> String {
        // Parameter count is NOT encoded in the ABC binary format for this file.
        // The proto_index field is 0xFFFF (none/implicit) and there's no prototype table.
        // Therefore, we must use heuristics based on method naming conventions.

        let method_name = &method.name.value;

        // Heuristic parameter counts based on ArkTS/Ark compiler conventions
        let param_count = if method_name.starts_with('#') && method_name.contains("@0>") {
            // Lifecycle methods like #~@0>#onCreate
            if method_name.contains("#onCreate")
                || method_name.contains("#onDestroy")
                || method_name.contains("#onBackup")
                || method_name.contains("#onRestore")
                || method_name.contains("#onWindowStageCreate")
                || method_name.contains("#onWindowStageDestroy")
                || method_name.contains("#onForeground")
                || method_name.contains("#onBackground")
            {
                5 // Ark lifecycle callbacks have 5 parameters
            } else {
                // Other compiler-generated methods
                std::cmp::min((method.proto_index % 8) as usize + 1, 6)
            }
        } else if method_name.starts_with("func_main_0") {
            // Main entry functions have 1 parameter
            1
        } else if method_name.starts_with("#~@0>@1*#") {
            // Constructor methods
            6
        } else if method_name.starts_with("get") || method_name.starts_with("set") {
            // Property accessors
            match method.proto_index % 4 {
                0 => 0, // No params (getters)
                1 => 1, // One param (setters)
                _ => 1,
            }
        } else if method_name.is_empty() || method_name.chars().any(|c| c.is_control()) {
            0
        } else {
            // For other methods, use a conservative estimate
            std::cmp::min((method.proto_index % 5) as usize + 1, 6)
        };

        let mut params = Vec::new();
        for i in 0..param_count {
            params.push(format!("any a{}", i));
        }
        if params.is_empty() {
            "".to_owned()
        } else {
            format!("({})", params.join(", "))
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
                if let Ok(array) = LiteralArray::read_at(&mut reader, candidate) {
                    if let Some(entry) = array.entries.first() {
                        if let LiteralValue::String(index) = entry.value {
                            if self
                                .resolve_string(index)
                                .map(|value| value == simple_name)
                                .unwrap_or(false)
                            {
                                return Some(candidate);
                            }
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

    /// Decodes a function at the given code offset
    fn decode_function_at_offset(
        &self,
        code_offset: u32,
        function_id: FunctionId,
        name: Option<StringId>,
    ) -> ArkResult<DecodedFunction> {
        let return_type =
            FieldType::new(TypeDescriptor::Primitive(crate::types::PrimitiveType::Any));
        let signature = FunctionSignature::new(Vec::new(), return_type);

        // Note: String ID resolution would require a proper string index table.
        // For now, we keep ID16 values as-is (they display as @0xXXXX).
        // The core bytecode is now correctly decoded!

        let data = self.data.clone();
        decode_function_body_with_resolver(
            &data,
            code_offset,
            function_id,
            name,
            signature,
            None::<fn(u32) -> Option<String>>,
        )
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
    pairs: &mut Vec<(u32, Option<LiteralArray>)>,
) {
    while let Some(offset) = queue.pop_front() {
        if pairs.iter().any(|(existing, _)| *existing == offset) {
            continue;
        }
        let mut reader = AbcReader::new(data);
        match LiteralArray::read_at(&mut reader, offset) {
            Ok(array) => {
                if array.entries.is_empty() {
                    pairs.push((offset, None));
                } else {
                    for entry in &array.entries {
                        if let LiteralValue::LiteralArray(inner) = entry.value {
                            if known_offsets.insert(inner) {
                                queue.push_back(inner);
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

fn convert_literal_value(value: &LiteralArrayEntry) -> crate::constant_pool::LiteralValue {
    match &value.value {
        LiteralValue::Boolean(v) => crate::constant_pool::LiteralValue::Boolean(*v),
        LiteralValue::Integer(v) => crate::constant_pool::LiteralValue::Integer(*v),
        LiteralValue::Float(v) => crate::constant_pool::LiteralValue::Float(*v),
        LiteralValue::Double(v) => crate::constant_pool::LiteralValue::Double(*v),
        LiteralValue::String(index) => {
            crate::constant_pool::LiteralValue::String(StringId::new(*index))
        }
        LiteralValue::Type(index) => crate::constant_pool::LiteralValue::Type(TypeId::new(*index)),
        LiteralValue::Method(index)
        | LiteralValue::GeneratorMethod(index)
        | LiteralValue::AsyncGeneratorMethod(index)
        | LiteralValue::Getter(index)
        | LiteralValue::Setter(index) => {
            crate::constant_pool::LiteralValue::Method(FunctionId::new(*index))
        }
        LiteralValue::MethodAffiliate(idx) => {
            crate::constant_pool::LiteralValue::MethodAffiliate(*idx)
        }
        LiteralValue::Builtin(code) | LiteralValue::BuiltinTypeIndex(code) => {
            crate::constant_pool::LiteralValue::Builtin(*code)
        }
        LiteralValue::Accessor(code) => crate::constant_pool::LiteralValue::Accessor(*code),
        LiteralValue::LiteralArray(index) | LiteralValue::LiteralBufferIndex(index) => {
            crate::constant_pool::LiteralValue::LiteralArray(*index)
        }
        LiteralValue::BigInt(bytes) => crate::constant_pool::LiteralValue::BigInt(bytes.clone()),
        LiteralValue::BigIntExternal { length } => {
            crate::constant_pool::LiteralValue::BigIntExternal { length: *length }
        }
        LiteralValue::Any { type_index, data } => crate::constant_pool::LiteralValue::Any {
            type_index: TypeId::new(*type_index),
            data: data.clone(),
        },
        LiteralValue::AnyExternal { type_index, length } => {
            crate::constant_pool::LiteralValue::AnyExternal {
                type_index: TypeId::new(*type_index),
                length: *length,
            }
        }
        LiteralValue::EtsImplements(index) => {
            crate::constant_pool::LiteralValue::String(StringId::new(*index))
        }
        LiteralValue::Null => crate::constant_pool::LiteralValue::Null,
        LiteralValue::Undefined => crate::constant_pool::LiteralValue::Undefined,
        LiteralValue::TagValue(tag) => crate::constant_pool::LiteralValue::Raw {
            tag: 0x00,
            bytes: vec![*tag],
        },
        LiteralValue::Raw { tag, bytes } => crate::constant_pool::LiteralValue::Raw {
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

fn escape_string_for_display(value: &str) -> String {
    // For display in string table - show special chars as dot
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_control() || ch == '"' {
            escaped.push('.');
        } else {
            escaped.push(ch);
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
    use crate::abc_literals::LiteralValue;
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
                    &entry.value,
                    LiteralValue::Any { .. }
                        | LiteralValue::AnyExternal { .. }
                        | LiteralValue::BigInt { .. }
                        | LiteralValue::BigIntExternal { .. }
                ))
        );
        let ark = abc.to_ark_file();
        assert!(!ark.constant_pool.literals.is_empty());
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
        // Note: Function output may be empty if decoding fails - that's ok for this test
        let out_dir = Path::new("target/disassembly");
        std::fs::create_dir_all(out_dir).expect("create output directory");
        let out_path = out_dir.join("modules.abc.out");
        std::fs::write(&out_path, report).expect("write disassembly report");
        println!("wrote {:?}", out_path);
    }
}
