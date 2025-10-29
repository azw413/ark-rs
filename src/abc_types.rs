use crate::error::{ArkError, ArkResult};

fn decode_mutf8(input: &[u8]) -> ArkResult<String> {
    let mut units: Vec<u16> = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        index += 1;

        match byte {
            0x00 => {
                return Err(ArkError::format("embedded NUL inside MUTF-8 string"));
            }
            0x01..=0x7f => {
                units.push(byte as u16);
            }
            0xc0..=0xdf => {
                if index >= input.len() {
                    return Err(ArkError::format("truncated MUTF-8 sequence"));
                }
                let b2 = input[index];
                index += 1;
                if byte == 0xc0 && b2 == 0x80 {
                    units.push(0);
                } else {
                    let value = (((byte & 0x1f) as u16) << 6) | ((b2 & 0x3f) as u16);
                    units.push(value);
                }
            }
            0xe0..=0xef => {
                if index + 1 >= input.len() {
                    return Err(ArkError::format("truncated three-byte MUTF-8 sequence"));
                }
                let b2 = input[index];
                let b3 = input[index + 1];
                index += 2;
                let value = (((byte & 0x0f) as u16) << 12)
                    | (((b2 & 0x3f) as u16) << 6)
                    | ((b3 & 0x3f) as u16);
                units.push(value);
            }
            _ => {
                return Err(ArkError::format("unsupported MUTF-8 leading byte"));
            }
        }
    }

    String::from_utf16(&units).map_err(|_| ArkError::format("invalid UTF-16 sequence"))
}

/// Simple cursor for reading Ark bytecode structures from an in-memory buffer.
pub struct AbcReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> AbcReader<'a> {
    /// Creates a new reader positioned at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        AbcReader { data, offset: 0 }
    }

    /// Returns the current position within the underlying slice.
    pub fn position(&self) -> usize {
        self.offset
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Advances the cursor by `len` bytes without reading them.
    pub fn skip(&mut self, len: usize) -> ArkResult<()> {
        self.ensure(len)?;
        self.offset += len;
        Ok(())
    }

    /// Repositions the cursor to an absolute offset measured from the start of the slice.
    pub fn seek(&mut self, offset: usize) -> ArkResult<()> {
        if offset > self.data.len() {
            return Err(ArkError::UnexpectedEof {
                offset: self.data.len(),
                expected: offset.saturating_sub(self.data.len()),
            });
        }
        self.offset = offset;
        Ok(())
    }

    /// Reads `len` bytes and returns a borrowed slice.
    pub fn read_bytes(&mut self, len: usize) -> ArkResult<&'a [u8]> {
        self.ensure(len)?;
        let start = self.offset;
        let end = self.offset + len;
        self.offset = end;
        Ok(&self.data[start..end])
    }

    /// Reads a fixed-size array from the stream.
    pub fn read_array<const N: usize>(&mut self) -> ArkResult<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        // Safety: length is statically known to be N.
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    /// Reads an unsigned LEB128 value from the stream.
    pub fn read_uleb128(&mut self) -> ArkResult<u32> {
        let mut result: u32 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u32) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(ArkError::format("uleb128 integer overflow"));
            }
        }
        Ok(result)
    }

    /// Reads a signed LEB128 value from the stream.
    pub fn read_sleb128(&mut self) -> ArkResult<i64> {
        let mut result: i64 = 0;
        let mut shift = 0u32;
        let mut byte: u8;
        loop {
            byte = self.read_u8()?;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
            if shift >= 64 {
                return Err(ArkError::format("sleb128 integer overflow"));
            }
        }

        if (shift < 64) && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }

        Ok(result)
    }

    /// Reads bytes until the terminating NUL without consuming it.
    fn read_cstring_bytes(&mut self) -> ArkResult<Vec<u8>> {
        let mut buffer = Vec::new();
        while self.remaining() > 0 {
            let byte = self.read_u8()?;
            if byte == 0 {
                break;
            }
            buffer.push(byte);
        }
        Ok(buffer)
    }

    /// Reads a single byte.
    pub fn read_u8(&mut self) -> ArkResult<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16(&mut self) -> ArkResult<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&mut self) -> ArkResult<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Reads a big-endian `u32`.
    pub fn read_u32_be(&mut self) -> ArkResult<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&mut self) -> ArkResult<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn ensure(&self, len: usize) -> ArkResult<()> {
        if self
            .offset
            .checked_add(len)
            .map_or(false, |end| end <= self.data.len())
        {
            Ok(())
        } else {
            Err(ArkError::UnexpectedEof {
                offset: self.offset,
                expected: len,
            })
        }
    }
}

/// Convenience builder for emitting Ark bytecode structures to memory.
#[derive(Default)]
pub struct AbcWriter {
    buffer: Vec<u8>,
}

impl AbcWriter {
    pub fn new() -> Self {
        AbcWriter { buffer: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        AbcWriter {
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }

    pub fn position(&self) -> usize {
        self.buffer.len()
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buffer.extend_from_slice(&[value]);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }
}

/// Raw version information stored in Ark bytecode files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbcVersion {
    bytes: [u8; 4],
}

impl AbcVersion {
    pub const fn new(bytes: [u8; 4]) -> Self {
        AbcVersion { bytes }
    }

    pub const fn bytes(self) -> [u8; 4] {
        self.bytes
    }

    pub const fn major(self) -> u8 {
        self.bytes[0]
    }

    pub const fn minor(self) -> u8 {
        self.bytes[1]
    }

    pub const fn patch(self) -> u8 {
        self.bytes[2]
    }

    pub const fn build(self) -> u8 {
        self.bytes[3]
    }
}

impl Default for AbcVersion {
    fn default() -> Self {
        AbcVersion { bytes: [0; 4] }
    }
}

/// Header located at the beginning of every Ark bytecode (ABC) file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub version: AbcVersion,
    pub file_size: u32,
    pub foreign_offset: u32,
    pub foreign_size: u32,
    pub class_count: u32,
    pub class_index_offset: u32,
    pub line_number_program_count: u32,
    pub line_number_program_index_offset: u32,
    pub literal_array_count: u32,
    pub literal_array_index_offset: u32,
    pub index_count: u32,
    pub index_section_offset: u32,
}

impl AbcHeader {
    pub const MAGIC: [u8; 8] = *b"PANDA\0\0\0";

    pub fn read(reader: &mut AbcReader<'_>) -> ArkResult<Self> {
        let magic = reader.read_array::<8>()?;
        if magic != Self::MAGIC {
            return Err(ArkError::InvalidMagic {
                expected: Self::MAGIC.to_vec(),
                found: magic.to_vec(),
            });
        }

        let checksum = reader.read_u32()?;
        let version = AbcVersion::new(reader.read_array::<4>()?);
        let file_size = reader.read_u32()?;
        let foreign_offset = reader.read_u32()?;
        let foreign_size = reader.read_u32()?;
        let class_count = reader.read_u32()?;
        let class_index_offset = reader.read_u32()?;
        let line_number_program_count = reader.read_u32()?;
        let line_number_program_index_offset = reader.read_u32()?;
        let literal_array_count = reader.read_u32()?;
        let literal_array_index_offset = reader.read_u32()?;
        let index_count = reader.read_u32()?;
        let index_section_offset = reader.read_u32()?;

        Ok(AbcHeader {
            magic,
            checksum,
            version,
            file_size,
            foreign_offset,
            foreign_size,
            class_count,
            class_index_offset,
            line_number_program_count,
            line_number_program_index_offset,
            literal_array_count,
            literal_array_index_offset,
            index_count,
            index_section_offset,
        })
    }

    pub fn write(&self, writer: &mut AbcWriter) {
        writer.write_bytes(&self.magic);
        writer.write_u32(self.checksum);
        writer.write_bytes(&self.version.bytes());
        writer.write_u32(self.file_size);
        writer.write_u32(self.foreign_offset);
        writer.write_u32(self.foreign_size);
        writer.write_u32(self.class_count);
        writer.write_u32(self.class_index_offset);
        writer.write_u32(self.line_number_program_count);
        writer.write_u32(self.line_number_program_index_offset);
        writer.write_u32(self.literal_array_count);
        writer.write_u32(self.literal_array_index_offset);
        writer.write_u32(self.index_count);
        writer.write_u32(self.index_section_offset);
    }
}

/// A single string entry stored within the ABC string table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcStringEntry {
    pub offset: u32,
    pub utf16_length: u32,
    pub is_ascii: bool,
    pub value: String,
}

impl AbcStringEntry {
    pub fn read_at(reader: &mut AbcReader<'_>, offset: u32) -> ArkResult<Self> {
        let saved = reader.position();
        reader.seek(offset as usize)?;
        let tag_len = reader.read_uleb128()?;
        let is_ascii = (tag_len & 1) != 0;
        let utf16_length = tag_len >> 1;
        let bytes = reader.read_cstring_bytes()?;
        let value = decode_mutf8(&bytes)?;
        reader.seek(saved)?;
        Ok(AbcStringEntry {
            offset,
            utf16_length,
            is_ascii,
            value,
        })
    }
}

/// Literal value stored inside a literal array section.
#[derive(Debug, Clone, PartialEq)]
pub enum AbcLiteralValue {
    Boolean(bool),
    Integer(i64),
    Float(f32),
    Double(f64),
    String(u32),
    Type(u32),
    Method(u32),
    GeneratorMethod(u32),
    AsyncGeneratorMethod(u32),
    MethodAffiliate(u16),
    Builtin(u8),
    BuiltinTypeIndex(u8),
    Accessor(u8),
    Getter(u32),
    Setter(u32),
    LiteralArray(u32),
    LiteralBufferIndex(u32),
    EtsImplements(u32),
    BigInt(Vec<u8>),
    BigIntExternal { length: u32 },
    Any { type_index: u32, data: Vec<u8> },
    AnyExternal { type_index: u32, length: u32 },
    Null,
    Undefined,
    TagValue(u8),
    Raw { tag: u8, bytes: Vec<u8> },
}

/// Literal array as encoded in the ABC literal section.
#[derive(Debug, Clone, PartialEq)]
pub struct AbcLiteralArray {
    pub offset: u32,
    pub byte_len: usize,
    pub entries: Vec<AbcLiteralValue>,
}

impl AbcLiteralArray {
    pub fn read_at(reader: &mut AbcReader<'_>, offset: u32) -> ArkResult<Self> {
        let saved = reader.position();
        reader.seek(offset as usize)?;

        let raw_count = reader.read_u32()?;
        let mut entries = Vec::new();
        let mut processed_pairs: u32 = 0;

        while processed_pairs < raw_count {
            let tag = reader.read_u8()?;
            processed_pairs = processed_pairs.saturating_add(2);

            let value = match tag {
                0x00 => {
                    let actual = reader.read_u8()?;
                    AbcLiteralValue::TagValue(actual)
                }
                0x01 => AbcLiteralValue::Boolean(reader.read_u8()? != 0),
                0x02 => AbcLiteralValue::Integer(reader.read_u32()? as i32 as i64),
                0x03 => AbcLiteralValue::Float(f32::from_bits(reader.read_u32()?)),
                0x04 => AbcLiteralValue::Double(f64::from_bits(reader.read_u64()?)),
                0x05 => AbcLiteralValue::String(reader.read_u32()?),
                0x06 => AbcLiteralValue::Method(reader.read_u32()?),
                0x07 => AbcLiteralValue::GeneratorMethod(reader.read_u32()?),
                0x08 => AbcLiteralValue::Accessor(reader.read_u8()?),
                0x09 => AbcLiteralValue::MethodAffiliate(reader.read_u16()?),
                0x0a => {
                    let type_index = reader.read_u32()?;
                    let len = reader.read_u32()? as usize;
                    if len > reader.remaining() {
                        AbcLiteralValue::AnyExternal {
                            type_index,
                            length: len as u32,
                        }
                    } else {
                        let data = reader.read_bytes(len)?.to_vec();
                        AbcLiteralValue::Any { type_index, data }
                    }
                }
                0x0b..=0x15 => {
                    let length = reader.read_u32()?;
                    let elem_size = match tag {
                        0x0b => ((length as usize) + 7) / 8,
                        0x0c | 0x0d => length as usize,
                        0x0e | 0x0f => (length as usize).saturating_mul(2),
                        0x10 | 0x11 | 0x13 => (length as usize).saturating_mul(4),
                        0x12 | 0x14 | 0x15 => (length as usize).saturating_mul(8),
                        _ => length as usize,
                    };
                    let mut bytes = Vec::with_capacity(4 + elem_size);
                    bytes.extend_from_slice(&length.to_le_bytes());
                    bytes.extend_from_slice(reader.read_bytes(elem_size)?);
                    processed_pairs = raw_count;
                    AbcLiteralValue::Raw { tag, bytes }
                }
                0x16 => AbcLiteralValue::AsyncGeneratorMethod(reader.read_u32()?),
                0x17 => AbcLiteralValue::LiteralBufferIndex(reader.read_u32()?),
                0x18 => AbcLiteralValue::LiteralArray(reader.read_u32()?),
                0x19 => AbcLiteralValue::BuiltinTypeIndex(reader.read_u8()?),
                0x1a => AbcLiteralValue::Getter(reader.read_u32()?),
                0x1b => AbcLiteralValue::Setter(reader.read_u32()?),
                0x1c => AbcLiteralValue::EtsImplements(reader.read_u32()?),
                0xff => {
                    let _ = reader.read_u8()?;
                    AbcLiteralValue::Null
                }
                other => {
                    let len = core::cmp::min(4, reader.remaining());
                    let bytes = reader.read_bytes(len)?.to_vec();
                    AbcLiteralValue::Raw { tag: other, bytes }
                }
            };

            if !matches!(value, AbcLiteralValue::TagValue(_)) {
                entries.push(value);
            }
        }

        let end_pos = reader.position();
        reader.seek(saved)?;
        Ok(AbcLiteralArray {
            offset,
            byte_len: end_pos.saturating_sub(offset as usize),
            entries,
        })
    }
}

impl AbcLiteralValue {
    pub fn encoded_size(&self) -> usize {
        1 + match self {
            AbcLiteralValue::Boolean(_) => 1,
            AbcLiteralValue::Integer(_) => 4,
            AbcLiteralValue::Float(_) => 4,
            AbcLiteralValue::Double(_) => 8,
            AbcLiteralValue::String(_) => 4,
            AbcLiteralValue::Type(_) => 4,
            AbcLiteralValue::Method(_) => 4,
            AbcLiteralValue::GeneratorMethod(_) => 4,
            AbcLiteralValue::AsyncGeneratorMethod(_) => 4,
            AbcLiteralValue::MethodAffiliate(_) => 2,
            AbcLiteralValue::Builtin(_) => 1,
            AbcLiteralValue::BuiltinTypeIndex(_) => 1,
            AbcLiteralValue::Accessor(_) => 1,
            AbcLiteralValue::Getter(_) => 4,
            AbcLiteralValue::Setter(_) => 4,
            AbcLiteralValue::LiteralArray(_) => 4,
            AbcLiteralValue::LiteralBufferIndex(_) => 4,
            AbcLiteralValue::EtsImplements(_) => 4,
            AbcLiteralValue::BigInt(bytes) => 4 + bytes.len(),
            AbcLiteralValue::BigIntExternal { .. } => 4,
            AbcLiteralValue::Any { data, .. } => 8 + data.len(),
            AbcLiteralValue::AnyExternal { .. } => 8,
            AbcLiteralValue::Null => 1,
            AbcLiteralValue::Undefined => 0,
            AbcLiteralValue::TagValue(_) => 1,
            AbcLiteralValue::Raw { bytes, .. } => bytes.len(),
        }
    }
}

/// Basic metadata stored in a class definition entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AbcClassDefinition {
    pub offset: u32,
    pub name: AbcStringEntry,
    pub super_class_id: u32,
    pub access_flags: u32,
    pub field_count: u32,
    pub method_count: u32,
}

impl AbcClassDefinition {
    pub fn read_at(reader: &mut AbcReader<'_>, offset: u32) -> ArkResult<Self> {
        let saved = reader.position();
        reader.seek(offset as usize)?;

        let tag_len = reader.read_uleb128()?;
        let name_offset = reader.position();
        let name_bytes = reader.read_cstring_bytes()?;
        let name_value = decode_mutf8(&name_bytes)?;
        let name_entry = AbcStringEntry {
            offset: name_offset as u32,
            utf16_length: tag_len >> 1,
            is_ascii: (tag_len & 1) != 0,
            value: name_value,
        };

        let super_class_id = reader.read_u32()?;
        let access_flags = reader.read_uleb128()?;
        let field_count = reader.read_uleb128()?;
        let method_count = reader.read_uleb128()?;

        reader.seek(saved)?;

        Ok(AbcClassDefinition {
            offset,
            name: name_entry,
            super_class_id,
            access_flags,
            field_count,
            method_count,
        })
    }
}

/// Metadata describing the ranges that store class, method, field, and proto indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcIndexHeader {
    pub start: u32,
    pub end: u32,
    pub class_index_size: u32,
    pub class_index_offset: u32,
    pub method_index_size: u32,
    pub method_index_offset: u32,
    pub field_index_size: u32,
    pub field_index_offset: u32,
    pub proto_index_size: u32,
    pub proto_index_offset: u32,
}

impl AbcIndexHeader {
    pub fn read(reader: &mut AbcReader<'_>) -> ArkResult<Self> {
        Ok(AbcIndexHeader {
            start: reader.read_u32()?,
            end: reader.read_u32()?,
            class_index_size: reader.read_u32()?,
            class_index_offset: reader.read_u32()?,
            method_index_size: reader.read_u32()?,
            method_index_offset: reader.read_u32()?,
            field_index_size: reader.read_u32()?,
            field_index_offset: reader.read_u32()?,
            proto_index_size: reader.read_u32()?,
            proto_index_offset: reader.read_u32()?,
        })
    }

    pub fn write(&self, writer: &mut AbcWriter) {
        writer.write_u32(self.start);
        writer.write_u32(self.end);
        writer.write_u32(self.class_index_size);
        writer.write_u32(self.class_index_offset);
        writer.write_u32(self.method_index_size);
        writer.write_u32(self.method_index_offset);
        writer.write_u32(self.field_index_size);
        writer.write_u32(self.field_index_offset);
        writer.write_u32(self.proto_index_size);
        writer.write_u32(self.proto_index_offset);
    }
}

/// Identifier referencing a structure stored in the ABC file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AbcEntityId(pub u32);

impl AbcEntityId {
    pub const INVALID: AbcEntityId = AbcEntityId(0);

    pub fn is_valid(self) -> bool {
        self.0 > (AbcHeader::MAGIC.len() as u32)
    }

    pub fn offset(self) -> u32 {
        self.0
    }
}

/// Byte range within the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbcSectionRange {
    pub start: u32,
    pub end: u32,
}

impl AbcSectionRange {
    pub const fn new(start: u32, end: u32) -> Self {
        AbcSectionRange { start, end }
    }

    pub const fn len(self) -> u32 {
        self.end.saturating_sub(self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AbcClassDefinition, AbcHeader, AbcIndexHeader, AbcLiteralArray, AbcReader, AbcStringEntry,
    };
    use crate::error::ArkResult;

    #[test]
    fn read_header_and_index_header() -> ArkResult<()> {
        let bytes = std::fs::read("test-data/modules.abc")?;
        let mut reader = AbcReader::new(&bytes);
        let header = AbcHeader::read(&mut reader)?;

        assert_eq!(header.magic, AbcHeader::MAGIC);
        assert_eq!(header.file_size as usize, bytes.len());
        assert_eq!(header.class_count, 13);
        assert_eq!(header.class_index_offset, 0x3c);
        assert_eq!(header.line_number_program_count, 0x18);
        assert_eq!(header.index_count, 1);
        assert_eq!(header.index_section_offset, 0x70);

        let index_offset = header.index_section_offset as usize;
        let mut index_reader = AbcReader::new(&bytes[index_offset..]);
        let index_header = AbcIndexHeader::read(&mut index_reader)?;

        assert_eq!(index_header.start, 0x284);
        assert_eq!(index_header.end, header.file_size);
        assert_eq!(index_header.class_index_size, 0x0e);
        assert_eq!(index_header.class_index_offset, 0x98);
        assert_eq!(index_header.method_index_size, 0x6d);
        assert_eq!(index_header.method_index_offset, 0xd0);
        assert_eq!(index_header.field_index_size, u32::MAX);
        assert_eq!(index_header.field_index_offset, u32::MAX);

        Ok(())
    }

    #[test]
    fn read_known_string_entry() -> ArkResult<()> {
        let bytes = std::fs::read("test-data/modules.abc")?;
        let mut reader = AbcReader::new(&bytes);
        let entry = AbcStringEntry::read_at(&mut reader, 0x284)?;
        assert_eq!(
            entry.value,
            "L&entry/src/main/ets/entryability/EntryAbility&;"
        );
        assert!(entry.is_ascii);
        assert_eq!(entry.utf16_length, 48);
        Ok(())
    }

    #[test]
    fn read_literal_array_sample() -> ArkResult<()> {
        let bytes = std::fs::read("test-data/modules.abc")?;
        let mut reader = AbcReader::new(&bytes);
        let literal = AbcLiteralArray::read_at(&mut reader, 0x1812)?;
        assert_eq!(literal.entries.len(), 3);
        Ok(())
    }

    #[test]
    fn read_class_definition_header() -> ArkResult<()> {
        let bytes = std::fs::read("test-data/modules.abc")?;
        let mut reader = AbcReader::new(&bytes);
        let class = AbcClassDefinition::read_at(&mut reader, 0x284)?;
        assert_eq!(
            class.name.value,
            "L&entry/src/main/ets/entryability/EntryAbility&;"
        );
        assert_eq!(class.field_count, 6);
        assert_eq!(class.method_count, 9);
        Ok(())
    }
}
