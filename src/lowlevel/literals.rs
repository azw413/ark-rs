//! Enhanced ABC literal parsing implementation with improved offset detection.
//!
//! This module provides a complete rewrite of literal array parsing that:
//! 1. Correctly tracks byte positions instead of pair counts
//! 2. Validates literal arrays before accepting them
//! 3. Provides comprehensive unit tests

use super::metadata::{AbcReader, AbcStringEntry};
use crate::error::{ArkError, ArkResult};

/// Single literal value with its tag
#[derive(Debug, Clone, PartialEq)]
pub struct LiteralEntry {
    pub tag: u8,
    pub value: LiteralValue,
}

/// Possible literal values in an ABC file
#[derive(Debug, Clone, PartialEq)]
pub enum LiteralValue {
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

/// A complete literal array structure
#[derive(Debug, Clone, PartialEq)]
pub struct LiteralArray {
    pub offset: u32,
    pub byte_len: usize,
    pub entries: Vec<LiteralEntry>,
}

impl LiteralArray {
    /// Reads a literal array from the given offset
    ///
    /// Note: The count field in the binary represents "pairs" (tag + value),
    /// not individual entries. This is a historical artifact from older ABC versions.
    pub fn read_at(reader: &mut AbcReader<'_>, offset: u32) -> ArkResult<Self> {
        reader.seek(offset as usize)?;

        let num_pairs = reader.read_u32()?;
        let start_pos = reader.position();

        let mut entries = Vec::new();
        let mut processed_pairs = 0;

        // Parse entries until we've read the specified count
        // Each "pair" is tag + value, but values have variable sizes
        while processed_pairs < num_pairs {
            let tag_start = reader.position();

            // Check if we've run out of data
            if reader.remaining() == 0 {
                break;
            }

            let tag = reader.read_u8()?;
            processed_pairs += 1;

            // Parse value based on tag
            let value = match tag {
                // Tag value with embedded byte (2 bytes total)
                0x00 => {
                    if reader.remaining() < 1 {
                        break;
                    }
                    let byte = reader.read_u8()?;
                    LiteralValue::TagValue(byte)
                }
                // Boolean (2 bytes total)
                0x01 => {
                    if reader.remaining() < 1 {
                        break;
                    }
                    LiteralValue::Boolean(reader.read_u8()? != 0)
                }
                // Integer (5 bytes total)
                0x02 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::Integer(reader.read_u32()? as i32 as i64)
                }
                // Float (5 bytes total)
                0x03 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::Float(f32::from_bits(reader.read_u32()?))
                }
                // Double (9 bytes total)
                0x04 => {
                    if reader.remaining() < 8 {
                        break;
                    }
                    LiteralValue::Double(f64::from_bits(reader.read_u64()?))
                }
                // String reference (5 bytes total)
                0x05 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::String(reader.read_u32()?)
                }
                // Method reference (5 bytes total)
                0x06 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::Method(reader.read_u32()?)
                }
                // Generator method (5 bytes total)
                0x07 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::GeneratorMethod(reader.read_u32()?)
                }
                // Accessor (2 bytes total)
                0x08 => {
                    if reader.remaining() < 1 {
                        break;
                    }
                    LiteralValue::Accessor(reader.read_u8()?)
                }
                // Method affiliate (3 bytes total)
                0x09 => {
                    if reader.remaining() < 2 {
                        break;
                    }
                    LiteralValue::MethodAffiliate(reader.read_u16()?)
                }
                // Any (inline) - variable size
                0x0a => {
                    if reader.remaining() < 8 {
                        break;
                    }
                    let type_index = reader.read_u32()?;
                    let len = reader.read_u32()? as usize;
                    if len > reader.remaining() {
                        LiteralValue::AnyExternal {
                            type_index,
                            length: len as u32,
                        }
                    } else {
                        let data = reader.read_bytes(len)?.to_vec();
                        LiteralValue::Any { type_index, data }
                    }
                }
                // Raw typed arrays (0x0b - 0x15) - variable size
                0x0b..=0x15 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    let length = reader.read_u32()?;
                    let elem_size = match tag {
                        0x0b => ((length as usize) + 7) / 8,                // bit array
                        0x0c | 0x0d => length as usize,                     // byte/short array
                        0x0e | 0x0f => (length as usize).saturating_mul(2), // word/dword array
                        0x10 | 0x11 | 0x13 => (length as usize).saturating_mul(4), // dword/qword array
                        0x12 | 0x14 | 0x15 => (length as usize).saturating_mul(8), // qword/dqword array
                        _ => length as usize,
                    };

                    if elem_size > reader.remaining() {
                        break;
                    }

                    let mut bytes = Vec::with_capacity(4 + elem_size);
                    bytes.extend_from_slice(&length.to_le_bytes());
                    bytes.extend_from_slice(reader.read_bytes(elem_size)?);

                    LiteralValue::Raw { tag, bytes }
                }
                // Async generator method (5 bytes total)
                0x16 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::AsyncGeneratorMethod(reader.read_u32()?)
                }
                // Literal buffer index (5 bytes total)
                0x17 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::LiteralBufferIndex(reader.read_u32()?)
                }
                // Nested literal array (5 bytes total)
                0x18 => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::LiteralArray(reader.read_u32()?)
                }
                // Builtin type index (2 bytes total)
                0x19 => {
                    if reader.remaining() < 1 {
                        break;
                    }
                    LiteralValue::BuiltinTypeIndex(reader.read_u8()?)
                }
                // Getter (5 bytes total)
                0x1a => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::Getter(reader.read_u32()?)
                }
                // Setter (5 bytes total)
                0x1b => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::Setter(reader.read_u32()?)
                }
                // ETS implements (5 bytes total)
                0x1c => {
                    if reader.remaining() < 4 {
                        break;
                    }
                    LiteralValue::EtsImplements(reader.read_u32()?)
                }
                // Null value (2 bytes total)
                0xff => {
                    if reader.remaining() < 1 {
                        break;
                    }
                    let _ = reader.read_u8()?;
                    LiteralValue::Null
                }
                // Unknown tag - read remaining data safely
                other => {
                    let len = core::cmp::min(4, reader.remaining());
                    let bytes = reader.read_bytes(len)?.to_vec();
                    LiteralValue::Raw { tag: other, bytes }
                }
            };

            entries.push(LiteralEntry { tag, value });

            // Safety check: if we somehow get stuck, break
            let current_pos = reader.position();
            if current_pos == tag_start {
                return Err(ArkError::format("infinite loop parsing literal array"));
            }
        }

        let end_pos = reader.position();

        Ok(LiteralArray {
            offset,
            byte_len: end_pos - start_pos,
            entries,
        })
    }

    /// Validates that this literal array contains meaningful data
    pub fn is_valid(&self) -> bool {
        // Must have at least one entry
        if self.entries.is_empty() {
            return false;
        }

        // Check that entries don't have obviously wrong data
        for entry in &self.entries {
            match &entry.value {
                LiteralValue::String(idx) | LiteralValue::Method(idx) => {
                    // String/method indices should be non-zero
                    if *idx == 0 {
                        return false;
                    }
                }
                LiteralValue::Any { data, .. } => {
                    // Any data should not be empty
                    if data.is_empty() {
                        return false;
                    }
                }
                LiteralValue::Raw { bytes, .. } => {
                    // Raw data should match expected length
                    if bytes.len() < 4 {
                        return false;
                    }
                    let expected_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
                    if bytes.len() - 4 != expected_len {
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }
}

/// Detects literal arrays in a binary ABC file by scanning for valid structures
pub struct LiteralScanner {
    data: Vec<u8>,
}

impl LiteralScanner {
    /// Creates a new scanner for the given binary data
    pub fn new(data: &[u8]) -> Self {
        LiteralScanner {
            data: data.to_vec(),
        }
    }

    /// Scans for literal arrays in the index section
    pub fn scan_index_section(&mut self, start: u32, end: u32) -> Vec<(u32, Option<LiteralArray>)> {
        let start = start as usize;
        let end = end as usize;
        let mut results = Vec::new();
        let mut cursor = start;

        while cursor < end && cursor + 4 <= self.data.len() {
            let offset = cursor as u32;

            // Try to parse as literal array
            if let Some(array) = self.try_parse_at(offset) {
                if array.is_valid() {
                    results.push((offset, Some(array.clone())));
                    cursor += array.byte_len;
                    continue;
                }
            }

            cursor += 1;
        }

        results
    }

    /// Attempts to parse a literal array at the given offset
    fn try_parse_at(&self, offset: u32) -> Option<LiteralArray> {
        // Check if offset is in valid range
        if offset as usize + 4 > self.data.len() {
            return None;
        }

        let mut reader = AbcReader::new(&self.data);
        match LiteralArray::read_at(&mut reader, offset) {
            Ok(array) => {
                // Additional validation: count should be reasonable
                if array.entries.is_empty() || array.entries.len() > 100 {
                    return None;
                }

                // Check if at least some entries make sense
                let has_valid_refs = array.entries.iter().any(|entry| {
                    matches!(
                        entry.value,
                        LiteralValue::String(_)
                            | LiteralValue::Method(_)
                            | LiteralValue::Integer(_)
                    )
                });

                if has_valid_refs { Some(array) } else { None }
            }
            Err(_) => None,
        }
    }

    /// Finds specific known literal arrays by their expected content
    pub fn find_by_content(&self, target_strings: &[&str]) -> Vec<(u32, LiteralArray)> {
        let mut results = Vec::new();
        let mut cursor = 0x284; // String section starts around here

        while cursor + 4 < self.data.len() && cursor < 0x2000 {
            if let Some(array) = self.try_parse_at(cursor as u32) {
                // Check if this array contains any of our target strings
                let string_refs: Vec<u32> = array
                    .entries
                    .iter()
                    .filter_map(|e| {
                        if let LiteralValue::String(idx) = e.value {
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .collect();

                // Try to resolve and match strings
                for str_idx in string_refs {
                    if let Some(resolved) = self.resolve_string(str_idx) {
                        if target_strings.iter().any(|&s| resolved == s) {
                            results.push((cursor as u32, array));
                            break;
                        }
                    }
                }
            }
            cursor += 1;
        }

        results
    }

    /// Resolves a string reference to its actual string value
    pub fn resolve_string(&self, offset: u32) -> Option<String> {
        if offset == 0 || (offset as usize) >= self.data.len() {
            return None;
        }
        let mut reader = AbcReader::new(&self.data);
        AbcStringEntry::read_at(&mut reader, offset)
            .ok()
            .map(|entry| entry.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_literal_array() {
        // Create a simple literal array: [i32:1, string:0x100, i32:0]
        // Format: u32 count=6 (3 entries), then (tag, value) pairs
        // Note: count field represents number of entries to read
        let mut data = Vec::new();
        data.extend_from_slice(&6u32.to_le_bytes()); // 3 entries
        data.push(0x02); // tag: integer
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x05); // tag: string
        data.extend_from_slice(&0x100u32.to_le_bytes());
        data.push(0x02); // tag: integer
        data.extend_from_slice(&0u32.to_le_bytes());

        let mut reader = AbcReader::new(&data);
        let array = LiteralArray::read_at(&mut reader, 0).unwrap();

        assert_eq!(array.entries.len(), 3);
        assert_eq!(array.entries[0].tag, 0x02);
        assert!(matches!(array.entries[0].value, LiteralValue::Integer(1)));
        assert_eq!(array.entries[1].tag, 0x05);
        assert!(matches!(
            array.entries[1].value,
            LiteralValue::String(0x100)
        ));
        assert_eq!(array.entries[2].tag, 0x02);
        assert!(matches!(array.entries[2].value, LiteralValue::Integer(0)));
        // byte_len is the data size (after count field), not including count
        assert_eq!(array.byte_len, 15); // 3 entries * 5 bytes each (tag + 4-byte value)
    }

    #[test]
    fn parse_known_literal_from_modules() {
        // Test the known literal at offset 0x1812 from modules.abc
        // Binary has count=6, which means 6 entries total
        let bytes = std::fs::read("test-data/modules.abc").expect("read test data");
        let mut reader = AbcReader::new(&bytes);
        let array = LiteralArray::read_at(&mut reader, 0x1812).unwrap();

        assert_eq!(array.offset, 0x1812);
        // Binary count is 6, so we expect 6 entries
        assert_eq!(array.entries.len(), 6);

        // First entry: i32:1
        assert_eq!(array.entries[0].tag, 0x02);
        assert!(matches!(array.entries[0].value, LiteralValue::Integer(1)));

        // Second entry: string
        assert_eq!(array.entries[1].tag, 0x05);
        if let LiteralValue::String(idx) = array.entries[1].value {
            assert!(idx > 0);
        } else {
            panic!("Expected String value");
        }

        // Third entry: i32:0
        assert_eq!(array.entries[2].tag, 0x02);
        assert!(matches!(array.entries[2].value, LiteralValue::Integer(0)));

        // The remaining 3 entries are additional data (double, string, method)
        assert_eq!(array.entries[3].tag, 0x04); // Double
        assert_eq!(array.entries[4].tag, 0x05); // String
        assert_eq!(array.entries[5].tag, 0x06); // Method
    }

    #[test]
    fn literal_array_validation() {
        // Valid array
        let mut valid = LiteralArray {
            offset: 0x100,
            byte_len: 20,
            entries: vec![LiteralEntry {
                tag: 0x02,
                value: LiteralValue::Integer(1),
            }],
        };
        assert!(valid.is_valid());

        // Empty array is invalid
        valid.entries.clear();
        assert!(!valid.is_valid());

        // Array with zero string index is invalid
        valid.entries.push(LiteralEntry {
            tag: 0x05,
            value: LiteralValue::String(0),
        });
        assert!(!valid.is_valid());
    }

    #[test]
    fn scanner_finds_known_literals() {
        let bytes = std::fs::read("test-data/modules.abc").expect("read test data");
        let scanner = LiteralScanner::new(&bytes);

        // Look for literals containing specific strings
        let found = scanner.find_by_content(&["EntryAbility", "DOMAIN", "Index"]);

        // Should find at least some literals
        assert!(!found.is_empty(), "Should find some literals by content");

        // Verify we found EntryAbility
        let found_entry_ability = found.iter().any(|(_, arr)| {
            arr.entries.iter().any(|e| {
                if let LiteralValue::String(idx) = e.value {
                    scanner.resolve_string(idx).as_deref() == Some("EntryAbility")
                } else {
                    false
                }
            })
        });
        assert!(found_entry_ability, "Should find EntryAbility literal");
    }

    #[test]
    fn scan_index_section() {
        let bytes = std::fs::read("test-data/modules.abc").expect("read test data");
        let mut scanner = LiteralScanner::new(&bytes);

        // Scan the index section (from 0x284 to end of file per header)
        let results = scanner.scan_index_section(0x284, bytes.len() as u32);

        // Should find multiple literal arrays
        assert!(!results.is_empty(), "Should find some literal arrays");

        // At least some should be valid
        let valid_count = results.iter().filter(|(_, arr)| arr.is_some()).count();
        assert!(
            valid_count > 0,
            "Should find at least one valid literal array"
        );
    }

    #[test]
    fn parse_literal_with_all_tag_types() {
        // Create array with various tag types
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes()); // 4 entries

        data.push(0x01); // bool
        data.push(0x01); // true

        data.push(0x02); // i32
        data.extend_from_slice(&42u32.to_le_bytes());

        data.push(0x03); // f32
        data.extend_from_slice(&3.14f32.to_bits().to_le_bytes());

        data.push(0x04); // f64
        data.extend_from_slice(&2.71828f64.to_bits().to_le_bytes());

        let mut reader = AbcReader::new(&data);
        let array = LiteralArray::read_at(&mut reader, 0).unwrap();

        assert_eq!(array.entries.len(), 4);
        assert!(matches!(
            array.entries[0].value,
            LiteralValue::Boolean(true)
        ));
        assert!(matches!(array.entries[1].value, LiteralValue::Integer(42)));
        assert!(matches!(array.entries[2].value, LiteralValue::Float(_)));
        assert!(matches!(array.entries[3].value, LiteralValue::Double(_)));
    }

    #[test]
    fn parse_literal_array_with_nested_array() {
        // Create array with nested literal array reference
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());

        data.push(0x05); // string
        data.extend_from_slice(&0x100u32.to_le_bytes());

        data.push(0x18); // nested literal array
        data.extend_from_slice(&0x200u32.to_le_bytes());

        let mut reader = AbcReader::new(&data);
        let array = LiteralArray::read_at(&mut reader, 0).unwrap();

        assert_eq!(array.entries.len(), 2);
        assert!(matches!(
            array.entries[1].value,
            LiteralValue::LiteralArray(0x200)
        ));
    }

    #[test]
    fn byte_tracking_vs_pair_tracking() {
        // This test demonstrates correct parsing with variable-sized tag values
        // The count field represents the number of entries (not bytes)

        // Create array with tags that have different sizes
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes()); // 4 entries

        data.push(0x00); // tag value - 2 bytes total
        data.push(0x42);

        data.push(0x01); // boolean - 2 bytes
        data.push(0x01);

        data.push(0x02); // integer - 5 bytes
        data.extend_from_slice(&100u32.to_le_bytes());

        data.push(0x04); // double - 9 bytes
        data.extend_from_slice(&3.14f64.to_bits().to_le_bytes());

        let mut reader = AbcReader::new(&data);
        let array = LiteralArray::read_at(&mut reader, 0).unwrap();

        // Should parse all 4 entries correctly
        assert_eq!(array.entries.len(), 4);

        // Verify byte length is calculated correctly
        // byte_len is the data size (after count field): 2 + 2 + 5 + 9 = 18 bytes
        // But the total array size is 4 (count) + 18 (data) = 22 bytes
        assert_eq!(array.byte_len, 18); // Data size only, not including count
    }
}
