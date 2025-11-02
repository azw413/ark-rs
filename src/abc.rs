//! Parsing utilities for Ark disassembly (modules.txt) files.

use crate::constant_pool::ConstantPool;
use crate::disassembly::format_function;
use crate::functions::Function;
use crate::parser::{ParseError as FunctionParseError, normalize_function_text, parse_function};

#[derive(Debug, Default, Clone)]
pub struct AbcFile {
    pub language: Option<String>,
    pub literals: Vec<LiteralEntry>,
    pub records: Vec<RecordEntry>,
    pub functions: Vec<FunctionEntry>,
    pub segments: Vec<AbcSegment>,
}

#[derive(Debug, Clone)]
pub struct LiteralEntry {
    pub index: u32,
    pub offset: u32,
    pub body: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RecordEntry {
    pub name: String,
    pub body: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub annotations: Vec<String>,
    pub raw_text: String,
    pub canonical_text: String,
    pub parsed: Option<Function>,
    pub parse_error: Option<FunctionParseError>,
    pub pool: Option<ConstantPool>,
}

#[derive(Debug, Clone)]
pub enum AbcSegment {
    Raw(String),
    Language(String),
    Literal(usize),
    Record(usize),
    Function(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcParseError {
    pub line: usize,
    pub message: String,
}

impl AbcParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        AbcParseError {
            line,
            message: message.into(),
        }
    }
}

pub fn parse_abc_file(input: &str) -> Result<AbcFile, AbcParseError> {
    let mut file = AbcFile::default();
    let lines: Vec<&str> = input.lines().collect();
    let mut index = 0usize;
    let mut pending_annotations: Vec<String> = Vec::new();

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            file.segments.push(AbcSegment::Raw(String::new()));
            index += 1;
            continue;
        }

        if trimmed.starts_with('#') {
            file.segments.push(AbcSegment::Raw(line.to_owned()));
            index += 1;
            continue;
        }

        if trimmed.starts_with(".language ") {
            file.language = Some(trimmed[10..].trim().to_owned());
            file.segments.push(AbcSegment::Language(line.to_owned()));
            index += 1;
            continue;
        }

        if trimmed.ends_with(':') {
            pending_annotations.push(line.to_owned());
            index += 1;
            continue;
        }

        if !pending_annotations.is_empty()
            && (line.starts_with('\t') || line.starts_with(' '))
            && !trimmed.starts_with(".function ")
        {
            pending_annotations.push(line.to_owned());
            index += 1;
            continue;
        }

        if trimmed.starts_with(".function ") {
            let block_lines = collect_block(&lines, &mut index);
            let original = block_lines.join("\n");
            let mut raw_text = original.clone();
            if !raw_text.ends_with('\n') {
                raw_text.push('\n');
            }
            let normalized = normalize_function_text(&raw_text);
            let mut pool = ConstantPool::default();
            let (parsed, canonical_text, parse_error) = match parse_function(&normalized, &mut pool)
            {
                Ok(func) => {
                    let formatted =
                        format_function(&func, &pool).unwrap_or_else(|_| normalized.clone());
                    (Some(func), formatted, None)
                }
                Err(err) => (None, normalized.clone(), Some(err)),
            };
            let pool_snapshot = if parsed.is_some() {
                Some(pool)
            } else {
                None
            };

            file.functions.push(FunctionEntry {
                annotations: pending_annotations.clone(),
                raw_text,
                canonical_text,
                parsed,
                parse_error,
                pool: pool_snapshot,
            });
            pending_annotations.clear();
            let fn_index = file.functions.len() - 1;
            file.segments.push(AbcSegment::Function(fn_index));
            continue;
        }

        if trimmed.starts_with(".record ") {
            let block_lines = collect_block(&lines, &mut index);
            let header = block_lines
                .first()
                .ok_or_else(|| AbcParseError::new(index + 1, "invalid record header"))?;
            let name = header
                .trim()
                .strip_prefix(".record ")
                .and_then(|rest| rest.split('{').next())
                .map(|s| s.trim().to_owned())
                .ok_or_else(|| AbcParseError::new(index + 1, "invalid record header"))?;
            let body = block_lines.join("\n");
            file.records.push(RecordEntry {
                name,
                body,
                lines: block_lines.clone(),
            });
            let rec_index = file.records.len() - 1;
            file.segments.push(AbcSegment::Record(rec_index));
            continue;
        }

        if trimmed
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            let block_lines = collect_block(&lines, &mut index);
            let header = block_lines
                .first()
                .ok_or_else(|| AbcParseError::new(index + 1, "missing literal header"))?;
            let mut parts = header.trim().splitn(3, ' ');
            let idx_str = parts
                .next()
                .ok_or_else(|| AbcParseError::new(index + 1, "missing literal index"))?;
            let offset_str = parts
                .next()
                .ok_or_else(|| AbcParseError::new(index + 1, "missing literal offset"))?;
            let literal_index = idx_str.parse::<u32>().map_err(|_| {
                AbcParseError::new(index + 1, format!("invalid literal index {idx_str}"))
            })?;
            let literal_offset = parse_hex_u32(offset_str)?;
            let body = block_lines.join("\n");
            file.literals.push(LiteralEntry {
                index: literal_index,
                offset: literal_offset,
                body,
                lines: block_lines.clone(),
            });
            let lit_index = file.literals.len() - 1;
            file.segments.push(AbcSegment::Literal(lit_index));
            continue;
        }

        file.segments.push(AbcSegment::Raw(line.to_owned()));
        index += 1;
    }

    Ok(file)
}

fn collect_block(lines: &[&str], index: &mut usize) -> Vec<String> {
    let mut depth = 0usize;
    let mut buffer = Vec::new();
    while *index < lines.len() {
        let line = lines[*index];
        buffer.push(line.to_owned());
        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
        *index += 1;
        if depth == 0 {
            break;
        }
    }
    buffer
}

fn parse_hex_u32(token: &str) -> Result<u32, AbcParseError> {
    let trimmed = token.trim_start_matches('+');
    let without_prefix = trimmed.trim_start_matches("0x");
    u32::from_str_radix(without_prefix, 16)
        .map_err(|_| AbcParseError::new(0, format!("invalid hex literal {token}")))
}

impl AbcFile {
    pub fn to_string(&self) -> String {
        let mut output = String::new();
        for segment in &self.segments {
            match segment {
                AbcSegment::Raw(line) => {
                    output.push_str(line);
                    output.push('\n');
                }
                AbcSegment::Language(line) => {
                    output.push_str(line);
                    output.push('\n');
                }
                AbcSegment::Literal(idx) => {
                    if let Some(entry) = self.literals.get(*idx) {
                        for line in &entry.lines {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
                AbcSegment::Record(idx) => {
                    if let Some(entry) = self.records.get(*idx) {
                        for line in &entry.lines {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
                AbcSegment::Function(idx) => {
                    if let Some(entry) = self.functions.get(*idx) {
                        if let (Some(function), Some(pool)) = (&entry.parsed, entry.pool.as_ref()) {
                            if entry.raw_text.is_empty() {
                                let text = function.to_string(&entry.annotations, pool);
                                output.push_str(&text);
                                if !text.ends_with('\n') {
                                    output.push('\n');
                                }
                                continue;
                            }
                        }

                        if entry.raw_text.is_empty() {
                            if let (Some(function), Some(pool)) = (&entry.parsed, entry.pool.as_ref()) {
                                let text = function.to_string(&entry.annotations, pool);
                                output.push_str(&text);
                                if !text.ends_with('\n') {
                                    output.push('\n');
                                }
                            }
                        } else {
                            for annotation in &entry.annotations {
                                output.push_str(annotation);
                                if !annotation.ends_with('\n') {
                                    output.push('\n');
                                }
                            }
                            output.push_str(&entry.raw_text);
                            if !entry.raw_text.ends_with('\n') {
                                output.push('\n');
                            }
                        }
                    }
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_modules_fixture() {
        let data = std::fs::read_to_string("test-data/modules.txt").expect("fixture missing");
        let abc = parse_abc_file(&data).expect("failed to parse modules file");
        assert_eq!(abc.language.as_deref(), Some("ECMAScript"));
        assert!(!abc.literals.is_empty());
        assert!(!abc.records.is_empty());
        assert!(!abc.functions.is_empty());
        let parsed_count = abc
            .functions
            .iter()
            .filter(|entry| entry.parsed.is_some())
            .count();
        assert!(parsed_count > 0, "no functions parsed successfully");
        let rendered = abc.to_string();
        assert_eq!(data, rendered);

        fs::write("test-data/modules.out", abc.to_string()).expect("failed to write modules file");
    }
}
