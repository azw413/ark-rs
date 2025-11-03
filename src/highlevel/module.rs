//! Parsing utilities for Ark disassembly (modules.txt) files.

use super::disassembly::format_function;
use super::functions::Function;
use super::parser::{ParseError as FunctionParseError, normalize_function_text, parse_function};

/// Top-level container representing a textual Ark module (either parsed from
/// `.txt` or derived from a binary `.abc`).
#[derive(Debug, Default, Clone)]
pub struct ArkModule {
    pub language: Option<String>,
    pub literals: Vec<LiteralEntry>,
    pub records: Vec<RecordEntry>,
    pub functions: Vec<FunctionEntry>,
    pub segments: Vec<ArkSegment>,
}

/// Literals as they appear in the textual format.
#[derive(Debug, Clone)]
pub struct LiteralEntry {
    pub index: u32,
    pub offset: u32,
    pub body: String,
    pub lines: Vec<String>,
}

/// Record declarations (e.g. classes) captured from the textual format.
#[derive(Debug, Clone)]
pub struct RecordEntry {
    pub name: String,
    pub body: String,
    pub lines: Vec<String>,
}

/// Function blocks within the textual module, including parsed representation when available.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub annotations: Vec<String>,
    pub raw_text: String,
    pub canonical_text: String,
    pub parsed: Option<Function>,
    pub parse_error: Option<FunctionParseError>,
}

/// Tracks which logical segment produced a given line when round-tripping.
#[derive(Debug, Clone)]
pub enum ArkSegment {
    Raw(String),
    Language(String),
    Literal(usize),
    Record(usize),
    Function(usize),
}

/// Error emitted while parsing a textual Ark module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkParseError {
    pub line: usize,
    pub message: String,
}

impl ArkParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        ArkParseError {
            line,
            message: message.into(),
        }
    }
}

/// Parses a textual Ark disassembly file into an [`ArkModule`].
pub fn parse_ark_module(input: &str) -> Result<ArkModule, ArkParseError> {
    let mut file = ArkModule::default();
    let lines: Vec<&str> = input.lines().collect();
    let mut index = 0usize;
    let mut pending_annotations: Vec<String> = Vec::new();

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            file.segments.push(ArkSegment::Raw(String::new()));
            index += 1;
            continue;
        }

        if trimmed.starts_with('#') {
            file.segments.push(ArkSegment::Raw(line.to_owned()));
            index += 1;
            continue;
        }

        if trimmed.starts_with(".language ") {
            file.language = Some(trimmed[10..].trim().to_owned());
            file.segments.push(ArkSegment::Language(line.to_owned()));
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
            let (parsed, canonical_text, parse_error) = match parse_function(&normalized) {
                Ok(func) => {
                    let formatted = format_function(&func).unwrap_or_else(|_| normalized.clone());
                    (Some(func), formatted, None)
                }
                Err(err) => (None, normalized.clone(), Some(err)),
            };

            file.functions.push(FunctionEntry {
                annotations: pending_annotations.clone(),
                raw_text,
                canonical_text,
                parsed,
                parse_error,
            });
            pending_annotations.clear();
            let fn_index = file.functions.len() - 1;
            file.segments.push(ArkSegment::Function(fn_index));
            continue;
        }

        if trimmed.starts_with(".record ") {
            let block_lines = collect_block(&lines, &mut index);
            let header = block_lines
                .first()
                .ok_or_else(|| ArkParseError::new(index + 1, "invalid record header"))?;
            let name = header
                .trim()
                .strip_prefix(".record ")
                .and_then(|rest| rest.split('{').next())
                .map(|s| s.trim().to_owned())
                .ok_or_else(|| ArkParseError::new(index + 1, "invalid record header"))?;
            let body = block_lines.join("\n");
            file.records.push(RecordEntry {
                name,
                body,
                lines: block_lines.clone(),
            });
            let rec_index = file.records.len() - 1;
            file.segments.push(ArkSegment::Record(rec_index));
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
                .ok_or_else(|| ArkParseError::new(index + 1, "missing literal header"))?;
            let mut parts = header.trim().splitn(3, ' ');
            let idx_str = parts
                .next()
                .ok_or_else(|| ArkParseError::new(index + 1, "missing literal index"))?;
            let offset_str = parts
                .next()
                .ok_or_else(|| ArkParseError::new(index + 1, "missing literal offset"))?;
            let literal_index = idx_str.parse::<u32>().map_err(|_| {
                ArkParseError::new(index + 1, format!("invalid literal index {idx_str}"))
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
            file.segments.push(ArkSegment::Literal(lit_index));
            continue;
        }

        file.segments.push(ArkSegment::Raw(line.to_owned()));
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

fn parse_hex_u32(token: &str) -> Result<u32, ArkParseError> {
    let trimmed = token.trim_start_matches('+');
    let without_prefix = trimmed.trim_start_matches("0x");
    u32::from_str_radix(without_prefix, 16)
        .map_err(|_| ArkParseError::new(0, format!("invalid hex literal {token}")))
}

impl ArkModule {
    /// Renders the module back into Ark textual disassembly.
    pub fn to_string(&self) -> String {
        let mut output = String::new();
        for segment in &self.segments {
            match segment {
                ArkSegment::Raw(line) => {
                    output.push_str(line);
                    output.push('\n');
                }
                ArkSegment::Language(line) => {
                    output.push_str(line);
                    output.push('\n');
                }
                ArkSegment::Literal(idx) => {
                    if let Some(entry) = self.literals.get(*idx) {
                        for line in &entry.lines {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
                ArkSegment::Record(idx) => {
                    if let Some(entry) = self.records.get(*idx) {
                        for line in &entry.lines {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
                ArkSegment::Function(idx) => {
                    if let Some(entry) = self.functions.get(*idx) {
                        if let Some(function) = &entry.parsed {
                            if entry.raw_text.is_empty() {
                                let text = function.to_string(&entry.annotations);
                                output.push_str(&text);
                                if !text.ends_with('\n') {
                                    output.push('\n');
                                }
                                continue;
                            }
                        }

                        if entry.raw_text.is_empty() {
                            if let Some(function) = &entry.parsed {
                                let text = function.to_string(&entry.annotations);
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
        let abc = parse_ark_module(&data).expect("failed to parse modules file");
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
