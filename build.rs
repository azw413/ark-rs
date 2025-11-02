//! Build script to generate instruction definitions from isa.yaml

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct IsaSpec {
    #[serde(rename = "groups")]
    groups: Vec<InstructionGroup>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct InstructionGroup {
    #[serde(rename = "title")]
    title: Option<String>,
    #[serde(rename = "instructions")]
    instructions: Vec<InstructionDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct InstructionDef {
    #[serde(rename = "sig")]
    signature: String,
    #[serde(rename = "acc")]
    accumulator: Option<String>,
    #[serde(rename = "opcode_idx")]
    opcode_idx: Vec<String>,
    #[serde(rename = "format")]
    format: Vec<String>,
    #[serde(rename = "prefix")]
    prefix: Option<String>,
    #[serde(rename = "properties")]
    properties: Option<Vec<String>>,
    #[serde(rename = "description")]
    description: Option<String>,
}

fn main() -> std::io::Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let isa_yaml_path = PathBuf::from("specs/isa.yaml");

    println!("cargo:rerun-if-changed={}", isa_yaml_path.display());
    eprintln!("DEBUG: Attempting to parse: {}", isa_yaml_path.display());

    // Parse ISA specification
    let isa_spec: IsaSpec = match serde_yaml::from_reader(File::open(&isa_yaml_path)?) {
        Ok(spec) => {
            eprintln!("DEBUG: Successfully parsed YAML");
            spec
        }
        Err(e) => {
            eprintln!("ERROR: Failed to parse isa.yaml: {}", e);
            eprintln!("Generating empty instruction table");
            generate_empty_file(&out_dir)?;
            return Ok(());
        }
    };

    // Build instruction tables
    let (plain_instructions, prefixed_instructions) = build_instruction_tables(&isa_spec);

    eprintln!(
        "DEBUG: Built {} plain and {} prefixed instructions",
        plain_instructions.len(),
        prefixed_instructions.len()
    );

    // Generate Rust code
    generate_rust_code(&out_dir, &plain_instructions, &prefixed_instructions)?;

    Ok(())
}

#[derive(Debug, Clone)]
struct InstructionEntry {
    signature: String,
    format: String,
    prefix: Option<u8>,
}

fn build_instruction_tables(
    spec: &IsaSpec,
) -> (
    HashMap<u8, InstructionEntry>,
    HashMap<(u8, u8), InstructionEntry>,
) {
    let mut plain = HashMap::new();
    let mut prefixed = HashMap::new();

    for group in &spec.groups {
        for instr in &group.instructions {
            if instr.opcode_idx.len() != instr.format.len() {
                eprintln!(
                    "WARNING: opcode/format length mismatch for '{}': {} opcodes vs {} formats",
                    instr.signature,
                    instr.opcode_idx.len(),
                    instr.format.len()
                );
                continue;
            }

            let prefix_byte = instr.prefix.as_deref().and_then(prefix_name_to_byte);

            if instr.prefix.is_some() && prefix_byte.is_none() {
                eprintln!(
                    "WARNING: unknown prefix '{}' on instruction '{}'",
                    instr.prefix.as_deref().unwrap_or(""),
                    instr.signature
                );
                continue;
            }

            for (opcode_hex, format_token) in instr.opcode_idx.iter().zip(instr.format.iter()) {
                let opcode_byte = parse_hex_u8(opcode_hex);
                let entry = InstructionEntry {
                    signature: instr.signature.clone(),
                    format: format_token.clone(),
                    prefix: prefix_byte,
                };

                if let Some(prefix) = prefix_byte {
                    if prefixed
                        .insert((prefix, opcode_byte), entry.clone())
                        .is_some()
                    {
                        eprintln!(
                            "WARNING: duplicate prefixed opcode 0x{:02x} for prefix 0x{:02x}",
                            opcode_byte, prefix
                        );
                    }
                } else if plain.insert(opcode_byte, entry.clone()).is_some() {
                    eprintln!("WARNING: duplicate opcode 0x{:02x}", opcode_byte);
                }
            }
        }
    }

    (plain, prefixed)
}

fn parse_hex_u8(s: &str) -> u8 {
    // Remove 0x prefix if present and parse
    let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    u8::from_str_radix(clean, 16).unwrap_or(0)
}

fn prefix_name_to_byte(prefix: &str) -> Option<u8> {
    match prefix {
        "throw" => Some(0xFE),
        "wide" => Some(0xFD),
        "deprecated" => Some(0xFC),
        "callruntime" => Some(0xFB),
        _ => None,
    }
}

fn generate_empty_file(out_dir: &PathBuf) -> std::io::Result<()> {
    let mut file = File::create(out_dir.join("isa_generated.rs"))?;
    writeln!(file, "//! Auto-generated from isa.yaml - placeholder")?;
    writeln!(file, "use crate::instructions::InstructionFormat;")?;
    writeln!(file)?;
    writeln!(
        file,
        "pub const INSTRUCTION_TABLE: &[Option<InstructionEntry>] = &[];"
    )?;
    writeln!(
        file,
        "pub const PREFIXED_INSTRUCTION_TABLE: &[Option<PrefixedInstructionEntry>] = &[];"
    )?;
    writeln!(file)?;
    writeln!(file, "#[derive(Debug, Clone, Copy)]")?;
    writeln!(
        file,
        "pub struct InstructionEntry {{\n    pub opcode: u8,\n    pub signature: &'static str,\n    pub format: InstructionFormat,\n    pub prefix: Option<u8>,\n}}"
    )?;
    writeln!(file)?;
    writeln!(file, "#[derive(Debug, Clone, Copy)]")?;
    writeln!(
        file,
        "pub struct PrefixedInstructionEntry {{\n    pub prefix: u8,\n    pub opcode: u8,\n    pub signature: &'static str,\n    pub format: InstructionFormat,\n}}"
    )?;
    Ok(())
}

fn generate_rust_code(
    _out_dir: &PathBuf,
    plain: &HashMap<u8, InstructionEntry>,
    prefixed: &HashMap<(u8, u8), InstructionEntry>,
) -> std::io::Result<()> {
    // Write to src/isa_generated.rs so it's included in the build
    let src_path = PathBuf::from("src/isa_generated.rs");
    let mut file = File::create(&src_path)?;

    writeln!(
        file,
        "//! Auto-generated instruction definitions from isa.yaml"
    )?;
    writeln!(
        file,
        "//! This file is generated by build.rs - do not edit manually"
    )?;
    writeln!(file)?;
    writeln!(file, "//! Regenerate with: cargo build")?;
    writeln!(file)?;

    writeln!(file, "use crate::instructions::InstructionFormat;")?;
    writeln!(file)?;

    // Generate plain instruction table
    writeln!(
        file,
        "/// Plain (non-prefixed) instruction table indexed by opcode byte"
    )?;
    writeln!(
        file,
        "pub const INSTRUCTION_TABLE: &[Option<InstructionEntry>] = &["
    )?;

    for byte in 0..=0xFF {
        if let Some(entry) = plain.get(&byte) {
            let signature_literal = quote_literal(&entry.signature);
            let format_ident = format_to_enum_ident(&entry.format);
            let prefix_literal = format_prefix_literal(entry.prefix);
            writeln!(
                file,
                "    Some(InstructionEntry {{ opcode: 0x{:02x}, signature: {}, format: InstructionFormat::{}, prefix: {} }}),",
                byte, signature_literal, format_ident, prefix_literal
            )?;
        } else {
            writeln!(file, "    None,")?;
        }
    }
    writeln!(file, "];")?;
    writeln!(file)?;

    // Generate prefixed instruction table
    writeln!(
        file,
        "/// Prefixed instruction table indexed by (prefix_byte, opcode_byte)"
    )?;
    writeln!(
        file,
        "pub const PREFIXED_INSTRUCTION_TABLE: &[Option<PrefixedInstructionEntry>] = &["
    )?;

    let mut entries = vec![None; 256 * 256];
    for ((prefix, opcode), entry) in prefixed {
        let index = (*prefix as usize) * 256 + (*opcode as usize);
        entries[index] = Some(PrefixedInstructionEntry {
            prefix: *prefix,
            opcode: *opcode,
            signature: entry.signature.clone(),
            format: entry.format.clone(),
        });
    }

    for entry in entries.iter() {
        if let Some(e) = entry {
            let signature_literal = quote_literal(&e.signature);
            let format_ident = format_to_enum_ident(&e.format);
            writeln!(
                file,
                "    Some(PrefixedInstructionEntry {{ prefix: 0x{:02x}, opcode: 0x{:02x}, signature: {}, format: InstructionFormat::{} }}),",
                e.prefix, e.opcode, signature_literal, format_ident
            )?;
        } else {
            writeln!(file, "    None,")?;
        }
    }
    writeln!(file, "];")?;
    writeln!(file)?;

    // Generate entry structs
    writeln!(file, "/// Entry for plain instructions")?;
    writeln!(file, "#[derive(Debug, Clone, Copy)]")?;
    writeln!(
        file,
        "pub struct InstructionEntry {{\n    pub opcode: u8,\n    pub signature: &'static str,\n    pub format: InstructionFormat,\n    pub prefix: Option<u8>,\n}}"
    )?;
    writeln!(file)?;

    writeln!(file, "/// Entry for prefixed instructions")?;
    writeln!(file, "#[derive(Debug, Clone, Copy)]")?;
    writeln!(
        file,
        "pub struct PrefixedInstructionEntry {{\n    pub prefix: u8,\n    pub opcode: u8,\n    pub signature: &'static str,\n    pub format: InstructionFormat,\n}}"
    )?;

    eprintln!(
        "Generated {} plain and {} prefixed instruction entries to src/isa_generated.rs",
        plain.len(),
        prefixed.len()
    );

    Ok(())
}

fn quote_literal(value: &str) -> String {
    format!("{:?}", value)
}

fn format_prefix_literal(prefix: Option<u8>) -> String {
    match prefix {
        Some(byte) => format!("Some(0x{:02x})", byte),
        None => "None".to_string(),
    }
}

fn format_to_enum_ident(token: &str) -> &'static str {
    match token {
        "op_id_16" => "ID16",
        "op_imm1_16_id1_16_id2_16_imm2_16_v_8" => "IMM16_ID16_ID16_IMM16_V8",
        "op_imm1_16_id_16_imm2_8" => "IMM16_ID16_IMM8",
        "op_imm1_16_imm2_16" => "IMM16_IMM16",
        "op_imm1_16_imm2_8_v_8" => "IMM16_IMM8_V8",
        "op_imm1_16_v_8_imm2_16" => "IMM16_V8_IMM16",
        "op_imm1_4_imm2_4" => "IMM4_IMM4",
        "op_imm1_8_id1_16_id2_16_imm2_16_v_8" => "IMM8_ID16_ID16_IMM16_V8",
        "op_imm1_8_id_16_imm2_8" => "IMM8_ID16_IMM8",
        "op_imm1_8_imm2_16" => "IMM8_IMM16",
        "op_imm1_8_imm2_16_imm3_16" => "IMM8_IMM16_IMM16",
        "op_imm1_8_imm2_16_imm3_16_v_8" => "IMM8_IMM16_IMM16_V8",
        "op_imm1_8_imm2_8" => "IMM8_IMM8",
        "op_imm1_8_imm2_8_v_8" => "IMM8_IMM8_V8",
        "op_imm1_8_v_8_imm2_16" => "IMM8_V8_IMM16",
        "op_imm_16" => "IMM16",
        "op_imm_16_id_16" => "IMM16_ID16",
        "op_imm_16_id_16_v_8" => "IMM16_ID16_V8",
        "op_imm_16_v1_8_v2_8" => "IMM16_V8_V8",
        "op_imm_16_v_8" => "IMM16_V8",
        "op_imm_32" => "IMM32",
        "op_imm_64" => "IMM64",
        "op_imm_8" => "IMM8",
        "op_imm_8_id_16" => "IMM8_ID16",
        "op_imm_8_id_16_v_8" => "IMM8_ID16_V8",
        "op_imm_8_v1_8_v2_8" => "IMM8_V8_V8",
        "op_imm_8_v1_8_v2_8_v3_8" => "IMM8_V8_V8_V8",
        "op_imm_8_v1_8_v2_8_v3_8_v4_8" => "IMM8_V8_V8_V8_V8",
        "op_imm_8_v_8" => "IMM8_V8",
        "op_none" => "NONE",
        "op_v1_16_v2_16" => "V16_V16",
        "op_v1_4_v2_4" => "V4_V4",
        "op_v1_8_v2_8" => "V8_V8",
        "op_v1_8_v2_8_v3_8" => "V8_V8_V8",
        "op_v1_8_v2_8_v3_8_v4_8" => "V8_V8_V8_V8",
        "op_v_8" => "V8",
        "op_v_8_imm_16" => "V8_IMM16",
        "op_v_8_imm_8" => "V8_IMM8",
        "pref_op_id_16" => "PREF_ID16",
        "pref_op_id_16_imm1_16_imm2_16_v1_8_v2_8" => "PREF_ID16_IMM16_IMM16_V8_V8",
        "pref_op_id_32" => "PREF_ID32",
        "pref_op_id_32_imm_8" => "PREF_ID32_IMM8",
        "pref_op_id_32_v_8" => "PREF_ID32_V8",
        "pref_op_imm1_16_id1_16_id2_16_imm2_16_v_8" => "PREF_IMM16_ID16_ID16_IMM16_V8",
        "pref_op_imm1_16_imm2_16" => "PREF_IMM16_IMM16",
        "pref_op_imm1_16_imm2_16_v_8" => "PREF_IMM16_IMM16_V8",
        "pref_op_imm1_4_imm2_4" => "PREF_IMM4_IMM4",
        "pref_op_imm1_4_imm2_4_v_8" => "PREF_IMM4_IMM4_V8",
        "pref_op_imm1_8_imm2_16_imm3_16_v_8" => "PREF_IMM8_IMM16_IMM16_V8",
        "pref_op_imm1_8_imm2_32_v_8" => "PREF_IMM8_IMM32_V8",
        "pref_op_imm1_8_imm2_8" => "PREF_IMM8_IMM8",
        "pref_op_imm1_8_imm2_8_v_8" => "PREF_IMM8_IMM8_V8",
        "pref_op_imm_16" => "PREF_IMM16",
        "pref_op_imm_16_id_16" => "PREF_IMM16_ID16",
        "pref_op_imm_16_v1_8_v2_8" => "PREF_IMM16_V8_V8",
        "pref_op_imm_16_v_8" => "PREF_IMM16_V8",
        "pref_op_imm_32" => "PREF_IMM32",
        "pref_op_imm_8" => "PREF_IMM8",
        "pref_op_imm_8_v1_8_v2_8" => "PREF_IMM8_V8_V8",
        "pref_op_imm_8_v_8" => "PREF_IMM8_V8",
        "pref_op_none" => "PREF_NONE",
        "pref_op_v1_8_v2_8" => "PREF_V8_V8",
        "pref_op_v1_8_v2_8_v3_8" => "PREF_V8_V8_V8",
        "pref_op_v1_8_v2_8_v3_8_v4_8" => "PREF_V8_V8_V8_V8",
        "pref_op_v_8" => "PREF_V8",
        "pref_op_v_8_imm_32" => "PREF_V8_IMM32",
        _ => panic!("Unknown instruction format token: {}", token),
    }
}

#[derive(Debug, Clone)]
struct PrefixedInstructionEntry {
    prefix: u8,
    opcode: u8,
    signature: String,
    format: String,
}
