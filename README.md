# Ark RS

Rust tooling for exploring HarmonyOS Ark (ArkTS) `.abc` bytecode files. The
crate mirrors the textual disassembly format while incrementally reverse
engineering the binary container.

## Current Capabilities

- Parse Ark disassembly text (e.g. `modules.txt`) into high-level Rust structs
  and emit byte-identical output for round-trip testing.
- Read binary `.abc` modules: headers, index tables, string table, class
  metadata, method index stubs, and the literal array region.
- Decode literal arrays using the recovered spec (`specs/literals.md` and
  `specs/abc-combined.md`) including module request/import/export blocks,
  affiliate tags, getter/setter references, and nested literal arrays.
- Decode function bodies (register counts, instructions, exception handlers)
  and surface them as string-backed `ArkFunction` structures ready for
  rendering or inspection.
- Convert binary modules into `ArkModule` and render their textual disassembly
  directly (`ArkModule::to_string()`), including resolved function names and
  string operands.
- Provide fixtures (`test-data/modules.abc`, `test-data/wechat.abc`) and tests
  (`cargo test`) that exercise both textual and binary pipelines.

## Quick Start

Load a binary `.abc` file and list the decoded functions together with their
disassembly:

```rust
use ark_rs::{format_function, AbcFile};

fn main() -> anyhow::Result<()> {
    let bytes = std::fs::read("test-data/modules.abc")?;
    let module = AbcFile::parse(&bytes)?.to_ark_module();

    for (idx, entry) in module.functions.iter().enumerate() {
        let name = entry
            .parsed
            .as_ref()
            .and_then(|func| func.name.clone())
            .unwrap_or_else(|| format!("function#{idx}"));

        println!("=== {} ===", name);

        if let Some(func) = &entry.parsed {
            print!("{}", format_function(func)?);
        } else {
            print!("{}", entry.raw_text);
        }
    }

    Ok(())
}
```

## Outstanding Work

1. **Record Reconstruction** – Class record bodies are still placeholders; they
   need to be rebuilt from decoded fields, methods, and annotations.
2. **Richer Metadata** – Constant-pool entities other than strings (field
   descriptors, method prototypes, annotations) are surfaced only at the
   low-level. Promote them into the high-level model and tie them back to
   disassembly output.
3. **Binary Writer / Round Trip** – Implement an emitter that serialises
   `ArkModule` (and low-level structures) back to `.abc` bytes while preserving
   layout and checksums.
4. **Version Support & Large Literals** – Literal decoding recognises BigInt and
   `any` payloads but still truncates binary data. Validate size limits and
   format differences across Ark versions, and expose friendly views.
5. **Tooling & CI** – Add snapshot comparisons against `ark_disasm`, set up
   `cargo fmt`/Clippy gates, and wire CI once the repository is public.

## Development

```bash
cargo test
```

The test suite will read fixtures from `test-data/`. Disassembly previews are
written to `target/disassembly/` by the binary parsing tests.

## Resources

- `specs/literals.md`, `specs/abc-combined.md` — current understanding of the
  literal and constant pool layouts.
- `test-data/` — sample `.abc` binaries and their textual dumps.

## Known Issues

- Record bodies are placeholders; field/method counts come from the binary but
  no member declarations are emitted yet.
- Literal output for `any`/`bigint` values is summarised (`len=…`) rather than a
  full decode.
- Type and field identifiers in instruction operands still appear with
  `type#…`/`field#…` placeholders until their metadata is fully resolved.
