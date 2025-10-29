# Ark RS

Rust tooling for exploring HarmonyOS Ark (ArkTS) `.abc` bytecode files. The
crate mirrors the textual disassembly format while incrementally reverse
engineering the binary container.

## Current Capabilities

- Parse Ark disassembly text (e.g. `modules.txt`) into structured Rust types and
  emit byte-identical output for round-trip testing.
- Read binary `.abc` modules: headers, index tables, string table, class
  metadata, method index stubs, and the literal array region.
- Decode literal arrays using the recovered spec (`specs/literals.md` and
  `specs/abc-combined.md`) including module request/import/export blocks,
  affiliate tags, getter/setter references, and nested literal arrays.
- Convert the decoded binary form into the existing high-level `AbcFile` model
  so that `AbcFile::to_string()` can render a preview disassembly directly from
  `.abc` inputs (see `target/disassembly/modules.abc.out`).
- Provide fixtures (`test-data/modules.abc`, `test-data/wechat.abc`) and tests
  (`cargo test`) that exercise both textual and binary pipelines.

## Outstanding Work

1. **Method and Record Resolution** – Map method/code offsets onto the high-level
   method table so function headers and literal references are named exactly as
   `ark_disasm` reports (e.g. `#~@0>#onCreate`). Record bodies are currently
   placeholders and need to be rebuilt from class metadata and literals.
2. **Instruction Streams** – Function bodies are stubbed; decoding opcodes,
   register layouts, exception tables, and debug info is still ahead.
3. **Constant Pool Coverage** – Fields, method prototypes, method handles,
   metadata blobs, and annotation tables are only partially surfaced. These need
   to be read from the index section and wired into the `ConstantPool` model.
4. **Writers / Round-Trip** – There is not yet a binary emitter. Once decoding is
   complete, we need to serialise the in-memory representation back to `.abc`
   while preserving layout and checksums.
5. **Version Gates & Large Literals** – Literal decoding now recognises BigInt
   and Any payloads but prints summaries rather than full values. We still need
   to validate size limits and format differences across Ark file versions.
6. **Tooling & CI** – Add snapshot comparisons against `ark_disasm`, hook up
   `cargo fmt`, Clippy, and CI scripts once the repository is public.

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

- `.function` headers currently display normalised string table entries instead
  of the canonical `ark_disasm` symbol names.
- Literal output for `any`/`bigint` values is summarised (`len=…`) rather than a
  full decode.
- Record bodies are placeholders; field/method counts come from the binary but
  no member declarations are emitted yet.
