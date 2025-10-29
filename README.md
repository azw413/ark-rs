# Ark RS

Rust tooling for exploring HarmonyOS Ark (ArkTS) `.abc` bytecode files. The
project currently focuses on understanding the binary format while keeping the
existing textual disassembly round-trip capable.

## Current Capabilities

- Parse textual disassembly (`modules.txt`) into structured types and re-emit
  the exact text (round-trip is covered by the existing test fixtures).
- Decode binary `.abc` headers, index tables, class metadata, and string table
  entries.
- Recover literal array specifications based on reverse-engineered sources
  (`specs/literals.md`) and expose a partial reader implementation.
- Provide fixtures for both small (`modules.abc`) and realistic
  (`wechat.abc`) apps to drive reverse-engineering efforts.

## What’s Missing for Full Round-Trip Support

The following gaps prevent us from decoding a binary `.abc` into our in-memory
model and serialising it back to an equivalent binary or textual form:

1. **Literal Arrays**
   - Implement robust decoding for the *Any* (`0x0A`) and *BigInt* (`0x0C`)
     literal payloads. Current readers treat these as raw blobs because the
     length fields can be extremely large (e.g. `0x1000000`, `0x5000000`). We
     need length guards and a better understanding of the encoding.
   - Map literal arrays into the constant pool and ensure nested array
     references (`0x18`) are handled correctly.

2. **Complete Constant Pool Coverage**
   - Only strings, types, and literal arrays are carried over today. Field and
     method descriptors, method handles, metadata, and annotations still need
     to be parsed from the binary sections.

3. **Function Bodies and Instructions**
   - Instruction sections are currently untouched. We can parse textual
     instructions, but the binary format requires decoding register layouts,
     operands, exception tables, and debug info.

4. **Round-Trip Writer**
   - There is no binary writer yet. Once parsing is feature-complete we will
     need to serialise the in-memory representation back to `.abc`, preserving
     section offsets, checksums, and alignment rules.

5. **Version Compatibility**
   - The literal specification notes a “half-count rule” for older versions and
     hints at evolving tag values. We should validate against multiple runtime
     versions and gate behaviours via `AbcVersion`.

6. **Testing & Tooling**
   - Add snapshot/fixture tests for binary literal arrays once decoding is
     stable.
   - Wire up CI (Rustfmt, Clippy, `cargo test`) after publishing the repo.

## Development

```bash
cargo test
```

The project currently depends only on the standard library. When experimenting
with new fixtures, drop the `.abc` files into `test-data/` and point tests at
them.

## Resources

- `specs/literals.md` — current understanding of literal tags and payloads.
- `test-data/` — sample `.abc` binaries and their corresponding textual dumps.

Please file issues or PRs once the GitHub repository is available.

## Known issues
function listings have the wrong names (random string entries)