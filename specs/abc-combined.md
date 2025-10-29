# .abc file format spec

**Date:** 2025-10-29
**Source:** [chat.openai.com](https://chatgpt.com/share/69022d24-6eb8-8007-8f77-f96476d7d44e)


## 0. Conventions

- **Endianness:** little-endian for all multibyte scalars.   
- **Offsets:** absolute byte offsets from file start unless a field explicitly says “relative.”  
- **ULEB128 / SLEB128:** standard base-128 varints; counts/sizes → ULEB, signed literals → SLEB.   
- **Strings:** MUTF-8 with `(utf16_len << 1) | is_ascii` prefix and trailing NUL.   
- **Index pools/regions:** 16-bit indices resolved via per-region tables (Index Section). 32-bit “EntityId” fields are absolute offsets.   
- **Alignment:** byte-aligned unless otherwise noted; scalar literals align to their width. Preserve zero padding when rewriting.   

> **Version key used below**
>
> - **≤ 12.0.6.0** = pre-API-12.0.6 era (legacy features present)
> - **= 12.0.6.0** = Huawei API-12 baseline document
> - **≥ 12.0.6.0** = modern (legacy features removed)
>
> When in doubt, prefer “≥ 12.0.6.0” behavior for new encoders; add **compat mode** for older files.

---

## 1. Top-Level File Layout
```

0x00 +-------------------------------+
| Header                        | 32 bytes
+-------------------------------+
| Class Index Table             | num_classes × u32 (offsets)
+-------------------------------+
| [Literal Array Index Table]*  | legacy (≤12.0.6.0)
+-------------------------------+
| Index Section                 | region headers + pools
+-------------------------------+
| Foreign Item Area (optional)  |
+-------------------------------+
| Main Item Area                | strings, types, classes, fields,
|                               | methods, code, values, literals, ...
+-------------------------------+
| Line Number Program Index     | num_lnps × u32 (offsets)
+-------------------------------+

```
yaml
\* **Literal Array Index Table** exists only in older builds; modern files discover literal arrays from tagged records. See §2.2. 

---

## 2. Header

### 2.1 Binary Layout
```

offset size  field
------+----- ----------------------------------------------
0x00   8     magic = "PANDA\\0\\0\\0"
0x08   4     checksum (Adler-32 over [0x0C..file_size))
0x0C   4     version[4] (bytecode version)
0x10   4     file_size
0x14   4     foreign_off
0x18   4     foreign_size
0x1C   4     num_classes
0x20   4     class_idx_off
0x24   4     num_lnps
0x28   4     lnp_idx_off
0x2C   4     num_literalarrays        // legacy, ≤12.0.6.0 (see notes)
0x30   4     literalarray_idx_off     // legacy, ≤12.0.6.0
0x34   4     num_indexes
0x38   4     index_section_off

```
pgsql
> Some builds show a 32-byte header; others extend with index section pointers. Treat unknown trailing header fields conservatively and rely on the offsets present. The reverse-engineered doc shows index-section pointers, foreign area, and LNP index — use them if non-zero. 

### 2.2 Notes, Discrepancies & Version Gates

- **magic/checksum/version/file_size**: match on all sources. Checksum = Adler-32 with the checksum field zeroed at compute time.   
- **LiteralArray header coupling**:
  - **Your/Reverse spec:** includes `num_literalarrays` + `literalarray_idx_off`. 
  - **Huawei API-12:** **no such fields**; literal arrays are not header-indexed.  
  - **Action:** Mark **obsolete** for ≥12.0.6.0. Keep a **parser fallback**: if `num_literalarrays != 0xFFFFFFFF` (or non-zero), read table; otherwise, ignore and discover via tags.
- **Index Section:**
  - **Your spec:** class/method/field/proto pools per region. 
  - **Huawei API-12:** mentions only ClassRegion and MethodStringLiteral region indexes.
  - **Action:** Support broader pools; when absent in a header, treat size/off = `0xFFFFFFFF` sentinel (unsupported in that region). 

### 2.3 Rust (illustrative)

```rust
#[repr(C)]
pub struct Header {
    pub magic: [u8; 8],          // "PANDA\\0\\0\\0"
    pub checksum: u32,           // Adler-32 of bytes [0x0C..file_size)
    pub version: [u8; 4],        // e.g., {13,0,1,0} for API~18 mappings
    pub file_size: u32,

    pub foreign_off: u32,
    pub foreign_size: u32,

    pub num_classes: u32,
    pub class_idx_off: u32,

    pub num_lnps: u32,
    pub lnp_idx_off: u32,

    // legacy (≤12.0.6.0). If absent in file size, treat as not present.
    pub num_literalarrays: u32,      // 0xFFFFFFFF if removed
    pub literalarray_idx_off: u32,   // 0xFFFFFFFF if removed

    pub num_indexes: u32,
    pub index_section_off: u32,
}
```

## 3. Index Section (16-bit ID resolution)
###   3.1 Region Header

```
pgsqloffset size field
------+---- ---------------------------------------------
0x00   4    start     // inclusive offset covered by region
0x04   4    end       // exclusive
0x08   4    class_idx_size   // or 0xFFFFFFFF
0x0C   4    class_idx_off
0x10   4    method_idx_size  // "method/string/literal" pool
0x14   4    method_idx_off
0x18   4    field_idx_size
0x1C   4    field_idx_off
0x20   4    proto_idx_size
0x24   4    proto_idx_off
```

Each pool is a dense array of 4-byte EntityId (absolute offsets). Implementations may omit some pools (sentinel size/off pair). Pools apply to items whose offsets fall in [start,end).

Huawei API-12 only documents “ClassRegionIndex” and “MethodStringLiteralRegionIndex”. The broader pool set appears in OpenHarmony emissions and is needed to resolve all 16-bit IDs in practice. Keep both models: if a header doesn’t advertise a pool, treat 16-bit IDs of that kind as invalid in that region.

### 3.2 Constraints

Max entries per region: 65536 (fits 16-bit IDs). (Official doc)

Region headers must be sorted by start; non-overlapping recommended. (Official doc)

## 4. Foreign Items
   Purpose: represent external (not defined in this file) classes/fields/methods while still providing indexable offsets for references.

Your spec: a single “foreign items” region.

Huawei: two distinct record types at least (ForeignClass, ForeignMethod), with dedicated layouts.

Action: keep ForeignClass, ForeignField, ForeignMethod as separate item kinds. All set a “foreign” bit; payload mirrors the corresponding local item’s primary identity fields (name/type/proto), omitting tags not applicable to externals.

## 5. Shared Building Blocks
###   5.1 Strings

```
bashULEB128 len_and_ascii = (utf16_len << 1) | is_ascii
u8 payload[utf8_bytes + 1]  // trailing NUL, MUTF-8
```

Participates in the “method/string/literal” index pool.
### 5.2 Types

Primitive encodings are table-driven; reference types share the class/type index pool. (OpenHarmony concept)

### 5.3 Method Prototypes (when present)
Reverse-engineered shorty packing (4-bit per type) followed by 16-bit reference-type indices in appearance order. Consider optional in Ark TS V5 (Huawei does not expose ProtoItem publicly). Keep support for legacy input; new encoders may skip emitting standalone ProtoItem and encode prototype semantics via method tags only.

## 6. Classes
###   6.1 Layout (reverse-engineered)

```
cssStringItem name
u32 super_class_offset        // 0 if none  (legacy; see note)
ULEB128 access_flags
ULEB128 num_fields
ULEB128 num_methods
[tagged stream terminated by 0x00]
FieldItem[num_fields]
MethodItem[num_methods]
```

Huawei: superclass is implicit via a ClassTag entry rather than a raw field.

Action: For ≥12.0.6.0, do not expect a dedicated super_class_offset; consume the relation via tags (see below). For older files, accept the field if encountered.

### 6.2 ClassTag (enumeration) — must implement
A tagged stream terminated by ClassTag::NOTHING (0x00). Include at least:

INTERFACES → ULEB count, then count × u16 class indices.

SOURCE_LANG → 1 byte enum.

SOURCE_FILE → u32 StringItem offset.

RUNTIME_ANNOTATION, ANNOTATION, RUNTIME_TYPE_ANNOTATION, TYPE_ANNOTATION → u32 offsets (repeatable).

Huawei-only detail: the tag list is sorted ascending except the terminator (0x00); adopt this to maximize compatibility.

Assembler rule: When emitting, sort tag IDs ascending; terminate with 0x00. When reading, accept any order but normalize internally.

### 6.3 Access Flags
Low 16 bits = Java-like ACC flags; upper bits reserved runtime metadata. Reuse same base for methods.

## 7. Fields
###   7.1 Layout

```
rustu16 class_index
u16 type_index
u32 name_offset  // StringItem
ULEB128 access_flags
[tagged stream terminated by 0x00]
```

### 7.2 FieldTag — must implement

INT_VALUE (0x01) → SLEB128 32-bit integer inline.

VALUE (0x02) → either inline 4-byte payload (32-bit float/ID) or u32 offset to a ValueItem for wider scalars/arrays.

Annotation tags same as class.

Huawei enumerates exact widths (INTEGER=32, LONG=64, FLOAT=32, DOUBLE=64, ID=32). Use those widths when deciding inline vs referenced encoding.

## 8. Methods
###   8.1 Base Layout

```
rustu16 class_index
u16 proto_index (0xFFFF if none/implicit)
u32 name_offset
ULEB128 access_flags_or_index_data
[tagged stream terminated by 0x00]
```

Your spec: proto_index present; access_flags split into function kind + header index.

Huawei API-12 encoding: packs header_index (16) + function_kind (8) + reserved (8) into a fixed 32-bit index_data field (not ULEB).

Action (assembler):

For API-12 files, encode the 32-bit index_data bitfield exactly (do not varint it).

For legacy, you may encounter/read ULEB; normalize to internal struct then re-emit per target version.

FunctionKind (8-bit) (from OpenHarmony/Huawei convergence):

```
vbnet0 None / Normal
1 Function
2 Non-Constructor Function (NC_FUNCTION)
3 Generator Function
4 Async Function
5 Async Generator Function
6 Async Non-Constructor
7 Concurrent Function
bit3 (0x8) often used as SENDABLE mask in some trees (treat as impl-specific)
```

(Exact values per tree; keep table configurable in the encoder.)
### 8.2 MethodTag — must implement
TagPayloadCODE (0x01)u32 offset → CodeItemSOURCE_LANG (0x02)1 byteRUNTIME_ANNOTATION (0x03)u32 offset (repeatable)RUNTIME_PARAM_ANNOTATION (0x04)u32 offset → ParamAnnotationsItemDEBUG_INFO (0x05)u32 offset → DebugInfoItemANNOTATION (0x06)u32 offset (repeatable)PARAM_ANNOTATION (0x07)u32 offset → ParamAnnotationsItemTYPE_ANNOTATION (0x08)u32 offset (repeatable)RUNTIME_TYPE_ANNOTATION (0x09)u32 offset (repeatable)
(Reverse-engineered list; compatible with Huawei structure.)

## 9. CodeItem & Exceptions
###   9.1 CodeItem

```
cssULEB num_vregs
ULEB num_args
ULEB code_size_bytes
ULEB try_block_count
u8   instructions[code_size_bytes]
TryBlock[try_block_count]
```

Alignment: The bytecode stream is byte-packed; some runtimes align the following table — keep writer conservative (pad to 1).

Try blocks count: ULEB (Huawei aligns with your doc).

### 9.2 TryBlock & CatchBlock

```
cppTryBlock:
  ULEB start_pc
  ULEB length
  ULEB catch_count
  CatchBlock[catch_count]

CatchBlock:
  ULEB (type_index + 1)  // 0 => catch-all
  ULEB handler_pc
  ULEB code_size         // was named code_size_hint in your doc → rename exact
```

Your doc used code_size_hint; Huawei calls this code_size. Treat as exact size.

## 10. Bytecode ISA (Instruction Set)

Opcode byte with optional prefix bytes (0xFE throw, 0xFD wide, 0xFC deprecated, 0xFB callruntime). Two-byte opcodes when prefixed. (OpenHarmony ISA docs)

Format strings determine operand packing (packed bitfields after opcode(s)). (Reverse doc)

Operand kinds: v registers; id → 16-bit pool IDs resolved via the method’s selected index header; imm sign/zero extended by type.

Implementation: Generate encoder/decoder tables from isa.yaml of your toolchain to guarantee fidelity; accept unknown opcodes with a recovery strategy in disassembler (emit .byte).

## 11. Literal Arrays & Values (fully expanded)
    This area is historically under-documented in Huawei’s spec — your critique calls this out. Below is a union of behaviors observed in OpenHarmony writers + Huawei doc’s size taxonomy.
###    11.1 LiteralArrayItem (container)
    Modern canonical form:

```
lessu32 count              // number of element entries that follow
LiteralEntry[count]
```

Legacy quirk (some ≤12.0.6.0 builds): count may encode 2× elements (“half-count rule”). If the subsequent bytes exceed file bounds when reading count entries, retry using count / 2. Writers must not emit half-count for ≥12.0.6.0 targets. (Empirical workaround retained for compatibility.)
Discovery:

Modern: arrays are referenced from items via tags/offsets (header table removed).

Legacy: optional “Literal Array Index Table” in header gives offsets (see §2.2).

### 11.2 LiteralEntry (tagged)
Two families are in the wild:
A) Tag + Payload (OpenHarmony, reverse-engineered)

```
rustu8 tag
payload...
```

TagMeaningEncoding0x00EMPTY/NONE—0x01INT_VALUESLEB1280x02FLOAT_VALUEu32 bits (IEEE-754)0x03DOUBLE_VALUEu64 bits (IEEE-754)0x04STRING_LITERALu32 offset → StringItem0x05TYPE_DESCRIPTORu32 offset → Type/Class item0x06NULL_LITERAL—0x07ARRAY_LITERALu32 count; then nested LiteralEntry[count] (apply half-count quirk)0x08BOOLEAN_LITERALu8 (0/1)0x09BIGINT_LITERALu32 len; then len raw bytes (two’s-complement big-endian or impl-specific)0x0AANY_LITERALu32 type_idx; u32 len; len bytes0x0BUNDEFINED_LITERAL—

Unknowns: Exact encoding for BIGINT’s sign/endianness varies across trees; treat contents as opaque byte string and surface in disassembly as bigint:0x…. Treat new tags ≥0x0C as Unknown{tag, raw} with a forward-compatible skip strategy. (These tags reflect the reverse-engineered pathway and are not fully enumerated by Huawei.)

B) Width-coded entries (Huawei “ByteOne/Two/Four/Eight” taxonomy)
Huawei’s doc categorizes literal element encodings by width rather than semantic tag:

ByteOne (1 byte): e.g., boolean, small int

ByteTwo (2 bytes): small numeric / index

ByteFour (4 bytes): INTEGER, FLOAT, ID (offset), or element size for arrays

ByteEight (8 bytes): LONG, DOUBLE

Assembler guidance: Support both semantic tags (A) and width forms (B). When serializing for API-12 targets, prefer Huawei’s widths:

INTEGER → write 4 bytes

LONG → 8 bytes

FLOAT → 4

DOUBLE → 8

ID → 4 (absolute offset)

Arrays → length (ULEB or u32 per container) then packed elements by component width

Reader strategy:

If a byte looks like a small tag but following bytes decode cleanly as Huawei width patterns, accept that decoding.

If the container explicitly says ARRAY with a nested count, consume recursively (A).

In practice, OpenHarmony/Dayu pipelines use Tag+Payload; Huawei doc describes the canonical widths. Supporting both lets your tools round-trip across ecosystems.

### 11.3 ValueItem (for FieldTag::VALUE, arrays, etc.)

Scalars:

INTEGER (u32), LONG (u64), FLOAT (u32 bits), DOUBLE (u64 bits), ID (u32) — inline where allowed (FieldTag::VALUE) if 4 bytes; otherwise emitted as a ValueItem and referenced by u32 offset. (Huawei rule aligns with your doc’s “inline for 32-bit”.)

Arrays:

ULEB count then tightly packed elements by component width (1/2/4/8 or ref). Component ref elements are u32 offsets.

### 11.4 Suggested Internal Rust enum

```rust
rustpub enum Literal {
    Empty,
    Int(i64),                  // sleb128
    Float(f32),
    Double(f64),
    String(Offset),            // u32
    Type(Offset),              // u32
    Null,
    Bool(bool),
    Array(Vec<Literal>),
    BigInt(Vec<u8>),           // raw
    Any { type_idx: u32, data: Vec<u8> },
    Undefined,
    Unknown { tag: u8, raw: Vec<u8> },
}
```

Assembler rules:

For API-12 target, map to Huawei widths where applicable; otherwise emit Tag+Payload form.

For legacy input that uses half-count arrays, normalize internally and re-emit count per target version (never emit half-count for modern).

## 12. Annotations
    AnnotationElementTag: Huawei provides a table for element tags ('1'..'#' etc.). Your doc alludes to annotations but not the tag char set—include it in your encoder/decoder table. For unknown tags, preserve raw bytes.
    AnnotationItem (OpenHarmony form) encodes class index (u16), element count, name offsets (u32 → String), and value payloads with width/offset rules mirroring ValueItem.

## 13. Debug Info & Line Number Programs
###    13.1 DebugInfoItem

```
lessULEB line_start
ULEB parameter_count
repeat parameter_count times:
  ULEB string_off_or_zero
ULEB const_pool_size
u8[const_pool_size]
ULEB line_program_index  // index into LNP index table (not raw offset)
```

Note: Huawei fixes LINE_BASE = −4, LINE_RANGE = 15, OPCODE_BASE = 0x0C for the special-opcode scheme. Your doc lacked the constants; include them in decoding. (Official doc per your critique.)
13.2 Line Number Program (LNP)

Opcodes 0x00..0x0B (END_SEQUENCE, ADVANCE_PC, ADVANCE_LINE, START_LOCAL, START_LOCAL_EXTENDED, END_LOCAL, RESTART_LOCAL, SET_PROLOGUE_END, SET_EPILOGUE_BEGIN, SET_FILE, SET_SOURCE_CODE, SET_COLUMN) with ULEB/SLEB operands as indicated by the opcode.

Special opcodes ≥ OPCODE_BASE (0x0C):
delta_line = LINE_BASE + ((opcode - OPCODE_BASE) % LINE_RANGE)
delta_pc   = (opcode - OPCODE_BASE) / LINE_RANGE
Update current state accordingly.

Indexing: Methods point to LNP via index into the LNP index table (lnp_idx_off, num_lnps), not a raw offset.

## 14. Misc: Module Records & Method Handles

Module records: stored inside literal arrays; five tagged blocks (regular imports, namespace imports, local exports, indirect exports, star exports). Use ULEB counts followed by fixed forms defined in your reverse spec.

Method handles: 1-byte kind + ULEB target EntityId (offset). Keep kind table configurable.

## 15. Discrepancy & Compatibility Matrix
    AreaCombined Spec BehaviorHuawei API-12Reverse/OpenHarmonyAction for ImplementersHeader literal array fieldsObsolete ≥12.0.6.0; accept legacy if presentAbsentPresentParse if present; do not emit for API-12+.Foreign itemsSeparate ForeignClass/Field/MethodDistinct formsRegion existsKeep distinct records; set “foreign” bit.Index Section poolsClass/Method(+string+literal)/Field/ProtoOnly class & method+string literalAll presentSupport broad superset; tolerate missing pools per region.Class super linkVia tag, not raw fieldTag-basedRaw super_class_offset observedRead both; emit tag-based for modern.Method index data32-bit bitfield (header_idx:16kind:8rsrv:8)As documentedCodeItem try blocksULEB sizesULEBULEBAlign semantics; rename catch code_size (not hint).Literal arraysTag+Payload OR Width-codedWidth-coded taxonomyTag+Payload widely usedReader supports both; writer: pick per target.Literal array half-countTolerate on read onlyNot documentedObserved in older filesDo not emit; read with heuristic.Debug LNP constantsInclude LINE_BASE, LINE_RANGE, OPCODE_BASEDocumentedOmittedImplement DWARF-style rules with constants.ISA prefixes0xFD/0xFE/0xFC/0xFB supportedPartially/undocumentedPresentTreat as implementation-specific but supported.

## 16. Assembler & Disassembler Guidance
###    16.1 Disassembler Pipeline

Header: validate magic, version, checksum; collect pointers.

Index Section: load region headers; build resolvers for 16-bit IDs.

Class Index: enumerate classes; for each, parse tagged attributes, fields, methods.

Methods: decode index_data/access_flags, follow tags to CodeItem/DebugInfo.

Code: decode instructions using ISA tables; resolve IDs via selected region header.

Literals/Values: detect Tag+Payload vs Width-coded; print canonical form.

Debug: load LNP by index; interpret opcodes using Huawei constants.

### 16.2 Assembler Pipeline

Collect atoms: strings, types, classes, fields, methods, values, literal arrays, code, debug.

Assign offsets with provisional sizes; compute index regions covering all items referenced by 16-bit IDs.

Emit: header (checksum=0), class index, [legacy literal index], index section headers + pools, foreign items, main items, line program index.

Checksum: recompute Adler-32 and rewrite header checksum.

### 16.3 Version Targeting

Target API-12+:

Drop header literal-array fields.

Encode method index_data as 32-bit bitfield.

Prefer width-coded literal element sizes in arrays where applicable.

Legacy emit: only if explicitly requested; otherwise normalize to modern layout.

## 17. Rust Type Hints (non-ABI, for implementers)

```rust
rustpub type Offset = u32;

pub struct IndexRegionHeader {
    pub start: u32, pub end: u32,
    pub class_idx_size: u32, pub class_idx_off: u32,
    pub method_idx_size: u32, pub method_idx_off: u32,
    pub field_idx_size: u32, pub field_idx_off: u32,
    pub proto_idx_size: u32, pub proto_idx_off: u32,
}

pub struct CodeItem {
    pub num_vregs: u32,  // decoded ULEB
    pub num_args: u32,
    pub code: Vec<u8>,
    pub tries: Vec<TryBlock>,
}

pub struct TryBlock { pub start_pc: u32, pub length: u32, pub catches: Vec<CatchBlock> }
pub struct CatchBlock { pub type_index_plus1: u32, pub handler_pc: u32, pub code_size: u32 }

pub enum Lit { /* see §11.4 */ }
```

## 18. Open Questions / Unknowns

BIGINT endianness/signing across all Ark variants (store opaque, display hex).

ANY literal payload conventions beyond (type_idx,len,bytes) (treat as opaque).

ISA private prefixes semantics (callruntime, deprecated specifics) — treat as impl-specific.

Method Prototype exposure in Ark TS V5 (optional; many trees hide it).

When in doubt, preserve bytes on disassembly and allow verbatim re-emit in assembler.

## 19. Minimal Conformance Tests (suggested)

Round-trip: disassemble → assemble → byte-compare (allow header checksum differences).

Index regions: craft files with multiple region headers; validate 16-bit ID resolution windows.

Literals: arrays with nested arrays; mixed Tag+Payload and width-coded paths; half-count read acceptance.

Debug: verify LNP with special-opcode math (LINE_BASE/LINE_RANGE).

Foreign: reference foreign class/method; ensure distinct record types survive round-trip.

## 20. References & Provenance

Reverse-engineered spec (OpenHarmony code paths): Harmony ABC File Format Specification — basis for many structural fields (header, indexes, items).

Huawei API-12 spec (official): source for tag enumerations, width rules, debug constants, and constraints called out in the critique you provided.

Your critique: drove corrections on legacy header fields, method index_data bit-packing, literal/array completeness, sorting/termination rules, and debug constants.

This combined spec is intended to be prescriptive for encoders targeting API-12+ while remaining permissive on read for legacy artifacts. Where ambiguity exists, the guidance favors round-trip fidelity over normalization.

```
pgsql
If you want, I can also scaffold a **Rust crate** with parser/encoder skeletons (`header.rs`, `index.rs`, `class.rs`, `method.rs`, `code.rs`, `literal.rs`, `debug.rs`) wired to this spec, plus a set of goldens for round-trip tests.
::contentReference[oaicite:44]{index=44}
```

---
