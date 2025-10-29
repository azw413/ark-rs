//! Definitions for the Ark bytecode file header and shared metadata.

/// File endianness marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

/// Identifies the kind of module encoded in the bytecode file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    EcmaScript,
    ArkTs,
    PandaAssembly,
    Library,
    Other(u16),
}

impl ModuleKind {
    /// Create a [`ModuleKind`] from the raw discriminant stored in the file header.
    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            0 => ModuleKind::EcmaScript,
            1 => ModuleKind::ArkTs,
            2 => ModuleKind::PandaAssembly,
            3 => ModuleKind::Library,
            other => ModuleKind::Other(other),
        }
    }

    /// Retrieve the raw discriminant used in the binary header.
    pub const fn to_raw(self) -> u16 {
        match self {
            ModuleKind::EcmaScript => 0,
            ModuleKind::ArkTs => 1,
            ModuleKind::PandaAssembly => 2,
            ModuleKind::Library => 3,
            ModuleKind::Other(value) => value,
        }
    }
}

/// A tuple struct used to capture feature flags exposed by the Ark bytecode header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFlags(pub u32);

impl FileFlags {
    pub const NONE: FileFlags = FileFlags(0);
    pub const HAS_DEBUG_INFO: FileFlags = FileFlags(1 << 0);
    pub const HAS_ANNOTATIONS: FileFlags = FileFlags(1 << 1);
    pub const HAS_TYPE_INFO: FileFlags = FileFlags(1 << 2);
    pub const RESERVED0: FileFlags = FileFlags(1 << 3);

    /// Combine two flag sets.
    pub const fn union(self, other: FileFlags) -> FileFlags {
        FileFlags(self.0 | other.0)
    }

    /// Remove [`other`] from this flag set.
    pub const fn difference(self, other: FileFlags) -> FileFlags {
        FileFlags(self.0 & !other.0)
    }

    /// Check whether all bits of [`other`] are present in `self`.
    pub const fn contains(self, other: FileFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for FileFlags {
    fn default() -> Self {
        FileFlags::NONE
    }
}

/// Semantic version used by the Ark bytecode specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl FileVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        FileVersion {
            major,
            minor,
            patch,
        }
    }
}

impl Default for FileVersion {
    fn default() -> Self {
        FileVersion::new(0, 0, 0)
    }
}

/// High level metadata placed at the front of Ark bytecode modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: FileVersion,
    pub module_kind: ModuleKind,
    pub endianness: Endianness,
    pub flags: FileFlags,
    pub checksum: u32,
    pub file_size: u32,
    pub section_count: u16,
    pub reserved: u16,
}

impl FileHeader {
    pub const MAGIC: [u8; 4] = *b"ARK\0";
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            magic: FileHeader::MAGIC,
            version: FileVersion::default(),
            module_kind: ModuleKind::ArkTs,
            endianness: Endianness::Little,
            flags: FileFlags::default(),
            checksum: 0,
            file_size: 0,
            section_count: 0,
            reserved: 0,
        }
    }
}
