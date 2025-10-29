use std::error::Error as StdError;
use std::fmt;
use std::io;

/// Result alias for operations that may produce an [`ArkError`].
pub type ArkResult<T> = Result<T, ArkError>;

/// Errors that can occur while reading or writing Ark bytecode artifacts.
#[derive(Debug)]
pub enum ArkError {
    /// Wrapper around [`io::Error`] for filesystem and stream operations.
    Io(io::Error),
    /// The file did not start with the expected magic bytes.
    InvalidMagic { expected: Vec<u8>, found: Vec<u8> },
    /// The stream terminated before enough bytes could be read.
    UnexpectedEof { offset: usize, expected: usize },
    /// The file declared a version that is not supported yet.
    UnsupportedVersion { version: [u8; 4] },
    /// Any other format violation detected while decoding the file.
    Format(String),
}

impl ArkError {
    /// Creates a new [`ArkError::Format`] with the provided message.
    pub fn format(message: impl Into<String>) -> Self {
        ArkError::Format(message.into())
    }
}

impl fmt::Display for ArkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArkError::Io(err) => write!(f, "IO error: {err}"),
            ArkError::InvalidMagic { expected, found } => write!(
                f,
                "invalid magic bytes: expected {expected:02x?}, found {found:02x?}"
            ),
            ArkError::UnexpectedEof { offset, expected } => write!(
                f,
                "unexpected end of file at byte {offset}, expected {expected} more"
            ),
            ArkError::UnsupportedVersion { version } => {
                write!(f, "unsupported abc version: {version:02x?}")
            }
            ArkError::Format(message) => write!(f, "format error: {message}"),
        }
    }
}

impl StdError for ArkError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ArkError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ArkError {
    fn from(value: io::Error) -> Self {
        ArkError::Io(value)
    }
}
