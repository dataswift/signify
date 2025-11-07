/// Error types for Signify operations
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignifyError {
    #[error("Empty material error: {0}")]
    EmptyMaterial(String),

    #[error("Invalid code: {0}")]
    InvalidCode(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    #[error("Invalid CESR encoding: {0}")]
    InvalidCesr(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("Invalid event: {0}")]
    InvalidEvent(String),

    #[error("Invalid index: {0}")]
    InvalidIndex(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    HttpError(String),

    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SignifyError>;

// Implement From for common error types
impl From<String> for SignifyError {
    fn from(s: String) -> Self {
        SignifyError::Other(s)
    }
}

impl From<&str> for SignifyError {
    fn from(s: &str) -> Self {
        SignifyError::Other(s.to_string())
    }
}

impl From<reqwest::Error> for SignifyError {
    fn from(e: reqwest::Error) -> Self {
        SignifyError::HttpError(e.to_string())
    }
}

impl From<argon2::Error> for SignifyError {
    fn from(e: argon2::Error) -> Self {
        SignifyError::Argon2Error(e.to_string())
    }
}
