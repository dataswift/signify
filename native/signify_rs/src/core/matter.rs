use crate::core::codes::{extract_code, raw_size, sizage};
/// Matter - Base class for all CESR primitives
use crate::error::{Result, SignifyError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Matter is the base class for all CESR (Composable Event Streaming Representation) primitives.
/// It handles encoding/decoding between raw bytes, qb64 (qualified base64), and qb2 (binary).
#[derive(Debug, Clone)]
pub struct Matter {
    /// CESR code identifying the primitive type
    code: String,
    /// Raw binary data
    raw: Vec<u8>,
    /// Qualified base64 encoding (code + base64 data)
    qb64: String,
    /// Qualified base64 as bytes
    qb64b: Vec<u8>,
    /// Binary encoding (code + raw data)
    qb2: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MatterOpts {
    pub raw: Option<Vec<u8>>,
    pub code: Option<String>,
    pub qb64: Option<String>,
    pub qb64b: Option<Vec<u8>>,
    pub qb2: Option<Vec<u8>>,
}

impl Matter {
    /// Create a new Matter from various input formats
    pub fn new(opts: MatterOpts) -> Result<Self> {
        // Priority: qb64 > qb64b > qb2 > raw
        if let Some(qb64) = opts.qb64 {
            Self::from_qb64(&qb64)
        } else if let Some(qb64b) = opts.qb64b {
            let qb64 = String::from_utf8(qb64b)
                .map_err(|e| SignifyError::InvalidCesr(format!("Invalid UTF-8 in qb64b: {}", e)))?;
            Self::from_qb64(&qb64)
        } else if let Some(qb2) = opts.qb2 {
            Self::from_qb2(&qb2)
        } else if let Some(raw) = opts.raw {
            let code = opts.code.ok_or(SignifyError::InvalidCode(
                "Code required with raw".to_string(),
            ))?;
            Self::from_raw(&raw, &code)
        } else {
            Err(SignifyError::EmptyMaterial(
                "No material provided".to_string(),
            ))
        }
    }

    /// Create Matter from raw bytes and code
    pub fn from_raw(raw: &[u8], code: &str) -> Result<Self> {
        // Validate code
        let _sz = sizage(code)?;
        let expected_size = raw_size(code)?;

        if raw.len() != expected_size {
            return Err(SignifyError::InvalidSize {
                expected: expected_size,
                actual: raw.len(),
            });
        }

        // Encode to base64
        let b64 = URL_SAFE_NO_PAD.encode(raw);
        let qb64 = format!("{}{}", code, b64);
        let qb64b = qb64.as_bytes().to_vec();

        // Create qb2 (binary encoding)
        let mut qb2 = code.as_bytes().to_vec();
        qb2.extend_from_slice(raw);

        Ok(Self {
            code: code.to_string(),
            raw: raw.to_vec(),
            qb64,
            qb64b,
            qb2,
        })
    }

    /// Create Matter from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        if qb64.is_empty() {
            return Err(SignifyError::InvalidCesr("Empty qb64 string".to_string()));
        }

        // Extract code
        let code = extract_code(qb64)?;
        let sz = sizage(&code)?;

        // Validate length
        if let Some(fs) = sz.fs {
            if qb64.len() != fs {
                return Err(SignifyError::InvalidSize {
                    expected: fs,
                    actual: qb64.len(),
                });
            }
        }

        // Extract and decode data
        let b64_data = &qb64[sz.hs..];
        let raw = URL_SAFE_NO_PAD
            .decode(b64_data)
            .map_err(|e| SignifyError::Base64Error(e))?;

        // Verify raw size
        let expected_raw_size = raw_size(&code)?;
        if raw.len() != expected_raw_size {
            return Err(SignifyError::InvalidSize {
                expected: expected_raw_size,
                actual: raw.len(),
            });
        }

        let qb64b = qb64.as_bytes().to_vec();

        // Create qb2
        let mut qb2 = code.as_bytes().to_vec();
        qb2.extend_from_slice(&raw);

        Ok(Self {
            code,
            raw,
            qb64: qb64.to_string(),
            qb64b,
            qb2,
        })
    }

    /// Create Matter from qb2 (binary encoding)
    pub fn from_qb2(qb2: &[u8]) -> Result<Self> {
        if qb2.is_empty() {
            return Err(SignifyError::InvalidCesr("Empty qb2".to_string()));
        }

        // Extract code
        let code_str = String::from_utf8_lossy(&qb2[..std::cmp::min(4, qb2.len())]);
        let code = extract_code(&code_str)?;
        let sz = sizage(&code)?;

        // Extract raw data
        let raw = qb2[sz.hs..].to_vec();

        // Verify size
        let expected_raw_size = raw_size(&code)?;
        if raw.len() != expected_raw_size {
            return Err(SignifyError::InvalidSize {
                expected: expected_raw_size,
                actual: raw.len(),
            });
        }

        // Encode to qb64
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        let qb64 = format!("{}{}", code, b64);
        let qb64b = qb64.as_bytes().to_vec();

        Ok(Self {
            code,
            raw,
            qb64,
            qb64b,
            qb2: qb2.to_vec(),
        })
    }

    /// Get the CESR code
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get the raw binary data
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Get the qb64 string
    pub fn qb64(&self) -> &str {
        &self.qb64
    }

    /// Get the qb64 as bytes
    pub fn qb64b(&self) -> &[u8] {
        &self.qb64b
    }

    /// Get the qb2 binary encoding
    pub fn qb2(&self) -> &[u8] {
        &self.qb2
    }

    /// Convert to qb64 string (convenience method)
    pub fn to_qb64(&self) -> String {
        self.qb64.clone()
    }

    /// Convert to qb2 binary (convenience method)
    pub fn to_qb2(&self) -> Vec<u8> {
        self.qb2.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::codes::matter_codes;

    #[test]
    fn test_matter_from_raw() {
        let raw = vec![0u8; 32]; // 32 zero bytes
        let matter = Matter::from_raw(&raw, matter_codes::ED25519_SEED).unwrap();

        assert_eq!(matter.code(), matter_codes::ED25519_SEED);
        assert_eq!(matter.raw().len(), 32);
        assert!(matter.qb64().starts_with("A"));
        assert_eq!(matter.qb64().len(), 44);
    }

    #[test]
    fn test_matter_from_qb64() {
        // Known Ed25519 seed in qb64 format (44 chars: 1 char code + 43 chars data)
        let qb64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let matter = Matter::from_qb64(qb64).unwrap();

        assert_eq!(matter.code(), matter_codes::ED25519_SEED);
        assert_eq!(matter.raw().len(), 32);
        assert_eq!(matter.qb64(), qb64);
    }

    #[test]
    fn test_matter_roundtrip() {
        let raw = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let matter1 = Matter::from_raw(&raw, matter_codes::ED25519_SEED).unwrap();
        let qb64 = matter1.qb64();
        let matter2 = Matter::from_qb64(qb64).unwrap();

        assert_eq!(matter1.raw(), matter2.raw());
        assert_eq!(matter1.code(), matter2.code());
        assert_eq!(matter1.qb64(), matter2.qb64());
    }

    #[test]
    fn test_matter_qb2_roundtrip() {
        let raw = vec![255u8; 32];
        let matter1 = Matter::from_raw(&raw, matter_codes::ED25519_SEED).unwrap();
        let qb2 = matter1.qb2();
        let matter2 = Matter::from_qb2(qb2).unwrap();

        assert_eq!(matter1.raw(), matter2.raw());
        assert_eq!(matter1.code(), matter2.code());
    }

    #[test]
    fn test_matter_different_codes() {
        // Test Ed25519 seed
        let seed = vec![42u8; 32];
        let m1 = Matter::from_raw(&seed, matter_codes::ED25519_SEED).unwrap();
        assert_eq!(m1.qb64().len(), 44);

        // Test Ed25519 signature
        let sig = vec![42u8; 64];
        let m2 = Matter::from_raw(&sig, matter_codes::ED25519_SIG).unwrap();
        assert_eq!(m2.qb64().len(), 88);

        // Test Salt_128
        let salt = vec![42u8; 16];
        let m3 = Matter::from_raw(&salt, matter_codes::SALT_128).unwrap();
        assert_eq!(m3.qb64().len(), 24);
    }

    #[test]
    fn test_matter_invalid_size() {
        let raw = vec![0u8; 16]; // Wrong size for Ed25519 seed (need 32)
        let result = Matter::from_raw(&raw, matter_codes::ED25519_SEED);
        assert!(result.is_err());
    }

    #[test]
    fn test_matter_empty_material() {
        let result = Matter::new(MatterOpts::default());
        assert!(result.is_err());
    }
}
