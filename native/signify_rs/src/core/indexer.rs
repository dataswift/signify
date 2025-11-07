/// Indexer - Indexed signature material with dual index encoding
///
/// Indexer provides CESR encoding for indexed signatures used in KERI events.
/// It encodes both a signature index and an optional ondex (other index) for
/// multi-signature scenarios.
///
/// Index encoding:
/// - Small codes (1 char): support index 0-63 (6 bits)
/// - Big codes (2 char): support index 0-16383 (14 bits + 2 bits for ondex)
///
/// Current vs Both:
/// - Current (Crt): signature appears only in current event
/// - Both (Bth): signature appears in both current and prior events
use crate::error::{Result, SignifyError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// Indexer size table
use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IndexerSizage {
    pub hs: usize, // Hard size (code length)
    pub ss: usize, // Soft size (index length)
    pub fs: usize, // Full size (total qb64 length)
}

/// Size table for indexed signature codes
static INDEXER_SIZES: Lazy<HashMap<&'static str, IndexerSizage>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Small indexed signatures (1 char code + 1 char index)
    // 64-byte signature = 86 base64 chars + 1 code + 1 index = 88 total
    m.insert(
        "A",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );
    m.insert(
        "B",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );
    m.insert(
        "C",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );
    m.insert(
        "D",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );
    m.insert(
        "E",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );
    m.insert(
        "F",
        IndexerSizage {
            hs: 1,
            ss: 1,
            fs: 88,
        },
    );

    // Medium indexed signatures (2 char code + 2 char index)
    m.insert(
        "0A",
        IndexerSizage {
            hs: 2,
            ss: 2,
            fs: 156,
        },
    );
    m.insert(
        "0B",
        IndexerSizage {
            hs: 2,
            ss: 2,
            fs: 156,
        },
    );

    // Big indexed signatures (2 char code + 4 char dual index)
    m.insert(
        "2A",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "2B",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "2C",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "2D",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "2E",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "2F",
        IndexerSizage {
            hs: 2,
            ss: 4,
            fs: 92,
        },
    );
    m.insert(
        "3A",
        IndexerSizage {
            hs: 2,
            ss: 6,
            fs: 160,
        },
    );
    m.insert(
        "3B",
        IndexerSizage {
            hs: 2,
            ss: 6,
            fs: 160,
        },
    );

    m
});

fn indexer_sizage(code: &str) -> Option<&IndexerSizage> {
    INDEXER_SIZES.get(code)
}

/// Indexer codes for different signature types and sizes
pub struct IndexerCodex;

impl IndexerCodex {
    // Small codes (1 char, index 0-63)
    pub const ED25519_SIG: &'static str = "A"; // Ed25519 sig in both lists
    pub const ED25519_CRT_SIG: &'static str = "B"; // Ed25519 sig in current only
    pub const ECDSA_256K1_SIG: &'static str = "C"; // ECDSA secp256k1 in both
    pub const ECDSA_256K1_CRT_SIG: &'static str = "D"; // ECDSA secp256k1 current only
    pub const ECDSA_256R1_SIG: &'static str = "E"; // ECDSA secp256r1 in both
    pub const ECDSA_256R1_CRT_SIG: &'static str = "F"; // ECDSA secp256r1 current only

    // Medium codes (2 char, Ed448)
    pub const ED448_SIG: &'static str = "0A"; // Ed448 sig in both lists
    pub const ED448_CRT_SIG: &'static str = "0B"; // Ed448 sig in current only

    // Big codes (2 char, index 0-16383)
    pub const ED25519_BIG_SIG: &'static str = "2A"; // Ed25519 big in both
    pub const ED25519_BIG_CRT_SIG: &'static str = "2B"; // Ed25519 big current only
    pub const ECDSA_256K1_BIG_SIG: &'static str = "2C"; // ECDSA secp256k1 big both
    pub const ECDSA_256K1_BIG_CRT_SIG: &'static str = "2D"; // ECDSA secp256k1 big current
    pub const ECDSA_256R1_BIG_SIG: &'static str = "2E"; // ECDSA secp256r1 big both
    pub const ECDSA_256R1_BIG_CRT_SIG: &'static str = "2F"; // ECDSA secp256r1 big current
    pub const ED448_BIG_SIG: &'static str = "3A"; // Ed448 big both
    pub const ED448_BIG_CRT_SIG: &'static str = "3B"; // Ed448 big current only

    /// Check if code is a valid indexed signature code
    pub fn is_valid(code: &str) -> bool {
        matches!(
            code,
            "A" | "B"
                | "C"
                | "D"
                | "E"
                | "F"
                | "0A"
                | "0B"
                | "2A"
                | "2B"
                | "2C"
                | "2D"
                | "2E"
                | "2F"
                | "3A"
                | "3B"
        )
    }

    /// Check if code is a "current only" signature
    pub fn is_current_only(code: &str) -> bool {
        matches!(code, "B" | "D" | "F" | "0B" | "2B" | "2D" | "2F" | "3B")
    }

    /// Check if code is a "both" signature
    pub fn is_both(code: &str) -> bool {
        matches!(code, "A" | "C" | "E" | "0A" | "2A" | "2C" | "2E" | "3A")
    }

    /// Check if code supports big indices (> 63)
    pub fn is_big(code: &str) -> bool {
        matches!(code, "2A" | "2B" | "2C" | "2D" | "2E" | "2F" | "3A" | "3B")
    }
}

/// Indexed signature primitive
pub struct Indexer {
    raw: Vec<u8>, // raw signature bytes
    code: String, // CESR code
    index: u32,   // signature index
    ondex: u32,   // other index (for dual indexing)
}

impl Indexer {
    /// Create new Indexer from raw signature and indices
    pub fn new(raw: &[u8], code: &str, index: u32, ondex: Option<u32>) -> Result<Self> {
        if !IndexerCodex::is_valid(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid indexer code: {}",
                code
            )));
        }

        // Get size info for this indexer code
        let _sizage = indexer_sizage(code)
            .ok_or_else(|| SignifyError::InvalidCode(format!("Unknown indexer code: {}", code)))?;

        // Validate raw signature size (should be 64 bytes for Ed25519, 114 for Ed448, etc.)
        // For now, we accept any size since different signature algorithms have different sizes
        // The qb64 encoding will handle the size properly

        // Validate index range based on code
        if IndexerCodex::is_big(code) {
            if index > 16383 {
                return Err(SignifyError::InvalidIndex(format!(
                    "Index {} exceeds maximum 16383 for big codes",
                    index
                )));
            }
        } else if index > 63 {
            return Err(SignifyError::InvalidIndex(format!(
                "Index {} exceeds maximum 63 for small codes",
                index
            )));
        }

        // Default ondex to index if not provided
        let ondex = ondex.unwrap_or(index);

        // Validate ondex
        if IndexerCodex::is_big(code) {
            if ondex > 16383 {
                return Err(SignifyError::InvalidIndex(format!(
                    "Ondex {} exceeds maximum 16383 for big codes",
                    ondex
                )));
            }
        } else if ondex > 63 {
            return Err(SignifyError::InvalidIndex(format!(
                "Ondex {} exceeds maximum 63 for small codes",
                ondex
            )));
        }

        Ok(Self {
            raw: raw.to_vec(),
            code: code.to_string(),
            index,
            ondex,
        })
    }

    /// Create Indexer from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        // Extract code
        let code = if qb64.len() >= 2 && qb64.starts_with(|c: char| c.is_ascii_digit()) {
            &qb64[0..2]
        } else if !qb64.is_empty() {
            &qb64[0..1]
        } else {
            return Err(SignifyError::InvalidFormat("Empty qb64 string".to_string()));
        };

        if !IndexerCodex::is_valid(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid indexer code in qb64: {}",
                code
            )));
        }

        // Get size info from indexer size table
        let sizage = indexer_sizage(code)
            .ok_or_else(|| SignifyError::InvalidCode(format!("Unknown indexer code: {}", code)))?;

        let hs = sizage.hs;
        let ss = sizage.ss;
        let fs = sizage.fs;

        if qb64.len() < fs {
            return Err(SignifyError::InvalidFormat(format!(
                "qb64 string too short: {} < {}",
                qb64.len(),
                fs
            )));
        }

        // Extract index from qb64
        // For small codes: 1 char code + 1 char index (6 bits)
        // For big codes: 2 char code + 4 chars index (2 + 2)
        let (index, ondex) = if IndexerCodex::is_big(code) {
            // Big codes use 2 chars for code + 4 chars for indices
            let index_str = &qb64[hs..hs + 2];
            let ondex_str = &qb64[hs + 2..hs + 4];
            let index = b64_to_int(index_str)? as u32;
            let ondex = b64_to_int(ondex_str)? as u32;
            (index, ondex)
        } else {
            // Small codes use 1 char for index (6 bits)
            let index_char = &qb64[hs..hs + 1];
            let index = b64_to_int(index_char)? as u32;
            (index, index) // ondex = index for small codes
        };

        // Decode signature bytes from qb64
        let sig_part = &qb64[hs + ss..];
        let raw = URL_SAFE_NO_PAD
            .decode(sig_part)
            .map_err(|e| SignifyError::InvalidCesr(format!("Failed to decode signature: {}", e)))?;

        Ok(Self {
            raw,
            code: code.to_string(),
            index,
            ondex,
        })
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> String {
        let sizage = indexer_sizage(&self.code).unwrap();
        let hs = sizage.hs;
        let ss = sizage.ss;

        // Encode signature bytes to base64
        let sig_b64 = URL_SAFE_NO_PAD.encode(&self.raw);

        // Build qb64 string: code + index(es) + signature
        if IndexerCodex::is_big(&self.code) {
            // Big codes: 2 char code + 4 chars dual index + signature
            let index_b64 = int_to_b64(self.index as usize, 2);
            let ondex_b64 = int_to_b64(self.ondex as usize, 2);
            format!("{}{}{}{}", self.code, index_b64, ondex_b64, sig_b64)
        } else {
            // Small codes: 1 char code + 1 char index + signature
            let index_b64 = int_to_b64(self.index as usize, 1);
            format!("{}{}{}", self.code, index_b64, sig_b64)
        }
    }

    /// Get signature index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get other index
    pub fn ondex(&self) -> u32 {
        self.ondex
    }

    /// Get code
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get raw signature bytes
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

/// Convert base64url character(s) to integer
fn b64_to_int(s: &str) -> Result<usize> {
    let bytes = s.as_bytes();
    let mut result = 0usize;

    for &b in bytes {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as usize,
            b'a'..=b'z' => (b - b'a' + 26) as usize,
            b'0'..=b'9' => (b - b'0' + 52) as usize,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(SignifyError::InvalidFormat(format!(
                    "Invalid base64url character: {}",
                    b as char
                )))
            }
        };
        result = (result << 6) | val;
    }

    Ok(result)
}

/// Convert integer to base64url string of specified length
fn int_to_b64(mut n: usize, len: usize) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = Vec::with_capacity(len);

    for _ in 0..len {
        result.push(CHARS[n & 0x3f]);
        n >>= 6;
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_small_code() {
        let sig = vec![0u8; 64];
        let indexer = Indexer::new(&sig, IndexerCodex::ED25519_SIG, 5, None).unwrap();

        assert_eq!(indexer.index(), 5);
        assert_eq!(indexer.ondex(), 5);
        assert_eq!(indexer.code(), IndexerCodex::ED25519_SIG);
    }

    #[test]
    fn test_indexer_big_code() {
        let sig = vec![0u8; 64];
        let indexer = Indexer::new(&sig, IndexerCodex::ED25519_BIG_SIG, 100, Some(200)).unwrap();

        assert_eq!(indexer.index(), 100);
        assert_eq!(indexer.ondex(), 200);
        assert_eq!(indexer.code(), IndexerCodex::ED25519_BIG_SIG);
    }

    #[test]
    fn test_indexer_invalid_index() {
        let sig = vec![0u8; 64];

        // Small code with index > 63 should fail
        let result = Indexer::new(&sig, IndexerCodex::ED25519_SIG, 64, None);
        assert!(result.is_err());

        // Big code with index > 16383 should fail
        let result = Indexer::new(&sig, IndexerCodex::ED25519_BIG_SIG, 16384, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_indexer_qb64_roundtrip() {
        let sig = vec![1u8; 64];
        let indexer = Indexer::new(&sig, IndexerCodex::ED25519_SIG, 10, None).unwrap();

        let qb64 = indexer.qb64();
        let indexer2 = Indexer::from_qb64(&qb64).unwrap();

        assert_eq!(indexer.index(), indexer2.index());
        assert_eq!(indexer.code(), indexer2.code());
        assert_eq!(indexer.raw(), indexer2.raw());
    }

    #[test]
    fn test_b64_to_int() {
        assert_eq!(b64_to_int("A").unwrap(), 0);
        assert_eq!(b64_to_int("B").unwrap(), 1);
        assert_eq!(b64_to_int("_").unwrap(), 63);
        assert_eq!(b64_to_int("AA").unwrap(), 0);
        assert_eq!(b64_to_int("AB").unwrap(), 1);
    }

    #[test]
    fn test_int_to_b64() {
        assert_eq!(int_to_b64(0, 1), "A");
        assert_eq!(int_to_b64(1, 1), "B");
        assert_eq!(int_to_b64(63, 1), "_");
        assert_eq!(int_to_b64(64, 2), "BA");
    }

    #[test]
    fn test_indexer_codex_checks() {
        assert!(IndexerCodex::is_valid("A"));
        assert!(IndexerCodex::is_valid("2A"));
        assert!(!IndexerCodex::is_valid("Z"));

        assert!(IndexerCodex::is_current_only("B"));
        assert!(!IndexerCodex::is_current_only("A"));

        assert!(IndexerCodex::is_both("A"));
        assert!(!IndexerCodex::is_both("B"));

        assert!(IndexerCodex::is_big("2A"));
        assert!(!IndexerCodex::is_big("A"));
    }
}
