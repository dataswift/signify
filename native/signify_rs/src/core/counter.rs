/// Counter - Attachment counter for CESR encoded groups
///
/// Counter provides count encoding for grouped attachments in KERI events.
/// Used to specify how many items follow in a particular attachment group.
use crate::error::{Result, SignifyError};
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Counter codes for different attachment types
pub struct CounterCodex;

impl CounterCodex {
    pub const CONTROLLER_IDX_SIGS: &'static str = "-A"; // Controller indexed signatures
    pub const WITNESS_IDX_SIGS: &'static str = "-B"; // Witness indexed signatures
    pub const NON_TRANS_RCT: &'static str = "-C"; // Non-transferable receipt couples
    pub const TRANS_RCT: &'static str = "-D"; // Transferable receipt quadruples
    pub const FIRST_SEEN_RPY: &'static str = "-E"; // First seen replay couples
    pub const TRANS_IDX_SIG_GROUPS: &'static str = "-F"; // Transferable indexed sig groups
    pub const SEAL_SOURCE_COUPLES: &'static str = "-G"; // Seal source couples
    pub const TRANS_LAST_IDX_SIG_GROUPS: &'static str = "-H"; // Trans last indexed sig groups
    pub const SEAL_SOURCE_TRIPLES: &'static str = "-I"; // Seal source triples
    pub const SAD_PATH_SIG: &'static str = "-J"; // SAD path signature
    pub const SAD_PATH_SIG_GROUP: &'static str = "-K"; // SAD path signature group
    pub const PATHED_MATERIAL_QUADLETS: &'static str = "-L"; // Pathed material quadlets
    pub const ATTACHED_MATERIAL_QUADLETS: &'static str = "-V"; // Attached material quadlets
    pub const BIG_ATTACHED_MATERIAL_QUADLETS: &'static str = "-0V"; // Big attached quadlets
    pub const KERI_PROTOCOL_STACK: &'static str = "--AAA"; // KERI protocol stack version

    /// Check if code is valid
    pub fn is_valid(code: &str) -> bool {
        COUNTER_SIZES.contains_key(code)
    }
}

#[derive(Debug, Clone)]
pub struct CounterSizage {
    pub hs: usize, // Hard size (code length)
    pub ss: usize, // Soft size (count length)
    pub fs: usize, // Full size (total length)
}

/// Size table for counter codes
static COUNTER_SIZES: Lazy<HashMap<&'static str, CounterSizage>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Standard 2-char codes with 2-char count (fs=4)
    m.insert(
        "-A",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-B",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-C",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-D",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-E",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-F",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-G",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-H",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-I",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-J",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-K",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-L",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );
    m.insert(
        "-V",
        CounterSizage {
            hs: 2,
            ss: 2,
            fs: 4,
        },
    );

    // Big counter (3-char code + 5-char count = 8)
    m.insert(
        "-0V",
        CounterSizage {
            hs: 3,
            ss: 5,
            fs: 8,
        },
    );

    // Protocol stack version (5-char code + 3-char version = 8)
    m.insert(
        "--AAA",
        CounterSizage {
            hs: 5,
            ss: 3,
            fs: 8,
        },
    );

    m
});

fn counter_sizage(code: &str) -> Option<&CounterSizage> {
    COUNTER_SIZES.get(code)
}

/// Counter for attachment groups
pub struct Counter {
    code: String,
    count: u32,
}

impl Counter {
    /// Create new Counter with code and count
    pub fn new(code: &str, count: u32) -> Result<Self> {
        if !CounterCodex::is_valid(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid counter code: {}",
                code
            )));
        }

        let sizage = counter_sizage(code).unwrap();

        // Validate count range
        let max_count = 64_u32.pow(sizage.ss as u32) - 1;
        if count > max_count {
            return Err(SignifyError::InvalidIndex(format!(
                "Count {} exceeds maximum {} for code {}",
                count, max_count, code
            )));
        }

        Ok(Self {
            code: code.to_string(),
            count,
        })
    }

    /// Create Counter from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        if qb64.is_empty() {
            return Err(SignifyError::InvalidFormat("Empty qb64 string".to_string()));
        }

        // Extract code - counters start with '-'
        let code = if qb64.starts_with("--") {
            // 5-char code
            if qb64.len() < 5 {
                return Err(SignifyError::InvalidFormat(
                    "qb64 too short for -- code".to_string(),
                ));
            }
            &qb64[0..5]
        } else if qb64.starts_with("-0") {
            // 3-char code
            if qb64.len() < 3 {
                return Err(SignifyError::InvalidFormat(
                    "qb64 too short for -0 code".to_string(),
                ));
            }
            &qb64[0..3]
        } else if qb64.starts_with('-') {
            // 2-char code
            if qb64.len() < 2 {
                return Err(SignifyError::InvalidFormat(
                    "qb64 too short for - code".to_string(),
                ));
            }
            &qb64[0..2]
        } else {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid counter code prefix in: {}",
                qb64
            )));
        };

        if !CounterCodex::is_valid(code) {
            return Err(SignifyError::InvalidCode(format!(
                "Unknown counter code: {}",
                code
            )));
        }

        let sizage = counter_sizage(code).unwrap();

        if qb64.len() < sizage.fs {
            return Err(SignifyError::InvalidFormat(format!(
                "qb64 too short: {} < {}",
                qb64.len(),
                sizage.fs
            )));
        }

        // Extract and decode count
        let count_str = &qb64[sizage.hs..sizage.fs];
        let count = b64_to_int(count_str)? as u32;

        Ok(Self {
            code: code.to_string(),
            count,
        })
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> String {
        let sizage = counter_sizage(&self.code).unwrap();
        let count_b64 = int_to_b64(self.count as usize, sizage.ss);
        format!("{}{}", self.code, count_b64)
    }

    /// Get code
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get count
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// Convert base64url string to integer
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
    fn test_counter_basic() {
        let counter = Counter::new(CounterCodex::CONTROLLER_IDX_SIGS, 5).unwrap();
        assert_eq!(counter.code(), CounterCodex::CONTROLLER_IDX_SIGS);
        assert_eq!(counter.count(), 5);
    }

    #[test]
    fn test_counter_qb64() {
        let counter = Counter::new(CounterCodex::WITNESS_IDX_SIGS, 10).unwrap();
        let qb64 = counter.qb64();

        assert!(qb64.starts_with("-B"));
        assert_eq!(qb64.len(), 4);

        let counter2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(counter.code(), counter2.code());
        assert_eq!(counter.count(), counter2.count());
    }

    #[test]
    fn test_counter_max_count() {
        // Standard counter: 2 char count = 64^2 - 1 = 4095 max
        let counter = Counter::new(CounterCodex::CONTROLLER_IDX_SIGS, 4095).unwrap();
        assert_eq!(counter.count(), 4095);

        // Exceeding max should fail
        let result = Counter::new(CounterCodex::CONTROLLER_IDX_SIGS, 4096);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_big() {
        // Big counter: 5 char count = 64^5 - 1 max
        let counter = Counter::new(CounterCodex::BIG_ATTACHED_MATERIAL_QUADLETS, 1000000).unwrap();
        assert_eq!(counter.count(), 1000000);

        let qb64 = counter.qb64();
        assert!(qb64.starts_with("-0V"));
        assert_eq!(qb64.len(), 8);

        let counter2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(counter.count(), counter2.count());
    }

    #[test]
    fn test_counter_protocol_stack() {
        let counter = Counter::new(CounterCodex::KERI_PROTOCOL_STACK, 100).unwrap();
        let qb64 = counter.qb64();
        assert!(qb64.starts_with("--AAA"));
        assert_eq!(qb64.len(), 8);
    }

    #[test]
    fn test_counter_invalid_code() {
        let result = Counter::new("-Z", 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_from_qb64_invalid() {
        let result = Counter::from_qb64("invalid");
        assert!(result.is_err());

        let result = Counter::from_qb64("-X");
        assert!(result.is_err());
    }

    #[test]
    fn test_b64_conversions() {
        assert_eq!(b64_to_int("A").unwrap(), 0);
        assert_eq!(b64_to_int("B").unwrap(), 1);
        assert_eq!(b64_to_int("_").unwrap(), 63);
        assert_eq!(b64_to_int("BA").unwrap(), 64);

        assert_eq!(int_to_b64(0, 1), "A");
        assert_eq!(int_to_b64(1, 1), "B");
        assert_eq!(int_to_b64(63, 1), "_");
        assert_eq!(int_to_b64(64, 2), "BA");
        assert_eq!(int_to_b64(4095, 2), "__"); // Max for 2 chars
    }
}
