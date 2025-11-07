/// Seqner - Sequence number encoding for KERI events
///
/// Seqner provides fully qualified format for ordinal numbers such as sequence numbers
/// or first seen ordering numbers when provided as attached cryptographic material.
use crate::core::matter::Matter;
use crate::core::matter_codes;
use crate::error::{Result, SignifyError};

/// Seqner for sequence number encoding
///
/// Uses Matter code "0A" (Salt_128/Huge) for 16-byte sequence numbers.
/// Provides conversion between u128 sequence numbers and CESR encoding.
pub struct Seqner {
    matter: Matter,
}

impl Seqner {
    /// Create new Seqner from sequence number
    pub fn new(sn: u128) -> Result<Self> {
        // Convert sequence number to 16-byte big-endian representation
        let raw = sn.to_be_bytes();
        let matter = Matter::from_raw(&raw, matter_codes::SALT_128)?;
        Ok(Self { matter })
    }

    /// Create Seqner from hex string representation
    pub fn from_snh(snh: &str) -> Result<Self> {
        let sn = u128::from_str_radix(snh, 16).map_err(|e| {
            SignifyError::InvalidFormat(format!("Invalid hex sequence number: {}", e))
        })?;
        Self::new(sn)
    }

    /// Create Seqner from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;

        // Validate code
        if matter.code() != matter_codes::SALT_128 {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid code {} for Seqner, expected {}",
                matter.code(),
                matter_codes::SALT_128
            )));
        }

        Ok(Self { matter })
    }

    /// Create Seqner from qb2 bytes
    pub fn from_qb2(qb2: &[u8]) -> Result<Self> {
        let matter = Matter::from_qb2(qb2)?;

        // Validate code
        if matter.code() != matter_codes::SALT_128 {
            return Err(SignifyError::InvalidCode(format!(
                "Invalid code {} for Seqner, expected {}",
                matter.code(),
                matter_codes::SALT_128
            )));
        }

        Ok(Self { matter })
    }

    /// Get sequence number as u128
    pub fn sn(&self) -> u128 {
        // Convert 16-byte big-endian to u128
        let raw = self.matter.raw();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(raw);
        u128::from_be_bytes(bytes)
    }

    /// Get sequence number as hex string
    pub fn snh(&self) -> String {
        format!("{:x}", self.sn())
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    /// Get qb2 encoding
    pub fn qb2(&self) -> &[u8] {
        self.matter.qb2()
    }

    /// Get raw bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Get underlying Matter
    pub fn matter(&self) -> &Matter {
        &self.matter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seqner_zero() {
        let seqner = Seqner::new(0).unwrap();
        assert_eq!(seqner.sn(), 0);
        assert_eq!(seqner.snh(), "0");
        assert_eq!(seqner.code(), matter_codes::SALT_128);
    }

    #[test]
    fn test_seqner_basic() {
        let seqner = Seqner::new(42).unwrap();
        assert_eq!(seqner.sn(), 42);
        assert_eq!(seqner.snh(), "2a");
        assert_eq!(seqner.code(), matter_codes::SALT_128);
    }

    #[test]
    fn test_seqner_large_number() {
        let sn = 1_000_000_u128;
        let seqner = Seqner::new(sn).unwrap();
        assert_eq!(seqner.sn(), sn);
        assert_eq!(seqner.snh(), "f4240");
    }

    #[test]
    fn test_seqner_max_u64() {
        let sn = u64::MAX as u128;
        let seqner = Seqner::new(sn).unwrap();
        assert_eq!(seqner.sn(), sn);
        assert_eq!(seqner.snh(), "ffffffffffffffff");
    }

    #[test]
    fn test_seqner_from_snh() {
        let seqner = Seqner::from_snh("2a").unwrap();
        assert_eq!(seqner.sn(), 42);

        let seqner = Seqner::from_snh("f4240").unwrap();
        assert_eq!(seqner.sn(), 1_000_000);

        let seqner = Seqner::from_snh("0").unwrap();
        assert_eq!(seqner.sn(), 0);
    }

    #[test]
    fn test_seqner_from_snh_invalid() {
        let result = Seqner::from_snh("invalid");
        assert!(result.is_err());

        let result = Seqner::from_snh("zz");
        assert!(result.is_err());
    }

    #[test]
    fn test_seqner_qb64_roundtrip() {
        let seqner1 = Seqner::new(12345).unwrap();
        let qb64 = seqner1.qb64();

        let seqner2 = Seqner::from_qb64(qb64).unwrap();
        assert_eq!(seqner1.sn(), seqner2.sn());
        assert_eq!(seqner1.snh(), seqner2.snh());
        assert_eq!(seqner1.qb64(), seqner2.qb64());
    }

    #[test]
    fn test_seqner_qb2_roundtrip() {
        let seqner1 = Seqner::new(54321).unwrap();
        let qb2 = seqner1.qb2();

        let seqner2 = Seqner::from_qb2(qb2).unwrap();
        assert_eq!(seqner1.sn(), seqner2.sn());
        assert_eq!(seqner1.snh(), seqner2.snh());
    }

    #[test]
    fn test_seqner_invalid_code() {
        // Create matter with different code
        let raw = [0u8; 32];
        let matter = Matter::from_raw(&raw, matter_codes::ED25519_SEED).unwrap();
        let qb64 = matter.qb64();

        // Should fail when trying to parse as Seqner
        let result = Seqner::from_qb64(qb64);
        assert!(result.is_err());
    }

    #[test]
    fn test_seqner_sequence() {
        // Test incrementing sequence numbers like in KERI events
        for i in 0..10 {
            let seqner = Seqner::new(i).unwrap();
            assert_eq!(seqner.sn(), i);
            assert_eq!(seqner.snh(), format!("{:x}", i));
        }
    }

    #[test]
    fn test_seqner_hex_formats() {
        // Test various hex formats
        let seqner = Seqner::new(255).unwrap();
        assert_eq!(seqner.snh(), "ff");

        let seqner = Seqner::new(256).unwrap();
        assert_eq!(seqner.snh(), "100");

        let seqner = Seqner::new(4096).unwrap();
        assert_eq!(seqner.snh(), "1000");
    }

    #[test]
    fn test_seqner_raw_bytes() {
        let seqner = Seqner::new(42).unwrap();
        let raw = seqner.raw();
        assert_eq!(raw.len(), 16);

        // Should be big-endian: 42 = 0x2a in the last byte
        assert_eq!(raw[15], 0x2a);
        for i in 0..15 {
            assert_eq!(raw[i], 0);
        }
    }

    #[test]
    fn test_seqner_equality_through_different_constructors() {
        let sn = 99999_u128;

        let seqner1 = Seqner::new(sn).unwrap();
        let seqner2 = Seqner::from_snh(&format!("{:x}", sn)).unwrap();
        let seqner3 = Seqner::from_qb64(seqner1.qb64()).unwrap();
        let seqner4 = Seqner::from_qb2(seqner1.qb2()).unwrap();

        assert_eq!(seqner1.sn(), seqner2.sn());
        assert_eq!(seqner1.sn(), seqner3.sn());
        assert_eq!(seqner1.sn(), seqner4.sn());
        assert_eq!(seqner1.snh(), seqner2.snh());
        assert_eq!(seqner1.snh(), seqner3.snh());
        assert_eq!(seqner1.snh(), seqner4.snh());
    }
}
