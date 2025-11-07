use crate::core::{matter_codes, Matter, MatterOpts};
/// Diger - Cryptographic digest operations with CESR encoding
use crate::error::{Result, SignifyError};
use blake3;
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

#[allow(unused_imports)]
use sha3::Digest as _;

/// Diger handles cryptographic digests (hashes) with CESR encoding
#[derive(Debug, Clone)]
pub struct Diger {
    matter: Matter,
}

impl Diger {
    /// Create Diger from raw digest bytes
    pub fn from_raw(raw: &[u8], code: &str) -> Result<Self> {
        let matter = Matter::from_raw(raw, code)?;
        Ok(Self { matter })
    }

    /// Create Diger from qb64 string
    pub fn from_qb64(qb64: &str) -> Result<Self> {
        let matter = Matter::from_qb64(qb64)?;
        Ok(Self { matter })
    }

    /// Create Diger by computing digest of serialization
    ///
    /// # Arguments
    /// * `code` - CESR code indicating hash algorithm (e.g., "E" for Blake3-256)
    /// * `ser` - Serialization bytes to hash
    pub fn new(code: &str, ser: &[u8]) -> Result<Self> {
        let digest = Self::compute_digest(code, ser)?;
        Self::from_raw(&digest, code)
    }

    /// Create Diger with optional serialization
    /// If ser is None, code and raw must be provided via MatterOpts
    pub fn with_opts(opts: MatterOpts, ser: Option<&[u8]>) -> Result<Self> {
        if let Some(ser_data) = ser {
            // Compute digest from serialization
            let code = opts.code.ok_or(SignifyError::InvalidCode(
                "Code required for digest computation".to_string(),
            ))?;
            Self::new(&code, ser_data)
        } else {
            // Create from existing digest
            let matter = Matter::new(opts)?;
            Ok(Self { matter })
        }
    }

    /// Compute raw digest bytes for given algorithm
    fn compute_digest(code: &str, ser: &[u8]) -> Result<Vec<u8>> {
        match code {
            matter_codes::BLAKE3_256 => {
                let hash = blake3::hash(ser);
                Ok(hash.as_bytes().to_vec())
            }
            matter_codes::BLAKE3_512 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(ser);
                let hash = hasher.finalize();
                Ok(hash.as_bytes()[..64].to_vec())
            }
            matter_codes::SHA2_256 => {
                let mut hasher = Sha256::new();
                hasher.update(ser);
                Ok(hasher.finalize().to_vec())
            }
            matter_codes::SHA2_512 => {
                let mut hasher = Sha512::new();
                hasher.update(ser);
                Ok(hasher.finalize().to_vec())
            }
            matter_codes::SHA3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(ser);
                Ok(hasher.finalize().to_vec())
            }
            matter_codes::SHA3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(ser);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(SignifyError::UnsupportedAlgorithm(format!(
                "Unsupported digest code: {}",
                code
            ))),
        }
    }

    /// Verify that this digest matches the given serialization
    pub fn verify(&self, ser: &[u8]) -> Result<bool> {
        let computed = Self::new(self.matter.code(), ser)?;
        Ok(computed.matter.raw() == self.matter.raw())
    }

    /// Compare with another digest or diger
    /// Returns true if digests match (even if codes differ but both verify same data)
    pub fn compare(&self, ser: &[u8], other: &Diger) -> Result<bool> {
        // If codes match, just compare raw bytes
        if self.matter.code() == other.matter.code() {
            return Ok(self.matter.raw() == other.matter.raw());
        }

        // Different codes - verify both match the serialization
        Ok(self.verify(ser)? && other.verify(ser)?)
    }

    /// Get the underlying Matter representation
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get CESR code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Get raw digest bytes
    pub fn raw(&self) -> &[u8] {
        self.matter.raw()
    }

    /// Get qb64 encoding
    pub fn qb64(&self) -> &str {
        self.matter.qb64()
    }

    /// Get qb64 as bytes
    pub fn qb64b(&self) -> &[u8] {
        self.matter.qb64b()
    }

    /// Get qb2 binary encoding
    pub fn qb2(&self) -> &[u8] {
        self.matter.qb2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diger_blake3_256() {
        let data = b"test data for hashing";
        let diger = Diger::new(matter_codes::BLAKE3_256, data).unwrap();

        assert_eq!(diger.code(), matter_codes::BLAKE3_256);
        assert_eq!(diger.raw().len(), 32); // 256 bits = 32 bytes
        assert!(diger.qb64().starts_with("E"));
        assert_eq!(diger.qb64().len(), 44);
        assert!(diger.verify(data).unwrap());

        // Wrong data should not verify
        let wrong_data = b"different data";
        assert!(!diger.verify(wrong_data).unwrap());
    }

    #[test]
    fn test_diger_sha2_256() {
        let data = b"SHA2 test data";
        let diger = Diger::new(matter_codes::SHA2_256, data).unwrap();

        assert_eq!(diger.code(), matter_codes::SHA2_256);
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_sha3_256() {
        let data = b"SHA3 test data";
        let diger = Diger::new(matter_codes::SHA3_256, data).unwrap();

        assert_eq!(diger.code(), matter_codes::SHA3_256);
        assert_eq!(diger.raw().len(), 32);
        assert!(diger.verify(data).unwrap());
    }

    #[test]
    fn test_diger_from_qb64() {
        let data = b"original data";
        let diger1 = Diger::new(matter_codes::BLAKE3_256, data).unwrap();
        let qb64 = diger1.qb64();

        let diger2 = Diger::from_qb64(qb64).unwrap();

        assert_eq!(diger1.raw(), diger2.raw());
        assert_eq!(diger1.code(), diger2.code());
        assert_eq!(diger1.qb64(), diger2.qb64());
    }

    #[test]
    fn test_diger_compare_same_code() {
        let data = b"comparison test";
        let diger1 = Diger::new(matter_codes::BLAKE3_256, data).unwrap();
        let diger2 = Diger::new(matter_codes::BLAKE3_256, data).unwrap();

        assert!(diger1.compare(data, &diger2).unwrap());
    }

    #[test]
    fn test_diger_compare_different_codes() {
        let data = b"multi-algorithm test";
        let diger_blake3 = Diger::new(matter_codes::BLAKE3_256, data).unwrap();
        let diger_sha2 = Diger::new(matter_codes::SHA2_256, data).unwrap();

        // Different algorithms produce different hashes, but both should verify the data
        assert!(diger_blake3.verify(data).unwrap());
        assert!(diger_sha2.verify(data).unwrap());
        assert!(diger_blake3.compare(data, &diger_sha2).unwrap());
    }

    #[test]
    fn test_diger_empty_data() {
        let data = b"";
        let diger = Diger::new(matter_codes::BLAKE3_256, data).unwrap();

        assert!(diger.verify(data).unwrap());
        assert_eq!(diger.raw().len(), 32);
    }

    #[test]
    fn test_diger_large_data() {
        let data = vec![42u8; 1_000_000]; // 1MB of data
        let diger = Diger::new(matter_codes::BLAKE3_256, &data).unwrap();

        assert!(diger.verify(&data).unwrap());
    }

    #[test]
    fn test_diger_unsupported_code() {
        let data = b"test";
        let result = Diger::new("INVALID", data);
        assert!(result.is_err());
    }
}
