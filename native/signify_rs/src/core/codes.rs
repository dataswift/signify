use once_cell::sync::Lazy;
/// CESR Code tables and size definitions
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Sizage {
    pub hs: usize,         // Hard size (code length)
    pub ss: usize,         // Soft size (length descriptor size)
    pub fs: Option<usize>, // Full size (total qb64 length)
    pub ls: usize,         // Lead size (raw size mod 3)
}

impl Sizage {
    pub fn new(hs: usize, ss: usize, fs: Option<usize>, ls: usize) -> Self {
        Self { hs, ss, fs, ls }
    }
}

/// Matter code definitions
pub mod matter_codes {
    pub const ED25519_SEED: &str = "A"; // Ed25519 256 bit seed
    pub const ED25519N: &str = "B"; // Ed25519 non-transferable key
    pub const X25519: &str = "C"; // X25519 public encryption key
    pub const ED25519: &str = "D"; // Ed25519 transferable key
    pub const BLAKE3_256: &str = "E"; // Blake3 256 bit digest
    pub const BLAKE2B_256: &str = "F"; // Blake2b 256 bit digest
    pub const BLAKE2S_256: &str = "G"; // Blake2s 256 bit digest
    pub const SHA3_256: &str = "H"; // SHA3 256 bit digest
    pub const SHA2_256: &str = "I"; // SHA2 256 bit digest
    pub const ECDSA_256K1_SEED: &str = "J"; // ECDSA secp256k1 seed
    pub const X25519_PRIVATE: &str = "O"; // X25519 private key
    pub const X25519_CIPHER_SEED: &str = "P"; // X25519 cipher of seed
    pub const ECDSA_256R1_SEED: &str = "Q"; // ECDSA secp256r1 seed

    pub const SALT_128: &str = "0A"; // 128 bit salt
    pub const ED25519_SIG: &str = "0B"; // Ed25519 signature
    pub const ECDSA_256K1_SIG: &str = "0C"; // ECDSA secp256k1 signature
    pub const BLAKE3_512: &str = "0D"; // Blake3 512 bit digest
    pub const BLAKE2B_512: &str = "0E"; // Blake2b 512 bit digest
    pub const SHA3_512: &str = "0F"; // SHA3 512 bit digest
    pub const SHA2_512: &str = "0G"; // SHA2 512 bit digest
    pub const SHORT_NUM: &str = "M"; // Short 2 byte number
    pub const LONG_NUM: &str = "0H"; // Long 4 byte number
    pub const BIG_NUM: &str = "N"; // Big 8 byte number
    pub const ECDSA_256R1_SIG: &str = "0I"; // ECDSA secp256r1 signature

    pub const ECDSA_256K1N: &str = "1AAA"; // ECDSA secp256k1 non-transferable
    pub const ECDSA_256K1: &str = "1AAB"; // ECDSA secp256k1 transferable
    pub const X25519_CIPHER_SALT: &str = "1AAH"; // X25519 cipher of salt
    pub const ECDSA_256R1N: &str = "1AAI"; // ECDSA secp256r1 non-transferable
    pub const ECDSA_256R1: &str = "1AAJ"; // ECDSA secp256r1 transferable

    pub const STR_B64_L0: &str = "4A"; // String Base64 Lead 0
    pub const STR_B64_L1: &str = "5A"; // String Base64 Lead 1
    pub const STR_B64_L2: &str = "6A"; // String Base64 Lead 2
    pub const STR_B64_BIG_L0: &str = "7AAA"; // String Base64 Big Lead 0
    pub const STR_B64_BIG_L1: &str = "8AAA"; // String Base64 Big Lead 1
    pub const STR_B64_BIG_L2: &str = "9AAA"; // String Base64 Big Lead 2
}

/// Indexer code definitions
pub mod indexer_codes {
    pub const ED25519_SIG: &str = "A"; // Ed25519 indexed signature
    pub const ED25519_CRT_SIG: &str = "B"; // Ed25519 current only indexed signature
    pub const ECDSA_256K1_SIG: &str = "C"; // ECDSA secp256k1 indexed signature
    pub const ECDSA_256K1_CRT_SIG: &str = "D"; // ECDSA secp256k1 current only
    pub const ED25519_BIG_SIG: &str = "0A"; // Ed25519 big indexed signature
    pub const ED25519_BIG_CRT_SIG: &str = "0B"; // Ed25519 big current only
    pub const ECDSA_256R1_SIG: &str = "0C"; // ECDSA secp256r1 indexed signature
    pub const ECDSA_256R1_CRT_SIG: &str = "0D"; // ECDSA secp256r1 current only
}

/// Counter code definitions
pub mod counter_codes {
    pub const CONTROLLER_IDX_SIGS: &str = "-A"; // Controller indexed signatures
    pub const WITNESS_IDX_SIGS: &str = "-B"; // Witness indexed signatures
    pub const NON_TRANS_RCT: &str = "-C"; // Non-transferable receipt
    pub const TRANS_RCT: &str = "-D"; // Transferable receipt
    pub const FIRST_SEEN_RPY: &str = "-E"; // First seen reply
    pub const TRANS_IDX_SIG_GROUPS: &str = "-F"; // Transferable indexed sig groups
    pub const ESCROW_RPY: &str = "-G"; // Escrowed reply
    pub const LOCATION_SEAL: &str = "-H"; // Location seal
    pub const ANCHOR_SEAL: &str = "-I"; // Anchor seal
    pub const SOURCE_SEAL: &str = "-J"; // Source seal
}

/// Size table for CESR codes
pub static SIZES: Lazy<HashMap<&'static str, Sizage>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Single character codes (1 char hard size)
    m.insert("A", Sizage::new(1, 0, Some(44), 0));
    m.insert("B", Sizage::new(1, 0, Some(44), 0));
    m.insert("C", Sizage::new(1, 0, Some(44), 0));
    m.insert("D", Sizage::new(1, 0, Some(44), 0));
    m.insert("E", Sizage::new(1, 0, Some(44), 0));
    m.insert("F", Sizage::new(1, 0, Some(44), 0));
    m.insert("G", Sizage::new(1, 0, Some(44), 0));
    m.insert("H", Sizage::new(1, 0, Some(44), 0));
    m.insert("I", Sizage::new(1, 0, Some(44), 0));
    m.insert("J", Sizage::new(1, 0, Some(44), 0));
    m.insert("K", Sizage::new(1, 0, Some(76), 0));
    m.insert("L", Sizage::new(1, 0, Some(76), 0));
    m.insert("M", Sizage::new(1, 0, Some(4), 0));
    m.insert("N", Sizage::new(1, 0, Some(12), 0));
    m.insert("O", Sizage::new(1, 0, Some(44), 0));
    m.insert("P", Sizage::new(1, 0, Some(124), 0));
    m.insert("Q", Sizage::new(1, 0, Some(44), 0));

    // Two character codes
    m.insert("0A", Sizage::new(2, 0, Some(24), 0));
    m.insert("0B", Sizage::new(2, 0, Some(88), 0));
    m.insert("0C", Sizage::new(2, 0, Some(88), 0));
    m.insert("0D", Sizage::new(2, 0, Some(88), 0));
    m.insert("0E", Sizage::new(2, 0, Some(88), 0));
    m.insert("0F", Sizage::new(2, 0, Some(88), 0));
    m.insert("0G", Sizage::new(2, 0, Some(88), 0));
    m.insert("0H", Sizage::new(2, 0, Some(8), 0));
    m.insert("0I", Sizage::new(2, 0, Some(88), 0));

    // Indexed signature codes (2 char code + index info)
    // Format: 2 char code + 4 chars for dual index (index + ondex)
    m.insert("2A", Sizage::new(2, 4, Some(92), 0)); // Ed25519 big indexed sig
    m.insert("2B", Sizage::new(2, 4, Some(92), 0)); // Ed25519 big current indexed sig
    m.insert("2C", Sizage::new(2, 4, Some(92), 0)); // ECDSA secp256k1 big indexed sig
    m.insert("2D", Sizage::new(2, 4, Some(92), 0)); // ECDSA secp256k1 big current
    m.insert("2E", Sizage::new(2, 4, Some(92), 0)); // ECDSA secp256r1 big indexed sig
    m.insert("2F", Sizage::new(2, 4, Some(92), 0)); // ECDSA secp256r1 big current
    m.insert("3A", Sizage::new(2, 6, Some(160), 0)); // Ed448 big indexed sig
    m.insert("3B", Sizage::new(2, 6, Some(160), 0)); // Ed448 big current indexed sig

    // Four character codes
    m.insert("1AAA", Sizage::new(4, 0, Some(48), 0));
    m.insert("1AAB", Sizage::new(4, 0, Some(48), 0));
    m.insert("1AAC", Sizage::new(4, 0, Some(80), 0));
    m.insert("1AAD", Sizage::new(4, 0, Some(80), 0));
    m.insert("1AAE", Sizage::new(4, 0, Some(56), 0));
    m.insert("1AAF", Sizage::new(4, 0, Some(8), 0));
    m.insert("1AAG", Sizage::new(4, 0, Some(36), 0));
    m.insert("1AAH", Sizage::new(4, 0, Some(100), 0));
    m.insert("1AAI", Sizage::new(4, 0, Some(48), 0));
    m.insert("1AAJ", Sizage::new(4, 0, Some(48), 0));

    // Variable length codes
    m.insert("4A", Sizage::new(2, 2, None, 0));
    m.insert("5A", Sizage::new(2, 2, None, 1));
    m.insert("6A", Sizage::new(2, 2, None, 2));
    m.insert("7AAA", Sizage::new(4, 4, None, 0));
    m.insert("8AAA", Sizage::new(4, 4, None, 1));
    m.insert("9AAA", Sizage::new(4, 4, None, 2));

    m
});

/// Get hard size for a given first character
pub static HARDS: Lazy<HashMap<char, usize>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Single char codes
    for c in 'A'..='Q' {
        m.insert(c, 1);
    }

    // Two char codes starting with '0', '2', '3'
    m.insert('0', 2);
    m.insert('2', 2);
    m.insert('3', 2);

    // Four char codes starting with '1'
    m.insert('1', 4);

    // Variable length codes
    m.insert('4', 2);
    m.insert('5', 2);
    m.insert('6', 2);
    m.insert('7', 4);
    m.insert('8', 4);
    m.insert('9', 4);

    m
});

/// Extract code from qb64 string
pub fn extract_code(qb64: &str) -> crate::error::Result<String> {
    if qb64.is_empty() {
        return Err(crate::error::SignifyError::InvalidCesr(
            "Empty qb64 string".to_string(),
        ));
    }

    let first_char = qb64.chars().next().unwrap();
    let hard_size = HARDS.get(&first_char).ok_or_else(|| {
        crate::error::SignifyError::InvalidCode(format!("Unknown code prefix: {}", first_char))
    })?;

    if qb64.len() < *hard_size {
        return Err(crate::error::SignifyError::InvalidCesr(format!(
            "qb64 too short for code: {}",
            qb64
        )));
    }

    Ok(qb64[..*hard_size].to_string())
}

/// Get size info for a code
pub fn sizage(code: &str) -> crate::error::Result<&Sizage> {
    SIZES
        .get(code)
        .ok_or_else(|| crate::error::SignifyError::InvalidCode(format!("Unknown code: {}", code)))
}

/// Calculate raw size from code
pub fn raw_size(code: &str) -> crate::error::Result<usize> {
    let sz = sizage(code)?;
    if let Some(fs) = sz.fs {
        // Fixed size: calculate raw from qb64 size
        // qb64_size = hs + ceil((raw_size + ls) * 4 / 3)
        // Solve for raw_size:
        let qb64_data_size = fs - sz.hs;
        let raw_with_pad = (qb64_data_size * 3) / 4;
        Ok(raw_with_pad - sz.ls)
    } else {
        Err(crate::error::SignifyError::InvalidCode(format!(
            "Variable size code requires explicit size: {}",
            code
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_code() {
        assert_eq!(
            extract_code("AKvp4T9yNzJxQ3mH5c0v8L2fR9pD1nW6sX4jG7kB3hM8").unwrap(),
            "A"
        );
        assert_eq!(extract_code("0BABCDEFabcdef").unwrap(), "0B");
        assert_eq!(extract_code("1AAABCDEFabcdef").unwrap(), "1AAA");
    }

    #[test]
    fn test_raw_size() {
        assert_eq!(raw_size("A").unwrap(), 32); // Ed25519 seed
        assert_eq!(raw_size("0B").unwrap(), 64); // Ed25519 signature
        assert_eq!(raw_size("0A").unwrap(), 16); // Salt_128
    }
}
