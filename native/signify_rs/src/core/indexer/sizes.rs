/// Size definitions specific to indexed signatures
/// These are separate from Matter codes because the same code letter
/// means different things in different contexts
use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IndexerSizage {
    pub hs: usize, // Hard size (code length)
    pub ss: usize, // Soft size (index length)
    pub fs: usize, // Full size (total qb64 length)
    pub ls: usize, // Lead size (raw size mod 3)
}

impl IndexerSizage {
    pub fn new(hs: usize, ss: usize, fs: usize, ls: usize) -> Self {
        Self { hs, ss, fs, ls }
    }
}

/// Size table for indexed signature codes
pub static INDEXER_SIZES: Lazy<HashMap<&'static str, IndexerSizage>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Small indexed signatures (1 char code + 1 char index)
    // 64-byte signature = 86 base64 chars + 1 code + 1 index = 88 total
    m.insert("A", IndexerSizage::new(1, 1, 88, 0)); // Ed25519 indexed sig
    m.insert("B", IndexerSizage::new(1, 1, 88, 0)); // Ed25519 current only
    m.insert("C", IndexerSizage::new(1, 1, 88, 0)); // ECDSA secp256k1 indexed sig
    m.insert("D", IndexerSizage::new(1, 1, 88, 0)); // ECDSA secp256k1 current only
    m.insert("E", IndexerSizage::new(1, 1, 88, 0)); // ECDSA secp256r1 indexed sig
    m.insert("F", IndexerSizage::new(1, 1, 88, 0)); // ECDSA secp256r1 current only

    // Medium indexed signatures (2 char code + 2 char index)
    m.insert("0A", IndexerSizage::new(2, 2, 156, 0)); // Ed448 indexed sig
    m.insert("0B", IndexerSizage::new(2, 2, 156, 0)); // Ed448 current only

    // Big indexed signatures (2 char code + 4 char dual index)
    // 64-byte signature = 86 base64 chars + 2 code + 4 index = 92 total
    m.insert("2A", IndexerSizage::new(2, 4, 92, 0)); // Ed25519 big indexed sig
    m.insert("2B", IndexerSizage::new(2, 4, 92, 0)); // Ed25519 big current only
    m.insert("2C", IndexerSizage::new(2, 4, 92, 0)); // ECDSA secp256k1 big indexed sig
    m.insert("2D", IndexerSizage::new(2, 4, 92, 0)); // ECDSA secp256k1 big current
    m.insert("2E", IndexerSizage::new(2, 4, 92, 0)); // ECDSA secp256r1 big indexed sig
    m.insert("2F", IndexerSizage::new(2, 4, 92, 0)); // ECDSA secp256r1 big current
    m.insert("3A", IndexerSizage::new(2, 6, 160, 0)); // Ed448 big indexed sig
    m.insert("3B", IndexerSizage::new(2, 6, 160, 0)); // Ed448 big current only

    m
});

/// Get indexer sizage for a code
pub fn indexer_sizage(code: &str) -> Option<&IndexerSizage> {
    INDEXER_SIZES.get(code)
}
