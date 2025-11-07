use crate::core::cigar::Cigar;
use crate::core::cipher::Cipher;
use crate::core::codes::matter_codes;
use crate::core::decrypter::Decrypter;
use crate::core::diger::Diger;
use crate::core::encrypter::Encrypter;
use crate::core::salter::{Salter, Tier};
use crate::core::siger::Siger;
use crate::core::signer::Signer;
use crate::core::verfer::Verfer;
use crate::error::{Result, SignifyError};
use std::collections::HashMap;

/// Kinds of key pair generation algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algos {
    /// Random key generation (non-deterministic)
    Randy,
    /// Salty key generation (deterministic based on salt and stem)
    Salty,
    /// Group multi-signature algorithm
    Group,
    /// External key pair algorithm (e.g., HSM)
    Extern,
}

impl Algos {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algos::Randy => "randy",
            Algos::Salty => "salty",
            Algos::Group => "group",
            Algos::Extern => "extern",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "randy" => Ok(Algos::Randy),
            "salty" => Ok(Algos::Salty),
            "group" => Ok(Algos::Group),
            "extern" => Ok(Algos::Extern),
            _ => Err(SignifyError::InvalidAlgorithm(format!(
                "Unknown algorithm: {}",
                s
            ))),
        }
    }
}

/// Set of signers with optional derivation paths
#[derive(Debug)]
pub struct Keys {
    /// The signing keys
    pub signers: Vec<Signer>,
    /// Optional derivation paths used to generate the keys (for salty algorithm)
    pub paths: Option<Vec<String>>,
}

impl Keys {
    pub fn new(signers: Vec<Signer>, paths: Option<Vec<String>>) -> Result<Self> {
        if let Some(ref p) = paths {
            if signers.len() != p.len() {
                return Err(SignifyError::InvalidArgument(
                    "If paths are provided, they must be the same length as signers".to_string(),
                ));
            }
        }
        Ok(Self { signers, paths })
    }
}

/// Interface for creating key pairs based on an algorithm
pub trait Creator {
    /// Creates key pairs
    ///
    /// # Arguments
    /// * `codes` - List of derivation codes, one per key pair to create
    /// * `count` - Count of key pairs to create if codes not provided
    /// * `code` - Derivation code to use for count key pairs if codes not provided
    /// * `transferable` - True means use transferable derivation code
    /// * `pidx` - Prefix index for this keypair sequence
    /// * `ridx` - Rotation index for this key pair set
    /// * `kidx` - Starting key index for this key pair set
    /// * `temp` - True means use temp stretch for testing
    fn create(
        &self,
        codes: Option<Vec<String>>,
        count: usize,
        code: &str,
        transferable: bool,
        pidx: usize,
        ridx: usize,
        kidx: usize,
        temp: bool,
    ) -> Result<Keys>;

    /// Salt used for key pair generation (salty only)
    fn salt(&self) -> &str;

    /// String prefix used to stretch the prefix, salt, and seed into the key pair (salty only)
    fn stem(&self) -> &str;

    /// Security tier used during stretching
    fn tier(&self) -> Tier;
}

/// Random key generator (non-deterministic)
pub struct RandyCreator;

impl RandyCreator {
    pub fn new() -> Self {
        Self
    }
}

impl Creator for RandyCreator {
    fn create(
        &self,
        codes: Option<Vec<String>>,
        count: usize,
        code: &str,
        transferable: bool,
        _pidx: usize,
        _ridx: usize,
        _kidx: usize,
        _temp: bool,
    ) -> Result<Keys> {
        let codes = codes.unwrap_or_else(|| vec![code.to_string(); count]);

        let mut signers = Vec::new();
        for code in codes {
            signers.push(Signer::new_random(&code, transferable)?);
        }

        Keys::new(signers, None)
    }

    fn salt(&self) -> &str {
        ""
    }

    fn stem(&self) -> &str {
        ""
    }

    fn tier(&self) -> Tier {
        Tier::Low
    }
}

/// Salty (deterministic) key generator based on salt and path stretching
pub struct SaltyCreator {
    /// The salter used to create key pairs
    pub salter: Salter,
    /// Key material prefix used during key stretching
    stem: String,
}

impl SaltyCreator {
    /// Create a new SaltyCreator
    ///
    /// # Arguments
    /// * `salt` - Optional qb64 encoded salt. If None, a random salt is generated
    /// * `tier` - Security tier for key stretching
    /// * `stem` - Optional stem prefix for key derivation paths
    pub fn new(salt: Option<&str>, tier: Option<Tier>, stem: Option<&str>) -> Result<Self> {
        let salter = if let Some(s) = salt {
            Salter::from_qb64(s, tier.unwrap_or(Tier::Low))?
        } else {
            Salter::new(tier.unwrap_or(Tier::Low))?
        };

        let stem = stem.unwrap_or("").to_string();

        Ok(Self { salter, stem })
    }
}

impl Creator for SaltyCreator {
    fn create(
        &self,
        codes: Option<Vec<String>>,
        count: usize,
        code: &str,
        transferable: bool,
        pidx: usize,
        ridx: usize,
        kidx: usize,
        temp: bool,
    ) -> Result<Keys> {
        let codes = codes.unwrap_or_else(|| vec![code.to_string(); count]);

        let mut signers = Vec::new();
        let mut paths = Vec::new();

        for (idx, code) in codes.iter().enumerate() {
            // Generate path: stem + ridx (hex) + (kidx+idx) (hex)
            // If stem is empty, just use pidx (hex) for backwards compatibility
            let path = if self.stem.is_empty() {
                format!("{:x}", pidx)
            } else {
                format!("{}{:x}{:x}", self.stem, ridx, kidx + idx)
            };

            let signer = self
                .salter
                .signer(code, transferable, &path, Some(self.tier()), temp)?;
            signers.push(signer);
            paths.push(path);
        }

        Keys::new(signers, Some(paths))
    }

    fn salt(&self) -> &str {
        self.salter.qb64()
    }

    fn stem(&self) -> &str {
        &self.stem
    }

    fn tier(&self) -> Tier {
        self.salter.tier()
    }
}

/// Describes a path to a specific derived keypair for a given identifier
#[derive(Debug, Clone)]
pub struct PubPath {
    /// The path to a specific keypair
    pub path: String,
    /// Derivation code indicating the kind of cryptographic keypair
    pub code: String,
    /// Security tier to use to generate a keypair
    pub tier: Tier,
    /// Flag to control whether to generate a low security, temporary key
    pub temp: bool,
}

/// Identifier prefix parameters for creating new key pairs
#[derive(Debug, Clone)]
pub struct PrePrm {
    /// Prefix index for this keypair sequence
    pub pidx: usize,
    /// Key generation algorithm type
    pub algo: Algos,
    /// Used for salty algo (encrypted if encrypter is available)
    pub salt: String,
    /// Default unique path prefix used by the salty algo during key generation
    pub stem: String,
    /// Security tier for stretch index
    pub tier: Tier,
}

/// Lot (set) of public keys as an ordered list with indexes and the time created
#[derive(Debug, Clone)]
pub struct PubLot {
    /// List of fully qualified, Base64 encoded public keys
    pub pubs: Vec<String>,
    /// Rotation index; index of rotation that uses this public key set
    pub ridx: usize,
    /// Key index; index of the starting key in the key set for this lot
    pub kidx: usize,
    /// Datetime of when key set created (ISO 8601)
    pub dt: String,
}

/// Prefix's public key situation (set of public keys)
#[derive(Debug, Clone)]
pub struct PreSit {
    /// Previous public key set
    pub old: PubLot,
    /// Current public key set
    pub new: PubLot,
    /// Next public key set
    pub nxt: PubLot,
}

/// An identifier prefix's public key set at a given rotation index
#[derive(Debug, Clone)]
pub struct PubSet {
    /// List of fully qualified, Base64 encoded public keys
    pub pubs: Vec<String>,
}

/// Key store interface for persisting key material and metadata
pub trait KeyStore: Send + Sync {
    // Global settings
    fn get_gbls(&self, key: &str) -> Option<String>;
    fn pin_gbls(&mut self, key: &str, val: &str);

    // Prefix parameters (PrePrm)
    fn get_prms(&self, pre: &str) -> Option<PrePrm>;
    fn put_prms(&mut self, pre: &str, data: &PrePrm) -> bool;
    fn pin_prms(&mut self, pre: &str, data: &PrePrm);

    // Private keys (encrypted)
    fn get_pris(&self, pub_key: &str, decrypter: &Decrypter) -> Option<Signer>;
    fn put_pris(&mut self, pub_key: &str, signer: &Signer, encrypter: &Encrypter) -> bool;
    fn pin_pris(&mut self, pub_key: &str, signer: &Signer, encrypter: &Encrypter);
    fn rem_pris(&mut self, pub_key: &str);

    // Public key paths (for salty without encryption)
    fn get_pths(&self, pub_key: &str) -> Option<PubPath>;
    fn put_pths(&mut self, pub_key: &str, val: &PubPath) -> bool;

    // Prefix identifiers
    fn get_pres(&self, pre: &str) -> Option<Vec<u8>>;
    fn put_pres(&mut self, pre: &str, val: &[u8]) -> bool;
    fn pin_pres(&mut self, pre: &str, val: &[u8]);

    // Prefix situations (public key sets)
    fn get_sits(&self, pre: &str) -> Option<PreSit>;
    fn put_sits(&mut self, pre: &str, val: &PreSit) -> bool;
    fn pin_sits(&mut self, pre: &str, val: &PreSit);

    // Public key sets by rotation index
    fn get_pubs(&self, key: &str) -> Option<PubSet>;
    fn put_pubs(&mut self, key: &str, data: &PubSet) -> bool;
}

/// In-memory implementation of KeyStore for testing and simple use cases
#[derive(Debug, Default)]
pub struct Keeper {
    gbls: HashMap<String, String>,
    pris: HashMap<String, Vec<u8>>, // Stores encrypted cipher qb64b
    pths: HashMap<String, PubPath>,
    pres: HashMap<String, Vec<u8>>,
    prms: HashMap<String, PrePrm>,
    sits: HashMap<String, PreSit>,
    pubs: HashMap<String, PubSet>,
}

impl Keeper {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for Keeper {
    fn get_gbls(&self, key: &str) -> Option<String> {
        self.gbls.get(key).cloned()
    }

    fn pin_gbls(&mut self, key: &str, val: &str) {
        self.gbls.insert(key.to_string(), val.to_string());
    }

    fn get_prms(&self, pre: &str) -> Option<PrePrm> {
        self.prms.get(pre).cloned()
    }

    fn put_prms(&mut self, pre: &str, data: &PrePrm) -> bool {
        if self.prms.contains_key(pre) {
            return false;
        }
        self.prms.insert(pre.to_string(), data.clone());
        true
    }

    fn pin_prms(&mut self, pre: &str, data: &PrePrm) {
        self.prms.insert(pre.to_string(), data.clone());
    }

    fn get_pris(&self, pub_key: &str, decrypter: &Decrypter) -> Option<Signer> {
        let cipher_bytes = self.pris.get(pub_key)?;
        let verfer = Verfer::from_qb64(pub_key).ok()?;

        match decrypter.decrypt(Some(cipher_bytes), None, verfer.transferable()) {
            Ok(crate::core::decrypter::DecryptedMatter::Signer(signer)) => Some(signer),
            _ => None,
        }
    }

    fn put_pris(&mut self, pub_key: &str, signer: &Signer, encrypter: &Encrypter) -> bool {
        if self.pris.contains_key(pub_key) {
            return false;
        }
        if let Ok(cipher) = encrypter.encrypt(Some(signer.matter().qb64b()), None) {
            self.pris
                .insert(pub_key.to_string(), cipher.qb64b().unwrap().clone());
            return true;
        }
        false
    }

    fn pin_pris(&mut self, pub_key: &str, signer: &Signer, encrypter: &Encrypter) {
        if let Ok(cipher) = encrypter.encrypt(Some(signer.matter().qb64b()), None) {
            self.pris
                .insert(pub_key.to_string(), cipher.qb64b().unwrap().clone());
        }
    }

    fn rem_pris(&mut self, pub_key: &str) {
        self.pris.remove(pub_key);
    }

    fn get_pths(&self, pub_key: &str) -> Option<PubPath> {
        self.pths.get(pub_key).cloned()
    }

    fn put_pths(&mut self, pub_key: &str, val: &PubPath) -> bool {
        if self.pths.contains_key(pub_key) {
            return false;
        }
        self.pths.insert(pub_key.to_string(), val.clone());
        true
    }

    fn get_pres(&self, pre: &str) -> Option<Vec<u8>> {
        self.pres.get(pre).cloned()
    }

    fn put_pres(&mut self, pre: &str, val: &[u8]) -> bool {
        if self.pres.contains_key(pre) {
            return false;
        }
        self.pres.insert(pre.to_string(), val.to_vec());
        true
    }

    fn pin_pres(&mut self, pre: &str, val: &[u8]) {
        self.pres.insert(pre.to_string(), val.to_vec());
    }

    fn get_sits(&self, pre: &str) -> Option<PreSit> {
        self.sits.get(pre).cloned()
    }

    fn put_sits(&mut self, pre: &str, val: &PreSit) -> bool {
        if self.sits.contains_key(pre) {
            return false;
        }
        self.sits.insert(pre.to_string(), val.clone());
        true
    }

    fn pin_sits(&mut self, pre: &str, val: &PreSit) {
        self.sits.insert(pre.to_string(), val.clone());
    }

    fn get_pubs(&self, key: &str) -> Option<PubSet> {
        self.pubs.get(key).cloned()
    }

    fn put_pubs(&mut self, key: &str, data: &PubSet) -> bool {
        if self.pubs.contains_key(key) {
            return false;
        }
        self.pubs.insert(key.to_string(), data.clone());
        true
    }
}

/// Generate rotation index key for pub sets
pub fn ri_key(pre: &str, ridx: usize) -> String {
    format!("{}.{:032x}", pre, ridx)
}

/// Factory for creating Creator instances based on algorithm
pub struct Creatory {
    algo: Algos,
}

impl Creatory {
    pub fn new(algo: Algos) -> Self {
        Self { algo }
    }

    /// Create a Creator instance based on the algorithm
    ///
    /// # Arguments for Salty
    /// * `salt` - Optional qb64 encoded salt
    /// * `tier` - Optional security tier
    /// * `stem` - Optional stem prefix
    pub fn make(
        &self,
        salt: Option<&str>,
        tier: Option<Tier>,
        stem: Option<&str>,
    ) -> Result<Box<dyn Creator>> {
        match self.algo {
            Algos::Randy => Ok(Box::new(RandyCreator::new())),
            Algos::Salty => Ok(Box::new(SaltyCreator::new(salt, tier, stem)?)),
            Algos::Group => Err(SignifyError::InvalidAlgorithm(
                "Group algorithm not yet implemented".to_string(),
            )),
            Algos::Extern => Err(SignifyError::InvalidAlgorithm(
                "Extern algorithm not yet implemented".to_string(),
            )),
        }
    }
}

/// Manager handles key pair creation, retrieval, and message signing
pub struct Manager {
    ks: Box<dyn KeyStore>,
    seed: Option<String>,
    encrypter: Option<Encrypter>,
    decrypter: Option<Decrypter>,
}

impl Manager {
    /// Create a new Manager
    ///
    /// # Arguments
    /// * `ks` - KeyStore implementation (defaults to Keeper if None)
    /// * `seed` - Optional seed for encryption/decryption
    /// * `aeid` - Optional auth encrypt id prefix
    /// * `pidx` - Optional prefix index
    /// * `algo` - Optional algorithm (defaults to Salty)
    /// * `salt` - Optional salt (as Salter for easier use)
    /// * `tier` - Optional security tier
    pub fn new(
        ks: Option<Box<dyn KeyStore>>,
        seed: Option<&str>,
        aeid: Option<&str>,
        pidx: Option<usize>,
        algo: Option<Algos>,
        salter: Option<&Salter>,
        tier: Option<Tier>,
    ) -> Result<Self> {
        let mut ks = ks.unwrap_or_else(|| Box::new(Keeper::new()));
        let seed = seed.map(|s| s.to_string());

        let pidx = pidx.unwrap_or(0);
        let algo = algo.unwrap_or(Algos::Salty);
        let tier = tier.unwrap_or(Tier::Low);

        // Set up encryption if seed and aeid provided
        let (encrypter, decrypter) = if let (Some(ref s), Some(a)) = (&seed, aeid) {
            // Pass aeid as verkey parameter to convert Ed25519 -> X25519
            let enc = Encrypter::new(
                crate::core::matter::MatterOpts {
                    raw: None,
                    code: None,
                    qb64: None,
                    qb64b: None,
                    qb2: None,
                },
                Some(a.as_bytes()),
            )?;

            // Verify seed matches aeid
            if !enc.verify_seed(s.as_bytes())? {
                return Err(SignifyError::InvalidKey(
                    "Seed does not match provided aeid".to_string(),
                ));
            }

            // Pass seed as parameter to convert Ed25519 -> X25519
            let dec = Decrypter::new(
                crate::core::matter::MatterOpts {
                    raw: None,
                    code: None,
                    qb64: None,
                    qb64b: None,
                    qb2: None,
                },
                Some(s.as_bytes()),
            )?;

            (Some(enc), Some(dec))
        } else {
            (None, None)
        };

        // Initialize global settings if not set
        if ks.get_gbls("pidx").is_none() {
            ks.pin_gbls("pidx", &format!("{:x}", pidx));
        }

        if ks.get_gbls("algo").is_none() {
            ks.pin_gbls("algo", algo.as_str());
        }

        if let Some(ref salter) = salter {
            if ks.get_gbls("salt").is_none() {
                let salt_val = if let Some(ref enc) = encrypter {
                    enc.encrypt(Some(salter.qb64().as_bytes()), None)?.qb64()?
                } else {
                    salter.qb64().to_string()
                };
                ks.pin_gbls("salt", &salt_val);
            }
        }

        if ks.get_gbls("tier").is_none() {
            ks.pin_gbls("tier", tier.as_str());
        }

        if let Some(a) = aeid {
            ks.pin_gbls("aeid", a);
        }

        Ok(Self {
            ks,
            seed,
            encrypter,
            decrypter,
        })
    }

    /// Get the key store
    pub fn ks(&self) -> &dyn KeyStore {
        &*self.ks
    }

    /// Get mutable key store
    pub fn ks_mut(&mut self) -> &mut dyn KeyStore {
        &mut *self.ks
    }

    /// Get the encryption ID (aeid)
    pub fn aeid(&self) -> Option<String> {
        self.ks.get_gbls("aeid")
    }

    /// Get the prefix index
    pub fn pidx(&self) -> Option<usize> {
        self.ks
            .get_gbls("pidx")
            .and_then(|s| usize::from_str_radix(&s, 16).ok())
    }

    /// Set the prefix index
    pub fn set_pidx(&mut self, pidx: usize) {
        self.ks.pin_gbls("pidx", &format!("{:x}", pidx));
    }

    /// Get the salt (decrypted if encrypter is available)
    pub fn salt(&self) -> Option<String> {
        let salt = self.ks.get_gbls("salt")?;

        if let Some(ref dec) = self.decrypter {
            // Salt is encrypted, decrypt it
            match dec.decrypt(Some(salt.as_bytes()), None, false) {
                Ok(crate::core::decrypter::DecryptedMatter::Salter(salter)) => {
                    Some(salter.qb64().to_string())
                }
                _ => None,
            }
        } else {
            Some(salt)
        }
    }

    /// Get the security tier
    pub fn tier(&self) -> Option<Tier> {
        self.ks
            .get_gbls("tier")
            .and_then(|s| Tier::from_str(&s).ok())
    }

    /// Get the algorithm
    pub fn algo(&self) -> Option<Algos> {
        self.ks
            .get_gbls("algo")
            .and_then(|s| Algos::from_str(&s).ok())
    }

    /// Get the encrypter if available
    pub fn encrypter(&self) -> Option<&Encrypter> {
        self.encrypter.as_ref()
    }

    /// Get the decrypter if available
    pub fn decrypter(&self) -> Option<&Decrypter> {
        self.decrypter.as_ref()
    }

    /// Incept a new identifier with initial and next key sets
    ///
    /// # Arguments
    /// * `icodes` - Optional list of derivation codes for inception keys
    /// * `icount` - Count of inception keys if codes not provided (default 1)
    /// * `icode` - Derivation code for inception keys (default ED25519_SEED)
    /// * `ncodes` - Optional list of derivation codes for next keys
    /// * `ncount` - Count of next keys if codes not provided (default 1)
    /// * `ncode` - Derivation code for next keys (default ED25519_SEED)
    /// * `dcode` - Digest code for next key digests (default BLAKE3_256)
    /// * `algo` - Optional override algorithm (defaults to manager's algo)
    /// * `salt` - Optional override salt
    /// * `stem` - Optional stem prefix for key paths
    /// * `tier` - Optional override tier
    /// * `rooted` - Use manager's settings if true (default)
    /// * `transferable` - Generate transferable keys (default true)
    /// * `temp` - Use temp/fast stretch for testing (default false)
    ///
    /// Returns (verfers, digers) - inception verifiers and next key digests
    pub fn incept(
        &mut self,
        icodes: Option<Vec<String>>,
        icount: usize,
        icode: &str,
        ncodes: Option<Vec<String>>,
        ncount: usize,
        ncode: &str,
        dcode: &str,
        algo: Option<Algos>,
        salt: Option<&str>,
        stem: Option<&str>,
        tier: Option<Tier>,
        rooted: bool,
        transferable: bool,
        temp: bool,
    ) -> Result<(Vec<Verfer>, Vec<Diger>)> {
        // Use manager settings if rooted
        let algo = if rooted {
            algo.or(self.algo()).unwrap_or(Algos::Salty)
        } else {
            algo.unwrap_or(Algos::Salty)
        };

        let manager_salt = self.salt();
        let salt = if rooted {
            salt.or(manager_salt.as_deref())
        } else {
            salt
        };

        let tier = if rooted {
            tier.or(self.tier()).unwrap_or(Tier::Low)
        } else {
            tier.unwrap_or(Tier::Low)
        };

        let pidx = self.pidx().unwrap_or(0);
        let ridx = 0; // Inception is always rotation 0
        let kidx = 0; // Start at key 0

        // Create key creator
        let creator = Creatory::new(algo).make(salt, Some(tier), stem)?;

        // Generate inception keys
        let icodes = icodes.unwrap_or_else(|| vec![icode.to_string(); icount]);
        let ikeys = creator.create(
            Some(icodes.clone()),
            0,
            matter_codes::ED25519_SEED,
            transferable,
            pidx,
            ridx,
            kidx,
            temp,
        )?;

        let verfers: Vec<Verfer> = ikeys.signers.iter().map(|s| s.verfer().clone()).collect();

        // Generate next keys (for future rotation)
        let ncodes = ncodes.unwrap_or_else(|| vec![ncode.to_string(); ncount]);
        let nkeys = creator.create(
            Some(ncodes.clone()),
            0,
            matter_codes::ED25519_SEED,
            transferable,
            pidx,
            ridx + 1,
            kidx + icodes.len(),
            temp,
        )?;

        // Create digests of next keys
        let digers: Vec<Diger> = nkeys
            .signers
            .iter()
            .map(|s| Diger::new(dcode, s.verfer().qb64b()))
            .collect::<Result<Vec<_>>>()?;

        // Store prefix parameters
        let pp = PrePrm {
            pidx,
            algo,
            salt: if let Some(ref enc) = self.encrypter {
                if !creator.salt().is_empty() {
                    enc.encrypt(Some(creator.salt().as_bytes()), None)?.qb64()?
                } else {
                    String::new()
                }
            } else {
                creator.salt().to_string()
            },
            stem: creator.stem().to_string(),
            tier: creator.tier(),
        };

        // Get current timestamp
        let dt = chrono::Utc::now().to_rfc3339();

        // Create public key lots
        let nw = PubLot {
            pubs: verfers.iter().map(|v| v.qb64().to_string()).collect(),
            ridx,
            kidx,
            dt: dt.clone(),
        };

        let nt = PubLot {
            pubs: nkeys
                .signers
                .iter()
                .map(|s| s.verfer().qb64().to_string())
                .collect(),
            ridx: ridx + 1,
            kidx: kidx + icodes.len(),
            dt,
        };

        let ps = PreSit {
            old: PubLot {
                pubs: vec![],
                ridx: 0,
                kidx: 0,
                dt: String::new(),
            },
            new: nw.clone(),
            nxt: nt.clone(),
        };

        // Use first verifier's qb64 as prefix
        let pre = verfers[0].qb64();

        // Store prefix
        if !self.ks.put_pres(pre, pre.as_bytes()) {
            return Err(SignifyError::Other(format!("Already incepted pre={}", pre)));
        }

        // Store parameters
        if !self.ks.put_prms(pre, &pp) {
            return Err(SignifyError::Other(format!(
                "Already incepted prm for pre={}",
                pre
            )));
        }

        // Increment pidx for next identifier
        self.set_pidx(pidx + 1);

        // Store situation
        if !self.ks.put_sits(pre, &ps) {
            return Err(SignifyError::Other(format!(
                "Already incepted sit for pre={}",
                pre
            )));
        }

        // Store keys based on encryption availability
        if let Some(ref enc) = self.encrypter {
            // Store encrypted private keys
            for signer in &ikeys.signers {
                self.ks.put_pris(signer.verfer().qb64(), signer, enc);
            }
            for signer in &nkeys.signers {
                self.ks.put_pris(signer.verfer().qb64(), signer, enc);
            }
        } else if let Some(ref ipaths) = ikeys.paths {
            // Store paths for salty without encryption
            for (idx, path) in ipaths.iter().enumerate() {
                let ppt = PubPath {
                    path: path.clone(),
                    code: icodes[idx].clone(),
                    tier,
                    temp,
                };
                self.ks.put_pths(ikeys.signers[idx].verfer().qb64(), &ppt);
            }
            if let Some(ref npaths) = nkeys.paths {
                for (idx, path) in npaths.iter().enumerate() {
                    let ppt = PubPath {
                        path: path.clone(),
                        code: ncodes[idx].clone(),
                        tier,
                        temp,
                    };
                    self.ks.put_pths(nkeys.signers[idx].verfer().qb64(), &ppt);
                }
            }
        } else {
            return Err(SignifyError::Other(
                "Invalid configuration: randy keys without encryption".to_string(),
            ));
        }

        // Store public key sets
        let pub_set = PubSet {
            pubs: ps.new.pubs.clone(),
        };
        self.ks.put_pubs(&ri_key(pre, ridx), &pub_set);

        let nxt_pub_set = PubSet {
            pubs: ps.nxt.pubs.clone(),
        };
        self.ks.put_pubs(&ri_key(pre, ridx + 1), &nxt_pub_set);

        Ok((verfers, digers))
    }

    /// Rotate keys for an existing identifier
    ///
    /// # Arguments
    /// * `pre` - The identifier prefix to rotate
    /// * `ncodes` - Optional list of derivation codes for new next keys
    /// * `ncount` - Count of next keys if codes not provided (default 1)
    /// * `ncode` - Derivation code for next keys (default ED25519_SEED)
    /// * `dcode` - Digest code for next key digests (default BLAKE3_256)
    /// * `transferable` - Generate transferable keys (default true)
    /// * `temp` - Use temp/fast stretch for testing (default false)
    ///
    /// Returns (verfers, digers) - current verifiers and new next key digests
    pub fn rotate(
        &mut self,
        pre: &str,
        ncodes: Option<Vec<String>>,
        ncount: usize,
        ncode: &str,
        dcode: &str,
        transferable: bool,
        temp: bool,
    ) -> Result<(Vec<Verfer>, Vec<Diger>)> {
        // Get prefix parameters
        let pp = self.ks.get_prms(pre).ok_or_else(|| {
            SignifyError::Other(format!("Attempt to rotate nonexistent pre={}", pre))
        })?;

        // Get prefix situation
        let mut ps = self.ks.get_sits(pre).ok_or_else(|| {
            SignifyError::Other(format!("Attempt to rotate nonexistent pre={}", pre))
        })?;

        if ps.nxt.pubs.is_empty() {
            return Err(SignifyError::Other(format!(
                "Attempt to rotate nontransferable pre={}",
                pre
            )));
        }

        // Shift key sets: old <- new, new <- nxt
        let old = ps.old;
        ps.old = ps.new.clone();
        ps.new = ps.nxt.clone();

        // Get current keys (from nxt, now becoming new)
        let verfers: Vec<Verfer> = if let Some(ref dec) = self.decrypter {
            // Decrypt from storage
            ps.new
                .pubs
                .iter()
                .map(|pub_key| {
                    self.ks
                        .get_pris(pub_key, dec)
                        .map(|s| s.verfer().clone())
                        .ok_or_else(|| {
                            SignifyError::Other(format!("Missing prikey for pubkey={}", pub_key))
                        })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            // Just create verfers from public keys
            ps.new
                .pubs
                .iter()
                .map(|pub_key| Verfer::from_qb64(pub_key))
                .collect::<Result<Vec<_>>>()?
        };

        // Decrypt salt if needed
        let salt = if !pp.salt.is_empty() {
            if let Some(ref dec) = self.decrypter {
                match dec.decrypt(Some(pp.salt.as_bytes()), None, false) {
                    Ok(crate::core::decrypter::DecryptedMatter::Salter(salter)) => {
                        salter.qb64().to_string()
                    }
                    _ => {
                        return Err(SignifyError::Other(
                            "Failed to decrypt salt for rotation".to_string(),
                        ))
                    }
                }
            } else {
                pp.salt.clone()
            }
        } else {
            self.salt().unwrap_or_default()
        };

        // Create key creator
        let creator = Creatory::new(pp.algo).make(Some(&salt), Some(pp.tier), Some(&pp.stem))?;

        // Generate new next keys
        let ncodes = ncodes.unwrap_or_else(|| vec![ncode.to_string(); ncount]);
        let pidx = pp.pidx;
        let ridx = ps.new.ridx + 1;
        let kidx = ps.nxt.kidx + ps.new.pubs.len();

        let keys = creator.create(
            Some(ncodes.clone()),
            0,
            matter_codes::ED25519_SEED,
            transferable,
            pidx,
            ridx,
            kidx,
            temp,
        )?;

        // Create digests of new next keys
        let digers: Vec<Diger> = keys
            .signers
            .iter()
            .map(|s| Diger::new(dcode, s.verfer().qb64b()))
            .collect::<Result<Vec<_>>>()?;

        // Update next key set
        let dt = chrono::Utc::now().to_rfc3339();
        ps.nxt = PubLot {
            pubs: keys
                .signers
                .iter()
                .map(|s| s.verfer().qb64().to_string())
                .collect(),
            ridx,
            kidx,
            dt,
        };

        // Update situation
        self.ks.pin_sits(pre, &ps);

        // Store new next keys
        if let Some(ref enc) = self.encrypter {
            for signer in &keys.signers {
                self.ks.put_pris(signer.verfer().qb64(), signer, enc);
            }
        } else if let Some(ref paths) = keys.paths {
            for (idx, path) in paths.iter().enumerate() {
                let ppt = PubPath {
                    path: path.clone(),
                    code: ncodes[idx].clone(),
                    tier: pp.tier,
                    temp,
                };
                self.ks.put_pths(keys.signers[idx].verfer().qb64(), &ppt);
            }
        } else {
            return Err(SignifyError::Other(
                "Invalid configuration: randy keys without encryption".to_string(),
            ));
        }

        // Store new next public key set
        let new_ps = PubSet {
            pubs: ps.nxt.pubs.clone(),
        };
        self.ks.put_pubs(&ri_key(pre, ps.nxt.ridx), &new_ps);

        // Optionally erase old keys (for security)
        for pub_key in &old.pubs {
            self.ks.rem_pris(pub_key);
        }

        Ok((verfers, digers))
    }

    /// Sign serialized data with keys from a prefix
    ///
    /// # Arguments
    /// * `ser` - Serialized data to sign
    /// * `pubs` - Optional list of public key qb64 strings to sign with
    /// * `verfers` - Optional list of Verfers to sign with (alternative to pubs)
    /// * `indexed` - Create indexed signatures for multi-sig (default true)
    /// * `indices` - Optional custom indices for indexed signatures
    ///
    /// Returns Cigar (non-indexed) or Siger (indexed) signatures
    pub fn sign(
        &self,
        ser: &[u8],
        pubs: Option<&[String]>,
        verfers: Option<&[Verfer]>,
        indexed: bool,
        indices: Option<&[usize]>,
    ) -> Result<Vec<u8>> {
        if pubs.is_none() && verfers.is_none() {
            return Err(SignifyError::InvalidArgument(
                "pubs or verfers required for signing".to_string(),
            ));
        }

        let mut signers = Vec::new();

        if let Some(pub_keys) = pubs {
            for pub_key in pub_keys {
                if let Some(ref dec) = self.decrypter {
                    // Decrypt from storage
                    let signer = self.ks.get_pris(pub_key, dec).ok_or_else(|| {
                        SignifyError::Other(format!("Missing prikey for pubkey={}", pub_key))
                    })?;
                    signers.push(signer);
                } else {
                    // Regenerate from path
                    let verfer = Verfer::from_qb64(pub_key)?;
                    let ppt = self.ks.get_pths(pub_key).ok_or_else(|| {
                        SignifyError::Other(format!("Missing prikey for pubkey={}", pub_key))
                    })?;
                    let salt = self.salt().ok_or_else(|| {
                        SignifyError::Other("Missing salt for key regeneration".to_string())
                    })?;
                    let salter = Salter::from_qb64(&salt, ppt.tier)?;
                    let signer = salter.signer(
                        &ppt.code,
                        verfer.transferable(),
                        &ppt.path,
                        Some(ppt.tier),
                        ppt.temp,
                    )?;
                    signers.push(signer);
                }
            }
        } else if let Some(verfer_list) = verfers {
            for verfer in verfer_list {
                let pub_key = verfer.qb64();
                if let Some(ref dec) = self.decrypter {
                    let signer = self.ks.get_pris(pub_key, dec).ok_or_else(|| {
                        SignifyError::Other(format!("Missing prikey for pubkey={}", pub_key))
                    })?;
                    signers.push(signer);
                } else {
                    let ppt = self.ks.get_pths(pub_key).ok_or_else(|| {
                        SignifyError::Other(format!("Missing prikey for pubkey={}", pub_key))
                    })?;
                    let salt = self.salt().ok_or_else(|| {
                        SignifyError::Other("Missing salt for key regeneration".to_string())
                    })?;
                    let salter = Salter::from_qb64(&salt, ppt.tier)?;
                    let signer = salter.signer(
                        &ppt.code,
                        verfer.transferable(),
                        &ppt.path,
                        Some(ppt.tier),
                        ppt.temp,
                    )?;
                    signers.push(signer);
                }
            }
        }

        if let Some(idx) = indices {
            if idx.len() != signers.len() {
                return Err(SignifyError::InvalidArgument(format!(
                    "Mismatch indices length={} and signers length={}",
                    idx.len(),
                    signers.len()
                )));
            }
        }

        // Sign with all signers
        if indexed {
            // Create indexed signatures (Siger)
            let mut result = Vec::new();
            for (i, signer) in signers.iter().enumerate() {
                let index = indices.map(|idx| idx[i]).unwrap_or(i) as u32;
                let sig = signer.sign(ser)?;
                // Determine signature code based on transferability
                let code = if signer.transferable() {
                    matter_codes::ED25519
                } else {
                    matter_codes::ED25519N
                };
                let siger = Siger::new(&sig, code, index, None, Some(signer.verfer().clone()))?;
                result.extend_from_slice(siger.qb64().as_bytes());
            }
            Ok(result)
        } else {
            // Create non-indexed signatures (Cigar)
            let mut result = Vec::new();
            for signer in &signers {
                let sig = signer.sign(ser)?;
                let code = if signer.transferable() {
                    matter_codes::ED25519
                } else {
                    matter_codes::ED25519N
                };
                let cigar = Cigar::new(&sig, code, Some(signer.verfer().clone()))?;
                result.extend_from_slice(cigar.qb64().as_bytes());
            }
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algos_str_conversion() {
        assert_eq!(Algos::Randy.as_str(), "randy");
        assert_eq!(Algos::Salty.as_str(), "salty");
        assert_eq!(Algos::from_str("randy").unwrap(), Algos::Randy);
        assert_eq!(Algos::from_str("salty").unwrap(), Algos::Salty);
    }

    #[test]
    fn test_randy_creator() {
        let creator = RandyCreator::new();
        let keys = creator
            .create(None, 3, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();

        assert_eq!(keys.signers.len(), 3);
        assert!(keys.paths.is_none());

        // Each signer should be different (random)
        assert_ne!(keys.signers[0].qb64(), keys.signers[1].qb64());
        assert_ne!(keys.signers[1].qb64(), keys.signers[2].qb64());
    }

    #[test]
    fn test_salty_creator() {
        let creator = SaltyCreator::new(None, Some(Tier::Low), Some("test")).unwrap();
        let keys1 = creator
            .create(None, 3, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();

        assert_eq!(keys1.signers.len(), 3);
        assert!(keys1.paths.is_some());
        assert_eq!(keys1.paths.as_ref().unwrap().len(), 3);

        // Same salt and paths should generate same keys
        let salt = creator.salt();
        let creator2 = SaltyCreator::new(Some(salt), Some(Tier::Low), Some("test")).unwrap();
        let keys2 = creator2
            .create(None, 3, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();

        assert_eq!(keys1.signers[0].qb64(), keys2.signers[0].qb64());
        assert_eq!(keys1.signers[1].qb64(), keys2.signers[1].qb64());
        assert_eq!(keys1.signers[2].qb64(), keys2.signers[2].qb64());
    }

    #[test]
    fn test_salty_creator_different_paths() {
        let creator = SaltyCreator::new(None, Some(Tier::Low), Some("test")).unwrap();
        let salt = creator.salt();

        // Keys at different rotation indices should be different
        let keys1 = creator
            .create(None, 2, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();

        let keys2 = creator
            .create(None, 2, matter_codes::ED25519_SEED, true, 0, 1, 2, false)
            .unwrap();

        assert_ne!(keys1.signers[0].qb64(), keys2.signers[0].qb64());
    }

    #[test]
    fn test_creatory() {
        let creatory = Creatory::new(Algos::Randy);
        let creator = creatory.make(None, None, None).unwrap();
        let keys = creator
            .create(None, 2, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();
        assert_eq!(keys.signers.len(), 2);

        let creatory = Creatory::new(Algos::Salty);
        let creator = creatory.make(None, Some(Tier::Low), Some("test")).unwrap();
        let keys = creator
            .create(None, 2, matter_codes::ED25519_SEED, true, 0, 0, 0, false)
            .unwrap();
        assert_eq!(keys.signers.len(), 2);
    }
    #[test]
    fn test_manager_basic_workflow_salty() {
        // Use Salty with paths (no encryption) - this is allowed and fast
        let salter = Salter::new(Tier::Low).unwrap();
        let mut mgr = Manager::new(
            Some(Box::new(Keeper::new())),
            None, // No seed = no encryption
            None, // No AEID
            None,
            Some(Algos::Salty),
            Some(&salter),
            Some(Tier::Low),
        )
        .unwrap();

        // Incept with 2 keys using paths
        let (verfers, digers) = mgr
            .incept(
                None,
                2,
                matter_codes::ED25519_SEED,
                None,
                2,
                matter_codes::ED25519_SEED,
                matter_codes::BLAKE3_256,
                None,
                None,
                Some("test"),
                None,
                true, // rooted
                true, // transferable
                false,
            )
            .unwrap();

        assert_eq!(verfers.len(), 2);
        assert_eq!(digers.len(), 2);

        // Verify keys are stored as paths
        assert!(mgr.ks.get_pths(verfers[0].qb64()).is_some());

        // Test signing using verfers
        let message = b"test message";
        let sigs = mgr.sign(message, None, Some(&verfers), true, None).unwrap();
        assert!(sigs.len() > 0);

        // Test rotation
        let pre = verfers[0].qb64();
        let (new_verfers, new_digers) = mgr
            .rotate(
                &pre,
                None,
                2,
                matter_codes::ED25519_SEED,
                matter_codes::BLAKE3_256,
                true,
                false,
            )
            .unwrap();

        assert_eq!(new_verfers.len(), 2);
        assert_eq!(new_digers.len(), 2);
        assert_ne!(verfers[0].qb64(), new_verfers[0].qb64());

        // Verify rotation index incremented
        let sit = mgr.ks.get_sits(&pre).unwrap();
        assert_eq!(sit.new.ridx, 1);
    }

    #[test]
    fn test_manager_sign_fails_without_keys() {
        let mgr = Manager::new(
            Some(Box::new(Keeper::new())),
            None,
            None,
            None,
            Some(Algos::Randy),
            None,
            None,
        )
        .unwrap();

        let message = b"test";
        let result = mgr.sign(message, None, None, true, None);
        assert!(result.is_err());
    }
}
