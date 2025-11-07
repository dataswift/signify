use crate::core::{
    matter_codes,
    utils::{deversify, versify, Protocols, Serials, Version},
    Diger,
};
/// Serder - Serializer/Deserializer for KERI events with SAID calculation
use crate::error::{Result, SignifyError};
use serde_json::{json, Value};

/// Serder handles KERI event serialization with Self-Addressing IDentifiers (SAID)
#[derive(Debug, Clone)]
pub struct Serder {
    /// The serialized event as a string
    raw: String,
    /// The self-addressing data (event as JSON object)
    sad: Value,
    /// Protocol type (KERI or ACDC)
    proto: Protocols,
    /// Serialization kind (JSON, CBOR, MGPK)
    kind: Serials,
    /// Size of the serialized event in bytes
    size: usize,
    /// Version of the protocol
    version: Version,
    /// Digest code used for SAID
    code: String,
}

impl Serder {
    /// Create a new Serder from a self-addressing data dictionary
    ///
    /// # Arguments
    /// * `sad` - Self-addressing data as JSON Value
    /// * `kind` - Serialization type (default: JSON)
    /// * `code` - Digest code for SAID (default: Blake3_256)
    pub fn new(sad: Value, kind: Option<Serials>, code: Option<&str>) -> Result<Self> {
        let kind = kind.unwrap_or(Serials::JSON);
        let code = code.unwrap_or(matter_codes::BLAKE3_256).to_string();

        let (raw, proto, kind, sad, version) = Self::sizeify(sad, kind)?;
        let size = raw.len();

        Ok(Self {
            raw,
            sad,
            proto,
            kind,
            size,
            version,
            code,
        })
    }

    /// Create Serder from raw serialized event
    pub fn from_raw(raw: &str) -> Result<Self> {
        let sad: Value = serde_json::from_str(raw)
            .map_err(|e| SignifyError::SerializationError(e.to_string()))?;

        // Extract version to determine protocol and kind
        let version_str = sad
            .get("v")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SignifyError::InvalidEvent("Missing version string".to_string()))?
            .to_string();

        let (proto, version, kind, size) = deversify(&version_str)?;

        // Get digest code from 'd' field if present
        let code = if let Some(d) = sad.get("d").and_then(|v| v.as_str()) {
            // Extract code from qb64 SAID (first character)
            if !d.is_empty() {
                d[0..1].to_string()
            } else {
                matter_codes::BLAKE3_256.to_string()
            }
        } else {
            matter_codes::BLAKE3_256.to_string()
        };

        Ok(Self {
            raw: raw.to_string(),
            sad,
            proto,
            kind,
            size,
            version,
            code,
        })
    }

    /// Calculate SAID (Self-Addressing IDentifier) for the event
    ///
    /// This replaces the 'd' field with a dummy value, serializes, hashes,
    /// and returns the digest as qb64
    pub fn said(&self, code: Option<&str>) -> Result<String> {
        let code = code.unwrap_or(&self.code);
        let (digest_bytes, _) = Self::derive_said(&self.sad, code, Some(self.kind))?;

        // Create a Diger from the digest bytes
        let diger = Diger::from_raw(&digest_bytes, code)?;
        Ok(diger.qb64().to_string())
    }

    /// Derive SAID from a SAD (Self-Addressing Data) dictionary
    ///
    /// This is the core SAID calculation algorithm:
    /// 1. Clone the SAD
    /// 2. Replace 'd' field with dummy value (correct length of '#' chars)
    /// 3. Update version string with correct size
    /// 4. Serialize to JSON
    /// 5. Hash the serialized data
    pub fn derive_said(sad: &Value, code: &str, kind: Option<Serials>) -> Result<(Vec<u8>, Value)> {
        let kind = kind.unwrap_or(Serials::JSON);

        // Clone SAD and set dummy SAID field
        let mut sad = sad.clone();
        let sad_obj = sad
            .as_object_mut()
            .ok_or_else(|| SignifyError::InvalidEvent("SAD must be an object".to_string()))?;

        // Get the qb64 size for this digest code
        let qb64_size = crate::core::codes::sizage(code)?
            .fs
            .ok_or_else(|| SignifyError::InvalidCode(format!("No qb64 size for code {}", code)))?;

        // Set dummy value for 'd' field
        let dummy = "#".repeat(qb64_size);
        sad_obj.insert("d".to_string(), json!(dummy));

        // Update version string with size
        let (raw, _, _, sad, _) = Self::sizeify(sad, kind)?;

        // Hash the serialized data
        let digest_bytes = blake3::hash(raw.as_bytes()).as_bytes().to_vec();

        Ok((digest_bytes, sad))
    }

    /// Sizeify: Calculate size and update version string
    ///
    /// This updates the version string to include the correct byte size
    /// of the serialized event
    fn sizeify(
        mut sad: Value,
        kind: Serials,
    ) -> Result<(String, Protocols, Serials, Value, Version)> {
        // Check for version string
        let version_str = sad
            .get("v")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SignifyError::InvalidEvent("Missing or empty version string".to_string())
            })?
            .to_string();

        let (proto, version, _kind, _size) = deversify(&version_str)?;

        // Serialize to get size
        let raw = Self::dumps(&sad, kind)?;
        let size = raw.len();

        // Update version string with correct size
        let new_version_str = versify(proto, Some(version), Some(kind), size);

        // Now we can mutably borrow sad_obj
        let sad_obj = sad
            .as_object_mut()
            .ok_or_else(|| SignifyError::InvalidEvent("SAD must be an object".to_string()))?;
        sad_obj.insert("v".to_string(), json!(new_version_str));

        // Serialize again with updated version
        let raw = Self::dumps(&sad, kind)?;

        Ok((raw, proto, kind, sad, version))
    }

    /// Serialize SAD to string based on kind
    fn dumps(sad: &Value, kind: Serials) -> Result<String> {
        match kind {
            Serials::JSON => {
                // Use compact JSON (no pretty printing)
                serde_json::to_string(sad)
                    .map_err(|e| SignifyError::SerializationError(e.to_string()))
            }
            Serials::CBOR | Serials::MGPK => Err(SignifyError::SerializationError(
                "CBOR and MGPK not yet supported".to_string(),
            )),
        }
    }

    // Getters
    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn sad(&self) -> &Value {
        &self.sad
    }

    pub fn proto(&self) -> Protocols {
        self.proto
    }

    pub fn kind(&self) -> Serials {
        self.kind
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get the identifier prefix from the 'i' field
    pub fn pre(&self) -> Option<&str> {
        self.sad.get("i").and_then(|v| v.as_str())
    }

    /// Get the SAID from the 'd' field
    pub fn said_field(&self) -> Option<&str> {
        self.sad.get("d").and_then(|v| v.as_str())
    }

    /// Get the sequence number from the 's' field
    pub fn sn(&self) -> Option<u64> {
        self.sad
            .get("s")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s, 16).ok())
    }

    /// Get the event type (ilk) from the 't' field
    pub fn ilk(&self) -> Option<&str> {
        self.sad.get("t").and_then(|v| v.as_str())
    }

    /// Pretty print the SAD
    pub fn pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.sad)
            .map_err(|e| SignifyError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serder_basic() {
        let sad = json!({
            "v": "KERI10JSON00006a_",
            "t": "icp",
            "d": "",
            "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "s": "0",
            "kt": "1",
            "k": ["DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"],
            "n": ["EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM"],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        let serder = Serder::new(sad, None, None).unwrap();
        assert_eq!(serder.proto(), Protocols::KERI);
        assert_eq!(serder.kind(), Serials::JSON);
        assert!(serder.size() > 0);
    }

    #[test]
    fn test_serder_from_raw() {
        let raw = r#"{"v":"KERI10JSON00006a_","t":"icp","d":"E","i":"EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM","s":"0"}"#;
        let serder = Serder::from_raw(raw).unwrap();

        assert_eq!(serder.proto(), Protocols::KERI);
        assert_eq!(serder.ilk(), Some("icp"));
        assert_eq!(serder.sn(), Some(0));
    }

    #[test]
    fn test_serder_said_calculation() {
        let sad = json!({
            "v": "KERI10JSON00006a_",
            "t": "icp",
            "d": "",
            "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "s": "0"
        });

        let serder = Serder::new(sad.clone(), None, Some(matter_codes::BLAKE3_256)).unwrap();
        let said = serder.said(None).unwrap();

        // SAID should be a valid qb64 string
        assert_eq!(said.len(), 44); // Blake3-256 qb64 is 44 chars
        assert!(said.starts_with('E')); // Blake3-256 code
    }

    #[test]
    fn test_serder_sizeify() {
        let sad = json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "test"
        });

        let (raw, proto, kind, updated_sad, _) = Serder::sizeify(sad, Serials::JSON).unwrap();

        // Version string should be updated with correct size
        let version = updated_sad["v"].as_str().unwrap();
        assert!(version.contains(&format!("{:06x}", raw.len())));
        assert_eq!(proto, Protocols::KERI);
        assert_eq!(kind, Serials::JSON);
    }

    #[test]
    fn test_serder_getters() {
        let sad = json!({
            "v": "KERI10JSON00006a_",
            "t": "icp",
            "d": "EaU6JR2nmwyZ",
            "i": "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",
            "s": "5"
        });

        let serder = Serder::new(sad, None, None).unwrap();

        assert_eq!(serder.ilk(), Some("icp"));
        assert_eq!(
            serder.pre(),
            Some("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM")
        );
        assert_eq!(serder.sn(), Some(5));
        assert_eq!(serder.said_field(), Some("EaU6JR2nmwyZ"));
    }

    #[test]
    fn test_serder_derive_said() {
        let sad = json!({
            "v": "KERI10JSON00006a_",
            "t": "icp",
            "d": "",
            "i": "test",
            "s": "0"
        });

        let (digest, updated_sad) =
            Serder::derive_said(&sad, matter_codes::BLAKE3_256, None).unwrap();

        // Digest should be 32 bytes (Blake3-256)
        assert_eq!(digest.len(), 32);

        // Updated SAD should have dummy 'd' field
        let d_field = updated_sad["d"].as_str().unwrap();
        assert!(d_field.chars().all(|c| c == '#'));
        assert_eq!(d_field.len(), 44); // Blake3-256 qb64 size
    }

    #[test]
    fn test_serder_pretty() {
        let sad = json!({
            "v": "KERI10JSON00006a_",
            "t": "icp",
            "d": "",
            "i": "test"
        });

        let serder = Serder::new(sad, None, None).unwrap();
        let pretty = serder.pretty().unwrap();

        // Pretty print should contain newlines and indentation
        assert!(pretty.contains('\n'));
        assert!(pretty.len() > serder.raw().len());
    }
}
