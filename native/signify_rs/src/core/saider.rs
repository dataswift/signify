//! SAID (Self-Addressing Identifier) support
//!
//! Provides Saider for creating and verifying SAIDs in KERI events

use crate::core::diger::Diger;
use crate::core::matter::{Matter, MatterOpts};
use crate::error::{Result, SignifyError};
use serde_json::Value;

/// Saider - Self-Addressing Identifier
///
/// A Saider is a Matter-based digest that can be embedded in a data structure
/// to make it self-addressing.
#[derive(Debug, Clone)]
pub struct Saider {
    matter: Matter,
}

impl Saider {
    /// Create a new Saider from Matter options
    pub fn new(opts: MatterOpts) -> Result<Self> {
        let matter = Matter::new(opts)?;
        Ok(Self { matter })
    }

    /// Get the underlying Matter
    pub fn matter(&self) -> &Matter {
        &self.matter
    }

    /// Get the qb64 representation
    pub fn qb64(&self) -> String {
        self.matter.qb64().to_string()
    }

    /// Get the code
    pub fn code(&self) -> &str {
        self.matter.code()
    }

    /// Create a SAID for a JSON value and update it with the SAID
    ///
    /// This function:
    /// 1. Takes a mutable reference to a JSON object
    /// 2. Sets the 'd' field to empty string
    /// 3. Serializes and hashes the object
    /// 4. Creates a Saider with that hash
    /// 5. Updates the 'd' field with the SAID qb64
    /// 6. Returns the Saider
    pub fn saidify(sad: &mut Value) -> Result<Self> {
        saidify_with_label(sad, "d")
    }

    /// Create a SAID for a JSON value with custom label
    pub fn saidify_with_label(sad: &mut Value, label: &str) -> Result<Self> {
        saidify_with_label(sad, label)
    }
}

/// Helper function to create SAID and update the sad
fn saidify_with_label(sad: &mut Value, label: &str) -> Result<Saider> {
    // Ensure the sad has the label field
    if !sad.is_object() {
        return Err(SignifyError::InvalidEvent(
            "SAD must be a JSON object".to_string(),
        ));
    }

    // Check for label field and set to empty string
    {
        let obj = sad.as_object_mut().unwrap();
        if !obj.contains_key(label) {
            return Err(SignifyError::InvalidEvent(format!(
                "Missing id field labeled={} in sad",
                label
            )));
        }
        // Set label field to empty string for digest calculation
        obj.insert(label.to_string(), Value::String(String::new()));
    } // Drop mutable borrow here

    // Serialize to JSON (canonical form)
    let json_bytes = serde_json::to_vec(&sad)
        .map_err(|e| SignifyError::SerializationError(format!("Failed to serialize SAD: {}", e)))?;

    // Create digest
    let diger = Diger::new(crate::core::codes::matter_codes::BLAKE3_256, &json_bytes)?;

    // Create Saider from the digest
    let saider = Saider::new(MatterOpts {
        raw: Some(diger.raw().to_vec()),
        code: Some(diger.code().to_string()),
        qb64: None,
        qb64b: None,
        qb2: None,
    })?;

    // Update the sad with the SAID
    let obj = sad.as_object_mut().unwrap();
    obj.insert(label.to_string(), Value::String(saider.qb64()));

    Ok(saider)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_saider_creation() {
        let raw = vec![1u8; 32];
        let saider = Saider::new(MatterOpts {
            raw: Some(raw),
            code: Some(crate::core::codes::matter_codes::BLAKE3_256.to_string()),
            qb64: None,
            qb64b: None,
            qb2: None,
        })
        .unwrap();

        assert_eq!(saider.code(), crate::core::codes::matter_codes::BLAKE3_256);
        assert!(!saider.qb64().is_empty());
    }

    #[test]
    fn test_saidify() {
        let mut sad = json!({
            "v": "KERI1.0JSON_000000",
            "t": "icp",
            "d": "",
            "i": "DSomePrefix",
            "s": "0",
            "kt": "1",
            "k": ["DKey1"],
            "nt": "0",
            "n": [],
            "bt": "0",
            "b": [],
            "c": [],
            "a": []
        });

        let saider = Saider::saidify(&mut sad).unwrap();

        // Verify SAID was set
        assert_ne!(sad["d"], "");
        assert_eq!(sad["d"], saider.qb64());
    }

    #[test]
    fn test_saidify_missing_field() {
        let mut sad = json!({
            "v": "KERI1.0JSON_000000",
            "t": "icp"
        });

        let result = Saider::saidify(&mut sad);
        assert!(result.is_err());
    }

    #[test]
    fn test_saidify_with_custom_label() {
        let mut sad = json!({
            "v": "KERI1.0JSON_000000",
            "t": "icp",
            "custom": "",
            "data": "test"
        });

        let saider = Saider::saidify_with_label(&mut sad, "custom").unwrap();

        // Verify SAID was set in custom field
        assert_ne!(sad["custom"], "");
        assert_eq!(sad["custom"], saider.qb64());
    }
}
