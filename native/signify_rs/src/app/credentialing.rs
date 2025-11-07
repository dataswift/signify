//! ACDC - Authentic Chained Data Containers (Verifiable Credentials)
//!
//! This module implements ACDC credentials following the ACDC specification.
//! ACDCs are self-addressing, self-certifying data containers used for
//! verifiable credentials in the KERI ecosystem.

use crate::core::saider::Saider;
use crate::core::serder::Serder;
use crate::core::utils::{Protocols, Serials, VRSN_1_0};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

/// ACDC Protocol version
pub const ACDC_VERSION: &str = "ACDC10JSON";

/// Credential types
pub mod credential_types {
    pub const ISSUED: &str = "issued";
    pub const RECEIVED: &str = "received";
}

/// Credential subject containing issuee information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// Issuee/holder identifier (AID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i: Option<String>,

    /// Issuance timestamp (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dt: Option<String>,

    /// Privacy salt (UUID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,

    /// Additional subject data
    #[serde(flatten)]
    pub data: HashMap<String, Value>,
}

impl CredentialSubject {
    /// Create a new credential subject
    pub fn new() -> Self {
        Self {
            i: None,
            dt: None,
            u: None,
            data: HashMap::new(),
        }
    }

    /// Set the issuee identifier
    pub fn with_issuee(mut self, issuee: String) -> Self {
        self.i = Some(issuee);
        self
    }

    /// Set the issuance timestamp
    pub fn with_timestamp(mut self, dt: String) -> Self {
        self.dt = Some(dt);
        self
    }

    /// Set the privacy salt
    pub fn with_salt(mut self, salt: String) -> Self {
        self.u = Some(salt);
        self
    }

    /// Add custom data field
    pub fn with_data(mut self, key: String, value: Value) -> Self {
        self.data.insert(key, value);
        self
    }
}

impl Default for CredentialSubject {
    fn default() -> Self {
        Self::new()
    }
}

/// ACDC Credential data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    /// ACDC version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,

    /// Self-addressing identifier (SAID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Privacy salt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,

    /// Issuer identifier (AID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i: Option<String>,

    /// Registry identifier
    pub ri: String,

    /// Schema identifier (SAID)
    pub s: String,

    /// Credential subject (attribute section)
    pub a: CredentialSubject,

    /// Evidence/source section
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<HashMap<String, Value>>,

    /// Rules section
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<HashMap<String, Value>>,
}

impl CredentialData {
    /// Create a new credential data
    pub fn new(registry_id: String, schema_id: String, subject: CredentialSubject) -> Self {
        Self {
            v: None,
            d: None,
            u: None,
            i: None,
            ri: registry_id,
            s: schema_id,
            a: subject,
            e: None,
            r: None,
        }
    }

    /// Set the issuer
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.i = Some(issuer);
        self
    }

    /// Set privacy salt
    pub fn with_salt(mut self, salt: String) -> Self {
        self.u = Some(salt);
        self
    }

    /// Set evidence section
    pub fn with_evidence(mut self, evidence: HashMap<String, Value>) -> Self {
        self.e = Some(evidence);
        self
    }

    /// Set rules section
    pub fn with_rules(mut self, rules: HashMap<String, Value>) -> Self {
        self.r = Some(rules);
        self
    }

    /// Convert to JSON Value for SAIDification
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Issuance event data for a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceData {
    /// Version string
    pub v: String,

    /// Event type (iss)
    pub t: String,

    /// SAID of the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// SAID of the credential being issued
    pub i: String,

    /// Sequence number (always "0" for issuance)
    pub s: String,

    /// Registry identifier
    pub ri: String,

    /// Issuance timestamp
    pub dt: String,
}

/// Result of credential issuance
#[derive(Debug, Clone)]
pub struct IssueCredentialResult {
    /// The ACDC credential
    pub acdc: Serder,

    /// Anchoring interaction event
    pub anc: Serder,

    /// Issuance event
    pub iss: Serder,
}

/// Credential builder for creating ACDC credentials
pub struct CredentialBuilder {
    data: CredentialData,
}

impl CredentialBuilder {
    /// Create a new credential builder
    pub fn new(registry_id: String, schema_id: String, subject: CredentialSubject) -> Self {
        Self {
            data: CredentialData::new(registry_id, schema_id, subject),
        }
    }

    /// Set the issuer
    pub fn issuer(mut self, issuer: String) -> Self {
        self.data = self.data.with_issuer(issuer);
        self
    }

    /// Set privacy salt
    pub fn salt(mut self, salt: String) -> Self {
        self.data = self.data.with_salt(salt);
        self
    }

    /// Set evidence
    pub fn evidence(mut self, evidence: HashMap<String, Value>) -> Self {
        self.data = self.data.with_evidence(evidence);
        self
    }

    /// Set rules
    pub fn rules(mut self, rules: HashMap<String, Value>) -> Self {
        self.data = self.data.with_rules(rules);
        self
    }

    /// Build the credential with SAIDification
    pub fn build(mut self) -> Result<Serder> {
        // Add timestamp to subject if not present
        if self.data.a.dt.is_none() {
            let now = chrono::Utc::now().to_rfc3339();
            self.data.a.dt = Some(now.clone());
        }

        // Convert subject to JSON (no need to SAIDify the subject separately)
        let subject_json = serde_json::to_value(&self.data.a)?;

        // Build the ACDC structure
        let mut acdc_json = json!({
            "v": crate::core::utils::versify(Protocols::ACDC, Some(VRSN_1_0), Some(Serials::JSON), 0),
            "d": "",
            "i": self.data.i.unwrap_or_else(|| "".to_string()),
            "ri": self.data.ri,
            "s": self.data.s,
            "a": subject_json,
        });

        // Add optional fields
        if let Some(ref u) = self.data.u {
            acdc_json["u"] = json!(u);
        }
        if let Some(ref e) = self.data.e {
            acdc_json["e"] = json!(e);
        }
        if let Some(ref r) = self.data.r {
            acdc_json["r"] = json!(r);
        }

        // SAIDify the complete ACDC
        let acdc_saider = Saider::saidify(&mut acdc_json)?;

        // Create Serder from the SAIDified ACDC
        Serder::new(acdc_json, None, None)
    }
}

/// Create an issuance event for a credential
pub fn create_issuance_event(
    credential_said: String,
    registry_id: String,
    timestamp: String,
) -> Result<Serder> {
    let mut iss_json = json!({
        "v": crate::core::utils::versify(Protocols::KERI, Some(VRSN_1_0), Some(Serials::JSON), 0),
        "t": "iss",
        "d": "",
        "i": credential_said,
        "s": "0",
        "ri": registry_id,
        "dt": timestamp,
    });

    // SAIDify the issuance event
    let _iss_saider = Saider::saidify(&mut iss_json)?;

    Serder::new(iss_json, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_subject_builder() {
        let subject = CredentialSubject::new()
            .with_issuee("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string())
            .with_data("name".to_string(), json!("John Doe"))
            .with_data("age".to_string(), json!(30));

        assert_eq!(
            subject.i,
            Some("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string())
        );
        assert_eq!(subject.data.get("name"), Some(&json!("John Doe")));
        assert_eq!(subject.data.get("age"), Some(&json!(30)));
    }

    #[test]
    fn test_credential_builder() {
        let subject = CredentialSubject::new()
            .with_issuee("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string())
            .with_data("name".to_string(), json!("John Doe"));

        let credential = CredentialBuilder::new(
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string(),
            "EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw".to_string(),
            subject,
        )
        .issuer("EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4".to_string())
        .build();

        if let Err(ref e) = credential {
            eprintln!("Credential build error: {:?}", e);
        }
        assert!(credential.is_ok());
        let cred = credential.unwrap();

        let sad = cred.sad();
        assert_eq!(sad.get("t"), None); // ACDC doesn't have 't' field
        assert!(sad.get("d").is_some());
        assert!(sad.get("a").is_some());
    }

    #[test]
    fn test_issuance_event() {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let iss = create_issuance_event(
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string(),
            "EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string(),
            timestamp,
        );

        assert!(iss.is_ok());
        let iss_event = iss.unwrap();

        let sad = iss_event.sad();
        assert_eq!(sad.get("t").and_then(|v| v.as_str()), Some("iss"));
        assert_eq!(sad.get("s").and_then(|v| v.as_str()), Some("0"));
        assert!(sad.get("d").is_some());
    }

    #[test]
    fn test_credential_data_serialization() {
        let subject = CredentialSubject::new()
            .with_issuee("EaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM".to_string())
            .with_data("field1".to_string(), json!("value1"));

        let data = CredentialData::new("reg123".to_string(), "schema456".to_string(), subject)
            .with_issuer("issuer789".to_string());

        let json_value = data.to_value();
        assert!(json_value.is_object());
        assert_eq!(
            json_value.get("ri").and_then(|v| v.as_str()),
            Some("reg123")
        );
        assert_eq!(
            json_value.get("s").and_then(|v| v.as_str()),
            Some("schema456")
        );
        assert_eq!(
            json_value.get("i").and_then(|v| v.as_str()),
            Some("issuer789")
        );
    }
}

//
// Credentials API Client
//

/// Result of a credential query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResult {
    /// Self-addressing data of the credential
    pub sad: Value,
    /// Credential status information
    pub status: Option<CredentialStatus>,
    /// Schema SAID
    pub schema: Option<String>,
}

/// Credential status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// Status type (e.g., "issued", "revoked")
    #[serde(rename = "et")]
    pub event_type: Option<String>,
    /// Status timestamp
    pub dt: Option<String>,
}

/// Filter for querying credentials
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialFilter {
    /// Filter criteria
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Value>,
    /// Sort order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<Vec<Value>>,
    /// Number of results to skip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip: Option<usize>,
    /// Maximum number of results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Credentials client for interacting with KERIA credential endpoints
pub struct Credentials {
    client: std::sync::Arc<crate::app::clienting::SignifyClient>,
}

impl Credentials {
    /// Create a new Credentials client
    ///
    /// # Arguments
    /// * `client` - SignifyClient instance
    pub fn new(client: std::sync::Arc<crate::app::clienting::SignifyClient>) -> Self {
        Self { client }
    }

    /// List credentials from KERIA
    ///
    /// # Arguments
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    /// List of credentials matching the filter
    ///
    /// # Example
    /// ```no_run
    /// use trustex::app::{Credentials, CredentialFilter};
    ///
    /// # async fn example(client: std::sync::Arc<trustex::app::SignifyClient>) -> trustex::error::Result<()> {
    /// let credentials = Credentials::new(client);
    /// let filter = CredentialFilter {
    ///     limit: Some(10),
    ///     ..Default::default()
    /// };
    /// let results = credentials.list(Some(filter)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self, filter: Option<CredentialFilter>) -> Result<Vec<CredentialResult>> {
        let path = "/credentials/query";

        let filter_data = filter.unwrap_or_else(|| CredentialFilter {
            filter: Some(json!({})),
            sort: Some(vec![]),
            skip: Some(0),
            limit: Some(25),
        });

        let body = json!({
            "filter": filter_data.filter.unwrap_or_else(|| json!({})),
            "sort": filter_data.sort.unwrap_or_else(Vec::new),
            "skip": filter_data.skip.unwrap_or(0),
            "limit": filter_data.limit.unwrap_or(25),
        });

        let response = self
            .client
            .fetch(path, reqwest::Method::POST, Some(body))
            .await?;

        let results: Vec<CredentialResult> = response
            .json()
            .await
            .map_err(|e| crate::error::SignifyError::ParseError(e.to_string()))?;

        Ok(results)
    }

    /// Get a specific credential by SAID
    ///
    /// # Arguments
    /// * `said` - SAID of the credential
    /// * `include_cesr` - If true, returns raw CESR format string; if false, returns JSON
    ///
    /// # Returns
    /// Either CredentialResult (JSON) or String (CESR) depending on include_cesr flag
    ///
    /// # Example
    /// ```no_run
    /// use trustex::app::Credentials;
    ///
    /// # async fn example(client: std::sync::Arc<trustex::app::SignifyClient>) -> trustex::error::Result<()> {
    /// let credentials = Credentials::new(client);
    ///
    /// // Get as JSON
    /// let result = credentials.get_json("EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS").await?;
    ///
    /// // Get as CESR
    /// let cesr = credentials.get_cesr("EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_json(&self, said: &str) -> Result<CredentialResult> {
        let path = format!("/credentials/{}", said);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        let response = self.client.fetch(&path, reqwest::Method::GET, None).await?;

        let result: CredentialResult = response
            .json()
            .await
            .map_err(|e| crate::error::SignifyError::ParseError(e.to_string()))?;

        Ok(result)
    }

    /// Get a credential in CESR format
    ///
    /// # Arguments
    /// * `said` - SAID of the credential
    ///
    /// # Returns
    /// Raw CESR format string
    pub async fn get_cesr(&self, said: &str) -> Result<String> {
        let path = format!("/credentials/{}", said);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json+cesr"),
        );

        let response = self.client.fetch(&path, reqwest::Method::GET, None).await?;

        let cesr_data = response
            .text()
            .await
            .map_err(|e| crate::error::SignifyError::NetworkError(e.to_string()))?;

        Ok(cesr_data)
    }

    /// Delete a credential from the KERIA database
    ///
    /// # Arguments
    /// * `said` - SAID of the credential to delete
    ///
    /// # Example
    /// ```no_run
    /// use trustex::app::Credentials;
    ///
    /// # async fn example(client: std::sync::Arc<trustex::app::SignifyClient>) -> trustex::error::Result<()> {
    /// let credentials = Credentials::new(client);
    /// credentials.delete("EINmHd5g7iV-UldkkkKyBIH052bIyxZNBn9pq-zNrYoS").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete(&self, said: &str) -> Result<()> {
        let path = format!("/credentials/{}", said);

        self.client
            .fetch(&path, reqwest::Method::DELETE, None)
            .await?;

        Ok(())
    }
}
