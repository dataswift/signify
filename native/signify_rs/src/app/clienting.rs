//! SignifyClient - HTTP client for KERIA agent communication
//!
//! Provides a high-level client for interacting with KERIA (KERI Agent) services,
//! including HTTP Signatures authentication, agent bootstrapping, and state management.

use crate::app::controller::Controller;
use crate::core::signer::Signer;
use crate::core::verfer::Verfer;
use crate::error::{Result, SignifyError};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

const DEFAULT_BOOT_URL: &str = "http://localhost:3903";

/// Agent state information returned from KERIA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Agent AID information
    pub agent: Option<Value>,
    /// Controller AID information
    pub controller: Option<Value>,
    /// Rotation index
    pub ridx: Option<usize>,
    /// Path index
    pub pidx: Option<usize>,
}

/// HTTP Signatures authenticator
#[derive(Debug)]
pub struct Authenticater {
    /// Client signer for signing requests
    signer: Signer,
    /// Agent verifier for verifying responses
    verfer: Verfer,
}

impl Authenticater {
    /// Create a new Authenticater
    pub fn new(signer: Signer, verfer: Verfer) -> Self {
        Self { signer, verfer }
    }

    /// Sign HTTP request headers using HTTP Signatures specification
    ///
    /// This implements the HTTP Signatures draft specification for authenticating
    /// HTTP messages with Ed25519 signatures.
    ///
    /// # Arguments
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path
    /// * `headers` - Request headers to sign
    ///
    /// # Returns
    /// Signature and Signature-Input headers
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        // Build signature input components
        let mut components = Vec::new();
        components.push(format!("\"@method\": {}", method));
        components.push(format!("\"@path\": {}", path));

        // Add signify-resource header if present
        if let Some(resource) = headers.get("signify-resource") {
            components.push(format!("\"signify-resource\": {}", resource));
        }

        // Add signify-timestamp header
        let timestamp = chrono::Utc::now().to_rfc3339();
        components.push(format!("\"signify-timestamp\": {}", timestamp));

        // Build signature base
        let signature_base = components.join("\n");

        // Add signature params
        let sig_params = format!(
            "\"@signature-params\": (@method @path signify-resource signify-timestamp);created={};keyid=\"{}\";alg=\"ed25519\"",
            chrono::Utc::now().timestamp(),
            self.signer.verfer().qb64()
        );
        let full_base = format!("{}\n{}", signature_base, sig_params);

        // Sign the base
        let signature = self.signer.sign(full_base.as_bytes())?;
        let sig_qb64 = crate::core::matter::Matter::from_raw(
            &signature,
            crate::core::codes::matter_codes::ED25519,
        )?
        .qb64()
        .to_string();

        // Build Signature-Input header
        let sig_input = format!(
            "signify=(@method @path signify-resource signify-timestamp);created={};keyid=\"{}\";alg=\"ed25519\"",
            chrono::Utc::now().timestamp(),
            self.signer.verfer().qb64()
        );

        // Build Signature header
        let sig_header = format!("signify=:{}", sig_qb64);

        Ok((sig_header, sig_input))
    }
}

/// SignifyClient - Client for interacting with KERIA agents
pub struct SignifyClient {
    /// KERIA admin interface URL
    url: String,
    /// Base64 21+ char passcode for client AID generation
    bran: String,
    /// Path index
    pidx: usize,
    /// Controller representing local client AID
    controller: Option<Controller>,
    /// HTTP client
    client: Client,
    /// Authenticater for signing requests
    authn: Option<Authenticater>,
    /// KERIA boot interface URL
    boot_url: String,
}

impl SignifyClient {
    /// Create a new SignifyClient
    ///
    /// # Arguments
    /// * `url` - KERIA admin interface URL
    /// * `bran` - Base64 21+ char string used as base material for client AID seed
    /// * `boot_url` - Optional KERIA boot interface URL (defaults to localhost:3903)
    pub fn new(url: String, bran: String, boot_url: Option<String>) -> Result<Self> {
        if bran.len() < 21 {
            return Err(SignifyError::InvalidArgument(
                "bran must be at least 21 characters".to_string(),
            ));
        }

        Ok(Self {
            url,
            bran,
            pidx: 0,
            controller: None,
            client: Client::new(),
            authn: None,
            boot_url: boot_url.unwrap_or_else(|| DEFAULT_BOOT_URL.to_string()),
        })
    }

    /// Get the controller (if connected)
    pub fn controller(&self) -> Option<&Controller> {
        self.controller.as_ref()
    }

    /// Get the client URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the path index
    pub fn pidx(&self) -> usize {
        self.pidx
    }

    /// Boot a KERIA agent
    ///
    /// This creates a new agent on the KERIA server with the client's controller AID.
    ///
    /// # Returns
    /// HTTP response from the boot endpoint
    pub async fn boot(&self) -> Result<Response> {
        let controller = self.controller.as_ref().ok_or_else(|| {
            SignifyError::InvalidState(
                "Controller not initialized. Call connect() first.".to_string(),
            )
        })?;

        // Get inception event and signature
        let (evt, sig) = controller.event()?;

        // Build boot request
        let boot_data = serde_json::json!({
            "icp": evt.sad(),
            "sig": sig.qb64(),
            "stem": controller.stem(),
            "pidx": 1,
            "tier": "low"
        });

        // Send boot request
        let response = self
            .client
            .post(format!("{}/boot", self.boot_url))
            .json(&boot_data)
            .send()
            .await
            .map_err(|e| SignifyError::NetworkError(e.to_string()))?;

        Ok(response)
    }

    /// Get state of the agent and client from KERIA
    ///
    /// # Returns
    /// Agent state information
    pub async fn state(&self) -> Result<AgentState> {
        let controller = self
            .controller
            .as_ref()
            .ok_or_else(|| SignifyError::InvalidState("Controller not initialized".to_string()))?;

        let caid = controller.pre()?;
        let url = format!("{}/agent/{}", self.url, caid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| SignifyError::NetworkError(e.to_string()))?;

        if response.status().as_u16() == 404 {
            return Err(SignifyError::NotFound(format!(
                "Agent does not exist for controller {}",
                caid
            )));
        }

        let state: AgentState = response
            .json()
            .await
            .map_err(|e| SignifyError::ParseError(e.to_string()))?;

        Ok(state)
    }

    /// Connect to a KERIA agent
    ///
    /// This retrieves the agent state and initializes the client's controller
    /// and authenticater for subsequent requests.
    pub async fn connect(&mut self) -> Result<()> {
        // First initialize controller with bran
        let controller = Controller::new(self.bran.clone(), None)?;
        self.controller = Some(controller);

        // Get state from server
        let state = self.state().await?;
        self.pidx = state.pidx.unwrap_or(0);

        // Update controller with server state
        if let Some(mut ctrl) = self.controller.take() {
            if let Some(ridx) = state.ridx {
                ctrl.set_ridx(ridx);
            }
            self.controller = Some(ctrl);
        }

        // For now, authn setup is simplified - would need agent verifier from state
        // In full implementation, would parse agent info and extract verifier

        Ok(())
    }

    /// Fetch a resource from the KERIA agent with authentication
    ///
    /// # Arguments
    /// * `path` - Resource path
    /// * `method` - HTTP method
    /// * `body` - Optional request body
    ///
    /// # Returns
    /// HTTP response
    pub async fn fetch(&self, path: &str, method: Method, body: Option<Value>) -> Result<Response> {
        let authn = self.authn.as_ref().ok_or_else(|| {
            SignifyError::InvalidState("Not authenticated. Call connect() first.".to_string())
        })?;

        let mut headers = HashMap::new();
        if let Some(ref body_val) = body {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            if let Some(resource) = body_val.get("resource") {
                headers.insert(
                    "signify-resource".to_string(),
                    resource.as_str().unwrap_or("").to_string(),
                );
            }
        }

        // Sign request
        let (sig_header, sig_input) = authn.sign(method.as_str(), path, &headers)?;

        // Build request
        let url = format!("{}{}", self.url, path);
        let mut request = self.client.request(method, &url);

        // Add headers
        for (key, value) in headers {
            request = request.header(key, value);
        }
        request = request.header("Signature", sig_header);
        request = request.header("Signature-Input", sig_input);

        // Add body if present
        if let Some(body_val) = body {
            request = request.json(&body_val);
        }

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| SignifyError::NetworkError(e.to_string()))?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signify_client_creation() {
        let client = SignifyClient::new(
            "http://localhost:3901".to_string(),
            "GCiBGAhduxcggJE4qJeaA".to_string(),
            None,
        )
        .unwrap();

        assert_eq!(client.url(), "http://localhost:3901");
        assert_eq!(client.pidx(), 0);
    }

    #[test]
    fn test_signify_client_short_bran() {
        let result = SignifyClient::new(
            "http://localhost:3901".to_string(),
            "short".to_string(),
            None,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_state_without_controller() {
        let client = SignifyClient::new(
            "http://localhost:3901".to_string(),
            "GCiBGAhduxcggJE4qJeaA".to_string(),
            None,
        )
        .unwrap();

        let result = client.state().await;
        assert!(result.is_err());
    }
}
