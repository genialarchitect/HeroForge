//! Opsgenie integration

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Opsgenie API base URL
const OPSGENIE_API_BASE: &str = "https://api.opsgenie.com/v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsgenieAlertRequest {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responders: Option<Vec<OpsgenieResponder>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsgenieResponder {
    #[serde(rename = "type")]
    pub responder_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsgenieAlertResponse {
    pub result: String,
    pub took: f64,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsgenieAlert {
    pub id: String,
    #[serde(rename = "tinyId")]
    pub tiny_id: String,
    pub message: String,
    pub status: String,
    pub priority: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

pub struct OpsgenieIntegration {
    api_key: String,
    base_url: String,
}

impl OpsgenieIntegration {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: OPSGENIE_API_BASE.to_string(),
        }
    }

    /// Create integration with custom API base URL (e.g., for EU region)
    pub fn with_base_url(api_key: String, base_url: String) -> Self {
        Self { api_key, base_url }
    }

    /// Create an Opsgenie alert
    ///
    /// # Arguments
    /// * `message` - Alert message (required)
    /// * `priority` - Alert priority (P1, P2, P3, P4, P5)
    ///
    /// # Returns
    /// The request ID of the created alert
    pub async fn create_alert(&self, message: &str, priority: &str) -> Result<String> {
        let client = reqwest::Client::new();

        // Validate and normalize priority
        let normalized_priority = match priority.to_uppercase().as_str() {
            "P1" | "CRITICAL" => "P1",
            "P2" | "HIGH" => "P2",
            "P3" | "MEDIUM" | "MODERATE" => "P3",
            "P4" | "LOW" => "P4",
            "P5" | "INFORMATIONAL" | "INFO" => "P5",
            _ => "P3", // Default to P3 if unknown
        };

        let alert_request = OpsgenieAlertRequest {
            message: message.to_string(),
            alias: None,
            description: None,
            responders: None,
            tags: Some(vec!["heroforge".to_string()]),
            priority: Some(normalized_priority.to_string()),
            entity: None,
            source: Some("HeroForge Security Platform".to_string()),
            details: None,
        };

        let url = format!("{}/alerts", self.base_url);

        let response = client
            .post(&url)
            .header("Authorization", format!("GenieKey {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&alert_request)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Opsgenie API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Opsgenie API error ({}): {}",
                status,
                body
            ));
        }

        let alert_response: OpsgenieAlertResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse Opsgenie response: {}", e))?;

        Ok(alert_response.request_id)
    }

    /// Create an alert with full options
    pub async fn create_alert_with_options(&self, request: OpsgenieAlertRequest) -> Result<String> {
        let client = reqwest::Client::new();
        let url = format!("{}/alerts", self.base_url);

        let response = client
            .post(&url)
            .header("Authorization", format!("GenieKey {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Opsgenie API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Opsgenie API error ({}): {}",
                status,
                body
            ));
        }

        let alert_response: OpsgenieAlertResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse Opsgenie response: {}", e))?;

        Ok(alert_response.request_id)
    }

    /// Close an alert by ID or alias
    pub async fn close_alert(&self, identifier: &str, by_alias: bool) -> Result<String> {
        let client = reqwest::Client::new();

        let mut url = format!("{}/alerts/{}/close", self.base_url, identifier);
        if by_alias {
            url.push_str("?identifierType=alias");
        }

        let response = client
            .post(&url)
            .header("Authorization", format!("GenieKey {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "source": "HeroForge Security Platform",
                "note": "Alert closed via HeroForge integration"
            }))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Opsgenie API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Opsgenie API error ({}): {}",
                status,
                body
            ));
        }

        let close_response: OpsgenieAlertResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse Opsgenie response: {}", e))?;

        Ok(close_response.request_id)
    }

    /// Get alert details by ID
    pub async fn get_alert(&self, alert_id: &str) -> Result<OpsgenieAlert> {
        let client = reqwest::Client::new();
        let url = format!("{}/alerts/{}", self.base_url, alert_id);

        let response = client
            .get(&url)
            .header("Authorization", format!("GenieKey {}", self.api_key))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Opsgenie API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Opsgenie API error: {}", response.status()));
        }

        #[derive(Deserialize)]
        struct AlertWrapper {
            data: OpsgenieAlert,
        }

        let wrapper: AlertWrapper = response.json().await
            .map_err(|e| anyhow!("Failed to parse alert: {}", e))?;

        Ok(wrapper.data)
    }

    /// Add a note to an alert
    pub async fn add_note(&self, alert_id: &str, note: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let url = format!("{}/alerts/{}/notes", self.base_url, alert_id);

        let response = client
            .post(&url)
            .header("Authorization", format!("GenieKey {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "note": note,
                "source": "HeroForge Security Platform"
            }))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to connect to Opsgenie API: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Opsgenie API error: {}", response.status()));
        }

        let note_response: OpsgenieAlertResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

        Ok(note_response.request_id)
    }
}
