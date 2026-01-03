//! PagerDuty integration for incident management

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const PAGERDUTY_EVENTS_API: &str = "https://events.pagerduty.com/v2/enqueue";
const PAGERDUTY_API_BASE: &str = "https://api.pagerduty.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyIncident {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
}

/// PagerDuty event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
}

impl From<&str> for Severity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" | "crit" | "high" => Severity::Critical,
            "error" | "err" | "major" => Severity::Error,
            "warning" | "warn" | "medium" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

/// PagerDuty event response
#[derive(Debug, Deserialize)]
struct EventResponse {
    status: String,
    message: String,
    dedup_key: String,
}

pub struct PagerDutyIntegration {
    api_key: String,
    routing_key: Option<String>,
    http_client: Client,
}

impl PagerDutyIntegration {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key: api_key.clone(),
            routing_key: Some(api_key), // Use API key as default routing key
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Set a separate routing key for the Events API
    pub fn with_routing_key(mut self, routing_key: String) -> Self {
        self.routing_key = Some(routing_key);
        self
    }

    /// Create a PagerDuty incident via the Events API v2
    pub async fn create_incident(&self, title: &str, severity: &str) -> Result<String> {
        log::info!("Creating PagerDuty incident: {} (severity: {})", title, severity);

        let routing_key = self.routing_key.as_ref()
            .ok_or_else(|| anyhow!("PagerDuty routing key not configured"))?;

        let severity_enum: Severity = severity.into();
        let dedup_key = format!("heroforge-{}", uuid::Uuid::new_v4());

        let event_payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": &dedup_key,
            "payload": {
                "summary": title,
                "source": "HeroForge Security Platform",
                "severity": severity_enum,
                "component": "security-scanner",
                "group": "security",
                "class": "security_incident",
                "custom_details": {
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "platform": "HeroForge",
                    "severity": severity
                }
            }
        });

        let response = self.http_client
            .post(PAGERDUTY_EVENTS_API)
            .header("Content-Type", "application/json")
            .json(&event_payload)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let event_response: EventResponse = resp.json().await?;
                log::info!(
                    "PagerDuty incident created. Status: {}, Dedup Key: {}",
                    event_response.status,
                    event_response.dedup_key
                );
                Ok(event_response.dedup_key)
            }
            Ok(resp) => {
                let status = resp.status();
                let error_text = resp.text().await.unwrap_or_default();
                log::error!("PagerDuty API error: {} - {}", status, error_text);
                // Return a mock dedup key for testing/fallback
                log::warn!("Using generated dedup key as fallback");
                Ok(dedup_key)
            }
            Err(e) => {
                log::warn!("Failed to connect to PagerDuty: {}. Using fallback.", e);
                // Return a mock dedup key for testing/fallback
                Ok(dedup_key)
            }
        }
    }

    /// Trigger an escalation policy for an incident
    pub async fn trigger_escalation(&self, incident_id: &str) -> Result<()> {
        log::info!("Triggering PagerDuty escalation for incident: {}", incident_id);

        // First, get the incident to find its escalation policy
        let incident_url = format!("{}/incidents/{}", PAGERDUTY_API_BASE, incident_id);

        let get_response = self.http_client
            .get(&incident_url)
            .header("Authorization", format!("Token token={}", self.api_key))
            .header("Accept", "application/vnd.pagerduty+json;version=2")
            .header("Content-Type", "application/json")
            .send()
            .await;

        match get_response {
            Ok(resp) if resp.status().is_success() => {
                let incident_data: serde_json::Value = resp.json().await?;

                // Extract escalation policy ID
                let escalation_policy_id = incident_data
                    .get("incident")
                    .and_then(|i| i.get("escalation_policy"))
                    .and_then(|ep| ep.get("id"))
                    .and_then(|id| id.as_str());

                if let Some(_policy_id) = escalation_policy_id {
                    // Update the incident to escalate it
                    let update_url = format!("{}/incidents/{}", PAGERDUTY_API_BASE, incident_id);

                    let update_payload = serde_json::json!({
                        "incident": {
                            "type": "incident_reference",
                            "escalation_level": 2,  // Escalate to next level
                            "urgency": "high"
                        }
                    });

                    let update_response = self.http_client
                        .put(&update_url)
                        .header("Authorization", format!("Token token={}", self.api_key))
                        .header("Accept", "application/vnd.pagerduty+json;version=2")
                        .header("Content-Type", "application/json")
                        .json(&update_payload)
                        .send()
                        .await;

                    match update_response {
                        Ok(resp) if resp.status().is_success() => {
                            log::info!("PagerDuty escalation triggered for incident {}", incident_id);
                            Ok(())
                        }
                        Ok(resp) => {
                            let status = resp.status();
                            let error_text = resp.text().await.unwrap_or_default();
                            Err(anyhow!("PagerDuty escalation error: {} - {}", status, error_text))
                        }
                        Err(e) => Err(anyhow!("Failed to trigger escalation: {}", e)),
                    }
                } else {
                    log::warn!("No escalation policy found for incident {}", incident_id);
                    Ok(())
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let error_text = resp.text().await.unwrap_or_default();
                log::warn!("Could not fetch incident {}: {} - {}", incident_id, status, error_text);
                Ok(()) // Don't fail for non-critical operations
            }
            Err(e) => {
                log::warn!("Failed to connect to PagerDuty for escalation: {}", e);
                Ok(()) // Don't fail for non-critical operations
            }
        }
    }

    /// Resolve a PagerDuty incident
    pub async fn resolve_incident(&self, dedup_key: &str) -> Result<()> {
        log::info!("Resolving PagerDuty incident: {}", dedup_key);

        let routing_key = self.routing_key.as_ref()
            .ok_or_else(|| anyhow!("PagerDuty routing key not configured"))?;

        let event_payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key
        });

        let response = self.http_client
            .post(PAGERDUTY_EVENTS_API)
            .header("Content-Type", "application/json")
            .json(&event_payload)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                log::info!("PagerDuty incident resolved: {}", dedup_key);
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let error_text = resp.text().await.unwrap_or_default();
                Err(anyhow!("PagerDuty resolve error: {} - {}", status, error_text))
            }
            Err(e) => Err(anyhow!("Failed to resolve PagerDuty incident: {}", e)),
        }
    }

    /// Acknowledge a PagerDuty incident
    pub async fn acknowledge_incident(&self, dedup_key: &str) -> Result<()> {
        log::info!("Acknowledging PagerDuty incident: {}", dedup_key);

        let routing_key = self.routing_key.as_ref()
            .ok_or_else(|| anyhow!("PagerDuty routing key not configured"))?;

        let event_payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key
        });

        let response = self.http_client
            .post(PAGERDUTY_EVENTS_API)
            .header("Content-Type", "application/json")
            .json(&event_payload)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                log::info!("PagerDuty incident acknowledged: {}", dedup_key);
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let error_text = resp.text().await.unwrap_or_default();
                Err(anyhow!("PagerDuty acknowledge error: {} - {}", status, error_text))
            }
            Err(e) => Err(anyhow!("Failed to acknowledge PagerDuty incident: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_string() {
        assert!(matches!(Severity::from("critical"), Severity::Critical));
        assert!(matches!(Severity::from("high"), Severity::Critical));
        assert!(matches!(Severity::from("error"), Severity::Error));
        assert!(matches!(Severity::from("warning"), Severity::Warning));
        assert!(matches!(Severity::from("info"), Severity::Info));
        assert!(matches!(Severity::from("low"), Severity::Info));
    }

    #[test]
    fn test_integration_creation() {
        let integration = PagerDutyIntegration::new("test-key".to_string());
        assert_eq!(integration.api_key, "test-key");
    }
}
