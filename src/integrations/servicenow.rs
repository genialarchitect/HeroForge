//! ServiceNow REST API client for creating incidents and change requests
//!
//! This module provides integration with ServiceNow for creating IT service
//! management tickets from vulnerability findings.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};

/// ServiceNow REST API client for creating and managing tickets
pub struct ServiceNowClient {
    instance_url: String,
    client: Client,
}

/// ServiceNow user settings stored in database
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceNowSettings {
    pub user_id: String,
    pub instance_url: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_encrypted: String,
    pub default_assignment_group: Option<String>,
    pub default_category: Option<String>,
    pub default_impact: i32,
    pub default_urgency: i32,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create or update ServiceNow settings
#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertServiceNowSettingsRequest {
    pub instance_url: String,
    pub username: String,
    pub password: String,
    pub default_assignment_group: Option<String>,
    pub default_category: Option<String>,
    pub default_impact: Option<i32>,
    pub default_urgency: Option<i32>,
    pub enabled: bool,
}

/// ServiceNow incident creation data
#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentData {
    pub short_description: String,
    pub description: String,
    pub category: Option<String>,
    pub impact: i32,
    pub urgency: i32,
    pub assignment_group: Option<String>,
    pub u_affected_ci: Option<String>,
    pub caller_id: Option<String>,
}

/// ServiceNow change request creation data
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeData {
    pub short_description: String,
    pub description: String,
    pub category: Option<String>,
    pub impact: i32,
    pub risk: i32,
    pub assignment_group: Option<String>,
    pub u_affected_ci: Option<String>,
    pub requested_by: Option<String>,
}

/// Response from ServiceNow when creating a ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketResponse {
    pub sys_id: String,
    pub number: String,
}

/// ServiceNow API result wrapper
#[derive(Debug, Deserialize)]
struct ServiceNowResult<T> {
    result: T,
}

/// ServiceNow API array result wrapper
#[derive(Debug, Deserialize)]
struct ServiceNowArrayResult<T> {
    result: Vec<T>,
}

/// ServiceNow created record response
#[derive(Debug, Deserialize)]
struct CreatedRecord {
    sys_id: String,
    number: String,
}

/// Ticket status information
#[derive(Debug, Serialize, Deserialize)]
pub struct TicketStatus {
    pub sys_id: String,
    pub number: String,
    pub state: String,
    pub short_description: String,
}

/// ServiceNow assignment group
#[derive(Debug, Serialize, Deserialize)]
pub struct AssignmentGroup {
    pub sys_id: String,
    pub name: String,
}

/// ServiceNow category
#[derive(Debug, Serialize, Deserialize)]
pub struct Category {
    pub label: String,
    pub value: String,
}

/// User information from ServiceNow
#[derive(Debug, Deserialize)]
struct UserInfo {
    #[allow(dead_code)]
    sys_id: String,
    #[allow(dead_code)]
    user_name: String,
}

impl ServiceNowClient {
    /// Create a new ServiceNow client with basic authentication
    pub fn new(instance_url: String, username: String, password: String) -> Result<Self> {
        let mut headers = header::HeaderMap::new();

        // Basic auth: base64(username:password)
        let auth = format!("{}:{}", username, password);
        let auth_header = format!("Basic {}", STANDARD.encode(auth));
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&auth_header)?,
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Ensure URL doesn't have trailing slash
        let instance_url = instance_url.trim_end_matches('/').to_string();

        Ok(Self {
            instance_url,
            client,
        })
    }

    /// Test connection to ServiceNow instance
    pub async fn test_connection(&self) -> Result<bool> {
        let url = format!("{}/api/now/table/sys_user?sysparm_limit=1", self.instance_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(true)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "ServiceNow connection test failed ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Create an incident from vulnerability data
    pub async fn create_incident(&self, data: IncidentData) -> Result<TicketResponse> {
        let url = format!("{}/api/now/table/incident", self.instance_url);

        // Build the request body
        let mut body = serde_json::json!({
            "short_description": data.short_description,
            "description": data.description,
            "impact": data.impact.to_string(),
            "urgency": data.urgency.to_string(),
        });

        if let Some(category) = &data.category {
            body["category"] = serde_json::json!(category);
        }
        if let Some(group) = &data.assignment_group {
            body["assignment_group"] = serde_json::json!(group);
        }
        if let Some(ci) = &data.u_affected_ci {
            body["u_affected_ci"] = serde_json::json!(ci);
        }
        if let Some(caller) = &data.caller_id {
            body["caller_id"] = serde_json::json!(caller);
        }

        let response = self.client.post(&url).json(&body).send().await?;

        if response.status().is_success() {
            let result: ServiceNowResult<CreatedRecord> = response.json().await?;
            Ok(TicketResponse {
                sys_id: result.result.sys_id,
                number: result.result.number,
            })
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to create ServiceNow incident ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Create a change request from vulnerability data
    pub async fn create_change(&self, data: ChangeData) -> Result<TicketResponse> {
        let url = format!("{}/api/now/table/change_request", self.instance_url);

        // Build the request body
        let mut body = serde_json::json!({
            "short_description": data.short_description,
            "description": data.description,
            "impact": data.impact.to_string(),
            "risk": data.risk.to_string(),
            "type": "normal",  // standard, normal, or emergency
        });

        if let Some(category) = &data.category {
            body["category"] = serde_json::json!(category);
        }
        if let Some(group) = &data.assignment_group {
            body["assignment_group"] = serde_json::json!(group);
        }
        if let Some(ci) = &data.u_affected_ci {
            body["u_affected_ci"] = serde_json::json!(ci);
        }
        if let Some(requested_by) = &data.requested_by {
            body["requested_by"] = serde_json::json!(requested_by);
        }

        let response = self.client.post(&url).json(&body).send().await?;

        if response.status().is_success() {
            let result: ServiceNowResult<CreatedRecord> = response.json().await?;
            Ok(TicketResponse {
                sys_id: result.result.sys_id,
                number: result.result.number,
            })
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to create ServiceNow change request ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get ticket status by number
    pub async fn get_ticket_status(&self, number: &str) -> Result<TicketStatus> {
        // Determine table based on ticket number prefix
        let table = if number.starts_with("INC") {
            "incident"
        } else if number.starts_with("CHG") {
            "change_request"
        } else {
            return Err(anyhow!("Unknown ticket type for number: {}", number));
        };

        let url = format!(
            "{}/api/now/table/{}?sysparm_query=number={}&sysparm_fields=sys_id,number,state,short_description",
            self.instance_url, table, number
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let result: ServiceNowArrayResult<TicketStatus> = response.json().await?;
            result
                .result
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("Ticket not found: {}", number))
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to get ServiceNow ticket status ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get list of assignment groups
    pub async fn get_assignment_groups(&self) -> Result<Vec<AssignmentGroup>> {
        let url = format!(
            "{}/api/now/table/sys_user_group?sysparm_fields=sys_id,name&sysparm_limit=100",
            self.instance_url
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let result: ServiceNowArrayResult<AssignmentGroup> = response.json().await?;
            Ok(result.result)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to get ServiceNow assignment groups ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get list of incident categories
    pub async fn get_categories(&self) -> Result<Vec<Category>> {
        // ServiceNow stores categories in sys_choice table
        let url = format!(
            "{}/api/now/table/sys_choice?sysparm_query=name=incident^element=category^inactive=false&sysparm_fields=label,value&sysparm_limit=100",
            self.instance_url
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let result: ServiceNowArrayResult<Category> = response.json().await?;
            Ok(result.result)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to get ServiceNow categories ({}): {}",
                status,
                error_text
            ))
        }
    }
}

/// Full incident details
#[derive(Debug, Serialize, Deserialize)]
pub struct Incident {
    pub sys_id: String,
    pub number: String,
    pub state: String,
    pub short_description: String,
    pub description: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<String>,
}

/// Work note (comment) on a ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkNote {
    pub sys_id: String,
    pub value: String,
    pub sys_created_on: String,
    pub sys_created_by: String,
}

impl ServiceNowClient {
    /// Get incident by sys_id
    pub async fn get_incident(&self, sys_id: &str) -> Result<Incident> {
        let url = format!(
            "{}/api/now/table/incident/{}?sysparm_fields=sys_id,number,state,short_description,description,priority,assigned_to",
            self.instance_url, sys_id
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let result: ServiceNowResult<Incident> = response.json().await?;
            Ok(result.result)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to get ServiceNow incident ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Update incident state
    pub async fn update_incident_state(&self, sys_id: &str, state: &str) -> Result<()> {
        let url = format!("{}/api/now/table/incident/{}", self.instance_url, sys_id);

        // Map common state names to ServiceNow state codes
        let state_code = match state.to_lowercase().as_str() {
            "open" | "new" => "1",
            "in progress" | "in_progress" | "active" => "2",
            "on hold" | "pending" => "3",
            "resolved" => "6",
            "closed" | "complete" => "7",
            "cancelled" => "8",
            _ => state, // Use as-is if not recognized
        };

        let body = serde_json::json!({
            "state": state_code
        });

        let response = self.client.patch(&url).json(&body).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to update ServiceNow incident state ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get work notes for an incident
    pub async fn get_work_notes(&self, sys_id: &str) -> Result<Vec<super::sync_engine::RemoteComment>> {
        // ServiceNow stores work notes in sys_journal_field table
        let url = format!(
            "{}/api/now/table/sys_journal_field?sysparm_query=element_id={}&sysparm_fields=sys_id,value,sys_created_on,sys_created_by&sysparm_limit=50",
            self.instance_url, sys_id
        );

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let result: ServiceNowArrayResult<WorkNote> = response.json().await?;
            let comments = result
                .result
                .into_iter()
                .filter_map(|note| {
                    // Parse ServiceNow datetime format
                    let created_at = chrono::NaiveDateTime::parse_from_str(
                        &note.sys_created_on,
                        "%Y-%m-%d %H:%M:%S",
                    )
                    .map(|dt| dt.and_utc())
                    .ok()?;

                    Some(super::sync_engine::RemoteComment {
                        id: note.sys_id,
                        author: note.sys_created_by,
                        body: note.value,
                        created_at,
                    })
                })
                .collect();
            Ok(comments)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to get ServiceNow work notes ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Add a work note to an incident
    pub async fn add_work_note(&self, sys_id: &str, note: &str) -> Result<()> {
        let url = format!("{}/api/now/table/incident/{}", self.instance_url, sys_id);

        let body = serde_json::json!({
            "work_notes": note
        });

        let response = self.client.patch(&url).json(&body).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to add ServiceNow work note ({}): {}",
                status,
                error_text
            ))
        }
    }
}

/// Map vulnerability severity to ServiceNow impact (1=High, 2=Medium, 3=Low)
pub fn severity_to_impact(severity: &str) -> i32 {
    match severity.to_lowercase().as_str() {
        "critical" => 1,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 3,
    }
}

/// Map vulnerability severity to ServiceNow urgency (1=High, 2=Medium, 3=Low)
pub fn severity_to_urgency(severity: &str) -> i32 {
    match severity.to_lowercase().as_str() {
        "critical" => 1,
        "high" => 2,
        "medium" => 2,
        "low" => 3,
        _ => 3,
    }
}

/// Format vulnerability details for ServiceNow description
pub fn format_vulnerability_description(
    vulnerability_id: &str,
    host_ip: &str,
    port: Option<i32>,
    severity: &str,
    notes: Option<&str>,
    cve_ids: Option<&str>,
    cvss_score: Option<f64>,
    remediation: Option<&str>,
) -> String {
    let mut description = String::new();

    description.push_str("=== Vulnerability Details ===\n\n");
    description.push_str(&format!("Vulnerability ID: {}\n", vulnerability_id));
    description.push_str(&format!("Affected Host: {}\n", host_ip));

    if let Some(p) = port {
        description.push_str(&format!("Port: {}\n", p));
    }

    description.push_str(&format!("Severity: {}\n", severity.to_uppercase()));

    if let Some(score) = cvss_score {
        description.push_str(&format!("CVSS Score: {:.1}\n", score));
    }

    if let Some(cves) = cve_ids {
        if !cves.is_empty() {
            description.push_str(&format!("CVE IDs: {}\n", cves));
        }
    }

    if let Some(n) = notes {
        description.push_str("\n=== Description ===\n\n");
        description.push_str(n);
        description.push('\n');
    }

    if let Some(r) = remediation {
        description.push_str("\n=== Remediation ===\n\n");
        description.push_str(r);
        description.push('\n');
    }

    description.push_str("\n---\nThis ticket was automatically created by Genial Architect Scanner.\n");

    description
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_to_impact() {
        assert_eq!(severity_to_impact("critical"), 1);
        assert_eq!(severity_to_impact("high"), 1);
        assert_eq!(severity_to_impact("medium"), 2);
        assert_eq!(severity_to_impact("low"), 3);
        assert_eq!(severity_to_impact("unknown"), 3);
    }

    #[test]
    fn test_severity_to_urgency() {
        assert_eq!(severity_to_urgency("critical"), 1);
        assert_eq!(severity_to_urgency("HIGH"), 2);
        assert_eq!(severity_to_urgency("medium"), 2);
        assert_eq!(severity_to_urgency("low"), 3);
    }

    #[test]
    fn test_format_description() {
        let desc = format_vulnerability_description(
            "CVE-2024-1234",
            "192.168.1.100",
            Some(443),
            "high",
            Some("SQL Injection vulnerability allowing data access"),
            Some("CVE-2024-1234"),
            Some(8.5),
            Some("Update to latest version"),
        );

        assert!(desc.contains("CVE-2024-1234"));
        assert!(desc.contains("192.168.1.100"));
        assert!(desc.contains("443"));
        assert!(desc.contains("HIGH"));
        assert!(desc.contains("8.5"));
        assert!(desc.contains("Update to latest version"));
        assert!(desc.contains("Genial Architect Scanner"));
    }

    #[tokio::test]
    async fn test_servicenow_test_connection_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/api/now/table/sys_user")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": [{"sys_id": "123", "user_name": "test"}]}"#)
            .create_async()
            .await;

        let client = ServiceNowClient::new(
            server.url(),
            "test_user".to_string(),
            "test_password".to_string(),
        )
        .unwrap();

        let result = client.test_connection().await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_servicenow_test_connection_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/api/now/table/sys_user")
            .match_query(mockito::Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error": {"message": "User Not Authenticated"}}"#)
            .create_async()
            .await;

        let client = ServiceNowClient::new(
            server.url(),
            "test_user".to_string(),
            "wrong_password".to_string(),
        )
        .unwrap();

        let result = client.test_connection().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("401"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_servicenow_create_incident_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/api/now/table/incident")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": {"sys_id": "abc123", "number": "INC0012345"}}"#)
            .create_async()
            .await;

        let client = ServiceNowClient::new(
            server.url(),
            "test_user".to_string(),
            "test_password".to_string(),
        )
        .unwrap();

        let data = IncidentData {
            short_description: "Critical vulnerability found".to_string(),
            description: "SQL Injection on port 443".to_string(),
            category: Some("security".to_string()),
            impact: 1,
            urgency: 1,
            assignment_group: Some("Security Team".to_string()),
            u_affected_ci: Some("192.168.1.100".to_string()),
            caller_id: None,
        };

        let result = client.create_incident(data).await;
        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert_eq!(ticket.sys_id, "abc123");
        assert_eq!(ticket.number, "INC0012345");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_servicenow_create_change_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/api/now/table/change_request")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": {"sys_id": "def456", "number": "CHG0001234"}}"#)
            .create_async()
            .await;

        let client = ServiceNowClient::new(
            server.url(),
            "test_user".to_string(),
            "test_password".to_string(),
        )
        .unwrap();

        let data = ChangeData {
            short_description: "Apply security patch".to_string(),
            description: "Remediation for critical vulnerability".to_string(),
            category: Some("security".to_string()),
            impact: 2,
            risk: 2,
            assignment_group: Some("Change Team".to_string()),
            u_affected_ci: Some("192.168.1.100".to_string()),
            requested_by: None,
        };

        let result = client.create_change(data).await;
        assert!(result.is_ok());
        let ticket = result.unwrap();
        assert_eq!(ticket.sys_id, "def456");
        assert_eq!(ticket.number, "CHG0001234");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_servicenow_get_assignment_groups() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/api/now/table/sys_user_group")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result": [{"sys_id": "grp1", "name": "Security Team"}, {"sys_id": "grp2", "name": "IT Operations"}]}"#)
            .create_async()
            .await;

        let client = ServiceNowClient::new(
            server.url(),
            "test_user".to_string(),
            "test_password".to_string(),
        )
        .unwrap();

        let result = client.get_assignment_groups().await;
        assert!(result.is_ok());
        let groups = result.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "Security Team");
        assert_eq!(groups[1].name, "IT Operations");

        mock.assert_async().await;
    }
}
