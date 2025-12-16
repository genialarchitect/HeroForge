// Allow unused code for public API features not yet exposed via web routes
#![allow(dead_code)]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};

/// JIRA REST API client for creating and managing issues
pub struct JiraClient {
    base_url: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JiraSettings {
    pub jira_url: String,
    pub api_token: String,
    pub username: String,
    pub project_key: String,
    pub issue_type: String,
    pub default_assignee: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIssueRequest {
    pub fields: IssueFields,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueFields {
    pub project: ProjectKey,
    pub summary: String,
    pub description: String,
    pub issuetype: IssueType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<Assignee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectKey {
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueType {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Priority {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assignee {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIssueResponse {
    pub id: String,
    pub key: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddCommentRequest {
    pub body: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JiraProject {
    pub id: String,
    pub key: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JiraIssueType {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectsResponse {
    pub values: Vec<JiraProject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueTypesResponse {
    pub values: Vec<JiraIssueType>,
}

impl JiraClient {
    /// Create a new JIRA client with basic authentication
    pub fn new(base_url: String, username: String, api_token: String) -> Result<Self> {
        let mut headers = header::HeaderMap::new();

        // Basic auth: base64(username:api_token)
        let auth = format!("{}:{}", username, api_token);
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

        Ok(Self { base_url, client })
    }

    /// Test connection to JIRA instance
    pub async fn test_connection(&self) -> Result<()> {
        let url = format!("{}/rest/api/3/myself", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "JIRA connection test failed ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Create a new JIRA issue
    pub async fn create_issue(&self, request: CreateIssueRequest) -> Result<CreateIssueResponse> {
        let url = format!("{}/rest/api/3/issue", self.base_url);
        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            let issue = response.json::<CreateIssueResponse>().await?;
            Ok(issue)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to create JIRA issue ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Add a comment to an existing JIRA issue
    pub async fn add_comment(&self, issue_key: &str, comment: &str) -> Result<()> {
        let url = format!("{}/rest/api/3/issue/{}/comment", self.base_url, issue_key);
        let request = AddCommentRequest {
            body: comment.to_string(),
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to add comment to JIRA issue ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Transition a JIRA issue to a different status
    pub async fn transition_issue(&self, issue_key: &str, transition_id: &str) -> Result<()> {
        let url = format!(
            "{}/rest/api/3/issue/{}/transitions",
            self.base_url, issue_key
        );
        let request = serde_json::json!({
            "transition": {
                "id": transition_id
            }
        });

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to transition JIRA issue ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get list of accessible projects
    pub async fn list_projects(&self) -> Result<Vec<JiraProject>> {
        let url = format!("{}/rest/api/3/project/search", self.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let projects = response.json::<ProjectsResponse>().await?;
            Ok(projects.values)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to list JIRA projects ({}): {}",
                status,
                error_text
            ))
        }
    }

    /// Get issue types for a project
    pub async fn list_issue_types(&self, project_key: &str) -> Result<Vec<JiraIssueType>> {
        let url = format!(
            "{}/rest/api/3/project/{}/statuses",
            self.base_url, project_key
        );
        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            // Parse the complex response structure
            let data: Vec<serde_json::Value> = response.json().await?;
            let mut issue_types = Vec::new();

            for item in data {
                if let Some(obj) = item.as_object() {
                    if let (Some(id), Some(name)) = (
                        obj.get("id").and_then(|v| v.as_str()),
                        obj.get("name").and_then(|v| v.as_str()),
                    ) {
                        issue_types.push(JiraIssueType {
                            id: id.to_string(),
                            name: name.to_string(),
                            description: obj
                                .get("description")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                        });
                    }
                }
            }

            Ok(issue_types)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!(
                "Failed to list issue types ({}): {}",
                status,
                error_text
            ))
        }
    }
}

/// Map vulnerability severity to JIRA priority
pub fn severity_to_jira_priority(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "critical" => "Highest",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Medium",
    }
}

/// Format vulnerability details for JIRA description (Markdown)
pub fn format_vulnerability_description(
    vulnerability_id: &str,
    host_ip: &str,
    port: Option<i32>,
    severity: &str,
    notes: Option<&str>,
) -> String {
    let mut description = String::new();

    description.push_str(&format!("h2. Vulnerability Details\n\n"));
    description.push_str(&format!("*Vulnerability ID:* {}\n", vulnerability_id));
    description.push_str(&format!("*Host:* {}\n", host_ip));

    if let Some(p) = port {
        description.push_str(&format!("*Port:* {}\n", p));
    }

    description.push_str(&format!("*Severity:* {}\n\n", severity));

    if let Some(n) = notes {
        description.push_str(&format!("h2. Additional Notes\n\n{}\n\n", n));
    }

    description.push_str(&format!(
        "h2. Remediation\n\nPlease review and remediate this vulnerability according to security best practices.\n\n"
    ));
    description.push_str(&format!(
        "_This issue was automatically created by HeroForge security scanner._\n"
    ));

    description
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_jira_priority("critical"), "Highest");
        assert_eq!(severity_to_jira_priority("HIGH"), "High");
        assert_eq!(severity_to_jira_priority("medium"), "Medium");
        assert_eq!(severity_to_jira_priority("low"), "Low");
        assert_eq!(severity_to_jira_priority("unknown"), "Medium");
    }

    #[test]
    fn test_format_description() {
        let desc = format_vulnerability_description(
            "CVE-2024-1234",
            "192.168.1.100",
            Some(443),
            "High",
            Some("This is a test vulnerability"),
        );

        assert!(desc.contains("CVE-2024-1234"));
        assert!(desc.contains("192.168.1.100"));
        assert!(desc.contains("443"));
        assert!(desc.contains("High"));
        assert!(desc.contains("This is a test vulnerability"));
    }

    #[tokio::test]
    async fn test_jira_test_connection_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/rest/api/3/myself")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"accountId": "123", "displayName": "Test User"}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client.test_connection().await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_test_connection_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/rest/api/3/myself")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errorMessages": ["Authentication failed"]}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "invalid-token".to_string(),
        )
        .unwrap();

        let result = client.test_connection().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("401"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_test_connection_server_error() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/rest/api/3/myself")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errorMessages": ["Internal server error"]}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client.test_connection().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_create_issue_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/rest/api/3/issue")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": "10001", "key": "SEC-123", "self": "https://jira.example.com/rest/api/3/issue/10001"}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let request = CreateIssueRequest {
            fields: IssueFields {
                project: ProjectKey {
                    key: "SEC".to_string(),
                },
                summary: "Critical vulnerability found".to_string(),
                description: "SQL Injection vulnerability on port 443".to_string(),
                issuetype: IssueType {
                    name: "Bug".to_string(),
                },
                priority: Some(Priority {
                    name: "Highest".to_string(),
                }),
                assignee: None,
                labels: Some(vec!["security".to_string(), "vulnerability".to_string()]),
            },
        };

        let result = client.create_issue(request).await;
        assert!(result.is_ok());
        let issue = result.unwrap();
        assert_eq!(issue.id, "10001");
        assert_eq!(issue.key, "SEC-123");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_create_issue_validation_error() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/rest/api/3/issue")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errorMessages": [], "errors": {"summary": "Summary is required"}}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let request = CreateIssueRequest {
            fields: IssueFields {
                project: ProjectKey {
                    key: "SEC".to_string(),
                },
                summary: "".to_string(), // Invalid empty summary
                description: "Test".to_string(),
                issuetype: IssueType {
                    name: "Bug".to_string(),
                },
                priority: None,
                assignee: None,
                labels: None,
            },
        };

        let result = client.create_issue(request).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("400"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_add_comment_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/rest/api/3/issue/SEC-123/comment")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": "10000", "body": "Test comment"}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client
            .add_comment("SEC-123", "Vulnerability has been verified")
            .await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_add_comment_not_found() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/rest/api/3/issue/INVALID-999/comment")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errorMessages": ["Issue does not exist"]}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client.add_comment("INVALID-999", "Test comment").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("404"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_transition_issue_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/rest/api/3/issue/SEC-123/transitions")
            .with_status(204)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client.transition_issue("SEC-123", "31").await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_list_projects_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/rest/api/3/project/search")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "values": [
                    {"id": "10000", "key": "SEC", "name": "Security"},
                    {"id": "10001", "key": "DEV", "name": "Development"}
                ]
            }"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let result = client.list_projects().await;
        assert!(result.is_ok());
        let projects = result.unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].key, "SEC");
        assert_eq!(projects[1].key, "DEV");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jira_basic_auth_header() {
        let mut server = mockito::Server::new_async().await;

        // Verify that the Basic auth header is correctly formed
        let expected_auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("test@example.com:test-api-token")
        );

        let mock = server
            .mock("GET", "/rest/api/3/myself")
            .match_header("Authorization", expected_auth.as_str())
            .with_status(200)
            .with_body(r#"{"accountId": "123"}"#)
            .create_async()
            .await;

        let client = JiraClient::new(
            server.url(),
            "test@example.com".to_string(),
            "test-api-token".to_string(),
        )
        .unwrap();

        let _ = client.test_connection().await;
        mock.assert_async().await;
    }
}
