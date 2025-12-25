//! Microsoft Teams Bot Integration
//!
//! Provides Teams adaptive card responses and bot activity handlers for HeroForge.

#![allow(dead_code)]

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Teams bot client
pub struct TeamsBot {
    client: Client,
    app_id: String,
    app_password: String,
    access_token: Option<String>,
}

/// Teams activity (incoming message)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsActivity {
    #[serde(rename = "type")]
    pub activity_type: String,
    pub id: String,
    pub timestamp: String,
    pub service_url: String,
    pub channel_id: String,
    pub from: TeamsChannelAccount,
    pub conversation: TeamsConversationAccount,
    pub recipient: TeamsChannelAccount,
    pub text: Option<String>,
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsChannelAccount {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamsConversationAccount {
    pub id: String,
    #[serde(rename = "conversationType")]
    pub conversation_type: Option<String>,
    /// Tenant ID for the conversation (Teams-specific)
    pub tenant_id: Option<String>,
}

/// Adaptive Card for Teams
#[derive(Debug, Serialize)]
pub struct AdaptiveCard {
    #[serde(rename = "type")]
    pub card_type: String,
    pub version: String,
    pub body: Vec<AdaptiveCardElement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<AdaptiveCardAction>>,
}

impl Default for AdaptiveCard {
    fn default() -> Self {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: Vec::new(),
            actions: None,
        }
    }
}

/// Adaptive Card elements
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum AdaptiveCardElement {
    TextBlock {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        weight: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        color: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wrap: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        spacing: Option<String>,
    },
    FactSet {
        facts: Vec<Fact>,
    },
    ColumnSet {
        columns: Vec<Column>,
    },
    Container {
        items: Vec<AdaptiveCardElement>,
        #[serde(skip_serializing_if = "Option::is_none")]
        style: Option<String>,
    },
    Image {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<String>,
    },
}

#[derive(Debug, Serialize)]
pub struct Fact {
    pub title: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Column {
    pub width: String,
    pub items: Vec<AdaptiveCardElement>,
}

/// Adaptive Card actions
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum AdaptiveCardAction {
    #[serde(rename = "Action.OpenUrl")]
    OpenUrl {
        title: String,
        url: String,
    },
    #[serde(rename = "Action.Submit")]
    Submit {
        title: String,
        data: serde_json::Value,
    },
}

/// Activity response for Teams
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityResponse {
    #[serde(rename = "type")]
    pub activity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub content_type: String,
    pub content: AdaptiveCard,
}

impl TeamsBot {
    /// Create a new Teams bot client
    pub fn new(app_id: String, app_password: String) -> Self {
        TeamsBot {
            client: Client::new(),
            app_id,
            app_password,
            access_token: None,
        }
    }

    /// Authenticate with Microsoft Bot Framework
    pub async fn authenticate(&mut self) -> Result<()> {
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.app_id),
            ("client_secret", &self.app_password),
            ("scope", "https://api.botframework.com/.default"),
        ];

        let response = self.client
            .post("https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token")
            .form(&params)
            .send()
            .await?;

        let token_response: TokenResponse = response.json().await?;
        self.access_token = Some(token_response.access_token);

        Ok(())
    }

    /// Parse command from message text
    pub fn parse_command(text: &str) -> TeamsCommand {
        let text = text.trim();

        // Remove bot mention if present
        let text = if text.starts_with("<at>") {
            text.split("</at>")
                .last()
                .unwrap_or(text)
                .trim()
        } else {
            text
        };

        let parts: Vec<&str> = text.split_whitespace().collect();

        if parts.is_empty() {
            return TeamsCommand::Help;
        }

        match parts[0].to_lowercase().as_str() {
            "scan" => {
                if parts.len() > 1 {
                    TeamsCommand::Scan {
                        target: parts[1..].join(" "),
                    }
                } else {
                    TeamsCommand::Help
                }
            }
            "status" => TeamsCommand::Status,
            "vulns" | "vulnerabilities" => {
                let severity = parts.get(1).map(|s| s.to_string());
                TeamsCommand::Vulns { severity }
            }
            "report" => {
                if parts.len() > 1 {
                    TeamsCommand::Report {
                        scan_id: parts[1].to_string(),
                    }
                } else {
                    TeamsCommand::Help
                }
            }
            "help" => TeamsCommand::Help,
            _ => TeamsCommand::Unknown(text.to_string()),
        }
    }

    /// Build help card
    pub fn build_help_card() -> AdaptiveCard {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: vec![
                AdaptiveCardElement::TextBlock {
                    text: "🛡️ HeroForge Commands".to_string(),
                    size: Some("Large".to_string()),
                    weight: Some("Bolder".to_string()),
                    color: None,
                    wrap: Some(true),
                    spacing: None,
                },
                AdaptiveCardElement::TextBlock {
                    text: "Available commands:".to_string(),
                    size: None,
                    weight: None,
                    color: None,
                    wrap: Some(true),
                    spacing: Some("Medium".to_string()),
                },
                AdaptiveCardElement::FactSet {
                    facts: vec![
                        Fact { title: "scan <target>".to_string(), value: "Start a quick scan".to_string() },
                        Fact { title: "status".to_string(), value: "View dashboard summary".to_string() },
                        Fact { title: "vulns [severity]".to_string(), value: "List vulnerabilities".to_string() },
                        Fact { title: "report <scan_id>".to_string(), value: "Generate report link".to_string() },
                        Fact { title: "help".to_string(), value: "Show this help".to_string() },
                    ],
                },
            ],
            actions: None,
        }
    }

    /// Build status card
    pub fn build_status_card(stats: &DashboardStats) -> AdaptiveCard {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: vec![
                AdaptiveCardElement::TextBlock {
                    text: "📊 HeroForge Dashboard".to_string(),
                    size: Some("Large".to_string()),
                    weight: Some("Bolder".to_string()),
                    color: None,
                    wrap: Some(true),
                    spacing: None,
                },
                AdaptiveCardElement::Container {
                    style: Some("emphasis".to_string()),
                    items: vec![
                        AdaptiveCardElement::TextBlock {
                            text: "Vulnerability Summary".to_string(),
                            size: Some("Medium".to_string()),
                            weight: Some("Bolder".to_string()),
                            color: None,
                            wrap: None,
                            spacing: None,
                        },
                        AdaptiveCardElement::ColumnSet {
                            columns: vec![
                                Column {
                                    width: "auto".to_string(),
                                    items: vec![
                                        AdaptiveCardElement::TextBlock {
                                            text: format!("🔴 {}", stats.critical_count),
                                            size: Some("ExtraLarge".to_string()),
                                            weight: Some("Bolder".to_string()),
                                            color: Some("Attention".to_string()),
                                            wrap: None,
                                            spacing: None,
                                        },
                                        AdaptiveCardElement::TextBlock {
                                            text: "Critical".to_string(),
                                            size: Some("Small".to_string()),
                                            weight: None,
                                            color: None,
                                            wrap: None,
                                            spacing: None,
                                        },
                                    ],
                                },
                                Column {
                                    width: "auto".to_string(),
                                    items: vec![
                                        AdaptiveCardElement::TextBlock {
                                            text: format!("🟠 {}", stats.high_count),
                                            size: Some("ExtraLarge".to_string()),
                                            weight: Some("Bolder".to_string()),
                                            color: Some("Warning".to_string()),
                                            wrap: None,
                                            spacing: None,
                                        },
                                        AdaptiveCardElement::TextBlock {
                                            text: "High".to_string(),
                                            size: Some("Small".to_string()),
                                            weight: None,
                                            color: None,
                                            wrap: None,
                                            spacing: None,
                                        },
                                    ],
                                },
                                Column {
                                    width: "auto".to_string(),
                                    items: vec![
                                        AdaptiveCardElement::TextBlock {
                                            text: format!("🟡 {}", stats.medium_count),
                                            size: Some("ExtraLarge".to_string()),
                                            weight: Some("Bolder".to_string()),
                                            color: None,
                                            wrap: None,
                                            spacing: None,
                                        },
                                        AdaptiveCardElement::TextBlock {
                                            text: "Medium".to_string(),
                                            size: Some("Small".to_string()),
                                            weight: None,
                                            color: None,
                                            wrap: None,
                                            spacing: None,
                                        },
                                    ],
                                },
                                Column {
                                    width: "auto".to_string(),
                                    items: vec![
                                        AdaptiveCardElement::TextBlock {
                                            text: format!("🟢 {}", stats.low_count),
                                            size: Some("ExtraLarge".to_string()),
                                            weight: Some("Bolder".to_string()),
                                            color: Some("Good".to_string()),
                                            wrap: None,
                                            spacing: None,
                                        },
                                        AdaptiveCardElement::TextBlock {
                                            text: "Low".to_string(),
                                            size: Some("Small".to_string()),
                                            weight: None,
                                            color: None,
                                            wrap: None,
                                            spacing: None,
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
                AdaptiveCardElement::FactSet {
                    facts: vec![
                        Fact { title: "Active Scans".to_string(), value: stats.active_scans.to_string() },
                        Fact { title: "Total Hosts".to_string(), value: stats.total_hosts.to_string() },
                        Fact { title: "Total Scans".to_string(), value: stats.total_scans.to_string() },
                    ],
                },
            ],
            actions: None,
        }
    }

    /// Build vulnerability list card
    pub fn build_vulns_card(vulns: &[super::slack::VulnSummary], severity_filter: Option<&str>) -> AdaptiveCard {
        let filter_text = severity_filter
            .map(|s| format!(" ({})", s.to_uppercase()))
            .unwrap_or_default();

        if vulns.is_empty() {
            return AdaptiveCard {
                card_type: "AdaptiveCard".to_string(),
                version: "1.4".to_string(),
                body: vec![
                    AdaptiveCardElement::TextBlock {
                        text: format!("✅ No vulnerabilities found{}", filter_text),
                        size: Some("Medium".to_string()),
                        weight: Some("Bolder".to_string()),
                        color: Some("Good".to_string()),
                        wrap: Some(true),
                        spacing: None,
                    },
                ],
                actions: None,
            };
        }

        let mut body = vec![
            AdaptiveCardElement::TextBlock {
                text: format!("🔍 Vulnerabilities{}", filter_text),
                size: Some("Large".to_string()),
                weight: Some("Bolder".to_string()),
                color: None,
                wrap: Some(true),
                spacing: None,
            },
        ];

        for (i, vuln) in vulns.iter().take(10).enumerate() {
            let severity_color = match vuln.severity.as_str() {
                "critical" => "Attention",
                "high" => "Warning",
                "medium" => "Accent",
                _ => "Default",
            };

            body.push(AdaptiveCardElement::TextBlock {
                text: format!("{}. {} - {} ({})", i + 1, vuln.title, vuln.severity.to_uppercase(), vuln.host),
                size: Some("Small".to_string()),
                weight: None,
                color: Some(severity_color.to_string()),
                wrap: Some(true),
                spacing: Some("Small".to_string()),
            });
        }

        if vulns.len() > 10 {
            body.push(AdaptiveCardElement::TextBlock {
                text: format!("_Showing 10 of {} vulnerabilities_", vulns.len()),
                size: Some("Small".to_string()),
                weight: None,
                color: Some("Accent".to_string()),
                wrap: Some(true),
                spacing: Some("Medium".to_string()),
            });
        }

        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body,
            actions: None,
        }
    }

    /// Build scan started card
    pub fn build_scan_card(target: &str, scan_id: &str) -> AdaptiveCard {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: vec![
                AdaptiveCardElement::TextBlock {
                    text: "🔍 Scan Started".to_string(),
                    size: Some("Large".to_string()),
                    weight: Some("Bolder".to_string()),
                    color: None,
                    wrap: Some(true),
                    spacing: None,
                },
                AdaptiveCardElement::FactSet {
                    facts: vec![
                        Fact { title: "Target".to_string(), value: target.to_string() },
                        Fact { title: "Scan ID".to_string(), value: scan_id.to_string() },
                    ],
                },
                AdaptiveCardElement::TextBlock {
                    text: "You'll be notified when the scan completes.".to_string(),
                    size: Some("Small".to_string()),
                    weight: None,
                    color: Some("Accent".to_string()),
                    wrap: Some(true),
                    spacing: Some("Medium".to_string()),
                },
            ],
            actions: None,
        }
    }

    /// Build report card
    pub fn build_report_card(scan_id: &str, report_url: &str) -> AdaptiveCard {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: vec![
                AdaptiveCardElement::TextBlock {
                    text: "📋 Report Generated".to_string(),
                    size: Some("Large".to_string()),
                    weight: Some("Bolder".to_string()),
                    color: None,
                    wrap: Some(true),
                    spacing: None,
                },
                AdaptiveCardElement::FactSet {
                    facts: vec![
                        Fact { title: "Scan ID".to_string(), value: scan_id.to_string() },
                    ],
                },
            ],
            actions: Some(vec![AdaptiveCardAction::OpenUrl {
                title: "View Report".to_string(),
                url: report_url.to_string(),
            }]),
        }
    }

    /// Build error card
    pub fn build_error_card(message: &str) -> AdaptiveCard {
        AdaptiveCard {
            card_type: "AdaptiveCard".to_string(),
            version: "1.4".to_string(),
            body: vec![
                AdaptiveCardElement::TextBlock {
                    text: "❌ Error".to_string(),
                    size: Some("Large".to_string()),
                    weight: Some("Bolder".to_string()),
                    color: Some("Attention".to_string()),
                    wrap: Some(true),
                    spacing: None,
                },
                AdaptiveCardElement::TextBlock {
                    text: message.to_string(),
                    size: None,
                    weight: None,
                    color: None,
                    wrap: Some(true),
                    spacing: Some("Medium".to_string()),
                },
            ],
            actions: None,
        }
    }

    /// Wrap card in activity response
    pub fn card_response(card: AdaptiveCard) -> ActivityResponse {
        ActivityResponse {
            activity_type: "message".to_string(),
            text: None,
            attachments: Some(vec![Attachment {
                content_type: "application/vnd.microsoft.card.adaptive".to_string(),
                content: card,
            }]),
        }
    }

    /// Send activity reply
    pub async fn reply(&self, service_url: &str, conversation_id: &str, activity_id: &str, response: &ActivityResponse) -> Result<()> {
        let url = format!(
            "{}/v3/conversations/{}/activities/{}",
            service_url.trim_end_matches('/'),
            conversation_id,
            activity_id
        );

        let token = self.access_token.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        self.client
            .post(&url)
            .bearer_auth(token)
            .json(response)
            .send()
            .await?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: i64,
}

/// Parsed Teams command
#[derive(Debug)]
pub enum TeamsCommand {
    Scan { target: String },
    Status,
    Vulns { severity: Option<String> },
    Report { scan_id: String },
    Help,
    Unknown(String),
}

/// Dashboard statistics
#[derive(Debug, Default)]
pub struct DashboardStats {
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub active_scans: i32,
    pub total_hosts: i32,
    pub total_scans: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_command() {
        match TeamsBot::parse_command("scan 192.168.1.1") {
            TeamsCommand::Scan { target } => assert_eq!(target, "192.168.1.1"),
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_status_command() {
        match TeamsBot::parse_command("status") {
            TeamsCommand::Status => {}
            _ => panic!("Expected Status command"),
        }
    }

    #[test]
    fn test_parse_with_mention() {
        match TeamsBot::parse_command("<at>HeroForge</at> scan 10.0.0.1") {
            TeamsCommand::Scan { target } => assert_eq!(target, "10.0.0.1"),
            _ => panic!("Expected Scan command"),
        }
    }
}
