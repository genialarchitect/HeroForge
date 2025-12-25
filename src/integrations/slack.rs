//! Slack Bot Integration
//!
//! Provides Slack slash command handlers and event processing for HeroForge.

#![allow(dead_code)]

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Slack bot client
pub struct SlackBot {
    client: Client,
    bot_token: String,
}

/// Slack slash command request
#[derive(Debug, Deserialize)]
pub struct SlashCommandRequest {
    pub token: String,
    pub team_id: String,
    pub team_domain: String,
    pub channel_id: String,
    pub channel_name: String,
    pub user_id: String,
    pub user_name: String,
    pub command: String,
    pub text: String,
    pub response_url: String,
    pub trigger_id: String,
}

/// Slack message block
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SlackBlock {
    #[serde(rename = "section")]
    Section {
        text: SlackText,
        #[serde(skip_serializing_if = "Option::is_none")]
        accessory: Option<SlackAccessory>,
    },
    #[serde(rename = "divider")]
    Divider {},
    #[serde(rename = "header")]
    Header { text: SlackText },
    #[serde(rename = "context")]
    Context { elements: Vec<SlackText> },
    #[serde(rename = "actions")]
    Actions { elements: Vec<SlackButton> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackText {
    #[serde(rename = "type")]
    pub text_type: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emoji: Option<bool>,
}

impl SlackText {
    pub fn mrkdwn(text: &str) -> Self {
        SlackText {
            text_type: "mrkdwn".to_string(),
            text: text.to_string(),
            emoji: None,
        }
    }

    pub fn plain(text: &str) -> Self {
        SlackText {
            text_type: "plain_text".to_string(),
            text: text.to_string(),
            emoji: Some(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackAccessory {
    #[serde(rename = "type")]
    pub accessory_type: String,
    pub image_url: String,
    pub alt_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackButton {
    #[serde(rename = "type")]
    pub button_type: String,
    pub text: SlackText,
    pub action_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
}

/// Slack message response
#[derive(Debug, Serialize)]
pub struct SlackResponse {
    pub response_type: String,  // "in_channel" or "ephemeral"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<SlackBlock>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<SlackAttachment>>,
}

#[derive(Debug, Serialize)]
pub struct SlackAttachment {
    pub color: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<SlackField>>,
}

#[derive(Debug, Serialize)]
pub struct SlackField {
    pub title: String,
    pub value: String,
    pub short: bool,
}

/// Parsed command from user input
#[derive(Debug)]
pub enum HeroForgeCommand {
    Scan { target: String },
    Status,
    Vulns { severity: Option<String> },
    Report { scan_id: String },
    Help,
    Unknown(String),
}

impl SlackBot {
    /// Create a new Slack bot client
    pub fn new(bot_token: String) -> Self {
        SlackBot {
            client: Client::new(),
            bot_token,
        }
    }

    /// Parse a slash command
    pub fn parse_command(text: &str) -> HeroForgeCommand {
        let parts: Vec<&str> = text.trim().split_whitespace().collect();

        if parts.is_empty() {
            return HeroForgeCommand::Help;
        }

        match parts[0].to_lowercase().as_str() {
            "scan" => {
                if parts.len() > 1 {
                    HeroForgeCommand::Scan {
                        target: parts[1..].join(" "),
                    }
                } else {
                    HeroForgeCommand::Help
                }
            }
            "status" => HeroForgeCommand::Status,
            "vulns" | "vulnerabilities" => {
                let severity = parts.get(1).map(|s| s.to_string());
                HeroForgeCommand::Vulns { severity }
            }
            "report" => {
                if parts.len() > 1 {
                    HeroForgeCommand::Report {
                        scan_id: parts[1].to_string(),
                    }
                } else {
                    HeroForgeCommand::Help
                }
            }
            "help" => HeroForgeCommand::Help,
            other => HeroForgeCommand::Unknown(other.to_string()),
        }
    }

    /// Build help response
    pub fn build_help_response() -> SlackResponse {
        let blocks = vec![
            SlackBlock::Header {
                text: SlackText::plain("🛡️ HeroForge Commands"),
            },
            SlackBlock::Divider {},
            SlackBlock::Section {
                text: SlackText::mrkdwn(
                    "*Available Commands:*\n\n\
                    `/heroforge scan <target>` - Start a quick scan\n\
                    `/heroforge status` - View dashboard summary\n\
                    `/heroforge vulns [critical|high]` - List vulnerabilities\n\
                    `/heroforge report <scan_id>` - Generate report link\n\
                    `/heroforge help` - Show this help message"
                ),
                accessory: None,
            },
            SlackBlock::Context {
                elements: vec![SlackText::mrkdwn("Need more help? Visit our documentation or contact support.")],
            },
        ];

        SlackResponse {
            response_type: "ephemeral".to_string(),
            text: Some("HeroForge Commands".to_string()),
            blocks: Some(blocks),
            attachments: None,
        }
    }

    /// Build scan response
    pub fn build_scan_response(target: &str, scan_id: &str) -> SlackResponse {
        let blocks = vec![
            SlackBlock::Section {
                text: SlackText::mrkdwn(&format!(
                    "🔍 *Scan Started*\n\nTarget: `{}`\nScan ID: `{}`",
                    target, scan_id
                )),
                accessory: None,
            },
            SlackBlock::Context {
                elements: vec![SlackText::mrkdwn("You'll be notified when the scan completes.")],
            },
        ];

        SlackResponse {
            response_type: "in_channel".to_string(),
            text: Some(format!("Scan started for {}", target)),
            blocks: Some(blocks),
            attachments: None,
        }
    }

    /// Build status response
    pub fn build_status_response(stats: &DashboardStats) -> SlackResponse {
        let severity_emoji = |count: i32, severity: &str| {
            if count > 0 {
                match severity {
                    "critical" => format!("🔴 {} Critical", count),
                    "high" => format!("🟠 {} High", count),
                    "medium" => format!("🟡 {} Medium", count),
                    "low" => format!("🟢 {} Low", count),
                    _ => format!("{} {}", count, severity),
                }
            } else {
                format!("✅ 0 {}", severity.to_uppercase())
            }
        };

        let blocks = vec![
            SlackBlock::Header {
                text: SlackText::plain("📊 HeroForge Dashboard"),
            },
            SlackBlock::Divider {},
            SlackBlock::Section {
                text: SlackText::mrkdwn(&format!(
                    "*Vulnerability Summary*\n\n\
                    {}\n{}\n{}\n{}",
                    severity_emoji(stats.critical_count, "critical"),
                    severity_emoji(stats.high_count, "high"),
                    severity_emoji(stats.medium_count, "medium"),
                    severity_emoji(stats.low_count, "low"),
                )),
                accessory: None,
            },
            SlackBlock::Section {
                text: SlackText::mrkdwn(&format!(
                    "*Recent Activity*\n\n\
                    📡 {} Active Scans\n\
                    🖥️ {} Hosts Monitored\n\
                    📋 {} Total Scans",
                    stats.active_scans,
                    stats.total_hosts,
                    stats.total_scans,
                )),
                accessory: None,
            },
        ];

        SlackResponse {
            response_type: "ephemeral".to_string(),
            text: Some("HeroForge Dashboard".to_string()),
            blocks: Some(blocks),
            attachments: None,
        }
    }

    /// Build vulnerability list response
    pub fn build_vulns_response(vulns: &[VulnSummary], severity_filter: Option<&str>) -> SlackResponse {
        let filter_text = severity_filter
            .map(|s| format!(" ({})", s.to_uppercase()))
            .unwrap_or_default();

        if vulns.is_empty() {
            return SlackResponse {
                response_type: "ephemeral".to_string(),
                text: Some(format!("No vulnerabilities found{}", filter_text)),
                blocks: Some(vec![
                    SlackBlock::Section {
                        text: SlackText::mrkdwn(&format!(
                            "✅ No vulnerabilities found{}.",
                            filter_text
                        )),
                        accessory: None,
                    },
                ]),
                attachments: None,
            };
        }

        let mut blocks = vec![
            SlackBlock::Header {
                text: SlackText::plain(&format!("🔍 Vulnerabilities{}", filter_text)),
            },
            SlackBlock::Divider {},
        ];

        for (i, vuln) in vulns.iter().take(10).enumerate() {
            let severity_icon = match vuln.severity.as_str() {
                "critical" => "🔴",
                "high" => "🟠",
                "medium" => "🟡",
                "low" => "🟢",
                _ => "⚪",
            };

            blocks.push(SlackBlock::Section {
                text: SlackText::mrkdwn(&format!(
                    "*{}. {}*\n{} {} | Host: `{}`",
                    i + 1,
                    vuln.title,
                    severity_icon,
                    vuln.severity.to_uppercase(),
                    vuln.host,
                )),
                accessory: None,
            });
        }

        if vulns.len() > 10 {
            blocks.push(SlackBlock::Context {
                elements: vec![SlackText::mrkdwn(&format!(
                    "_Showing 10 of {} vulnerabilities. View the full list in the dashboard._",
                    vulns.len()
                ))],
            });
        }

        SlackResponse {
            response_type: "ephemeral".to_string(),
            text: Some("Vulnerabilities".to_string()),
            blocks: Some(blocks),
            attachments: None,
        }
    }

    /// Build report response
    pub fn build_report_response(scan_id: &str, report_url: &str) -> SlackResponse {
        let blocks = vec![
            SlackBlock::Section {
                text: SlackText::mrkdwn(&format!(
                    "📋 *Report Generated*\n\nScan ID: `{}`",
                    scan_id
                )),
                accessory: None,
            },
            SlackBlock::Actions {
                elements: vec![SlackButton {
                    button_type: "button".to_string(),
                    text: SlackText::plain("View Report"),
                    action_id: "view_report".to_string(),
                    url: Some(report_url.to_string()),
                    value: None,
                    style: Some("primary".to_string()),
                }],
            },
        ];

        SlackResponse {
            response_type: "in_channel".to_string(),
            text: Some(format!("Report for scan {}", scan_id)),
            blocks: Some(blocks),
            attachments: None,
        }
    }

    /// Build error response
    pub fn build_error_response(message: &str) -> SlackResponse {
        SlackResponse {
            response_type: "ephemeral".to_string(),
            text: Some(format!("Error: {}", message)),
            blocks: Some(vec![SlackBlock::Section {
                text: SlackText::mrkdwn(&format!("❌ *Error*\n\n{}", message)),
                accessory: None,
            }]),
            attachments: None,
        }
    }

    /// Send a delayed response to Slack
    pub async fn send_response(&self, response_url: &str, response: &SlackResponse) -> Result<()> {
        self.client
            .post(response_url)
            .json(response)
            .send()
            .await?;

        Ok(())
    }

    /// Send a message to a channel
    pub async fn send_channel_message(&self, channel: &str, blocks: Vec<SlackBlock>) -> Result<()> {
        let mut payload = HashMap::new();
        payload.insert("channel", serde_json::json!(channel));
        payload.insert("blocks", serde_json::to_value(&blocks)?);

        self.client
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.bot_token)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }
}

/// Dashboard statistics for status command
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

/// Vulnerability summary for list command
#[derive(Debug)]
pub struct VulnSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_command() {
        match SlackBot::parse_command("scan 192.168.1.1") {
            HeroForgeCommand::Scan { target } => assert_eq!(target, "192.168.1.1"),
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_parse_vulns_command() {
        match SlackBot::parse_command("vulns critical") {
            HeroForgeCommand::Vulns { severity } => assert_eq!(severity, Some("critical".to_string())),
            _ => panic!("Expected Vulns command"),
        }
    }

    #[test]
    fn test_parse_help_command() {
        match SlackBot::parse_command("help") {
            HeroForgeCommand::Help => {}
            _ => panic!("Expected Help command"),
        }
    }
}
