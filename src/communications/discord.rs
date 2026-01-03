//! Discord integration

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Serialize;

pub struct DiscordIntegration {
    webhook_url: String,
    client: Client,
}

#[derive(Debug, Serialize)]
struct DiscordWebhookPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    embeds: Option<Vec<DiscordEmbed>>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbed {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer: Option<DiscordEmbedFooter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<DiscordEmbedAuthor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<DiscordEmbedField>>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbedFooter {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbedAuthor {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiscordEmbedField {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
}

impl DiscordIntegration {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: Client::new(),
        }
    }

    pub async fn send_message(&self, message: &str) -> Result<()> {
        let payload = DiscordWebhookPayload {
            content: Some(message.to_string()),
            username: Some("HeroForge".to_string()),
            avatar_url: None,
            embeds: None,
        };

        let response = self
            .client
            .post(&self.webhook_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 204 {
            log::info!("Discord message sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("Discord webhook error ({}): {}", status, error_text))
        }
    }

    pub async fn send_embed(&self, title: &str, description: &str, color: u32) -> Result<()> {
        let embed = DiscordEmbed {
            title: Some(title.to_string()),
            description: Some(description.to_string()),
            url: None,
            color: Some(color),
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            footer: Some(DiscordEmbedFooter {
                text: "HeroForge Security Platform".to_string(),
                icon_url: None,
            }),
            author: None,
            fields: None,
        };

        let payload = DiscordWebhookPayload {
            content: None,
            username: Some("HeroForge".to_string()),
            avatar_url: None,
            embeds: Some(vec![embed]),
        };

        let response = self
            .client
            .post(&self.webhook_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 204 {
            log::info!("Discord embed sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("Discord webhook error ({}): {}", status, error_text))
        }
    }

    /// Send a rich embed with multiple fields
    pub async fn send_rich_embed(
        &self,
        title: &str,
        description: &str,
        color: u32,
        fields: Vec<DiscordEmbedField>,
    ) -> Result<()> {
        let embed = DiscordEmbed {
            title: Some(title.to_string()),
            description: Some(description.to_string()),
            url: None,
            color: Some(color),
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            footer: Some(DiscordEmbedFooter {
                text: "HeroForge Security Platform".to_string(),
                icon_url: None,
            }),
            author: Some(DiscordEmbedAuthor {
                name: "HeroForge".to_string(),
                url: None,
                icon_url: None,
            }),
            fields: Some(fields),
        };

        let payload = DiscordWebhookPayload {
            content: None,
            username: Some("HeroForge".to_string()),
            avatar_url: None,
            embeds: Some(vec![embed]),
        };

        let response = self
            .client
            .post(&self.webhook_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 204 {
            log::info!("Discord rich embed sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("Discord webhook error ({}): {}", status, error_text))
        }
    }

    /// Send a security alert embed with appropriate coloring
    pub async fn send_security_alert(
        &self,
        severity: &str,
        title: &str,
        description: &str,
        details: Vec<(&str, &str)>,
    ) -> Result<()> {
        let color = match severity.to_lowercase().as_str() {
            "critical" => 0xFF0000, // Red
            "high" => 0xFF6600,     // Orange
            "medium" => 0xFFFF00,   // Yellow
            "low" => 0x00FF00,      // Green
            "info" => 0x0099FF,     // Blue
            _ => 0x808080,          // Gray
        };

        let fields: Vec<DiscordEmbedField> = details
            .into_iter()
            .map(|(name, value)| DiscordEmbedField {
                name: name.to_string(),
                value: value.to_string(),
                inline: Some(true),
            })
            .collect();

        self.send_rich_embed(
            &format!("[{}] {}", severity.to_uppercase(), title),
            description,
            color,
            fields,
        )
        .await
    }
}
