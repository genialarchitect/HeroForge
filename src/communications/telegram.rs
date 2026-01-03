//! Telegram integration

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

pub struct TelegramIntegration {
    bot_token: String,
    chat_id: String,
    client: Client,
}

#[derive(Debug, Serialize)]
struct SendMessageRequest {
    chat_id: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_web_page_preview: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_markup: Option<InlineKeyboardMarkup>,
}

#[derive(Debug, Serialize)]
struct InlineKeyboardMarkup {
    inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

#[derive(Debug, Serialize)]
pub struct InlineKeyboardButton {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct MessageResult {
    message_id: i64,
}

impl TelegramIntegration {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: Client::new(),
        }
    }

    pub async fn send_message(&self, message: &str) -> Result<()> {
        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, self.bot_token);

        let request = SendMessageRequest {
            chat_id: self.chat_id.clone(),
            text: message.to_string(),
            parse_mode: Some("HTML".to_string()),
            disable_web_page_preview: Some(true),
            disable_notification: None,
            reply_markup: None,
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let response_body: TelegramResponse<MessageResult> = response.json().await?;

        if response_body.ok {
            if let Some(result) = response_body.result {
                log::info!("Telegram message sent successfully. Message ID: {}", result.message_id);
            }
            Ok(())
        } else {
            Err(anyhow!(
                "Telegram API error ({}): {}",
                status,
                response_body.description.unwrap_or_else(|| "Unknown error".to_string())
            ))
        }
    }

    /// Send a message with Markdown formatting
    pub async fn send_markdown(&self, message: &str) -> Result<()> {
        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, self.bot_token);

        let request = SendMessageRequest {
            chat_id: self.chat_id.clone(),
            text: message.to_string(),
            parse_mode: Some("MarkdownV2".to_string()),
            disable_web_page_preview: Some(true),
            disable_notification: None,
            reply_markup: None,
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let response_body: TelegramResponse<MessageResult> = response.json().await?;

        if response_body.ok {
            log::info!("Telegram markdown message sent successfully");
            Ok(())
        } else {
            Err(anyhow!(
                "Telegram API error: {}",
                response_body.description.unwrap_or_else(|| "Unknown error".to_string())
            ))
        }
    }

    /// Send a message with inline keyboard buttons
    pub async fn send_message_with_buttons(
        &self,
        message: &str,
        buttons: Vec<Vec<InlineKeyboardButton>>,
    ) -> Result<()> {
        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, self.bot_token);

        let request = SendMessageRequest {
            chat_id: self.chat_id.clone(),
            text: message.to_string(),
            parse_mode: Some("HTML".to_string()),
            disable_web_page_preview: Some(true),
            disable_notification: None,
            reply_markup: Some(InlineKeyboardMarkup {
                inline_keyboard: buttons,
            }),
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let response_body: TelegramResponse<MessageResult> = response.json().await?;

        if response_body.ok {
            log::info!("Telegram message with buttons sent successfully");
            Ok(())
        } else {
            Err(anyhow!(
                "Telegram API error: {}",
                response_body.description.unwrap_or_else(|| "Unknown error".to_string())
            ))
        }
    }

    /// Send a security alert formatted for Telegram
    pub async fn send_security_alert(
        &self,
        severity: &str,
        title: &str,
        description: &str,
        details: &[(&str, &str)],
    ) -> Result<()> {
        let severity_icon = match severity.to_lowercase().as_str() {
            "critical" => "🔴",
            "high" => "🟠",
            "medium" => "🟡",
            "low" => "🟢",
            "info" => "🔵",
            _ => "⚪",
        };

        let mut message = format!(
            "{} <b>[{}] {}</b>\n\n{}\n",
            severity_icon,
            severity.to_uppercase(),
            html_escape(title),
            html_escape(description)
        );

        if !details.is_empty() {
            message.push_str("\n<b>Details:</b>\n");
            for (key, value) in details {
                message.push_str(&format!("• <b>{}:</b> {}\n", html_escape(key), html_escape(value)));
            }
        }

        message.push_str("\n<i>— HeroForge Security Platform</i>");

        self.send_message(&message).await
    }

    /// Send a message to a specific chat (overrides default chat_id)
    pub async fn send_to_chat(&self, chat_id: &str, message: &str) -> Result<()> {
        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, self.bot_token);

        let request = SendMessageRequest {
            chat_id: chat_id.to_string(),
            text: message.to_string(),
            parse_mode: Some("HTML".to_string()),
            disable_web_page_preview: Some(true),
            disable_notification: None,
            reply_markup: None,
        };

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let response_body: TelegramResponse<MessageResult> = response.json().await?;

        if response_body.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "Telegram API error: {}",
                response_body.description.unwrap_or_else(|| "Unknown error".to_string())
            ))
        }
    }
}

/// Escape HTML special characters for Telegram
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
