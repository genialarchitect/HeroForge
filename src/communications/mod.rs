//! Communications Module - Multi-channel messaging

#![allow(dead_code)]

pub mod discord;
pub mod telegram;
pub mod whatsapp;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Configuration for communication channels
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelConfig {
    pub discord: Option<DiscordConfig>,
    pub telegram: Option<TelegramConfig>,
    pub whatsapp: Option<WhatsAppConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub webhook_url: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppConfig {
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
    pub to_number: String,
    pub enabled: bool,
}

pub struct CommunicationsManager {
    config: ChannelConfig,
    discord: Option<discord::DiscordIntegration>,
    telegram: Option<telegram::TelegramIntegration>,
    whatsapp: Option<whatsapp::WhatsAppIntegration>,
}

impl CommunicationsManager {
    pub fn new() -> Self {
        Self {
            config: ChannelConfig::default(),
            discord: None,
            telegram: None,
            whatsapp: None,
        }
    }

    /// Create a new CommunicationsManager with configuration
    pub fn with_config(config: ChannelConfig) -> Self {
        let discord = config.discord.as_ref().and_then(|c| {
            if c.enabled {
                Some(discord::DiscordIntegration::new(c.webhook_url.clone()))
            } else {
                None
            }
        });

        let telegram = config.telegram.as_ref().and_then(|c| {
            if c.enabled {
                Some(telegram::TelegramIntegration::new(
                    c.bot_token.clone(),
                    c.chat_id.clone(),
                ))
            } else {
                None
            }
        });

        let whatsapp = config.whatsapp.as_ref().and_then(|c| {
            if c.enabled {
                Some(whatsapp::WhatsAppIntegration::with_from_number(
                    c.account_sid.clone(),
                    c.auth_token.clone(),
                    c.from_number.clone(),
                ))
            } else {
                None
            }
        });

        Self {
            config,
            discord,
            telegram,
            whatsapp,
        }
    }

    /// Configure Discord channel
    pub fn with_discord(mut self, webhook_url: String) -> Self {
        self.discord = Some(discord::DiscordIntegration::new(webhook_url.clone()));
        self.config.discord = Some(DiscordConfig {
            webhook_url,
            enabled: true,
        });
        self
    }

    /// Configure Telegram channel
    pub fn with_telegram(mut self, bot_token: String, chat_id: String) -> Self {
        self.telegram = Some(telegram::TelegramIntegration::new(
            bot_token.clone(),
            chat_id.clone(),
        ));
        self.config.telegram = Some(TelegramConfig {
            bot_token,
            chat_id,
            enabled: true,
        });
        self
    }

    /// Configure WhatsApp channel
    pub fn with_whatsapp(
        mut self,
        account_sid: String,
        auth_token: String,
        from_number: String,
        to_number: String,
    ) -> Self {
        self.whatsapp = Some(whatsapp::WhatsAppIntegration::with_from_number(
            account_sid.clone(),
            auth_token.clone(),
            from_number.clone(),
        ));
        self.config.whatsapp = Some(WhatsAppConfig {
            account_sid,
            auth_token,
            from_number,
            to_number,
            enabled: true,
        });
        self
    }

    pub async fn send_alert(&self, channel: &str, message: &str) -> Result<()> {
        match channel.to_lowercase().as_str() {
            "discord" => {
                if let Some(discord) = &self.discord {
                    discord.send_message(message).await
                } else {
                    Err(anyhow!("Discord channel not configured"))
                }
            }
            "telegram" => {
                if let Some(telegram) = &self.telegram {
                    telegram.send_message(message).await
                } else {
                    Err(anyhow!("Telegram channel not configured"))
                }
            }
            "whatsapp" => {
                if let Some(whatsapp) = &self.whatsapp {
                    let to = self
                        .config
                        .whatsapp
                        .as_ref()
                        .map(|c| c.to_number.as_str())
                        .unwrap_or("");
                    whatsapp.send_message(to, message).await
                } else {
                    Err(anyhow!("WhatsApp channel not configured"))
                }
            }
            "all" => {
                self.broadcast(message).await
            }
            _ => Err(anyhow!("Unknown channel: {}. Supported: discord, telegram, whatsapp, all", channel)),
        }
    }

    /// Broadcast message to all configured channels
    pub async fn broadcast(&self, message: &str) -> Result<()> {
        let mut results = Vec::new();

        if let Some(discord) = &self.discord {
            results.push(("discord", discord.send_message(message).await));
        }

        if let Some(telegram) = &self.telegram {
            results.push(("telegram", telegram.send_message(message).await));
        }

        if let Some(whatsapp) = &self.whatsapp {
            if let Some(config) = &self.config.whatsapp {
                results.push(("whatsapp", whatsapp.send_message(&config.to_number, message).await));
            }
        }

        // Check if any succeeded
        let successes: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
        let failures: Vec<_> = results
            .iter()
            .filter_map(|(name, r)| r.as_ref().err().map(|e| format!("{}: {}", name, e)))
            .collect();

        if successes.is_empty() && !results.is_empty() {
            Err(anyhow!("All channels failed: {}", failures.join("; ")))
        } else {
            if !failures.is_empty() {
                log::warn!("Some channels failed: {}", failures.join("; "));
            }
            Ok(())
        }
    }

    /// Send a security alert to all configured channels with appropriate formatting
    pub async fn send_security_alert(
        &self,
        severity: &str,
        title: &str,
        description: &str,
        details: Vec<(&str, &str)>,
    ) -> Result<()> {
        let mut results = Vec::new();

        if let Some(discord) = &self.discord {
            results.push((
                "discord",
                discord.send_security_alert(severity, title, description, details.clone()).await,
            ));
        }

        if let Some(telegram) = &self.telegram {
            results.push((
                "telegram",
                telegram.send_security_alert(severity, title, description, &details).await,
            ));
        }

        if let Some(whatsapp) = &self.whatsapp {
            if let Some(config) = &self.config.whatsapp {
                // Format message for WhatsApp (plain text)
                let mut msg = format!("[{}] {}\n\n{}", severity.to_uppercase(), title, description);
                if !details.is_empty() {
                    msg.push_str("\n\nDetails:");
                    for (key, value) in &details {
                        msg.push_str(&format!("\n- {}: {}", key, value));
                    }
                }
                results.push(("whatsapp", whatsapp.send_message(&config.to_number, &msg).await));
            }
        }

        let successes: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
        let failures: Vec<_> = results
            .iter()
            .filter_map(|(name, r)| r.as_ref().err().map(|e| format!("{}: {}", name, e)))
            .collect();

        if successes.is_empty() && !results.is_empty() {
            Err(anyhow!("All channels failed: {}", failures.join("; ")))
        } else {
            if !failures.is_empty() {
                log::warn!("Some channels failed: {}", failures.join("; "));
            }
            Ok(())
        }
    }

    /// Get list of configured channels
    pub fn configured_channels(&self) -> Vec<&str> {
        let mut channels = Vec::new();
        if self.discord.is_some() {
            channels.push("discord");
        }
        if self.telegram.is_some() {
            channels.push("telegram");
        }
        if self.whatsapp.is_some() {
            channels.push("whatsapp");
        }
        channels
    }
}

impl Default for CommunicationsManager {
    fn default() -> Self {
        Self::new()
    }
}
