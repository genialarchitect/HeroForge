//! Discord integration

use anyhow::Result;

pub struct DiscordIntegration {
    webhook_url: String,
}

impl DiscordIntegration {
    pub fn new(webhook_url: String) -> Self {
        Self { webhook_url }
    }

    pub async fn send_message(&self, message: &str) -> Result<()> {
        // TODO: Send Discord message via webhook
        Ok(())
    }

    pub async fn send_embed(&self, title: &str, description: &str, color: u32) -> Result<()> {
        // TODO: Send Discord embed
        Ok(())
    }
}
