//! Telegram integration

use anyhow::Result;

pub struct TelegramIntegration {
    bot_token: String,
    chat_id: String,
}

impl TelegramIntegration {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self { bot_token, chat_id }
    }

    pub async fn send_message(&self, message: &str) -> Result<()> {
        // TODO: Send Telegram message
        Ok(())
    }
}
