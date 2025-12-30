//! WhatsApp integration (via Twilio)

use anyhow::Result;

pub struct WhatsAppIntegration {
    account_sid: String,
    auth_token: String,
}

impl WhatsAppIntegration {
    pub fn new(account_sid: String, auth_token: String) -> Self {
        Self { account_sid, auth_token }
    }

    pub async fn send_message(&self, to: &str, message: &str) -> Result<()> {
        // TODO: Send WhatsApp message via Twilio
        Ok(())
    }
}
