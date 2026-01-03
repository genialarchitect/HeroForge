//! WhatsApp integration (via Twilio)

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;

pub struct WhatsAppIntegration {
    account_sid: String,
    auth_token: String,
    from_number: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct TwilioMessageResponse {
    sid: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct TwilioErrorResponse {
    code: Option<i32>,
    message: Option<String>,
}

impl WhatsAppIntegration {
    pub fn new(account_sid: String, auth_token: String) -> Self {
        Self::with_from_number(account_sid, auth_token, "+14155238886".to_string())
    }

    pub fn with_from_number(account_sid: String, auth_token: String, from_number: String) -> Self {
        Self {
            account_sid,
            auth_token,
            from_number,
            client: Client::new(),
        }
    }

    pub async fn send_message(&self, to: &str, message: &str) -> Result<()> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );

        // Twilio WhatsApp requires the "whatsapp:" prefix
        let from = if self.from_number.starts_with("whatsapp:") {
            self.from_number.clone()
        } else {
            format!("whatsapp:{}", self.from_number)
        };

        let to_formatted = if to.starts_with("whatsapp:") {
            to.to_string()
        } else {
            format!("whatsapp:{}", to)
        };

        let params = [
            ("From", from.as_str()),
            ("To", to_formatted.as_str()),
            ("Body", message),
        ];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            let msg_response: TwilioMessageResponse = response.json().await?;
            log::info!(
                "WhatsApp message sent successfully. SID: {}, Status: {}",
                msg_response.sid,
                msg_response.status
            );
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            if let Ok(error) = serde_json::from_str::<TwilioErrorResponse>(&error_text) {
                Err(anyhow!(
                    "Twilio API error ({}): {}",
                    error.code.unwrap_or(0),
                    error.message.unwrap_or_else(|| "Unknown error".to_string())
                ))
            } else {
                Err(anyhow!("Twilio API error ({}): {}", status, error_text))
            }
        }
    }

    /// Send a WhatsApp template message (for pre-approved templates)
    pub async fn send_template_message(
        &self,
        to: &str,
        template_sid: &str,
        content_variables: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );

        let from = if self.from_number.starts_with("whatsapp:") {
            self.from_number.clone()
        } else {
            format!("whatsapp:{}", self.from_number)
        };

        let to_formatted = if to.starts_with("whatsapp:") {
            to.to_string()
        } else {
            format!("whatsapp:{}", to)
        };

        let content_variables_json = serde_json::to_string(content_variables)?;

        let params = [
            ("From", from.as_str()),
            ("To", to_formatted.as_str()),
            ("ContentSid", template_sid),
            ("ContentVariables", content_variables_json.as_str()),
        ];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("WhatsApp template message sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("Twilio API error ({}): {}", status, error_text))
        }
    }
}
