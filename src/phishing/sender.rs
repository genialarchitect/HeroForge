//! Email Sender
//!
//! Handles SMTP email delivery for phishing campaigns.

use anyhow::{anyhow, Result};
use lettre::{
    message::{
        header::ContentType, Attachment, Mailbox, Message, MultiPart, SinglePart,
    },
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use std::time::Duration;

use super::types::{SmtpProfile, TemplateAttachment};

/// Email sender for phishing campaigns
#[derive(Clone)]
pub struct EmailSender {
    timeout: Duration,
}

impl Default for EmailSender {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailSender {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send an email using the specified SMTP profile
    pub async fn send_email(
        &self,
        profile: &SmtpProfile,
        to_email: &str,
        from_name: &str,
        from_email: &str,
        subject: &str,
        html_body: &str,
        text_body: Option<&str>,
        attachments: &[TemplateAttachment],
    ) -> Result<()> {
        // Parse email addresses
        let from_mailbox: Mailbox = format!("{} <{}>", from_name, from_email)
            .parse()
            .map_err(|e| anyhow!("Invalid from address: {}", e))?;

        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| anyhow!("Invalid to address: {}", e))?;

        // Build the message
        let message = if attachments.is_empty() {
            // Simple multipart message (HTML + optional text)
            let multipart = if let Some(text) = text_body {
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    )
            } else {
                MultiPart::alternative().singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body.to_string()),
                )
            };

            Message::builder()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(subject)
                .multipart(multipart)?
        } else {
            // Message with attachments
            let content_part = if let Some(text) = text_body {
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body.to_string()),
                    )
            } else {
                MultiPart::alternative().singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body.to_string()),
                )
            };

            let mut mixed = MultiPart::mixed().multipart(content_part);

            for attachment in attachments {
                let content = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &attachment.content_base64,
                )
                .map_err(|e| anyhow!("Invalid attachment encoding: {}", e))?;

                let content_type: ContentType = attachment
                    .content_type
                    .parse()
                    .unwrap_or(ContentType::parse("application/octet-stream").unwrap());

                let att = Attachment::new(attachment.name.clone()).body(content, content_type);
                mixed = mixed.singlepart(att);
            }

            Message::builder()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(subject)
                .multipart(mixed)?
        };

        // Build the SMTP transport
        let transport = self.build_transport(profile).await?;

        // Send the email
        transport
            .send(message)
            .await
            .map_err(|e| anyhow!("Failed to send email: {}", e))?;

        Ok(())
    }

    /// Build SMTP transport from profile
    async fn build_transport(
        &self,
        profile: &SmtpProfile,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let mut builder = if profile.use_tls {
            // Direct TLS connection (typically port 465)
            let tls_params = if profile.ignore_cert_errors {
                TlsParameters::builder(profile.host.clone())
                    .dangerous_accept_invalid_certs(true)
                    .dangerous_accept_invalid_hostnames(true)
                    .build()
                    .map_err(|e| anyhow!("TLS error: {}", e))?
            } else {
                TlsParameters::new(profile.host.clone())
                    .map_err(|e| anyhow!("TLS error: {}", e))?
            };

            AsyncSmtpTransport::<Tokio1Executor>::relay(&profile.host)
                .map_err(|e| anyhow!("SMTP relay error: {}", e))?
                .port(profile.port)
                .tls(Tls::Wrapper(tls_params))
        } else if profile.use_starttls {
            // STARTTLS connection (typically port 587)
            let tls_params = if profile.ignore_cert_errors {
                TlsParameters::builder(profile.host.clone())
                    .dangerous_accept_invalid_certs(true)
                    .dangerous_accept_invalid_hostnames(true)
                    .build()
                    .map_err(|e| anyhow!("TLS error: {}", e))?
            } else {
                TlsParameters::new(profile.host.clone())
                    .map_err(|e| anyhow!("TLS error: {}", e))?
            };

            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&profile.host)
                .map_err(|e| anyhow!("SMTP relay error: {}", e))?
                .port(profile.port)
                .tls(Tls::Required(tls_params))
        } else {
            // Plain connection (not recommended)
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&profile.host)
                .port(profile.port)
        };

        // Add credentials if provided
        if let (Some(username), Some(password)) = (&profile.username, &profile.password) {
            builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
        }

        builder = builder.timeout(Some(self.timeout));

        Ok(builder.build())
    }

    /// Test SMTP connection
    pub async fn test_connection(&self, profile: &SmtpProfile) -> Result<bool> {
        let transport = self.build_transport(profile).await?;
        transport
            .test_connection()
            .await
            .map_err(|e| anyhow!("Connection test failed: {}", e))
    }

    /// Send test email
    pub async fn send_test_email(
        &self,
        profile: &SmtpProfile,
        to_email: &str,
    ) -> Result<()> {
        self.send_email(
            profile,
            to_email,
            "HeroForge Phishing Test",
            &profile.from_address,
            "HeroForge SMTP Test",
            "<html><body><h1>SMTP Test Successful</h1><p>Your SMTP configuration is working correctly.</p></body></html>",
            Some("SMTP Test Successful\n\nYour SMTP configuration is working correctly."),
            &[],
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_sender_creation() {
        let sender = EmailSender::new();
        assert_eq!(sender.timeout, Duration::from_secs(30));

        let sender = EmailSender::new().with_timeout(Duration::from_secs(60));
        assert_eq!(sender.timeout, Duration::from_secs(60));
    }
}
