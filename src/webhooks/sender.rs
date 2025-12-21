#![allow(dead_code)]
//! Webhook HTTP sender with HMAC signing and retry logic
//!
//! This module handles the actual HTTP delivery of webhook payloads,
//! including HMAC-SHA256 signature generation and exponential backoff retries.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use std::time::Duration;
use tokio::time::sleep;

use crate::db::Webhook;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of retry attempts
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (in milliseconds)
const BASE_DELAY_MS: u64 = 1000;
/// Request timeout in seconds
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Maximum failure count before auto-disabling webhook
pub const MAX_FAILURE_COUNT: i32 = 10;

/// Result of a webhook delivery attempt
#[derive(Debug)]
pub struct DeliveryResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
    pub attempts: u32,
}

/// Send a webhook payload to the configured URL
pub async fn send_webhook(
    webhook: &Webhook,
    payload: &str,
) -> DeliveryResult {
    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .unwrap_or_default();

    // Parse custom headers if present
    let custom_headers: std::collections::HashMap<String, String> = webhook
        .headers
        .as_ref()
        .and_then(|h| serde_json::from_str(h).ok())
        .unwrap_or_default();

    let mut attempts = 0;

    loop {
        attempts += 1;

        match attempt_delivery(&client, webhook, payload, &custom_headers).await {
            Ok(result) => return DeliveryResult {
                success: result.success,
                status_code: result.status_code,
                response_body: result.response_body,
                error: result.error,
                attempts,
            },
            Err(e) => {
                if attempts >= MAX_RETRIES {
                    return DeliveryResult {
                        success: false,
                        status_code: None,
                        response_body: None,
                        error: Some(format!("Failed after {} attempts: {}", attempts, e)),
                        attempts,
                    };
                }

                // Exponential backoff
                let delay = BASE_DELAY_MS * 2u64.pow(attempts - 1);
                log::warn!(
                    "Webhook delivery attempt {} failed: {}. Retrying in {}ms...",
                    attempts,
                    e,
                    delay
                );
                sleep(Duration::from_millis(delay)).await;
            }
        }
    }
}

/// Single delivery attempt
async fn attempt_delivery(
    client: &Client,
    webhook: &Webhook,
    payload: &str,
    custom_headers: &std::collections::HashMap<String, String>,
) -> Result<DeliveryResult> {
    let mut request = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "HeroForge-Webhook/1.0");

    // Add HMAC signature if secret is configured
    if let Some(ref secret) = webhook.secret {
        let signature = generate_signature(payload, secret)?;
        request = request.header("X-Webhook-Signature", signature);
    }

    // Add custom headers
    for (key, value) in custom_headers {
        request = request.header(key.as_str(), value.as_str());
    }

    let response = request
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| anyhow!("HTTP request failed: {}", e))?;

    let status = response.status();
    let status_code = status.as_u16();

    // Read response body (limited to 10KB to prevent memory issues)
    let body = response
        .text()
        .await
        .ok()
        .map(|b| if b.len() > 10240 { b[..10240].to_string() } else { b });

    // Consider 2xx and 3xx as success
    let success = status.is_success() || status.is_redirection();

    if success {
        Ok(DeliveryResult {
            success: true,
            status_code: Some(status_code),
            response_body: body,
            error: None,
            attempts: 1,
        })
    } else {
        Ok(DeliveryResult {
            success: false,
            status_code: Some(status_code),
            response_body: body.clone(),
            error: Some(format!("HTTP {} response", status_code)),
            attempts: 1,
        })
    }
}

/// Generate HMAC-SHA256 signature for the payload
fn generate_signature(payload: &str, secret: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow!("Invalid HMAC key: {}", e))?;

    mac.update(payload.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());

    Ok(format!("sha256={}", signature))
}

/// Verify an incoming HMAC signature (useful for testing)
pub fn verify_signature(payload: &str, secret: &str, signature: &str) -> bool {
    let expected = match generate_signature(payload, secret) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Constant-time comparison to prevent timing attacks
    constant_time_compare(&expected, signature)
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_signature() {
        let payload = r#"{"event":"scan.completed","data":{}}"#;
        let secret = "test-secret-key";

        let signature = generate_signature(payload, secret).unwrap();
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), 7 + 64); // "sha256=" + 64 hex chars
    }

    #[test]
    fn test_verify_signature() {
        let payload = r#"{"event":"scan.completed","data":{}}"#;
        let secret = "test-secret-key";

        let signature = generate_signature(payload, secret).unwrap();
        assert!(verify_signature(payload, secret, &signature));

        // Wrong payload should fail
        assert!(!verify_signature("wrong payload", secret, &signature));

        // Wrong secret should fail
        assert!(!verify_signature(payload, "wrong-secret", &signature));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
    }
}
