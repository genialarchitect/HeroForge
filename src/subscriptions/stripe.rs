//! Stripe payment integration for subscription management
//!
//! Handles:
//! - Checkout session creation
//! - Webhook processing
//! - Customer and subscription management

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

/// Stripe API client
pub struct StripeClient {
    client: Client,
    secret_key: String,
    webhook_secret: Option<String>,
    base_url: String,
}

impl StripeClient {
    /// Create a new Stripe client from environment variables
    pub fn from_env() -> Result<Self> {
        let secret_key = env::var("STRIPE_SECRET_KEY")
            .map_err(|_| anyhow!("STRIPE_SECRET_KEY environment variable not set"))?;

        let webhook_secret = env::var("STRIPE_WEBHOOK_SECRET").ok();

        Ok(Self {
            client: Client::new(),
            secret_key,
            webhook_secret,
            base_url: "https://api.stripe.com/v1".to_string(),
        })
    }

    /// Create a new Stripe client with explicit credentials
    pub fn new(secret_key: String, webhook_secret: Option<String>) -> Self {
        Self {
            client: Client::new(),
            secret_key,
            webhook_secret,
            base_url: "https://api.stripe.com/v1".to_string(),
        }
    }

    /// Check if Stripe is configured
    pub fn is_configured() -> bool {
        env::var("STRIPE_SECRET_KEY").is_ok()
    }

    /// Create a checkout session for subscription
    pub async fn create_checkout_session(
        &self,
        price_id: &str,
        customer_email: &str,
        success_url: &str,
        cancel_url: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<CheckoutSession> {
        let mut form: Vec<(&str, String)> = vec![
            ("mode", "subscription".to_string()),
            ("customer_email", customer_email.to_string()),
            ("success_url", success_url.to_string()),
            ("cancel_url", cancel_url.to_string()),
            ("line_items[0][price]", price_id.to_string()),
            ("line_items[0][quantity]", "1".to_string()),
        ];

        // Add metadata if provided
        if let Some(meta) = metadata {
            for (key, value) in meta {
                form.push(("metadata[{}]", format!("{}={}", key, value)));
            }
        }

        let response = self
            .client
            .post(format!("{}/checkout/sessions", self.base_url))
            .basic_auth(&self.secret_key, Option::<&str>::None)
            .form(&form)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Stripe API error: {}", error_text));
        }

        let session: CheckoutSession = response.json().await?;
        Ok(session)
    }

    /// Retrieve a checkout session by ID
    pub async fn get_checkout_session(&self, session_id: &str) -> Result<CheckoutSession> {
        let response = self
            .client
            .get(format!("{}/checkout/sessions/{}", self.base_url, session_id))
            .basic_auth(&self.secret_key, Option::<&str>::None)
            .query(&[("expand[]", "customer"), ("expand[]", "subscription")])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Stripe API error: {}", error_text));
        }

        let session: CheckoutSession = response.json().await?;
        Ok(session)
    }

    /// Get customer by ID
    pub async fn get_customer(&self, customer_id: &str) -> Result<Customer> {
        let response = self
            .client
            .get(format!("{}/customers/{}", self.base_url, customer_id))
            .basic_auth(&self.secret_key, Option::<&str>::None)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Stripe API error: {}", error_text));
        }

        let customer: Customer = response.json().await?;
        Ok(customer)
    }

    /// Get subscription by ID
    pub async fn get_subscription(&self, subscription_id: &str) -> Result<Subscription> {
        let response = self
            .client
            .get(format!("{}/subscriptions/{}", self.base_url, subscription_id))
            .basic_auth(&self.secret_key, Option::<&str>::None)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Stripe API error: {}", error_text));
        }

        let subscription: Subscription = response.json().await?;
        Ok(subscription)
    }

    /// Cancel a subscription
    pub async fn cancel_subscription(&self, subscription_id: &str) -> Result<Subscription> {
        let response = self
            .client
            .delete(format!("{}/subscriptions/{}", self.base_url, subscription_id))
            .basic_auth(&self.secret_key, Option::<&str>::None)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Stripe API error: {}", error_text));
        }

        let subscription: Subscription = response.json().await?;
        Ok(subscription)
    }

    /// Verify webhook signature (returns event if valid)
    pub fn verify_webhook(&self, payload: &str, signature: &str) -> Result<WebhookEvent> {
        let webhook_secret = self
            .webhook_secret
            .as_ref()
            .ok_or_else(|| anyhow!("Webhook secret not configured"))?;

        // Parse the signature header
        let mut timestamp: Option<&str> = None;
        let mut signatures: Vec<&str> = Vec::new();

        for part in signature.split(',') {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() == 2 {
                match kv[0] {
                    "t" => timestamp = Some(kv[1]),
                    "v1" => signatures.push(kv[1]),
                    _ => {}
                }
            }
        }

        let timestamp = timestamp.ok_or_else(|| anyhow!("Missing timestamp in signature"))?;

        // Compute expected signature
        let signed_payload = format!("{}.{}", timestamp, payload);
        let expected_signature = hmac_sha256(webhook_secret, &signed_payload);

        // Verify at least one signature matches
        let signature_valid = signatures.iter().any(|sig| {
            constant_time_compare(&hex::decode(sig).unwrap_or_default(), &expected_signature)
        });

        if !signature_valid {
            return Err(anyhow!("Invalid webhook signature"));
        }

        // Parse the event
        let event: WebhookEvent = serde_json::from_str(payload)?;
        Ok(event)
    }
}

/// Stripe Checkout Session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub status: Option<String>,
    pub payment_status: Option<String>,
    pub customer: Option<String>,
    pub customer_email: Option<String>,
    pub subscription: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Stripe Customer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created: i64,
}

/// Stripe Subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub status: String,
    pub customer: String,
    pub current_period_start: i64,
    pub current_period_end: i64,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<i64>,
}

/// Stripe Webhook Event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: WebhookEventData,
    pub created: i64,
}

/// Webhook event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEventData {
    pub object: serde_json::Value,
}

// Helper: HMAC-SHA256
fn hmac_sha256(key: &str, data: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

// Helper: Constant-time comparison
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_configured_false() {
        // Should return false when env var not set
        // (may fail if STRIPE_SECRET_KEY is actually set in test environment)
        std::env::remove_var("STRIPE_SECRET_KEY");
        assert!(!StripeClient::is_configured());
    }
}
