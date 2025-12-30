//! Mock implementations for testing

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

/// Mock email service for testing
pub struct MockEmailService {
    sent_emails: Arc<Mutex<Vec<SentEmail>>>,
}

#[derive(Debug, Clone)]
pub struct SentEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl MockEmailService {
    pub fn new() -> Self {
        Self {
            sent_emails: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn send(&self, to: &str, subject: &str, body: &str) {
        let email = SentEmail {
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        };

        self.sent_emails.lock().unwrap().push(email);
    }

    pub fn get_sent_emails(&self) -> Vec<SentEmail> {
        self.sent_emails.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.sent_emails.lock().unwrap().clear();
    }
}

impl Default for MockEmailService {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock webhook service for testing
pub struct MockWebhookService {
    delivered_webhooks: Arc<Mutex<Vec<DeliveredWebhook>>>,
}

#[derive(Debug, Clone)]
pub struct DeliveredWebhook {
    pub url: String,
    pub event_type: String,
    pub payload: String,
}

impl MockWebhookService {
    pub fn new() -> Self {
        Self {
            delivered_webhooks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn deliver(&self, url: &str, event_type: &str, payload: &str) {
        let webhook = DeliveredWebhook {
            url: url.to_string(),
            event_type: event_type.to_string(),
            payload: payload.to_string(),
        };

        self.delivered_webhooks.lock().unwrap().push(webhook);
    }

    pub fn get_delivered_webhooks(&self) -> Vec<DeliveredWebhook> {
        self.delivered_webhooks.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.delivered_webhooks.lock().unwrap().clear();
    }
}

impl Default for MockWebhookService {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock Redis for testing (in-memory)
pub struct MockRedis {
    data: Arc<Mutex<HashMap<String, String>>>,
}

impl MockRedis {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn set(&self, key: &str, value: &str) {
        self.data.lock().unwrap().insert(key.to_string(), value.to_string());
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }

    pub fn delete(&self, key: &str) {
        self.data.lock().unwrap().remove(key);
    }

    pub fn clear(&self) {
        self.data.lock().unwrap().clear();
    }
}

impl Default for MockRedis {
    fn default() -> Self {
        Self::new()
    }
}
