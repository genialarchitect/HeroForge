//! Opsgenie integration

use anyhow::Result;

pub struct OpsgenieIntegration {
    api_key: String,
}

impl OpsgenieIntegration {
    pub fn new(api_key: String) -> Self {
        Self { api_key }
    }

    pub async fn create_alert(&self, message: &str, priority: &str) -> Result<String> {
        // TODO: Create Opsgenie alert
        Ok(String::new())
    }
}
