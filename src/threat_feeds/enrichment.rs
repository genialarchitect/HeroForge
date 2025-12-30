//! IOC enrichment and contextualization

use super::*;
use anyhow::Result;

pub struct IocEnricher {}

impl IocEnricher {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn enrich(&self, ioc: &str) -> Result<EnrichedIoc> {
        // TODO: Enrich IOC with context from multiple sources
        Ok(EnrichedIoc {
            ioc: ioc.to_string(),
            reputation_score: 0.0,
            first_seen: None,
            last_seen: None,
            threat_types: vec![],
        })
    }
}

impl Default for IocEnricher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrichedIoc {
    pub ioc: String,
    pub reputation_score: f32,
    pub first_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub threat_types: Vec<String>,
}
