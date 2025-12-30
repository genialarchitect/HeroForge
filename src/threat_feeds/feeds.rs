//! Threat feed ingestion

use super::*;
use anyhow::Result;

pub struct FeedIngester {}

impl FeedIngester {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn ingest_misp(&self) -> Result<Vec<ThreatIndicator>> {
        // TODO: Ingest MISP feed
        Ok(vec![])
    }

    pub async fn ingest_stix(&self) -> Result<Vec<ThreatIndicator>> {
        // TODO: Ingest STIX/TAXII feed
        Ok(vec![])
    }
}

impl Default for FeedIngester {
    fn default() -> Self {
        Self::new()
    }
}
