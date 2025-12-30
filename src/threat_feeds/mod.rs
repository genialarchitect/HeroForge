//! Threat Intelligence Feeds Module

#![allow(dead_code)]

pub mod feeds;
pub mod enrichment;
pub mod sharing;

use anyhow::Result;

pub struct ThreatFeedAggregator {}

impl ThreatFeedAggregator {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn fetch_feeds(&self) -> Result<Vec<ThreatIndicator>> {
        // TODO: Aggregate from MISP, STIX, custom feeds
        Ok(vec![])
    }
}

impl Default for ThreatFeedAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatIndicator {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}
