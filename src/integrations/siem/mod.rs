pub mod syslog;
pub mod splunk;
pub mod elasticsearch;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiemType {
    Syslog,
    Splunk,
    Elasticsearch,
}

impl SiemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Syslog => "syslog",
            Self::Splunk => "splunk",
            Self::Elasticsearch => "elasticsearch",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "syslog" => Some(Self::Syslog),
            "splunk" => Some(Self::Splunk),
            "elasticsearch" => Some(Self::Elasticsearch),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub event_type: String, // "scan_complete", "vulnerability_found", "host_discovered"
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub message: String,
    pub details: serde_json::Value,
    pub cve_ids: Vec<String>,
    pub cvss_score: Option<f32>,
    pub scan_id: String,
    pub user_id: String,
}

#[async_trait]
pub trait SiemExporter: Send + Sync {
    async fn export_event(&self, event: &SiemEvent) -> Result<()>;
    async fn export_events(&self, events: &[SiemEvent]) -> Result<()>;
    async fn test_connection(&self) -> Result<()>;
}

pub struct SiemConfig {
    pub siem_type: SiemType,
    pub endpoint_url: String,
    pub api_key: Option<String>,
    pub protocol: Option<String>, // For syslog: "tcp" or "udp"
}

pub async fn create_exporter(config: SiemConfig) -> Result<Box<dyn SiemExporter>> {
    match config.siem_type {
        SiemType::Syslog => {
            let exporter = syslog::SyslogExporter::new(
                &config.endpoint_url,
                config.protocol.as_deref().unwrap_or("tcp"),
            )?;
            Ok(Box::new(exporter))
        }
        SiemType::Splunk => {
            let api_key = config.api_key.ok_or_else(|| {
                anyhow::anyhow!("API key required for Splunk HEC")
            })?;
            let exporter = splunk::SplunkExporter::new(&config.endpoint_url, &api_key)?;
            Ok(Box::new(exporter))
        }
        SiemType::Elasticsearch => {
            let exporter = elasticsearch::ElasticsearchExporter::new(
                &config.endpoint_url,
                config.api_key.as_deref(),
            )?;
            Ok(Box::new(exporter))
        }
    }
}
