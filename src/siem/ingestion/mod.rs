//! Log ingestion module for receiving logs from various sources.
//!
//! This module provides log ingestion capabilities via:
//! - Syslog (UDP/TCP on port 514)
//! - HTTP (JSON logs via REST API)
//!
//! The ingestion pipeline:
//! 1. Receive raw log data
//! 2. Parse according to detected/configured format
//! 3. Enrich with metadata (source, timestamp, etc.)
//! 4. Store in the log database
//! 5. Queue for rule evaluation

#![allow(dead_code)]

pub mod http;
pub mod syslog;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

use super::parser::LogParser;
use super::storage::LogStorage;
use super::types::{IngestionStats, LogEntry, LogSource, SiemId};

/// Maximum number of entries to buffer before flushing to storage
const BUFFER_SIZE: usize = 1000;

/// Flush interval in seconds
const FLUSH_INTERVAL_SECS: u64 = 5;

/// Message sent through the ingestion pipeline
#[derive(Debug, Clone)]
pub struct IngestionMessage {
    /// The parsed log entry
    pub entry: LogEntry,
    /// Source ID that sent the log
    pub source_id: SiemId,
}

/// Configuration for the ingestion service
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Whether to enable syslog ingestion
    pub enable_syslog: bool,
    /// Syslog UDP port
    pub syslog_udp_port: u16,
    /// Syslog TCP port
    pub syslog_tcp_port: u16,
    /// Whether to enable HTTP ingestion
    pub enable_http: bool,
    /// HTTP ingestion port
    pub http_port: u16,
    /// Maximum buffer size before flush
    pub buffer_size: usize,
    /// Flush interval in seconds
    pub flush_interval_secs: u64,
    /// Whether to auto-detect log format
    pub auto_detect_format: bool,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            enable_syslog: true,
            syslog_udp_port: 514,
            syslog_tcp_port: 514,
            enable_http: true,
            http_port: 8514,
            buffer_size: BUFFER_SIZE,
            flush_interval_secs: FLUSH_INTERVAL_SECS,
            auto_detect_format: true,
        }
    }
}

/// Handle to control the ingestion service
pub struct IngestionHandle {
    /// Channel to send shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Channel to receive ingested entries (for rule evaluation)
    entry_rx: Option<mpsc::Receiver<IngestionMessage>>,
}

impl IngestionHandle {
    /// Shutdown the ingestion service
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Take the entry receiver channel
    pub fn take_entry_receiver(&mut self) -> Option<mpsc::Receiver<IngestionMessage>> {
        self.entry_rx.take()
    }
}

/// The main ingestion service that coordinates all ingestion methods
pub struct IngestionService {
    config: IngestionConfig,
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<tokio::sync::RwLock<IngestionStats>>,
}

impl IngestionService {
    /// Create a new ingestion service
    pub fn new(storage: LogStorage, config: IngestionConfig) -> Self {
        let parser = LogParser::new()
            .with_auto_detect(config.auto_detect_format);

        Self {
            config,
            storage: Arc::new(storage),
            parser: Arc::new(parser),
            stats: Arc::new(tokio::sync::RwLock::new(IngestionStats::new())),
        }
    }

    /// Start the ingestion service
    pub async fn start(self) -> Result<IngestionHandle> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (entry_tx, entry_rx) = mpsc::channel(10000);

        // Start syslog receiver if enabled
        if self.config.enable_syslog {
            let syslog_receiver = syslog::SyslogReceiver::new(
                self.config.syslog_udp_port,
                self.config.syslog_tcp_port,
                Arc::clone(&self.storage),
                Arc::clone(&self.parser),
                Arc::clone(&self.stats),
                entry_tx.clone(),
                shutdown_tx.subscribe(),
            );

            tokio::spawn(async move {
                if let Err(e) = syslog_receiver.run().await {
                    log::error!("Syslog receiver error: {}", e);
                }
            });

            log::info!(
                "Syslog ingestion started on UDP:{} TCP:{}",
                self.config.syslog_udp_port,
                self.config.syslog_tcp_port
            );
        }

        // Start HTTP receiver if enabled
        if self.config.enable_http {
            let http_receiver = http::HttpReceiver::new(
                self.config.http_port,
                Arc::clone(&self.storage),
                Arc::clone(&self.parser),
                Arc::clone(&self.stats),
                entry_tx,
                shutdown_tx.subscribe(),
            );

            tokio::spawn(async move {
                if let Err(e) = http_receiver.run().await {
                    log::error!("HTTP receiver error: {}", e);
                }
            });

            log::info!("HTTP ingestion started on port {}", self.config.http_port);
        }

        Ok(IngestionHandle {
            shutdown_tx,
            entry_rx: Some(entry_rx),
        })
    }

    /// Get current ingestion statistics
    pub async fn get_stats(&self) -> IngestionStats {
        self.stats.read().await.clone()
    }
}

/// Trait for log source resolvers
pub trait SourceResolver: Send + Sync {
    /// Resolve a source ID from connection metadata
    fn resolve_source(&self, ip: &str, port: u16) -> Option<LogSource>;
}

/// Default source resolver that creates auto-sources
pub struct AutoSourceResolver;

impl SourceResolver for AutoSourceResolver {
    fn resolve_source(&self, ip: &str, _port: u16) -> Option<LogSource> {
        Some(LogSource {
            id: format!("auto-{}", ip),
            name: format!("Auto-discovered: {}", ip),
            host: Some(ip.to_string()),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingestion_config_default() {
        let config = IngestionConfig::default();
        assert!(config.enable_syslog);
        assert!(config.enable_http);
        assert_eq!(config.syslog_udp_port, 514);
        assert_eq!(config.http_port, 8514);
    }
}
