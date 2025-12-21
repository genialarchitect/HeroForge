//! HTTP JSON log receiver for REST-based log ingestion.
//!
//! Provides an HTTP endpoint for receiving logs in JSON format.
//! Supports batch ingestion and source-specific endpoints.

#![allow(dead_code)]

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};

use super::{IngestionMessage, IngestionStats};
use crate::siem::parser::LogParser;
use crate::siem::storage::LogStorage;
use crate::siem::types::{LogEntry, LogFormat, SiemSeverity};

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};

/// Request body for single log ingestion
#[derive(Debug, Deserialize)]
pub struct IngestLogRequest {
    /// The log message or raw log data
    pub message: Option<String>,
    /// Pre-parsed log entry (optional)
    pub entry: Option<LogEntryInput>,
    /// Source identifier (optional, will be auto-generated if not provided)
    pub source_id: Option<String>,
    /// Log format hint (optional, will be auto-detected if not provided)
    pub format: Option<String>,
}

/// Input format for pre-parsed log entries
#[derive(Debug, Deserialize)]
pub struct LogEntryInput {
    pub timestamp: Option<String>,
    pub severity: Option<String>,
    pub message: String,
    pub hostname: Option<String>,
    pub application: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub user: Option<String>,
    pub category: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub tags: Option<Vec<String>>,
    pub fields: Option<serde_json::Value>,
}

/// Request body for batch log ingestion
#[derive(Debug, Deserialize)]
pub struct BatchIngestRequest {
    /// List of logs to ingest
    pub logs: Vec<IngestLogRequest>,
    /// Default source ID for all logs
    pub source_id: Option<String>,
}

/// Response for single log ingestion
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub success: bool,
    pub log_id: Option<String>,
    pub message: String,
}

/// Response for batch log ingestion
#[derive(Debug, Serialize)]
pub struct BatchIngestResponse {
    pub success: bool,
    pub total: usize,
    pub ingested: usize,
    pub failed: usize,
    pub log_ids: Vec<String>,
    pub errors: Vec<String>,
}

/// Shared state for HTTP handlers
pub struct HttpState {
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<RwLock<IngestionStats>>,
    entry_tx: mpsc::Sender<IngestionMessage>,
}

/// HTTP receiver for JSON log ingestion
pub struct HttpReceiver {
    port: u16,
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<RwLock<IngestionStats>>,
    entry_tx: mpsc::Sender<IngestionMessage>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl HttpReceiver {
    pub fn new(
        port: u16,
        storage: Arc<LogStorage>,
        parser: Arc<LogParser>,
        stats: Arc<RwLock<IngestionStats>>,
        entry_tx: mpsc::Sender<IngestionMessage>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            port,
            storage,
            parser,
            stats,
            entry_tx,
            shutdown_rx,
        }
    }

    /// Run the HTTP receiver
    pub async fn run(mut self) -> Result<()> {
        let bind_addr = format!("0.0.0.0:{}", self.port);

        let state = web::Data::new(HttpState {
            storage: Arc::clone(&self.storage),
            parser: Arc::clone(&self.parser),
            stats: Arc::clone(&self.stats),
            entry_tx: self.entry_tx.clone(),
        });

        let server = HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route("/ingest", web::post().to(handle_ingest))
                .route("/ingest/batch", web::post().to(handle_batch_ingest))
                .route("/ingest/{source_id}", web::post().to(handle_source_ingest))
                .route("/health", web::get().to(handle_health))
                .route("/stats", web::get().to(handle_stats))
        })
        .bind(&bind_addr)?
        .disable_signals()
        .run();

        log::info!("HTTP ingestion server listening on {}", bind_addr);

        // Run until shutdown
        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    log::error!("HTTP server error: {}", e);
                }
            }
            _ = self.shutdown_rx.recv() => {
                log::info!("HTTP receiver shutdown signal received");
            }
        }

        Ok(())
    }
}

/// Handle single log ingestion
async fn handle_ingest(
    req: HttpRequest,
    body: web::Json<IngestLogRequest>,
    state: web::Data<HttpState>,
) -> HttpResponse {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    match ingest_single_log(&body, &client_ip, &state).await {
        Ok(entry) => HttpResponse::Ok().json(IngestResponse {
            success: true,
            log_id: Some(entry.id),
            message: "Log ingested successfully".to_string(),
        }),
        Err(e) => HttpResponse::BadRequest().json(IngestResponse {
            success: false,
            log_id: None,
            message: format!("Failed to ingest log: {}", e),
        }),
    }
}

/// Handle batch log ingestion
async fn handle_batch_ingest(
    req: HttpRequest,
    body: web::Json<BatchIngestRequest>,
    state: web::Data<HttpState>,
) -> HttpResponse {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let total = body.logs.len();
    let mut ingested = 0;
    let mut log_ids = Vec::new();
    let mut errors = Vec::new();

    for (i, log) in body.logs.iter().enumerate() {
        // Use batch source_id if individual log doesn't have one
        let mut log_with_source = log.clone();
        if log_with_source.source_id.is_none() {
            log_with_source.source_id = body.source_id.clone();
        }

        match ingest_single_log(&log_with_source, &client_ip, &state).await {
            Ok(entry) => {
                ingested += 1;
                log_ids.push(entry.id);
            }
            Err(e) => {
                errors.push(format!("Log {}: {}", i, e));
            }
        }
    }

    HttpResponse::Ok().json(BatchIngestResponse {
        success: errors.is_empty(),
        total,
        ingested,
        failed: total - ingested,
        log_ids,
        errors,
    })
}

/// Handle source-specific ingestion
async fn handle_source_ingest(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<IngestLogRequest>,
    state: web::Data<HttpState>,
) -> HttpResponse {
    let source_id = path.into_inner();
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Override source_id with path parameter
    let mut log = body.into_inner();
    log.source_id = Some(source_id);

    match ingest_single_log(&log, &client_ip, &state).await {
        Ok(entry) => HttpResponse::Ok().json(IngestResponse {
            success: true,
            log_id: Some(entry.id),
            message: "Log ingested successfully".to_string(),
        }),
        Err(e) => HttpResponse::BadRequest().json(IngestResponse {
            success: false,
            log_id: None,
            message: format!("Failed to ingest log: {}", e),
        }),
    }
}

/// Handle health check
async fn handle_health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "siem-ingestion"
    }))
}

/// Handle stats request
async fn handle_stats(state: web::Data<HttpState>) -> HttpResponse {
    let stats = state.stats.read().await;
    HttpResponse::Ok().json(&*stats)
}

/// Ingest a single log entry
async fn ingest_single_log(
    log: &IngestLogRequest,
    client_ip: &str,
    state: &HttpState,
) -> Result<LogEntry> {
    // Update received stats
    {
        let mut stats = state.stats.write().await;
        stats.record_received(0);
    }

    // Generate source ID if not provided
    let source_id = log
        .source_id
        .clone()
        .unwrap_or_else(|| format!("http-{}", client_ip));

    // Create log entry
    let entry = if let Some(ref entry_input) = log.entry {
        // Pre-parsed entry
        create_entry_from_input(entry_input, &source_id)?
    } else if let Some(ref message) = log.message {
        // Raw message to parse
        let format = log
            .format
            .as_ref()
            .and_then(|f| LogFormat::from_str(f))
            .unwrap_or(LogFormat::Json);

        state.parser.parse_with_format(message, &source_id, format)?
    } else {
        return Err(anyhow::anyhow!("Either 'message' or 'entry' must be provided"));
    };

    // Store the entry
    state.storage.store_entry(&entry).await?;

    // Update stats
    {
        let mut stats = state.stats.write().await;
        stats.record_parsed();
        stats.record_stored();
    }

    // Send to rule evaluation pipeline
    let _ = state
        .entry_tx
        .send(IngestionMessage {
            entry: entry.clone(),
            source_id,
        })
        .await;

    Ok(entry)
}

/// Create a log entry from parsed input
fn create_entry_from_input(input: &LogEntryInput, source_id: &str) -> Result<LogEntry> {
    use chrono::{DateTime, Utc};

    let timestamp = if let Some(ref ts) = input.timestamp {
        DateTime::parse_from_rfc3339(ts)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    } else {
        Utc::now()
    };

    let severity = input
        .severity
        .as_ref()
        .map(|s| match s.to_lowercase().as_str() {
            "emergency" | "emerg" => SiemSeverity::Emergency,
            "alert" => SiemSeverity::Alert,
            "critical" | "crit" | "fatal" => SiemSeverity::Critical,
            "error" | "err" => SiemSeverity::Error,
            "warning" | "warn" => SiemSeverity::Warning,
            "notice" => SiemSeverity::Notice,
            "info" | "information" => SiemSeverity::Info,
            "debug" | "trace" => SiemSeverity::Debug,
            _ => SiemSeverity::Info,
        })
        .unwrap_or(SiemSeverity::Info);

    let mut entry = LogEntry::new(source_id.to_string(), input.message.clone(), input.message.clone());

    entry.timestamp = timestamp;
    entry.severity = severity;
    entry.format = LogFormat::Json;
    entry.hostname = input.hostname.clone();
    entry.application = input.application.clone();
    entry.source_ip = input.source_ip.as_ref().and_then(|s| s.parse().ok());
    entry.destination_ip = input.destination_ip.as_ref().and_then(|s| s.parse().ok());
    entry.source_port = input.source_port;
    entry.destination_port = input.destination_port;
    entry.protocol = input.protocol.clone();
    entry.user = input.user.clone();
    entry.category = input.category.clone();
    entry.action = input.action.clone();
    entry.outcome = input.outcome.clone();
    entry.tags = input.tags.clone().unwrap_or_default();

    // Add custom fields to structured data
    if let Some(ref fields) = input.fields {
        if let Some(obj) = fields.as_object() {
            for (k, v) in obj {
                entry.structured_data.insert(k.clone(), v.clone());
            }
        }
    }

    entry.update_partition_date();

    Ok(entry)
}

// Implement Clone for IngestLogRequest to support batch processing
impl Clone for IngestLogRequest {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
            entry: self.entry.as_ref().map(|e| LogEntryInput {
                timestamp: e.timestamp.clone(),
                severity: e.severity.clone(),
                message: e.message.clone(),
                hostname: e.hostname.clone(),
                application: e.application.clone(),
                source_ip: e.source_ip.clone(),
                destination_ip: e.destination_ip.clone(),
                source_port: e.source_port,
                destination_port: e.destination_port,
                protocol: e.protocol.clone(),
                user: e.user.clone(),
                category: e.category.clone(),
                action: e.action.clone(),
                outcome: e.outcome.clone(),
                tags: e.tags.clone(),
                fields: e.fields.clone(),
            }),
            source_id: self.source_id.clone(),
            format: self.format.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_entry_from_input() {
        let input = LogEntryInput {
            timestamp: Some("2024-01-15T10:30:00Z".to_string()),
            severity: Some("warning".to_string()),
            message: "Test log message".to_string(),
            hostname: Some("webserver01".to_string()),
            application: Some("nginx".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            destination_ip: Some("10.0.0.2".to_string()),
            source_port: Some(54321),
            destination_port: Some(443),
            protocol: Some("tcp".to_string()),
            user: Some("admin".to_string()),
            category: Some("access".to_string()),
            action: Some("request".to_string()),
            outcome: Some("success".to_string()),
            tags: Some(vec!["production".to_string(), "web".to_string()]),
            fields: Some(serde_json::json!({"request_id": "abc123"})),
        };

        let entry = create_entry_from_input(&input, "test-source").unwrap();

        assert_eq!(entry.source_id, "test-source");
        assert_eq!(entry.message, "Test log message");
        assert_eq!(entry.severity, SiemSeverity::Warning);
        assert_eq!(entry.hostname, Some("webserver01".to_string()));
        assert_eq!(entry.application, Some("nginx".to_string()));
        assert_eq!(entry.source_ip.map(|ip| ip.to_string()), Some("10.0.0.1".to_string()));
        assert_eq!(entry.destination_port, Some(443));
        assert_eq!(entry.tags.len(), 2);
    }

    #[test]
    fn test_severity_parsing() {
        let test_cases = vec![
            ("emergency", SiemSeverity::Emergency),
            ("CRITICAL", SiemSeverity::Critical),
            ("Error", SiemSeverity::Error),
            ("warn", SiemSeverity::Warning),
            ("INFO", SiemSeverity::Info),
            ("debug", SiemSeverity::Debug),
            ("unknown", SiemSeverity::Info),
        ];

        for (input, expected) in test_cases {
            let entry_input = LogEntryInput {
                timestamp: None,
                severity: Some(input.to_string()),
                message: "test".to_string(),
                hostname: None,
                application: None,
                source_ip: None,
                destination_ip: None,
                source_port: None,
                destination_port: None,
                protocol: None,
                user: None,
                category: None,
                action: None,
                outcome: None,
                tags: None,
                fields: None,
            };

            let entry = create_entry_from_input(&entry_input, "test").unwrap();
            assert_eq!(entry.severity, expected, "Failed for input: {}", input);
        }
    }
}
