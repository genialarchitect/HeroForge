//! Plugin API traits that plugins implement
//!
//! This module defines the traits that plugins must implement to integrate
//! with HeroForge's scanning, detection, reporting, and integration systems.

#![allow(dead_code)]

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{HostInfo, PortInfo, Vulnerability};

/// Result type for plugin operations
pub type PluginResult<T> = Result<T>;

/// Context provided to plugins during execution
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Plugin ID
    pub plugin_id: String,

    /// Plugin configuration (from user settings)
    pub config: serde_json::Value,

    /// Scan ID (if running within a scan context)
    pub scan_id: Option<String>,

    /// User ID who initiated the operation
    pub user_id: String,

    /// Working directory for the plugin
    pub work_dir: std::path::PathBuf,

    /// Environment variables available to the plugin
    pub env_vars: HashMap<String, String>,
}

impl Default for PluginContext {
    fn default() -> Self {
        Self {
            plugin_id: String::new(),
            config: serde_json::Value::Null,
            scan_id: None,
            user_id: String::new(),
            work_dir: std::env::temp_dir(),
            env_vars: HashMap::new(),
        }
    }
}

/// Scan target for scanner plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Target IP address or hostname
    pub target: String,

    /// Port range to scan (optional)
    pub port_range: Option<(u16, u16)>,

    /// Additional scan parameters
    pub params: HashMap<String, serde_json::Value>,
}

/// Result from a scanner plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    /// Discovered hosts
    pub hosts: Vec<HostInfo>,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Warnings or notes from the scan
    pub notes: Vec<String>,
}

/// Detection target for detector plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionTarget {
    /// Host information
    pub host: HostInfo,

    /// Port information (if targeting a specific port)
    pub port: Option<PortInfo>,

    /// Additional detection parameters
    pub params: HashMap<String, serde_json::Value>,
}

/// Result from a detector plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Report data for reporter plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    /// Scan ID
    pub scan_id: String,

    /// Scan name
    pub scan_name: String,

    /// Discovered hosts
    pub hosts: Vec<HostInfo>,

    /// Additional report metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Report output from a reporter plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOutput {
    /// Report content (bytes for binary formats, string for text)
    pub content: Vec<u8>,

    /// Content type (MIME type)
    pub content_type: String,

    /// Suggested filename
    pub filename: String,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Integration event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum IntegrationEvent {
    /// Scan started
    ScanStarted {
        scan_id: String,
        targets: Vec<String>,
    },

    /// Scan completed
    ScanCompleted {
        scan_id: String,
        host_count: usize,
        vulnerability_count: usize,
    },

    /// Vulnerability found
    VulnerabilityFound {
        scan_id: String,
        vulnerability: Vulnerability,
        host_ip: String,
    },

    /// Asset discovered
    AssetDiscovered {
        scan_id: String,
        host: HostInfo,
    },

    /// Custom event
    Custom {
        event_type: String,
        payload: serde_json::Value,
    },
}

/// Result from an integration plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationResult {
    /// Whether the operation succeeded
    pub success: bool,

    /// Response from the integration
    pub response: Option<serde_json::Value>,

    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Plugin Traits
// ============================================================================

/// Trait for scanner plugins
///
/// Scanner plugins discover hosts, ports, and services on a network.
#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, ctx: &PluginContext) -> PluginResult<()>;

    /// Execute a scan against the given targets
    async fn scan(&self, ctx: &PluginContext, targets: &[ScanTarget]) -> PluginResult<ScannerResult>;

    /// Check if the plugin can scan the given target type
    fn can_scan(&self, target: &ScanTarget) -> bool;

    /// Cleanup resources
    async fn cleanup(&mut self) -> PluginResult<()>;
}

/// Trait for detector plugins
///
/// Detector plugins identify vulnerabilities and misconfigurations.
#[async_trait]
pub trait DetectorPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Get the types of vulnerabilities this detector can find
    fn detection_categories(&self) -> Vec<String>;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, ctx: &PluginContext) -> PluginResult<()>;

    /// Run detection against the given target
    async fn detect(&self, ctx: &PluginContext, target: &DetectionTarget) -> PluginResult<DetectorResult>;

    /// Check if the plugin can detect vulnerabilities on the given target
    fn can_detect(&self, target: &DetectionTarget) -> bool;

    /// Cleanup resources
    async fn cleanup(&mut self) -> PluginResult<()>;
}

/// Trait for reporter plugins
///
/// Reporter plugins generate custom report formats.
#[async_trait]
pub trait ReporterPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Get the supported output format(s)
    fn supported_formats(&self) -> Vec<String>;

    /// Get the default file extension for reports
    fn file_extension(&self) -> &str;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, ctx: &PluginContext) -> PluginResult<()>;

    /// Generate a report from the given data
    async fn generate(&self, ctx: &PluginContext, data: &ReportData) -> PluginResult<ReportOutput>;

    /// Cleanup resources
    async fn cleanup(&mut self) -> PluginResult<()>;
}

/// Trait for integration plugins
///
/// Integration plugins connect HeroForge to external services.
#[async_trait]
pub trait IntegrationPlugin: Send + Sync {
    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Get the integration type (e.g., "ticketing", "siem", "notification")
    fn integration_type(&self) -> &str;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, ctx: &PluginContext) -> PluginResult<()>;

    /// Handle an integration event
    async fn handle_event(&self, ctx: &PluginContext, event: &IntegrationEvent) -> PluginResult<IntegrationResult>;

    /// Test the integration connection
    async fn test_connection(&self, ctx: &PluginContext) -> PluginResult<IntegrationResult>;

    /// Get the required configuration fields
    fn required_config_fields(&self) -> Vec<ConfigField>;

    /// Cleanup resources
    async fn cleanup(&mut self) -> PluginResult<()>;
}

/// Configuration field definition for integration plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigField {
    /// Field name
    pub name: String,

    /// Field label for UI
    pub label: String,

    /// Field type (string, number, boolean, select, password)
    pub field_type: String,

    /// Whether the field is required
    pub required: bool,

    /// Default value
    pub default: Option<serde_json::Value>,

    /// Description/help text
    pub description: Option<String>,

    /// Options for select fields
    pub options: Option<Vec<ConfigOption>>,
}

/// Option for select-type configuration fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOption {
    pub value: String,
    pub label: String,
}

// ============================================================================
// Plugin Host Interface
// ============================================================================

/// Interface for plugins to call back to the host system
#[async_trait]
pub trait PluginHost: Send + Sync {
    /// Log a message from the plugin
    fn log(&self, level: LogLevel, message: &str);

    /// Get a configuration value
    fn get_config(&self, key: &str) -> Option<serde_json::Value>;

    /// Store plugin data
    async fn store_data(&self, key: &str, value: &[u8]) -> PluginResult<()>;

    /// Retrieve plugin data
    async fn retrieve_data(&self, key: &str) -> PluginResult<Option<Vec<u8>>>;

    /// Make an HTTP request (if network permission granted)
    async fn http_request(&self, request: HttpRequest) -> PluginResult<HttpResponse>;
}

/// Log level for plugin logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// HTTP request for plugins
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

/// HTTP response for plugins
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_context_default() {
        let ctx = PluginContext::default();
        assert!(ctx.plugin_id.is_empty());
        assert!(ctx.scan_id.is_none());
    }

    #[test]
    fn test_scanner_result_serialization() {
        let result = ScannerResult {
            hosts: Vec::new(),
            metadata: HashMap::new(),
            notes: vec!["Test note".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScannerResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.notes.len(), 1);
    }

    #[test]
    fn test_integration_event_serialization() {
        let event = IntegrationEvent::ScanStarted {
            scan_id: "test-123".to_string(),
            targets: vec!["192.168.1.0/24".to_string()],
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ScanStarted"));
    }

    #[test]
    fn test_config_field() {
        let field = ConfigField {
            name: "api_key".to_string(),
            label: "API Key".to_string(),
            field_type: "password".to_string(),
            required: true,
            default: None,
            description: Some("Your API key".to_string()),
            options: None,
        };

        assert!(field.required);
        assert_eq!(field.field_type, "password");
    }
}
