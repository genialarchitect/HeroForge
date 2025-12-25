//! SIEM (Security Information and Event Management) module for HeroForge.
//!
//! This module provides full SIEM capabilities including:
//! - Log collection from multiple sources (syslog, HTTP, agents)
//! - Log parsing for various formats (CEF, LEEF, JSON, syslog RFC 3164/5424)
//! - Log storage with date-based partitioning for efficient querying
//! - Detection rules for threat detection (including Sigma rule support)
//! - Real-time correlation engine for advanced threat detection
//! - Alert generation, deduplication, and management
//! - SIEM dashboards with saved searches and widgets
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |   Log Sources    | --> |    Ingestion     | --> |     Parser       |
//! | (Syslog, HTTP)   |     |    Pipeline      |     | (CEF, LEEF, etc) |
//! +------------------+     +------------------+     +------------------+
//!                                                          |
//!                                                          v
//! +------------------+     +------------------+     +------------------+
//! |   Alert Mgmt     | <-- |  Rule Engine     | <-- |    Storage       |
//! |   Dashboard      |     | (Sigma, Corr.)   |     | (Partitioned DB) |
//! +------------------+     +------------------+     +------------------+
//! ```
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use heroforge::siem::{IngestionService, IngestionConfig, LogStorage};
//!
//! // Create storage
//! let storage = LogStorage::new(pool);
//!
//! // Configure ingestion
//! let config = IngestionConfig {
//!     enable_syslog: true,
//!     syslog_udp_port: 514,
//!     syslog_tcp_port: 514,
//!     enable_http: true,
//!     http_port: 8514,
//!     ..Default::default()
//! };
//!
//! // Start ingestion service
//! let service = IngestionService::new(storage, config);
//! let handle = service.start().await?;
//!
//! // Shutdown when done
//! handle.shutdown();
//! ```

#![allow(dead_code)]

pub mod correlation;
pub mod dashboard;
pub mod ingestion;
pub mod parser;
pub mod sigma;
pub mod storage;
pub mod types;

// Re-export commonly used types
#[allow(unused_imports)]
pub use ingestion::{IngestionConfig, IngestionHandle, IngestionMessage, IngestionService};
#[allow(unused_imports)]
pub use parser::LogParser;
#[allow(unused_imports)]
pub use storage::{LogStorage, StorageStats};
#[allow(unused_imports)]
pub use types::{
    AlertStatus, IngestionStats, LogEntry, LogFormat, LogQuery, LogQueryResult, LogSource,
    LogSourceStatus, RuleStatus, RuleType, SiemAlert, SiemId, SiemRule, SiemSeverity,
    SyslogFacility, TransportProtocol,
};

// Re-export Sigma types
#[allow(unused_imports)]
pub use sigma::{
    CompiledSigmaRule, SigmaParser, SigmaRule, SigmaSeverity, SigmaStatus,
    ValidationResult as SigmaValidationResult,
};

// Re-export correlation types
#[allow(unused_imports)]
pub use correlation::{
    CorrelationAlert, CorrelationEngine, CorrelationRule, CorrelationRuleType,
    CorrelationStats,
};

// Re-export dashboard types
#[allow(unused_imports)]
pub use dashboard::{
    AlertDeduplicator, AlertGroup, AlertWorkflow, DashboardOverview, DashboardWidget,
    DeduplicationConfig, SavedSearch, SeverityScorer, SiemDashboard, TimeRange,
    WidgetType,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify that all public types are accessible
        let _severity = SiemSeverity::Info;
        let _format = LogFormat::SyslogRfc5424;
        let _facility = SyslogFacility::Local0;
        let _protocol = TransportProtocol::Tcp;
        let _status = LogSourceStatus::Active;
        let _rule_type = RuleType::Pattern;
        let _rule_status = RuleStatus::Enabled;
        let _alert_status = AlertStatus::New;
    }
}
