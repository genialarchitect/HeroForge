//! Compliance Evidence Collection System
//!
//! This module provides automated and manual evidence collection capabilities
//! for continuous compliance. Key features include:
//!
//! - **Evidence Types**: Support for scan results, vulnerability findings,
//!   policy documents, screenshots, manual uploads, and more
//! - **Storage**: File and database storage with SHA-256 integrity hashing
//! - **Versioning**: Full version control with change tracking and rollback
//! - **Collection**: Automated collection from scans and scheduled jobs
//! - **Control Mapping**: Link evidence to specific compliance controls
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Evidence Collector                        │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │ Scan-Derived │  │   Scheduled  │  │  Manual Upload   │   │
//! │  │  Collector   │  │  Collection  │  │    Handler       │   │
//! │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
//! │         │                 │                    │             │
//! │         └─────────────────┼────────────────────┘             │
//! │                           ▼                                  │
//! │              ┌────────────────────────┐                      │
//! │              │   Evidence Storage     │                      │
//! │              │  ┌──────┐  ┌────────┐  │                      │
//! │              │  │ File │  │ Hash   │  │                      │
//! │              │  │Store │  │Compute │  │                      │
//! │              │  └──────┘  └────────┘  │                      │
//! │              └────────────────────────┘                      │
//! │                           │                                  │
//! │              ┌────────────▼────────────┐                     │
//! │              │   Evidence Versioning   │                     │
//! │              │  Version tracking,      │                     │
//! │              │  comparisons, rollback  │                     │
//! │              └─────────────────────────┘                     │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use heroforge::compliance::evidence::{
//!     EvidenceCollector, EvidenceStorage, StorageConfig,
//!     EvidenceType, CollectEvidenceRequest,
//! };
//!
//! // Initialize storage
//! let storage = EvidenceStorage::new(StorageConfig::from_env());
//! storage.init().await?;
//!
//! // Create collector
//! let mut collector = EvidenceCollector::new(storage);
//!
//! // Collect evidence from a scan
//! let request = CollectEvidenceRequest {
//!     evidence_type: "scan_result".to_string(),
//!     control_ids: vec!["AC-1".to_string()],
//!     framework_ids: vec!["nist_800_53".to_string()],
//!     title: "Network Scan Evidence".to_string(),
//!     description: Some("Monthly network security scan".to_string()),
//!     params: serde_json::json!({ "scan_id": "scan-123" }),
//! };
//!
//! let response = collector.collect(&pool, &request, "user-id").await?;
//! ```

#![allow(dead_code)]

pub mod collector;
pub mod collectors;
pub mod storage;
pub mod types;
pub mod versioning;

// Re-export commonly used types
#[allow(unused_imports)]
pub use collector::{CollectionResult, CollectionStats, EvidenceBuilder, EvidenceCollector};
#[allow(unused_imports)]
pub use collectors::ScanDerivedCollector;
#[allow(unused_imports)]
pub use storage::{EvidenceStorage, IntegrityCheckResult, StorageConfig, StorageStats, StoredFile};
#[allow(unused_imports)]
pub use types::{
    CollectEvidenceRequest, CollectEvidenceResponse, CollectionSource, ControlEvidenceSummary,
    Evidence, EvidenceCollectionSchedule, EvidenceContent, EvidenceControlMapping,
    EvidenceListQuery, EvidenceListResponse, EvidenceMetadata, EvidenceStatus, EvidenceType,
    RetentionPolicy,
};
#[allow(unused_imports)]
pub use versioning::{
    ChangeType, EvidenceVersion, EvidenceVersioning, VersionChange, VersionComparison,
    VersionHistory,
};
