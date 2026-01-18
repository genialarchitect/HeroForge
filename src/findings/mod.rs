// ============================================================================
// Findings Module
// ============================================================================
//
// This module provides finding deduplication and management capabilities.
// It enables tracking unique vulnerabilities across multiple scans,
// preventing duplicate entries and providing accurate metrics.
//
// Key features:
// - Fingerprint-based deduplication
// - Occurrence tracking across scans
// - Historical finding management
// - Deduplication statistics
// - Finding lifecycle state machine
// - SLA tracking and management

pub mod fingerprint;
pub mod dedup;
pub mod lifecycle;

pub use fingerprint::{
    FindingFingerprint,
    FingerprintComponents,
    FingerprintConfig,
    FingerprintGenerator,
};

pub use dedup::{
    DeduplicatedFinding,
    DeduplicationEngine,
    DeduplicationStats,
    RegisterFindingRequest,
    RegisterFindingResult,
};

pub use lifecycle::{
    FindingLifecycle,
    FindingState,
    LifecycleManager,
    LifecycleMetrics,
    SlAConfig,
    StateTransition,
};

use log::info;

/// Initialize the findings module
///
/// This should be called during application startup to ensure
/// required database tables exist.
pub async fn init(pool: &sqlx::SqlitePool) -> anyhow::Result<()> {
    // Tables are created via migrations in db/migrations.rs
    // This function can be used for any runtime initialization

    info!("Findings deduplication module initialized");
    Ok(())
}
