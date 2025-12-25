//! Password Cracking Integration Module
//!
//! This module provides integration with hashcat and John the Ripper for
//! cracking password hashes obtained during penetration tests.
//!
//! # Features
//!
//! - Hashcat GPU-accelerated cracking
//! - John the Ripper CPU-based cracking
//! - Auto-detection of hash types
//! - Wordlist and rule file management
//! - Progress tracking via WebSocket
//! - Credential correlation with assets
//!
//! # Example
//!
//! ```ignore
//! use heroforge::cracking::{CrackingEngine, HashType, CrackerType};
//!
//! let engine = CrackingEngine::new();
//! let job = engine.create_job(
//!     user_id,
//!     HashType::Ntlm,
//!     CrackerType::Hashcat,
//!     hashes,
//!     config,
//! ).await?;
//! engine.start_job(&job.id).await?;
//! ```

pub mod types;
pub mod engine;
pub mod hashcat;

// Re-export commonly used types
#[allow(unused_imports)]
pub use types::{
    HashType,
    CrackerType,
    CrackingJobStatus,
    AttackMode,
    HashEntry,
    CrackingJobConfig,
    CrackingProgress,
    CrackedCredential,
    CrackingJob,
    Wordlist,
    RuleFile,
    CreateCrackingJobRequest,
    CrackingProgressMessage,
    CrackingStats,
    DetectHashRequest,
    DetectHashResponse,
    HashTypeInfo,
};

pub use engine::CrackingEngine;
