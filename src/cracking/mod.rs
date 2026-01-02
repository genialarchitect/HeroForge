//! Password Cracking Integration Module
//!
//! This module provides both integration with external tools (hashcat, John the Ripper)
//! and a native pure-Rust password cracking engine.
//!
//! # Features
//!
//! ## External Tool Integration
//! - Hashcat GPU-accelerated cracking
//! - John the Ripper CPU-based cracking
//!
//! ## Native Cracking Engine
//! - Pure Rust implementation with no external dependencies
//! - Multiple hash types: MD5, SHA-1/256/512, NTLM, NetNTLMv2, bcrypt, Kerberos
//! - Attack modes: Dictionary, brute-force, mask, rule-based
//! - Built-in wordlists with common passwords
//! - Parallel processing via Rayon
//!
//! # Example
//!
//! ```ignore
//! // Using external tools (hashcat/john)
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
//!
//! // Using native engine (no external tools required)
//! use heroforge::cracking::native::{quick_crack, HashType as NativeHashType};
//!
//! let hashes = vec!["a4f49c406510bdcab6824ee7c30fd852".to_string()];
//! let results = quick_crack(hashes, NativeHashType::Ntlm).await;
//! ```

pub mod types;
pub mod engine;
pub mod hashcat;
pub mod native;

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
