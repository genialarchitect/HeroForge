//! Fuzzing Framework Module
//!
//! Provides protocol, HTTP, and file format fuzzing with mutation and generation-based strategies.

pub mod types;
pub mod engine;
pub mod mutators;
pub mod generators;
pub mod crash_triage;
pub mod coverage;
pub mod protocol_fuzzer;
pub mod http_fuzzer;
pub mod file_fuzzer;

pub use types::*;
pub use engine::FuzzingEngine;
pub use mutators::Mutator;
pub use generators::InputGenerator;
pub use crash_triage::CrashTriager;
pub use coverage::CoverageTracker;
