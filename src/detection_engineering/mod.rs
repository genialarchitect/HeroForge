//! Detection Engineering Module for HeroForge Blue Team
//!
//! This module provides comprehensive detection engineering capabilities:
//! - Detection-as-Code: YAML-like detection definitions with versioning
//! - Coverage Mapping: MITRE ATT&CK technique coverage and gap analysis
//! - False Positive Management: FP reporting, tracking, and tuning
//! - Detection Testing: Automated testing framework with sample log generation
//!
//! ## Architecture
//!
//! ```text
//! +-------------------+     +------------------+     +------------------+
//! |   Detections      |---->|  Coverage Map    |---->|  MITRE ATT&CK   |
//! | (YAML-like defs)  |     | (technique map)  |     |  (T1xxx refs)    |
//! +-------------------+     +------------------+     +------------------+
//!         |                         |
//!         v                         v
//! +-------------------+     +------------------+
//! |  False Positives  |     |  Testing         |
//! | (FP tracking)     |     | (regression)     |
//! +-------------------+     +------------------+
//! ```

pub mod detections;
pub mod coverage;
pub mod false_positives;
pub mod testing;

// Re-export main types
pub use detections::{
    Detection, DetectionSeverity, DetectionStatus, DetectionLogic,
    DetectionMetadata, DataSource, DetectionVersion,
};
pub use coverage::{
    CoverageMapping, CoverageType, CoverageGap, CoverageScore,
    TacticCoverage, TechniqueCoverage,
};
pub use false_positives::{
    FalsePositive, FalsePositiveStatus, FalsePositivePattern,
    TuningRecommendation, TuningType,
};
pub use testing::{
    DetectionTest, TestCase, TestResult, TestType,
    SampleLogGenerator, TestRun,
};
