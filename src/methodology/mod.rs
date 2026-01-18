//! Methodology Testing Module
//!
//! Provides scanner integration for methodology testing checklists (PTES, OWASP WSTG).
//! Maps methodology items to appropriate scanner functions and executes automated tests.

pub mod scanner_mapping;
pub mod test_executor;

pub use scanner_mapping::{get_all_mappings, get_mapping, ScannerMapping, ScannerType};
pub use test_executor::{MethodologyTestExecutor, TestExecutionRequest, TestExecutionResult};
