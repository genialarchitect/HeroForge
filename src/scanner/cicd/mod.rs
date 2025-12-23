//! CI/CD Pipeline Security Scanner
//!
//! Scans CI/CD configuration files for security issues:
//! - GitHub Actions workflows
//! - GitLab CI/CD pipelines
//! - Jenkins pipelines
//!
//! Detects issues like:
//! - Hardcoded secrets
//! - Script injection vulnerabilities
//! - Unpinned action versions
//! - Excessive permissions
//! - Supply chain risks

pub mod types;
pub mod github_actions;
pub mod gitlab_ci;
pub mod jenkins;
pub mod rules;

pub use types::*;
pub use github_actions::GitHubActionsScanner;
pub use gitlab_ci::GitLabCIScanner;
pub use jenkins::JenkinsScanner;
