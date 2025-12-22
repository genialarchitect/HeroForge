//! Asset Discovery Module
//!
//! Provides passive and active reconnaissance capabilities for discovering
//! assets associated with a target domain.
//!
//! ## Features
//!
//! - Certificate Transparency log search (crt.sh)
//! - DNS enumeration (A, AAAA, MX, TXT, NS, SOA records)
//! - Subdomain brute-forcing (optional)
//! - WHOIS information lookup
//! - Shodan API integration (requires API key)
//! - Technology fingerprinting
//! - Asset correlation and deduplication
//!
//! ## Example
//!
//! ```rust,no_run
//! use heroforge::scanner::asset_discovery::{AssetDiscoveryConfig, run_asset_discovery};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AssetDiscoveryConfig {
//!         domain: "example.com".to_string(),
//!         include_ct_logs: true,
//!         include_dns: true,
//!         include_whois: true,
//!         ..Default::default()
//!     };
//!
//!     let result = run_asset_discovery(config).await?;
//!     println!("Found {} assets", result.assets.len());
//!     Ok(())
//! }
//! ```

pub mod ct_logs;
pub mod discovery;
pub mod shodan;
pub mod types;
pub mod whois;

pub use discovery::run_asset_discovery;
pub use types::*;
