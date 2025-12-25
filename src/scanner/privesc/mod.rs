//! Privilege Escalation Scanner Module
//!
//! This module provides automated privilege escalation enumeration for both
//! Linux and Windows systems. It integrates with LinPEAS/WinPEAS and provides
//! additional manual checks for common privilege escalation vectors.
//!
//! # Features
//!
//! - **Linux enumeration**: SUID binaries, sudo rules, capabilities, cron jobs,
//!   kernel exploits, Docker socket access, NFS no_root_squash
//! - **Windows enumeration**: Unquoted service paths, weak service permissions,
//!   AlwaysInstallElevated, token privileges, UAC bypass, saved credentials
//! - **GTFOBins/LOLBAS integration**: Automatic mapping to known exploitation techniques
//! - **LinPEAS/WinPEAS integration**: Comprehensive enumeration scripts
//!
//! # Example
//!
//! ```rust,ignore
//! use heroforge::scanner::privesc::{run_privesc_scan, PrivescConfig, OsType};
//!
//! let config = PrivescConfig {
//!     target: "192.168.1.100".to_string(),
//!     os_type: OsType::Linux,
//!     ssh_username: Some("user".to_string()),
//!     ssh_key_path: Some("/home/user/.ssh/id_rsa".to_string()),
//!     ..Default::default()
//! };
//!
//! let result = run_privesc_scan(config).await?;
//! for finding in result.findings {
//!     println!("{}: {}", finding.severity, finding.title);
//! }
//! ```

mod gtfobins;
mod linpeas;
mod linux;
mod lolbas;
mod scanner;
mod types;
mod windows;
mod winpeas;

// Re-export main types
pub use types::*;

// Re-export scanner function
pub use scanner::run_privesc_scan;

// Re-export GTFOBins/LOLBAS utilities
#[allow(unused_imports)]
pub use gtfobins::lookup_gtfobins;
#[allow(unused_imports)]
pub use lolbas::lookup_lolbas;

// Re-export PEAS URLs
#[allow(unused_imports)]
pub use linpeas::LINPEAS_URL;
#[allow(unused_imports)]
pub use winpeas::{WINPEAS_URL, WINPEAS_X86_URL};
