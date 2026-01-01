//! Native SMB Protocol Implementation
//!
//! Provides pure-Rust SMB2/3 protocol support for share and user enumeration,
//! eliminating dependencies on external tools like smbclient and enum4linux.
//!
//! # Features
//!
//! - SMB2/3 protocol support (dialects 2.0.2 through 3.1.1)
//! - NTLM authentication
//! - Share enumeration via SRVSVC RPC
//! - User/group enumeration via SAMR RPC
//! - Session enumeration
//! - Server information queries
//!
//! # Example
//!
//! ```rust,no_run
//! use heroforge::scanner::smb_native::{SmbEnumerator, SmbResult};
//!
//! async fn enumerate_target() -> SmbResult<()> {
//!     let mut enumerator = SmbEnumerator::with_credentials(
//!         "192.168.1.100",
//!         "DOMAIN",
//!         "user",
//!         "password"
//!     );
//!
//!     enumerator.connect().await?;
//!
//!     // Enumerate shares
//!     let shares = enumerator.enumerate_shares().await?;
//!     for share in &shares {
//!         println!("Share: {} ({:?})", share.name, share.share_type);
//!     }
//!
//!     // Enumerate users
//!     let users = enumerator.enumerate_users().await?;
//!     for user in &users {
//!         println!("User: {} (RID: {})", user.name, user.rid);
//!     }
//!
//!     enumerator.disconnect().await;
//!     Ok(())
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    enumeration.rs                           │
//! │               High-level enumeration API                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │                     protocol.rs                             │
//! │              SMB connection management                      │
//! ├─────────────────┬───────────────────────────────────────────┤
//! │    smb2.rs      │              rpc/                         │
//! │  SMB2 packets   │   types.rs - DCE/RPC protocol             │
//! │                 │   srvsvc.rs - Share enumeration           │
//! │                 │   samr.rs - User/group enumeration        │
//! ├─────────────────┴───────────────────────────────────────────┤
//! │                   ntlm_auth.rs                              │
//! │              NTLM authentication                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │                     types.rs                                │
//! │                Core data structures                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod types;
pub mod ntlm_auth;
pub mod smb2;
pub mod protocol;
pub mod rpc;
pub mod enumeration;

// Re-export commonly used types
pub use types::*;
pub use enumeration::{
    SmbEnumerator,
    enumerate_shares,
    enumerate_users,
    enumerate_groups,
};
pub use protocol::{SmbClient, SmbConnection, SMB_PORT};
pub use ntlm_auth::NtlmCredentials;
pub use rpc::samr::{SamrUserEntry, SamrGroupEntry, user_flags};
pub use rpc::srvsvc::{ServerInfo, SessionInfo};
