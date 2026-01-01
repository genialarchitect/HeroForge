//! Protocol Handlers
//!
//! Protocol-specific request handlers for template execution.

pub mod http;
pub mod tcp;
pub mod dns;

pub use http::HttpHandler;
pub use tcp::TcpHandler;
pub use dns::DnsHandler;
