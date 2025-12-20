//! Webhooks (outbound) module
//!
//! This module provides functionality for sending HTTP webhook notifications
//! to external systems when events occur in HeroForge.
//!
//! ## Event Types
//!
//! The following events can trigger webhooks:
//! - `scan.started` - A scan has started
//! - `scan.completed` - A scan completed successfully
//! - `scan.failed` - A scan failed with an error
//! - `vulnerability.found` - A new vulnerability was discovered
//! - `vulnerability.critical` - A critical severity vulnerability was found
//! - `vulnerability.resolved` - A vulnerability was marked as resolved
//! - `asset.discovered` - A new asset was discovered
//! - `compliance.violation` - A compliance check failed
//!
//! ## Payload Format
//!
//! All webhooks use the following JSON payload format:
//!
//! ```json
//! {
//!   "event": "scan.completed",
//!   "timestamp": "2025-12-20T12:00:00Z",
//!   "data": {
//!     "scan_id": "...",
//!     "name": "...",
//!     ...event-specific data
//!   }
//! }
//! ```
//!
//! ## Security
//!
//! Webhooks can be configured with an HMAC secret. When configured, all requests
//! include an `X-Webhook-Signature` header containing an HMAC-SHA256 signature
//! of the payload body in the format `sha256=<hex_signature>`.
//!
//! ## Retry Logic
//!
//! Failed deliveries are automatically retried up to 3 times with exponential
//! backoff (1s, 2s, 4s). Webhooks that fail 10 consecutive times are automatically
//! disabled.

pub mod dispatcher;
pub mod sender;
pub mod types;

pub use dispatcher::{
    dispatch_event,
    dispatch_scan_started,
    dispatch_scan_completed,
    dispatch_scan_failed,
    dispatch_vulnerability_found,
    dispatch_vulnerability_resolved,
    dispatch_asset_discovered,
    dispatch_compliance_violation,
    send_test_webhook,
    DispatchResult,
};
pub use sender::{send_webhook, verify_signature, DeliveryResult, MAX_FAILURE_COUNT};
pub use types::{
    WebhookEventType,
    WebhookPayload,
    ScanStartedData,
    ScanCompletedData,
    ScanFailedData,
    VulnerabilityFoundData,
    VulnerabilityResolvedData,
    AssetDiscoveredData,
    ComplianceViolationData,
    TestWebhookData,
};
