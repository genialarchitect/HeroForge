//! Phishing Campaign Manager
//!
//! Full-featured phishing campaign management for security awareness training
//! and authorized penetration testing.
//!
//! # Features
//!
//! - Email template builder with variable substitution
//! - Website cloning for landing pages
//! - Credential harvesting with form capture
//! - Tracking pixels for email opens
//! - Click tracking for link visits
//! - Real-time campaign statistics
//! - Awareness training mode
//!
//! # Security Notice
//!
//! This module is intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized phishing is illegal. Always obtain proper authorization.

pub mod campaign;
pub mod cloner;
pub mod sender;
pub mod tracker;
pub mod types;

pub use campaign::CampaignManager;
pub use cloner::WebsiteCloner;
pub use sender::EmailSender;
pub use tracker::{Tracker, TRACKING_PIXEL};
pub use types::*;

use sqlx::SqlitePool;

/// Initialize the phishing module
pub fn init(pool: SqlitePool) -> (CampaignManager, Tracker, WebsiteCloner) {
    let sender = EmailSender::new();
    let campaign_manager = CampaignManager::new(pool.clone(), sender);
    let tracker = Tracker::new(pool);
    let cloner = WebsiteCloner::new();

    (campaign_manager, tracker, cloner)
}
