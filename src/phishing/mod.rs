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
//! - SMS phishing (smishing) campaigns with Twilio integration
//! - Pretexting templates for social engineering scenarios
//! - Voice phishing (vishing) campaign management
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
pub mod pretexts;
pub mod qrcode;
pub mod sender;
pub mod sms;
pub mod tracker;
pub mod types;
pub mod vishing;

pub use campaign::CampaignManager;
pub use cloner::WebsiteCloner;
#[allow(unused_imports)]
pub use pretexts::{
    CreatePretextRequest, PretextCategory, PretextDifficulty, PretextLibrary, PretextScript,
    PretextTemplate,
};
#[allow(unused_imports)]
pub use qrcode::{ErrorCorrectionLevel, QrCodeConfig, QrCodeFormat, QrCodeGenerator};
pub use sender::EmailSender;
#[allow(unused_imports)]
pub use sms::{SmsCampaignManager, SmsClient, SmsDeliveryStatus, TwilioClient, TwilioConfig};
pub use tracker::{Tracker, TRACKING_PIXEL};
#[allow(unused_imports)]
pub use types::*;
#[allow(unused_imports)]
pub use vishing::{
    CallFlowStage, CallOutcome, CreateVishingCampaignRequest, CreateVishingScriptRequest,
    CreateVishingTargetRequest, LogCallRequest, VishingCallLog, VishingCampaign,
    VishingCampaignStats, VishingCampaignStatus, VishingCampaignSummary, VishingManager,
    VishingScript, VishingTarget,
};

use sqlx::SqlitePool;

/// Initialize the phishing module
pub fn init(pool: SqlitePool) -> (CampaignManager, Tracker, WebsiteCloner) {
    let sender = EmailSender::new();
    let campaign_manager = CampaignManager::new(pool.clone(), sender);
    let tracker = Tracker::new(pool);
    let cloner = WebsiteCloner::new();

    (campaign_manager, tracker, cloner)
}
