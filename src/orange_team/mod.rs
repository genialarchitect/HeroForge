//! Orange Team - Security Awareness & Training
//!
//! This module provides a unified facade for all security awareness capabilities.
//! Orange Team focuses on educating users, testing human vulnerabilities, and
//! building a security-conscious culture.
//!
//! ## Core Capabilities
//!
//! ### Security Training
//! - Interactive training modules
//! - Role-based training paths
//! - Multi-format content (video, interactive, quizzes)
//! - Progress tracking and certification
//!
//! ### Gamification
//! - Points and achievement systems
//! - Leaderboards and competitions
//! - Badges and rewards
//! - Team challenges
//!
//! ### Phishing Simulation Analytics
//! - Campaign performance metrics
//! - Click rates and reporting rates
//! - User susceptibility analysis
//! - Department/team comparisons
//!
//! ### Just-in-Time Training
//! - Context-triggered training moments
//! - Real-time security guidance
//! - Micro-learning modules
//! - Behavioral intervention
//!
//! ### Compliance Training
//! - Regulatory compliance courses (GDPR, HIPAA, PCI-DSS)
//! - Completion tracking and reporting
//! - Audit-ready documentation
//! - Recurring training schedules
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::orange_team;
//!
//! // Assign training to users
//! let assignment = orange_team::TrainingAssignment::create(&pool, user_id, module_id).await?;
//!
//! // Analyze phishing campaign results
//! let analytics = orange_team::PhishingAnalytics::for_campaign(&pool, campaign_id).await?;
//!
//! // Trigger JIT training
//! orange_team::JitTraining::trigger(&pool, user_id, context).await?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE ORANGE TEAM MODULES
// =============================================================================

pub mod types;
pub mod training;
pub mod gamification;
pub mod phishing_analytics;
pub mod jit_training;
pub mod compliance_training;

pub use types::*;
pub use training::*;
pub use gamification::*;
pub use phishing_analytics::*;
pub use jit_training::*;
pub use compliance_training::*;

// =============================================================================
// INTEGRATION RE-EXPORTS
// =============================================================================

/// Phishing campaign management (for simulations)
pub mod phishing_campaigns {
    //! Phishing simulation campaign management

    pub use crate::phishing::{
        PhishingCampaign, CampaignStatus, PhishingTarget,
        CampaignStatistics, TargetEvent, TargetEventType,
        EmailTemplate, CampaignSummary,
    };
}

/// Email infrastructure for training
pub mod email {
    //! Email delivery for training and simulations

    pub use crate::email::*;
}

/// Notification channels
pub mod notifications {
    //! Training notifications and reminders

    pub use crate::notifications::*;
}
