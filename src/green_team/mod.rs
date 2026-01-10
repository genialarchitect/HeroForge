//! Green Team - Security Operations Center (SOC) Operations
//!
//! This module provides a unified facade for all SOC operations capabilities.
//! Green Team focuses on security operations, automation, orchestration, and
//! response coordination.
//!
//! ## Core Capabilities
//!
//! ### SOAR (Security Orchestration, Automation and Response)
//! - Playbook management and execution
//! - Multi-step orchestration workflows
//! - Action library (block IP, isolate host, enrich IOC, etc.)
//! - Integration with security tools
//!
//! ### Case Management
//! - Incident case tracking
//! - Evidence attachment
//! - Timeline management
//! - Collaboration and handoff
//!
//! ### Threat Intelligence Automation
//! - Automated IOC enrichment
//! - Feed aggregation and deduplication
//! - Alert-to-intel correlation
//! - Automated dissemination
//!
//! ### SOC Metrics & Analytics
//! - MTTD (Mean Time to Detect)
//! - MTTR (Mean Time to Respond)
//! - SLA compliance tracking
//! - Analyst performance metrics
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::green_team;
//!
//! // Execute a SOAR playbook
//! let engine = green_team::PlaybookEngine::new(pool);
//! let result = engine.execute_playbook(playbook_id, trigger).await?;
//!
//! // Track a case
//! let case = green_team::Case::create(pool, new_case).await?;
//!
//! // Get SOC metrics
//! let metrics = green_team::SocMetrics::calculate(pool, time_range).await?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE GREEN TEAM MODULES
// =============================================================================

pub mod types;
pub mod playbooks;
pub mod orchestration;
pub mod case_management;
pub mod threat_intel_automation;
pub mod metrics;

pub use types::*;
pub use playbooks::*;
pub use case_management::*;
pub use threat_intel_automation::*;
pub use metrics::*;

// =============================================================================
// INTEGRATION RE-EXPORTS
// =============================================================================

/// SIEM integration for SOC dashboards
pub mod siem_integration {
    //! SIEM dashboard access for SOC operations

    pub use crate::siem::{
        SiemDashboard, DashboardOverview, DashboardWidget, WidgetType,
        SavedSearch, TimeRange, AlertWorkflow,
    };
}

/// Incident response integration
pub mod incident_integration {
    //! Incident management integration

    pub use crate::incident_response::{
        incidents::*, timeline::*, evidence::*, automation::*,
    };
}

/// Notification and alerting
pub mod notifications {
    //! Multi-channel notifications for SOC

    pub use crate::notifications::*;
}

/// Webhook automation
pub mod webhooks {
    //! Outbound webhooks for automation

    pub use crate::webhooks::*;
}

/// Custom workflows
pub mod workflows {
    //! Custom remediation workflows

    pub use crate::workflows::*;
}
