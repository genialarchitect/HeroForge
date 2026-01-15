//! eMASS System Operations
//!
//! CRUD operations for eMASS systems.

use anyhow::Result;
use chrono::NaiveDate;

use super::client::EmassClient;
use super::types::*;

/// Get all accessible systems
pub async fn list_systems(client: &EmassClient) -> Result<Vec<EmassSystem>> {
    client.get_systems().await
}

/// Get system by ID
pub async fn get_system(client: &EmassClient, system_id: i64) -> Result<EmassSystem> {
    client.get_system(system_id).await
}

/// Get systems with specific authorization status
pub async fn get_systems_by_status(
    client: &EmassClient,
    status: AuthorizationStatus,
) -> Result<Vec<EmassSystem>> {
    let all_systems = client.get_systems().await?;
    Ok(all_systems
        .into_iter()
        .filter(|s| s.authorization_status == status)
        .collect())
}

/// Get systems with expiring ATOs
pub async fn get_expiring_atos(
    client: &EmassClient,
    days_until_expiration: i64,
) -> Result<Vec<EmassSystem>> {
    let all_systems = client.get_systems().await?;
    let today = chrono::Utc::now().date_naive();
    let threshold = today + chrono::Duration::days(days_until_expiration);

    Ok(all_systems
        .into_iter()
        .filter(|s| {
            if let Some(term_date) = s.authorization_termination_date {
                term_date <= threshold && term_date >= today
            } else {
                false
            }
        })
        .collect())
}

/// Get systems by security category
pub async fn get_systems_by_impact(
    client: &EmassClient,
    min_confidentiality: SecurityCategory,
    min_integrity: SecurityCategory,
    min_availability: SecurityCategory,
) -> Result<Vec<EmassSystem>> {
    let all_systems = client.get_systems().await?;

    Ok(all_systems
        .into_iter()
        .filter(|s| {
            category_value(s.confidentiality) >= category_value(min_confidentiality) &&
            category_value(s.integrity) >= category_value(min_integrity) &&
            category_value(s.availability) >= category_value(min_availability)
        })
        .collect())
}

/// Get security category numeric value for comparison
fn category_value(cat: SecurityCategory) -> u8 {
    match cat {
        SecurityCategory::Low => 1,
        SecurityCategory::Moderate => 2,
        SecurityCategory::High => 3,
    }
}

/// System summary statistics
#[derive(Debug, Clone, Default)]
pub struct SystemSummary {
    pub total_systems: usize,
    pub ato_active: usize,
    pub ato_inherited: usize,
    pub iato: usize,
    pub dato: usize,
    pub not_yet_authorized: usize,
    pub unauthorized: usize,
    pub expiring_30_days: usize,
    pub high_impact: usize,
    pub moderate_impact: usize,
    pub low_impact: usize,
}

/// Get summary statistics for all accessible systems
pub async fn get_system_summary(client: &EmassClient) -> Result<SystemSummary> {
    let systems = client.get_systems().await?;
    let today = chrono::Utc::now().date_naive();
    let threshold_30 = today + chrono::Duration::days(30);

    let mut summary = SystemSummary {
        total_systems: systems.len(),
        ..Default::default()
    };

    for system in &systems {
        // Count by authorization status
        match system.authorization_status {
            AuthorizationStatus::AtoActive => summary.ato_active += 1,
            AuthorizationStatus::AtoInherited => summary.ato_inherited += 1,
            AuthorizationStatus::Iato => summary.iato += 1,
            AuthorizationStatus::Dato => summary.dato += 1,
            AuthorizationStatus::NotYetAuthorized => summary.not_yet_authorized += 1,
            AuthorizationStatus::Unauthorized => summary.unauthorized += 1,
        }

        // Count expiring ATOs
        if let Some(term_date) = system.authorization_termination_date {
            if term_date <= threshold_30 && term_date >= today {
                summary.expiring_30_days += 1;
            }
        }

        // Count by impact level (highest of CIA triad)
        let max_impact = std::cmp::max(
            category_value(system.confidentiality),
            std::cmp::max(
                category_value(system.integrity),
                category_value(system.availability),
            ),
        );

        match max_impact {
            3 => summary.high_impact += 1,
            2 => summary.moderate_impact += 1,
            _ => summary.low_impact += 1,
        }
    }

    Ok(summary)
}

/// Check if a system's ATO is currently valid
pub fn is_ato_valid(system: &EmassSystem) -> bool {
    match system.authorization_status {
        AuthorizationStatus::AtoActive | AuthorizationStatus::AtoInherited => {
            if let Some(term_date) = system.authorization_termination_date {
                let today = chrono::Utc::now().date_naive();
                term_date > today
            } else {
                // No termination date means perpetual ATO
                true
            }
        }
        AuthorizationStatus::Iato => {
            // IATOs are typically valid for a short period
            if let Some(term_date) = system.authorization_termination_date {
                let today = chrono::Utc::now().date_naive();
                term_date > today
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Calculate days until ATO expiration
pub fn days_until_ato_expiration(system: &EmassSystem) -> Option<i64> {
    system.authorization_termination_date.map(|term_date| {
        let today = chrono::Utc::now().date_naive();
        (term_date - today).num_days()
    })
}
