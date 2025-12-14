#![allow(dead_code)]

/// Risk scoring utilities
/// Note: Primary risk scoring is implemented in types.rs (ReportSummary::from_hosts)
/// This module provides additional risk analysis functions if needed.

use crate::types::{HostInfo, Severity};

/// Calculate risk score for a single host
pub fn calculate_host_risk_score(host: &HostInfo) -> u8 {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for vuln in &host.vulnerabilities {
        match vuln.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
    }

    let open_ports = host.ports.iter()
        .filter(|p| p.state == crate::types::PortState::Open)
        .count();

    calculate_risk_score(critical, high, medium, low, open_ports)
}

/// Calculate overall risk score from vulnerability counts
pub fn calculate_risk_score(
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    open_ports: usize,
) -> u8 {
    // Weighted scoring: Critical=10, High=7, Medium=4, Low=1
    let vuln_score = (critical * 10 + high * 7 + medium * 4 + low) as f64;

    // Port exposure factor (capped at 30)
    let port_factor = (open_ports * 2).min(30) as f64;

    // Normalize to 0-100
    let raw_score = vuln_score + port_factor;
    let normalized = (raw_score / 2.0).min(100.0);

    normalized as u8
}

/// Get risk level string from score
pub fn risk_level_from_score(score: u8) -> &'static str {
    match score {
        0..=20 => "Low",
        21..=40 => "Medium",
        41..=60 => "High",
        61..=80 => "Very High",
        _ => "Critical",
    }
}

/// Risk level enum for typed operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    VeryHigh,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => RiskLevel::Low,
            21..=40 => RiskLevel::Medium,
            41..=60 => RiskLevel::High,
            61..=80 => RiskLevel::VeryHigh,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::VeryHigh => "Very High",
            RiskLevel::Critical => "Critical",
        }
    }
}
