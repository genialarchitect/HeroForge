//! AI Chat Context Builder
//!
//! Builds context from user's HeroForge data to provide to the AI assistant.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Summary of a scan for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub targets: Vec<String>,
    pub hosts_count: usize,
    pub ports_count: usize,
    pub vulns_count: usize,
    pub created_at: String,
}

/// Summary of a vulnerability for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host_ip: String,
    pub port: Option<u16>,
    pub status: String,
}

/// Summary of compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub frameworks_assessed: Vec<String>,
    pub overall_score: f32,
    pub critical_findings: usize,
    pub high_findings: usize,
}

/// Full user context for AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub recent_scans: Vec<ScanSummary>,
    pub critical_vulnerabilities: Vec<VulnSummary>,
    pub high_vulnerabilities: Vec<VulnSummary>,
    pub asset_count: usize,
    pub compliance_status: Option<ComplianceStatus>,
    pub current_page: Option<String>,
}

impl Default for UserContext {
    fn default() -> Self {
        Self {
            recent_scans: Vec::new(),
            critical_vulnerabilities: Vec::new(),
            high_vulnerabilities: Vec::new(),
            asset_count: 0,
            compliance_status: None,
            current_page: None,
        }
    }
}

/// Context builder for AI chat
pub struct ContextBuilder {
    pool: SqlitePool,
}

impl ContextBuilder {
    /// Create a new context builder
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Build full context for a user
    pub async fn build_context(
        &self,
        user_id: &str,
        page_context: Option<&str>,
    ) -> UserContext {
        let recent_scans = self.get_recent_scans(user_id, 5).await.unwrap_or_default();
        let critical_vulns = self.get_vulnerabilities_by_severity(user_id, "critical", 10).await.unwrap_or_default();
        let high_vulns = self.get_vulnerabilities_by_severity(user_id, "high", 10).await.unwrap_or_default();
        let asset_count = self.get_asset_count(user_id).await.unwrap_or(0);
        let compliance_status = self.get_compliance_status(user_id).await.ok();

        UserContext {
            recent_scans,
            critical_vulnerabilities: critical_vulns,
            high_vulnerabilities: high_vulns,
            asset_count,
            compliance_status,
            current_page: page_context.map(String::from),
        }
    }

    /// Get recent scans for a user
    async fn get_recent_scans(&self, user_id: &str, limit: usize) -> Result<Vec<ScanSummary>> {
        let all_scans = crate::db::scans::get_user_scans(&self.pool, user_id).await?;
        // Take only the most recent scans up to the limit
        let scans: Vec<_> = all_scans.into_iter().take(limit).collect();

        let summaries = scans
            .into_iter()
            .map(|s| {
                // Parse results to get counts
                let hosts: Vec<crate::types::HostInfo> = s
                    .results
                    .as_ref()
                    .and_then(|r| serde_json::from_str(r).ok())
                    .unwrap_or_default();

                let ports_count: usize = hosts.iter().map(|h| h.ports.len()).sum();
                let vulns_count: usize = hosts.iter().map(|h| h.vulnerabilities.len()).sum();

                ScanSummary {
                    id: s.id,
                    name: s.name,
                    status: s.status,
                    targets: s.targets.split(',').map(|t| t.trim().to_string()).collect(),
                    hosts_count: hosts.len(),
                    ports_count,
                    vulns_count,
                    created_at: s.created_at.to_rfc3339(),
                }
            })
            .collect();

        Ok(summaries)
    }

    /// Get vulnerabilities by severity
    async fn get_vulnerabilities_by_severity(
        &self,
        user_id: &str,
        severity: &str,
        limit: usize,
    ) -> Result<Vec<VulnSummary>> {
        // Get user's scans first to ensure they can only see their own vulns
        let all_scans = crate::db::scans::get_user_scans(&self.pool, user_id).await?;
        let scans: Vec<_> = all_scans.into_iter().take(100).collect();
        let scan_ids: Vec<String> = scans.iter().map(|s| s.id.clone()).collect();

        if scan_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut vulns = Vec::new();
        for scan_id in scan_ids.iter().take(10) {
            if let Ok(tracking) = crate::db::vulnerabilities::get_vulnerability_tracking_by_scan(
                &self.pool,
                scan_id,
                None,           // status
                Some(severity), // severity filter
            )
            .await
            {
                for v in tracking {
                    vulns.push(VulnSummary {
                        id: v.id,
                        title: v.vulnerability_id.clone(), // Use vulnerability_id as title
                        severity: v.severity,
                        host_ip: v.host_ip,
                        port: v.port.map(|p| p as u16),
                        status: v.status,
                    });
                    if vulns.len() >= limit {
                        break;
                    }
                }
            }
            if vulns.len() >= limit {
                break;
            }
        }

        Ok(vulns)
    }

    /// Get asset count for a user
    async fn get_asset_count(&self, user_id: &str) -> Result<usize> {
        let assets = crate::db::assets::get_user_assets(&self.pool, user_id, None, None, None).await?;
        Ok(assets.len())
    }

    /// Get compliance status summary
    async fn get_compliance_status(&self, _user_id: &str) -> Result<ComplianceStatus> {
        // Get compliance frameworks
        let frameworks = crate::compliance::types::ComplianceFramework::all();
        let framework_names: Vec<String> = frameworks.iter().map(|f| f.name().to_string()).collect();

        Ok(ComplianceStatus {
            frameworks_assessed: framework_names,
            overall_score: 0.0,  // Would need to calculate from actual assessments
            critical_findings: 0,
            high_findings: 0,
        })
    }

    /// Build system prompt with context
    pub fn build_system_prompt(context: &UserContext) -> String {
        let mut prompt = String::from(r#"You are Zeus, the AI security assistant for HeroForge, a penetration testing and vulnerability management platform.

You help users with:
- Understanding and remediating vulnerabilities
- Interpreting scan results
- Configuring and running scans
- Understanding compliance requirements (PCI-DSS, HIPAA, NIST, CIS, SOC2, FERPA, OWASP, HITRUST)
- Managing assets and attack surface
- Security best practices

"#);

        // Add context about user's data
        prompt.push_str("## Current User Context\n\n");

        // Scans
        if !context.recent_scans.is_empty() {
            prompt.push_str("### Recent Scans\n");
            for scan in context.recent_scans.iter().take(5) {
                prompt.push_str(&format!(
                    "- **{}** ({}): {} hosts, {} ports, {} vulnerabilities\n",
                    scan.name, scan.status, scan.hosts_count, scan.ports_count, scan.vulns_count
                ));
            }
            prompt.push('\n');
        } else {
            prompt.push_str("No recent scans found. User may be new or hasn't run any scans yet.\n\n");
        }

        // Critical vulnerabilities
        if !context.critical_vulnerabilities.is_empty() {
            prompt.push_str("### Critical Vulnerabilities Requiring Attention\n");
            for vuln in context.critical_vulnerabilities.iter().take(5) {
                let port_info = vuln.port.map(|p| format!(":{}", p)).unwrap_or_default();
                prompt.push_str(&format!(
                    "- **{}** on {}{} (Status: {})\n",
                    vuln.title, vuln.host_ip, port_info, vuln.status
                ));
            }
            prompt.push('\n');
        }

        // High vulnerabilities
        if !context.high_vulnerabilities.is_empty() {
            prompt.push_str("### High Severity Vulnerabilities\n");
            for vuln in context.high_vulnerabilities.iter().take(5) {
                let port_info = vuln.port.map(|p| format!(":{}", p)).unwrap_or_default();
                prompt.push_str(&format!(
                    "- **{}** on {}{} (Status: {})\n",
                    vuln.title, vuln.host_ip, port_info, vuln.status
                ));
            }
            prompt.push('\n');
        }

        // Assets
        prompt.push_str(&format!("### Asset Inventory\n- Total assets: {}\n\n", context.asset_count));

        // Compliance
        if let Some(compliance) = &context.compliance_status {
            prompt.push_str("### Compliance Frameworks Available\n");
            prompt.push_str(&format!("- Frameworks: {}\n", compliance.frameworks_assessed.join(", ")));
            prompt.push('\n');
        }

        // Current page context
        if let Some(page) = &context.current_page {
            prompt.push_str(&format!("### Current Page\nUser is currently on: {}\n\n", page));
        }

        // Action suggestions format
        prompt.push_str(r#"## Response Guidelines

1. Be concise and technical
2. When suggesting actions, format them as markdown links that the user can click:
   - To start a new scan: [Start Scan](/scans/new)
   - To view vulnerabilities: [View Vulnerabilities](/vulnerabilities)
   - To check compliance: [Compliance Dashboard](/compliance)
   - To view assets: [Asset Inventory](/assets)
   - To generate a report: [Generate Report](/reports)

3. When discussing specific vulnerabilities, reference their severity and provide actionable remediation steps
4. For compliance questions, reference the specific framework requirements
5. Always prioritize security best practices

Remember: You have access to the user's actual scan data and vulnerabilities. Use this context to provide personalized, actionable advice.
"#);

        prompt
    }
}
