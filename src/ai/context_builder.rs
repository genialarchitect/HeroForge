//! Enhanced Chat Context Builder
//!
//! Provides intelligent context injection for AI chat based on:
//! - Current scan data and results
//! - Finding explanations and remediation
//! - Historical trends and comparisons
//! - Asset and vulnerability context

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::types::{HostInfo, Severity, Vulnerability};

/// Context type for chat enrichment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextType {
    /// Context about a specific scan
    Scan,
    /// Context about vulnerabilities/findings
    Finding,
    /// Context about an asset
    Asset,
    /// Trend analysis context
    Trend,
    /// Compliance context
    Compliance,
    /// General security advice
    General,
}

/// Chat context with relevant data
#[derive(Debug, Clone, Serialize)]
pub struct ChatContext {
    pub context_type: ContextType,
    pub summary: String,
    pub details: serde_json::Value,
    pub suggested_prompts: Vec<String>,
    pub related_entities: Vec<RelatedEntity>,
}

/// Related entity for navigation
#[derive(Debug, Clone, Serialize)]
pub struct RelatedEntity {
    pub entity_type: String,
    pub entity_id: String,
    pub name: String,
    pub relevance: f64,
}

/// Trend data for analysis
#[derive(Debug, Clone, Serialize)]
pub struct TrendData {
    pub metric: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub change_percent: f64,
    pub trend_direction: TrendDirection,
    pub time_period: String,
}

/// Trend direction
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendDirection {
    Improving,
    Worsening,
    Stable,
}

/// Enhanced context builder
pub struct ContextBuilder {
    pool: SqlitePool,
}

impl ContextBuilder {
    /// Create a new context builder
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Build context for a scan
    pub async fn build_scan_context(&self, scan_id: &str) -> Result<ChatContext> {
        // Fetch scan data
        let scan = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>)>(
            "SELECT id, name, status, results, completed_at FROM scan_results WHERE id = ?",
        )
        .bind(scan_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scan not found"))?;

        let (id, name, status, results_json, completed_at) = scan;

        // Parse results if available
        let hosts: Vec<HostInfo> = if let Some(ref json) = results_json {
            serde_json::from_str(json).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Calculate statistics
        let total_hosts = hosts.len();
        let total_ports: usize = hosts.iter().map(|h| h.ports.len()).sum();
        let total_vulns: usize = hosts
            .iter()
            .map(|h| h.vulnerabilities.len())
            .sum();

        // Severity breakdown
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for host in &hosts {
            for vuln in &host.vulnerabilities {
                let severity = format!("{:?}", vuln.severity).to_lowercase();
                *severity_counts.entry(severity).or_insert(0) += 1;
            }
        }

        let summary = format!(
            "Scan '{}' ({}) found {} hosts, {} ports, {} vulnerabilities. Status: {}",
            name, id, total_hosts, total_ports, total_vulns, status
        );

        let details = serde_json::json!({
            "scan_id": id,
            "scan_name": name,
            "status": status,
            "completed_at": completed_at,
            "statistics": {
                "total_hosts": total_hosts,
                "total_ports": total_ports,
                "total_vulnerabilities": total_vulns,
                "severity_breakdown": severity_counts,
            },
            "top_findings": self.get_top_findings(&hosts, 5),
        });

        let suggested_prompts = vec![
            format!("What are the most critical vulnerabilities in scan {}?", id),
            format!("How should I prioritize remediation for scan {}?", id),
            format!("Are there any patterns in the vulnerabilities found in {}?", id),
            format!("Generate an executive summary for scan {}", id),
        ];

        Ok(ChatContext {
            context_type: ContextType::Scan,
            summary,
            details,
            suggested_prompts,
            related_entities: Vec::new(),
        })
    }

    /// Build context for a specific finding/vulnerability
    pub async fn build_finding_context(&self, finding_id: &str) -> Result<ChatContext> {
        // Query vulnerability tracking
        let finding = sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<String>)>(
            r#"SELECT id, title, severity, status, description, remediation
               FROM vulnerability_tracking WHERE id = ?"#,
        )
        .bind(finding_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Finding not found"))?;

        let (id, title, severity, status, description, remediation) = finding;

        // Get CVE info if available
        let cve_info = sqlx::query_as::<_, (String, Option<String>, Option<f64>)>(
            "SELECT cve_id, description, cvss_score FROM cve_cache WHERE cve_id IN (SELECT cve_id FROM vulnerability_tracking WHERE id = ?)"
        )
        .bind(finding_id)
        .fetch_optional(&self.pool)
        .await?;

        let summary = format!(
            "Finding: {} ({}). Severity: {}, Status: {}",
            title, id, severity, status
        );

        let mut details = serde_json::json!({
            "finding_id": id,
            "title": title,
            "severity": severity,
            "status": status,
            "description": description,
            "remediation": remediation,
        });

        if let Some((cve_id, cve_desc, cvss)) = cve_info {
            details["cve"] = serde_json::json!({
                "id": cve_id,
                "description": cve_desc,
                "cvss_score": cvss,
            });
        }

        // Generate explanation
        let explanation = self.generate_finding_explanation(&title, &severity, description.as_deref());
        details["explanation"] = serde_json::json!(explanation);

        let suggested_prompts = vec![
            format!("Explain {} in simple terms", title),
            format!("How do I fix {}?", title),
            format!("What is the business impact of {}?", title),
            format!("Are there any related vulnerabilities to {}?", title),
        ];

        Ok(ChatContext {
            context_type: ContextType::Finding,
            summary,
            details,
            suggested_prompts,
            related_entities: Vec::new(),
        })
    }

    /// Build trend analysis context
    pub async fn build_trend_context(&self, days: i64) -> Result<ChatContext> {
        let since = (Utc::now() - Duration::days(days)).to_rfc3339();

        // Get vulnerability counts over time
        let weekly_counts = sqlx::query_as::<_, (String, i64)>(
            r#"SELECT strftime('%Y-%W', created_at) as week, COUNT(*) as count
               FROM vulnerability_tracking
               WHERE created_at >= ?
               GROUP BY week
               ORDER BY week"#,
        )
        .bind(&since)
        .fetch_all(&self.pool)
        .await?;

        // Get current open vs closed
        let open_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vulnerability_tracking WHERE status NOT IN ('closed', 'false_positive', 'risk_accepted')"
        )
        .fetch_one(&self.pool)
        .await?;

        let closed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vulnerability_tracking WHERE status = 'closed'"
        )
        .fetch_one(&self.pool)
        .await?;

        // Calculate trends
        let mut trends: Vec<TrendData> = Vec::new();

        if weekly_counts.len() >= 2 {
            let current = weekly_counts.last().map(|(_, c)| *c).unwrap_or(0);
            let previous = weekly_counts.get(weekly_counts.len() - 2).map(|(_, c)| *c).unwrap_or(0);
            let change = if previous > 0 {
                ((current as f64 - previous as f64) / previous as f64) * 100.0
            } else {
                0.0
            };

            trends.push(TrendData {
                metric: "New Vulnerabilities".to_string(),
                current_value: current as f64,
                previous_value: previous as f64,
                change_percent: change,
                trend_direction: if change > 5.0 {
                    TrendDirection::Worsening
                } else if change < -5.0 {
                    TrendDirection::Improving
                } else {
                    TrendDirection::Stable
                },
                time_period: format!("Last {} days", days),
            });
        }

        // Calculate remediation rate
        let total = open_count + closed_count;
        let remediation_rate = if total > 0 {
            (closed_count as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        trends.push(TrendData {
            metric: "Remediation Rate".to_string(),
            current_value: remediation_rate,
            previous_value: 0.0,
            change_percent: 0.0,
            trend_direction: if remediation_rate > 70.0 {
                TrendDirection::Improving
            } else if remediation_rate < 30.0 {
                TrendDirection::Worsening
            } else {
                TrendDirection::Stable
            },
            time_period: "All time".to_string(),
        });

        let summary = format!(
            "Trend analysis for last {} days: {} open findings, {} closed, {:.1}% remediation rate",
            days, open_count, closed_count, remediation_rate
        );

        let details = serde_json::json!({
            "period_days": days,
            "open_findings": open_count,
            "closed_findings": closed_count,
            "remediation_rate": remediation_rate,
            "weekly_counts": weekly_counts,
            "trends": trends,
        });

        let suggested_prompts = vec![
            "What are the main vulnerability trends?".to_string(),
            "How is our security posture improving?".to_string(),
            "Which vulnerability categories are most common?".to_string(),
            "What should we focus on this week?".to_string(),
        ];

        Ok(ChatContext {
            context_type: ContextType::Trend,
            summary,
            details,
            suggested_prompts,
            related_entities: Vec::new(),
        })
    }

    /// Build asset context
    pub async fn build_asset_context(&self, asset_id: &str) -> Result<ChatContext> {
        let asset = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, String)>(
            "SELECT id, ip_address, hostname, os_info, criticality FROM assets WHERE id = ?"
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Asset not found"))?;

        let (id, ip, hostname, os_info, criticality) = asset;

        // Get ports for this asset
        let ports = sqlx::query_as::<_, (u16, String, Option<String>)>(
            "SELECT port, protocol, service_name FROM asset_ports WHERE asset_id = ?"
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await?;

        // Get vulnerability count
        let vuln_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vulnerability_tracking WHERE affected_asset LIKE ?"
        )
        .bind(format!("%{}%", ip))
        .fetch_one(&self.pool)
        .await?;

        let summary = format!(
            "Asset {} ({}) - {}, {} open ports, {} vulnerabilities",
            ip,
            hostname.as_deref().unwrap_or("unknown"),
            criticality,
            ports.len(),
            vuln_count
        );

        let details = serde_json::json!({
            "asset_id": id,
            "ip_address": ip,
            "hostname": hostname,
            "os_info": os_info,
            "criticality": criticality,
            "ports": ports.iter().map(|(p, proto, svc)| {
                serde_json::json!({
                    "port": p,
                    "protocol": proto,
                    "service": svc,
                })
            }).collect::<Vec<_>>(),
            "vulnerability_count": vuln_count,
        });

        let suggested_prompts = vec![
            format!("What services are running on {}?", ip),
            format!("What vulnerabilities affect {}?", ip),
            format!("How critical is asset {}?", ip),
            format!("What should I scan next on {}?", ip),
        ];

        Ok(ChatContext {
            context_type: ContextType::Asset,
            summary,
            details,
            suggested_prompts,
            related_entities: Vec::new(),
        })
    }

    /// Generate comprehensive context based on user query
    pub async fn infer_context(&self, query: &str) -> Result<Vec<ChatContext>> {
        let mut contexts: Vec<ChatContext> = Vec::new();

        // Check for scan references
        if query.contains("scan") || query.contains("results") {
            // Get most recent scan
            if let Ok(Some((scan_id,))) = sqlx::query_as::<_, (String,)>(
                "SELECT id FROM scan_results ORDER BY created_at DESC LIMIT 1"
            )
            .fetch_optional(&self.pool)
            .await
            {
                if let Ok(ctx) = self.build_scan_context(&scan_id).await {
                    contexts.push(ctx);
                }
            }
        }

        // Check for trend/analysis queries
        if query.contains("trend") || query.contains("analysis") || query.contains("overview") {
            if let Ok(ctx) = self.build_trend_context(30).await {
                contexts.push(ctx);
            }
        }

        // Check for vulnerability references
        if query.contains("vulnerability") || query.contains("vuln") || query.contains("cve") {
            // Add general vulnerability context
            let summary = self.get_vulnerability_summary().await?;
            contexts.push(ChatContext {
                context_type: ContextType::Finding,
                summary: summary.clone(),
                details: serde_json::json!({ "summary": summary }),
                suggested_prompts: vec![
                    "What are the top vulnerabilities?".to_string(),
                    "How do I prioritize remediation?".to_string(),
                ],
                related_entities: Vec::new(),
            });
        }

        Ok(contexts)
    }

    /// Build system prompt with context
    pub fn build_system_prompt(&self, contexts: &[ChatContext]) -> String {
        let mut prompt = String::from(
            "You are an expert security analyst assistant for HeroForge, a penetration testing platform. \
             You help users understand scan results, vulnerabilities, and security concepts. \
             Provide actionable, security-focused advice. Be concise but thorough.\n\n"
        );

        if !contexts.is_empty() {
            prompt.push_str("CURRENT CONTEXT:\n\n");

            for ctx in contexts {
                prompt.push_str(&format!("[{}]\n", format!("{:?}", ctx.context_type).to_uppercase()));
                prompt.push_str(&format!("Summary: {}\n", ctx.summary));
                prompt.push_str(&format!("Details: {}\n\n", ctx.details));
            }

            prompt.push_str("Use this context to provide relevant, specific answers. \
                            Reference specific findings, assets, or trends when applicable.\n");
        }

        prompt
    }

    // Helper methods

    fn get_top_findings(&self, hosts: &[HostInfo], limit: usize) -> Vec<serde_json::Value> {
        let mut vulns: Vec<(&Vulnerability, String)> = Vec::new();

        for host in hosts {
            let ip = host.target.ip.to_string();
            for vuln in &host.vulnerabilities {
                vulns.push((vuln, ip.clone()));
            }
        }

        // Sort by severity
        vulns.sort_by(|a, b| {
            let sev_a = severity_to_num(&a.0.severity);
            let sev_b = severity_to_num(&b.0.severity);
            sev_b.cmp(&sev_a)
        });

        vulns
            .into_iter()
            .take(limit)
            .map(|(v, ip)| {
                serde_json::json!({
                    "title": v.title,
                    "severity": format!("{:?}", v.severity),
                    "host": ip,
                    "cve": v.cve_id,
                })
            })
            .collect()
    }

    fn generate_finding_explanation(&self, title: &str, severity: &str, description: Option<&str>) -> String {
        let severity_context = match severity.to_lowercase().as_str() {
            "critical" => "This is a CRITICAL severity issue that requires immediate attention. It could allow an attacker to fully compromise the system.",
            "high" => "This is a HIGH severity issue that should be addressed urgently. It poses significant risk to the system's security.",
            "medium" => "This is a MEDIUM severity issue that should be remediated in your regular patching cycle.",
            "low" => "This is a LOW severity issue that should be documented and addressed when resources allow.",
            _ => "This finding should be reviewed and addressed based on your organization's risk tolerance.",
        };

        let desc = description.unwrap_or("No detailed description available.");

        format!(
            "{}\n\n{}\n\nDescription: {}",
            title, severity_context, desc
        )
    }

    async fn get_vulnerability_summary(&self) -> Result<String> {
        let counts = sqlx::query_as::<_, (String, i64)>(
            "SELECT severity, COUNT(*) FROM vulnerability_tracking WHERE status NOT IN ('closed', 'false_positive') GROUP BY severity"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut summary_parts: Vec<String> = Vec::new();
        for (severity, count) in counts {
            summary_parts.push(format!("{}: {}", severity, count));
        }

        Ok(format!("Open vulnerabilities - {}", summary_parts.join(", ")))
    }
}

/// Convert severity to numeric for sorting
fn severity_to_num(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trend_direction() {
        let trend = TrendData {
            metric: "Test".to_string(),
            current_value: 10.0,
            previous_value: 5.0,
            change_percent: 100.0,
            trend_direction: TrendDirection::Worsening,
            time_period: "7 days".to_string(),
        };

        assert!(matches!(trend.trend_direction, TrendDirection::Worsening));
    }
}
