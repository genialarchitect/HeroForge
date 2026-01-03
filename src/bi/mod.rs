//! Business Intelligence and Advanced Reporting Module

#![allow(dead_code)]

pub mod dashboards;
pub mod export;
pub mod metrics;
pub mod reports;

use anyhow::Result;

use dashboards::{DashboardBuilder, Widget};
use metrics::{MetricsCalculator, SecurityMetrics, VulnerabilityCounts};

pub struct BiEngine {
    dashboard_builder: DashboardBuilder,
    metrics_calculator: MetricsCalculator,
}

impl BiEngine {
    pub fn new() -> Self {
        Self {
            dashboard_builder: DashboardBuilder::new(),
            metrics_calculator: MetricsCalculator::new(),
        }
    }

    /// Generate an executive dashboard with key security metrics and KPIs
    pub async fn generate_executive_dashboard(&self) -> Result<String> {
        // Create dashboard with executive-level widgets
        let mut dashboard = self.dashboard_builder.create_dashboard("Executive Security Dashboard");

        // Add security posture overview widget
        dashboard.widgets.push(Widget {
            widget_type: "security_score".to_string(),
            title: "Security Posture Score".to_string(),
            config: serde_json::json!({
                "metric": "security_score",
                "target": 85.0,
                "thresholds": {
                    "critical": 50.0,
                    "warning": 70.0,
                    "good": 85.0
                }
            }),
        });

        // Add vulnerability summary widget
        dashboard.widgets.push(Widget {
            widget_type: "vulnerability_summary".to_string(),
            title: "Vulnerability Overview".to_string(),
            config: serde_json::json!({
                "show_severity_breakdown": true,
                "show_trend": true,
                "period_days": 30
            }),
        });

        // Add MTTD/MTTR metrics widget
        dashboard.widgets.push(Widget {
            widget_type: "response_metrics".to_string(),
            title: "Detection & Response Metrics".to_string(),
            config: serde_json::json!({
                "metrics": ["mttd", "mttr", "mttc"],
                "show_targets": true,
                "targets": {
                    "mttd_hours": 1.0,
                    "mttr_hours": 4.0,
                    "mttc_hours": 2.0
                }
            }),
        });

        // Add compliance status widget
        dashboard.widgets.push(Widget {
            widget_type: "compliance_status".to_string(),
            title: "Compliance Status".to_string(),
            config: serde_json::json!({
                "frameworks": ["PCI-DSS", "NIST 800-53", "CIS"],
                "show_trend": true
            }),
        });

        // Add active incidents widget
        dashboard.widgets.push(Widget {
            widget_type: "active_incidents".to_string(),
            title: "Active Incidents".to_string(),
            config: serde_json::json!({
                "show_severity": true,
                "max_items": 10,
                "sort_by": "severity"
            }),
        });

        // Add patch compliance widget
        dashboard.widgets.push(Widget {
            widget_type: "patch_compliance".to_string(),
            title: "Patch Compliance Rate".to_string(),
            config: serde_json::json!({
                "target": 95.0,
                "show_systems_at_risk": true
            }),
        });

        // Render the dashboard to HTML
        let html = self.dashboard_builder.render_dashboard(&dashboard).await?;
        Ok(html)
    }

    /// Generate security metrics summary
    pub fn generate_metrics_summary(&self) -> SecurityMetrics {
        // Return default metrics when no data is available
        SecurityMetrics {
            mttd: 0.0,
            mttr: 0.0,
            mttc: 0.0,
            mttr_remediate: 0.0,
            vulnerability_dwell_time: 0.0,
            patch_compliance_rate: 100.0,
            security_score: 100.0,
            active_threats: 0,
            vulnerability_counts: VulnerabilityCounts::default(),
        }
    }

    /// Get the dashboard builder for custom dashboard creation
    pub fn dashboard_builder(&self) -> &DashboardBuilder {
        &self.dashboard_builder
    }

    /// Get the metrics calculator for custom metric calculations
    pub fn metrics_calculator(&self) -> &MetricsCalculator {
        &self.metrics_calculator
    }
}

impl Default for BiEngine {
    fn default() -> Self {
        Self::new()
    }
}
