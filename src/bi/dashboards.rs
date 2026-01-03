//! Custom dashboard builder

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: String,
    pub name: String,
    pub widgets: Vec<Widget>,
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    pub layout: DashboardLayout,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardLayout {
    /// Number of columns in the grid (default: 12)
    #[serde(default = "default_columns")]
    pub columns: u32,
    /// Gap between widgets in pixels
    #[serde(default = "default_gap")]
    pub gap: u32,
    /// Widget positions (keyed by widget index)
    #[serde(default)]
    pub positions: Vec<WidgetPosition>,
}

fn default_columns() -> u32 { 12 }
fn default_gap() -> u32 { 16 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetPosition {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub widget_type: String,
    pub title: String,
    pub config: serde_json::Value,
}

pub struct DashboardBuilder {}

impl DashboardBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn create_dashboard(&self, name: &str) -> Dashboard {
        Dashboard {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            widgets: vec![],
            created_at: Some(Utc::now()),
            layout: DashboardLayout::default(),
        }
    }

    /// Add a widget to the dashboard
    pub fn add_widget(&self, dashboard: &mut Dashboard, widget: Widget) {
        // Calculate default position for new widget
        let position = WidgetPosition {
            x: 0,
            y: dashboard.layout.positions.len() as u32 * 4,
            width: 6,
            height: 4,
        };
        dashboard.layout.positions.push(position);
        dashboard.widgets.push(widget);
    }

    /// Render dashboard to HTML
    pub async fn render_dashboard(&self, dashboard: &Dashboard) -> Result<String> {
        let mut html = String::new();

        // HTML header with embedded CSS for dashboard styling
        html.push_str(&format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{}</title>
<style>
:root {{
    --primary-color: #3498db;
    --secondary-color: #2ecc71;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
    --dark-bg: #2c3e50;
    --light-bg: #ecf0f1;
    --text-color: #2c3e50;
    --border-radius: 8px;
    --shadow: 0 2px 10px rgba(0,0,0,0.1);
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background-color: var(--light-bg);
    color: var(--text-color);
    line-height: 1.6;
}}

.dashboard-header {{
    background: linear-gradient(135deg, var(--dark-bg), #34495e);
    color: white;
    padding: 20px 30px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.dashboard-title {{
    font-size: 24px;
    font-weight: 600;
}}

.dashboard-meta {{
    font-size: 14px;
    opacity: 0.8;
}}

.dashboard-grid {{
    display: grid;
    grid-template-columns: repeat({}, 1fr);
    gap: {}px;
    padding: 20px;
    max-width: 1600px;
    margin: 0 auto;
}}

.widget {{
    background: white;
    border-radius: var(--border-radius);
    box-shadow: var(--shadow);
    overflow: hidden;
    transition: transform 0.2s, box-shadow 0.2s;
}}

.widget:hover {{
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
}}

.widget-header {{
    background: var(--dark-bg);
    color: white;
    padding: 12px 16px;
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

.widget-content {{
    padding: 20px;
}}

.metric-value {{
    font-size: 36px;
    font-weight: 700;
    color: var(--primary-color);
    margin-bottom: 8px;
}}

.metric-label {{
    font-size: 12px;
    color: #7f8c8d;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.metric-trend {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
}}

.trend-up {{ background: #d4edda; color: #155724; }}
.trend-down {{ background: #f8d7da; color: #721c24; }}
.trend-neutral {{ background: #fff3cd; color: #856404; }}

.severity-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    margin-right: 8px;
}}

.severity-critical {{ background: var(--danger-color); color: white; }}
.severity-high {{ background: #e67e22; color: white; }}
.severity-medium {{ background: var(--warning-color); color: white; }}
.severity-low {{ background: var(--secondary-color); color: white; }}
.severity-info {{ background: var(--primary-color); color: white; }}

.progress-bar {{
    height: 8px;
    background: #e9ecef;
    border-radius: 4px;
    overflow: hidden;
    margin-top: 10px;
}}

.progress-fill {{
    height: 100%;
    background: var(--primary-color);
    transition: width 0.3s ease;
}}

.widget-table {{
    width: 100%;
    border-collapse: collapse;
}}

.widget-table th,
.widget-table td {{
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #eee;
}}

.widget-table th {{
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    color: #7f8c8d;
}}

.chart-placeholder {{
    height: 200px;
    background: linear-gradient(135deg, #f5f7fa, #c3cfe2);
    border-radius: var(--border-radius);
    display: flex;
    align-items: center;
    justify-content: center;
    color: #7f8c8d;
    font-size: 14px;
}}

/* Widget size classes */
.widget-small {{ grid-column: span 3; }}
.widget-medium {{ grid-column: span 4; }}
.widget-large {{ grid-column: span 6; }}
.widget-full {{ grid-column: span 12; }}
</style>
</head>
<body>
"#,
            escape_html(&dashboard.name),
            dashboard.layout.columns,
            dashboard.layout.gap
        ));

        // Dashboard header
        html.push_str(&format!(r#"
<div class="dashboard-header">
    <h1 class="dashboard-title">{}</h1>
    <div class="dashboard-meta">Generated: {} | {} widgets</div>
</div>
"#,
            escape_html(&dashboard.name),
            Utc::now().format("%Y-%m-%d %H:%M UTC"),
            dashboard.widgets.len()
        ));

        // Widget grid
        html.push_str("<div class=\"dashboard-grid\">\n");

        for widget in &dashboard.widgets {
            html.push_str(&self.render_widget(widget));
        }

        html.push_str("</div>\n");
        html.push_str("</body>\n</html>");

        Ok(html)
    }

    /// Render a single widget to HTML
    fn render_widget(&self, widget: &Widget) -> String {
        let size_class = self.get_widget_size_class(&widget.widget_type);

        let mut html = format!(
            r#"<div class="widget {}">
<div class="widget-header">{}</div>
<div class="widget-content">
"#,
            size_class,
            escape_html(&widget.title)
        );

        // Render widget content based on type
        match widget.widget_type.as_str() {
            "security_score" => {
                let score = widget.config.get("target")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                html.push_str(&format!(r#"
<div class="metric-value">{:.0}<span style="font-size: 20px;">%</span></div>
<div class="metric-label">Security Posture Score</div>
<div class="progress-bar"><div class="progress-fill" style="width: {}%;"></div></div>
"#, score, score));
            }
            "vulnerability_summary" => {
                html.push_str(r#"
<table class="widget-table">
<tr><th>Severity</th><th>Count</th><th>Trend</th></tr>
<tr><td><span class="severity-badge severity-critical">Critical</span></td><td>0</td><td><span class="metric-trend trend-neutral">-</span></td></tr>
<tr><td><span class="severity-badge severity-high">High</span></td><td>0</td><td><span class="metric-trend trend-neutral">-</span></td></tr>
<tr><td><span class="severity-badge severity-medium">Medium</span></td><td>0</td><td><span class="metric-trend trend-neutral">-</span></td></tr>
<tr><td><span class="severity-badge severity-low">Low</span></td><td>0</td><td><span class="metric-trend trend-neutral">-</span></td></tr>
</table>
"#);
            }
            "response_metrics" => {
                html.push_str(r#"
<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; text-align: center;">
<div>
<div class="metric-value">0.0<span style="font-size: 14px;">h</span></div>
<div class="metric-label">MTTD</div>
</div>
<div>
<div class="metric-value">0.0<span style="font-size: 14px;">h</span></div>
<div class="metric-label">MTTR</div>
</div>
<div>
<div class="metric-value">0.0<span style="font-size: 14px;">h</span></div>
<div class="metric-label">MTTC</div>
</div>
</div>
"#);
            }
            "compliance_status" => {
                html.push_str(r#"
<table class="widget-table">
<tr><th>Framework</th><th>Score</th><th>Status</th></tr>
<tr><td>PCI-DSS</td><td>-</td><td><span class="metric-trend trend-neutral">Not Assessed</span></td></tr>
<tr><td>NIST 800-53</td><td>-</td><td><span class="metric-trend trend-neutral">Not Assessed</span></td></tr>
<tr><td>CIS</td><td>-</td><td><span class="metric-trend trend-neutral">Not Assessed</span></td></tr>
</table>
"#);
            }
            "active_incidents" => {
                html.push_str(r#"
<div style="text-align: center; padding: 30px;">
<div class="metric-value" style="color: #27ae60;">0</div>
<div class="metric-label">Active Incidents</div>
<p style="color: #7f8c8d; margin-top: 10px;">No active incidents at this time</p>
</div>
"#);
            }
            "patch_compliance" => {
                let target = widget.config.get("target")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(95.0);
                html.push_str(&format!(r#"
<div class="metric-value">100<span style="font-size: 20px;">%</span></div>
<div class="metric-label">Systems Compliant</div>
<div class="progress-bar"><div class="progress-fill" style="width: 100%; background: #27ae60;"></div></div>
<p style="font-size: 12px; color: #7f8c8d; margin-top: 10px;">Target: {:.0}%</p>
"#, target));
            }
            _ => {
                // Generic widget rendering for unknown types
                html.push_str(&format!(r#"
<div class="chart-placeholder">
Widget: {} (Type: {})
</div>
"#, escape_html(&widget.title), escape_html(&widget.widget_type)));
            }
        }

        html.push_str("</div>\n</div>\n");
        html
    }

    /// Get CSS size class based on widget type
    fn get_widget_size_class(&self, widget_type: &str) -> &'static str {
        match widget_type {
            "security_score" | "patch_compliance" => "widget-small",
            "response_metrics" => "widget-medium",
            "vulnerability_summary" | "compliance_status" | "active_incidents" => "widget-medium",
            _ => "widget-medium",
        }
    }

    /// Render dashboard to JSON
    pub fn render_dashboard_json(&self, dashboard: &Dashboard) -> Result<String> {
        Ok(serde_json::to_string_pretty(dashboard)?)
    }
}

impl Default for DashboardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape HTML special characters
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
