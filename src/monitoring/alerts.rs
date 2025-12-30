//! Alerting system for monitoring thresholds

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub metric: String,
    pub threshold: f64,
    pub current_value: f64,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl Alert {
    pub fn new(severity: AlertSeverity, title: String, description: String, metric: String, threshold: f64, current_value: f64) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            severity,
            title,
            description,
            metric,
            threshold,
            current_value,
            created_at: Utc::now(),
            resolved_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.resolved_at.is_none()
    }

    pub fn resolve(&mut self) {
        self.resolved_at = Some(Utc::now());
    }
}

#[derive(Debug, Clone)]
pub struct AlertRule {
    pub name: String,
    pub metric: String,
    pub threshold: f64,
    pub comparison: Comparison,
    pub severity: AlertSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Comparison {
    GreaterThan,
    LessThan,
    Equals,
}

impl AlertRule {
    pub fn check(&self, value: f64) -> bool {
        match self.comparison {
            Comparison::GreaterThan => value > self.threshold,
            Comparison::LessThan => value < self.threshold,
            Comparison::Equals => (value - self.threshold).abs() < 0.001,
        }
    }
}

pub struct AlertManager {
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    rules: Arc<RwLock<Vec<AlertRule>>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add_rule(&self, rule: AlertRule) {
        self.rules.write().await.push(rule);
    }

    pub async fn check_metric(&self, metric: &str, value: f64) {
        let rules = self.rules.read().await;

        for rule in rules.iter().filter(|r| r.metric == metric) {
            if rule.check(value) {
                let alert = Alert::new(
                    rule.severity,
                    format!("Alert: {}", rule.name),
                    rule.description.clone(),
                    metric.to_string(),
                    rule.threshold,
                    value,
                );

                let mut alerts = self.alerts.write().await;
                alerts.insert(alert.id.clone(), alert);
            }
        }
    }

    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await
            .values()
            .filter(|a| a.is_active())
            .cloned()
            .collect()
    }

    pub async fn resolve_alert(&self, alert_id: &str) {
        if let Some(alert) = self.alerts.write().await.get_mut(alert_id) {
            alert.resolve();
        }
    }

    pub async fn get_default_rules() -> Vec<AlertRule> {
        vec![
            AlertRule {
                name: "High CPU Usage".to_string(),
                metric: "cpu_usage_percent".to_string(),
                threshold: 90.0,
                comparison: Comparison::GreaterThan,
                severity: AlertSeverity::Warning,
                description: "CPU usage exceeds 90%".to_string(),
            },
            AlertRule {
                name: "Critical Memory Usage".to_string(),
                metric: "memory_usage_percent".to_string(),
                threshold: 95.0,
                comparison: Comparison::GreaterThan,
                severity: AlertSeverity::Critical,
                description: "Memory usage exceeds 95%".to_string(),
            },
            AlertRule {
                name: "High Error Rate".to_string(),
                metric: "error_rate".to_string(),
                threshold: 5.0,
                comparison: Comparison::GreaterThan,
                severity: AlertSeverity::Warning,
                description: "Error rate exceeds 5%".to_string(),
            },
        ]
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}
