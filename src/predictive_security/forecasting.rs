use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration, Datelike, Weekday};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};

/// Historical metrics for forecasting
static HISTORICAL_METRICS: Lazy<Arc<RwLock<HistoricalMetrics>>> = Lazy::new(|| {
    Arc::new(RwLock::new(HistoricalMetrics::default()))
});

#[derive(Debug, Clone)]
struct HistoricalMetrics {
    daily_incidents: Vec<DailyMetric>,
    staffing_utilization: Vec<StaffingMetric>,
    infrastructure_usage: Vec<InfrastructureMetric>,
    attack_surface_data: Vec<AttackSurfaceMetric>,
    budget_history: Vec<BudgetMetric>,
}

impl Default for HistoricalMetrics {
    fn default() -> Self {
        // Initialize with simulated historical data
        let mut daily_incidents = Vec::new();
        let now = Utc::now();

        // Generate 90 days of historical data
        for i in 0..90 {
            let date = now - Duration::days(90 - i);
            let base = 40.0;
            let dow_factor = match date.weekday() {
                Weekday::Sat | Weekday::Sun => 0.5,
                Weekday::Mon => 1.2,
                _ => 1.0,
            };
            let noise = ((i as f64 * 13.0) % 20.0 - 10.0) / 100.0;
            let count = (base * dow_factor * (1.0 + noise)) as i32;

            daily_incidents.push(DailyMetric {
                date,
                value: count as f64,
                category: "total".to_string(),
            });
        }

        Self {
            daily_incidents,
            staffing_utilization: Vec::new(),
            infrastructure_usage: Vec::new(),
            attack_surface_data: Vec::new(),
            budget_history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct DailyMetric {
    date: chrono::DateTime<Utc>,
    value: f64,
    category: String,
}

#[derive(Debug, Clone)]
struct StaffingMetric {
    date: chrono::DateTime<Utc>,
    analysts_on_duty: i32,
    tickets_handled: i32,
    avg_resolution_hours: f64,
}

#[derive(Debug, Clone)]
struct InfrastructureMetric {
    date: chrono::DateTime<Utc>,
    cpu_utilization: f64,
    memory_utilization: f64,
    storage_used_tb: f64,
    network_throughput_gbps: f64,
}

#[derive(Debug, Clone)]
struct AttackSurfaceMetric {
    date: chrono::DateTime<Utc>,
    total_assets: i32,
    internet_facing: i32,
    vulnerabilities: i32,
    critical_vulns: i32,
}

#[derive(Debug, Clone)]
struct BudgetMetric {
    month: String,
    allocated: f64,
    spent: f64,
    categories: HashMap<String, f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceForecast {
    pub resource_type: String,
    pub current_capacity: f64,
    pub predicted_requirement: f64,
    pub horizon_days: i32,
    pub growth_rate: f64,
    pub confidence: f64,
    pub recommendations: Vec<String>,
}

/// Forecast SOC analyst staffing requirements
pub async fn forecast_soc_staffing(horizon_days: i32) -> Result<ResourceForecast> {
    let metrics = HISTORICAL_METRICS.read().unwrap();

    // Calculate current capacity and workload
    let current_analysts = 10.0; // Base team size
    let avg_incidents_per_day = calculate_average_incidents(&metrics.daily_incidents);
    let incidents_per_analyst = 8.0; // Target incidents per analyst per day

    // Calculate current utilization
    let current_utilization = avg_incidents_per_day / (current_analysts * incidents_per_analyst);

    // Predict incident growth using linear regression
    let growth_rate = calculate_incident_growth_rate(&metrics.daily_incidents);

    // Forecast future incident volume
    let future_incidents = avg_incidents_per_day * (1.0 + growth_rate * horizon_days as f64 / 365.0);

    // Calculate required analysts
    let predicted_requirement = (future_incidents / incidents_per_analyst).ceil();

    // Account for buffer (holidays, sick leave, training)
    let buffer_factor = 1.2;
    let recommended_staffing = predicted_requirement * buffer_factor;

    // Generate recommendations
    let mut recommendations = Vec::new();

    if recommended_staffing > current_analysts {
        let additional = (recommended_staffing - current_analysts).ceil() as i32;
        recommendations.push(format!("Consider hiring {} additional analysts", additional));
    }

    if current_utilization > 0.85 {
        recommendations.push("High utilization - risk of burnout, prioritize hiring".to_string());
    }

    if growth_rate > 0.1 {
        recommendations.push("Incident volume growing - invest in automation".to_string());
    }

    recommendations.push(format!(
        "Current utilization: {:.0}%, target: 70-80%",
        current_utilization * 100.0
    ));

    // Confidence based on data quality
    let confidence = calculate_forecast_confidence(metrics.daily_incidents.len(), horizon_days);

    Ok(ResourceForecast {
        resource_type: "SOC Analysts".to_string(),
        current_capacity: current_analysts,
        predicted_requirement: recommended_staffing,
        horizon_days,
        growth_rate,
        confidence,
        recommendations,
    })
}

/// Forecast infrastructure capacity requirements
pub async fn forecast_infrastructure_capacity(horizon_days: i32) -> Result<ResourceForecast> {
    // Current infrastructure metrics (simulated)
    let current_cpu_capacity: f64 = 100.0; // CPU cores
    let current_cpu_usage: f64 = 65.0;

    let current_memory_tb: f64 = 2.0;
    let current_memory_usage: f64 = 1.4;

    let current_storage_tb: f64 = 50.0;
    let current_storage_usage: f64 = 35.0;

    // Growth rates based on historical data
    let log_growth_rate: f64 = 0.08; // 8% monthly log volume growth
    let asset_growth_rate: f64 = 0.05; // 5% monthly asset growth

    // Calculate projected requirements
    let months = horizon_days as f64 / 30.0;

    // Storage forecast (most critical - logs grow continuously)
    let projected_storage = current_storage_usage * (1.0_f64 + log_growth_rate).powf(months);

    // CPU forecast (scales with processing)
    let projected_cpu = current_cpu_usage * (1.0_f64 + asset_growth_rate).powf(months);

    // Memory forecast
    let projected_memory = current_memory_usage * (1.0_f64 + asset_growth_rate * 0.5).powf(months);

    // Determine bottleneck
    let storage_ratio = projected_storage / current_storage_tb;
    let cpu_ratio = projected_cpu / current_cpu_capacity;
    let memory_ratio = projected_memory / current_memory_tb;

    let (resource_type, current, predicted, growth) = if storage_ratio >= cpu_ratio && storage_ratio >= memory_ratio {
        ("Storage (TB)".to_string(), current_storage_tb, projected_storage, log_growth_rate)
    } else if cpu_ratio >= memory_ratio {
        ("CPU Cores".to_string(), current_cpu_capacity, projected_cpu, asset_growth_rate)
    } else {
        ("Memory (TB)".to_string(), current_memory_tb, projected_memory, asset_growth_rate * 0.5)
    };

    let mut recommendations = Vec::new();

    if storage_ratio > 0.8 {
        recommendations.push(format!(
            "Storage will reach {:.0}% capacity - plan expansion",
            storage_ratio * 100.0
        ));
    }

    if cpu_ratio > 0.9 {
        recommendations.push("CPU capacity critical - consider horizontal scaling".to_string());
    }

    if memory_ratio > 0.85 {
        recommendations.push("Memory approaching limit - add RAM or optimize".to_string());
    }

    // General recommendations
    recommendations.push(format!("Log retention growth: {:.0}% per month", log_growth_rate * 100.0));
    recommendations.push(format!("Asset growth: {:.0}% per month", asset_growth_rate * 100.0));

    Ok(ResourceForecast {
        resource_type,
        current_capacity: current,
        predicted_requirement: predicted,
        horizon_days,
        growth_rate: growth,
        confidence: 0.75,
        recommendations,
    })
}

/// Forecast security budget requirements
pub async fn forecast_budget(horizon_months: i32) -> Result<f64> {
    // Base annual security budget
    let base_annual_budget: f64 = 1_200_000.0;

    // Growth factors
    let compliance_factor: f64 = 1.05; // 5% for new compliance requirements
    let threat_landscape_factor: f64 = 1.08; // 8% for evolving threats
    let asset_growth_factor: f64 = 1.06; // 6% for infrastructure expansion
    let inflation_factor: f64 = 1.03; // 3% inflation

    // Calculate compound growth
    let years = horizon_months as f64 / 12.0;

    let projected = base_annual_budget
        * compliance_factor.powf(years)
        * threat_landscape_factor.powf(years)
        * asset_growth_factor.powf(years)
        * inflation_factor.powf(years);

    // Pro-rate to requested horizon
    let monthly_projected = projected / 12.0;
    let total_for_horizon = monthly_projected * horizon_months as f64;

    Ok(total_for_horizon)
}

/// Forecast future risk posture score
pub async fn forecast_risk_posture(horizon_days: i32) -> Result<f64> {
    // Current risk score (1-10 scale, lower is better)
    let current_score = 6.5;

    // Factors affecting risk
    let planned_remediation_impact = -0.5; // Negative = risk reduction
    let threat_landscape_impact = 0.3; // Increasing threats
    let asset_growth_impact = 0.2; // More assets = more risk
    let security_investment_impact = -0.3; // Security improvements

    // Calculate projected change per quarter
    let quarterly_change = planned_remediation_impact
        + threat_landscape_impact
        + asset_growth_impact
        + security_investment_impact;

    // Project forward
    let quarters = horizon_days as f64 / 90.0;
    let projected_score = (current_score + quarterly_change * quarters).max(1.0).min(10.0);

    Ok(projected_score)
}

/// Forecast attack surface growth
pub async fn forecast_attack_surface_growth(horizon_days: i32) -> Result<f64> {
    // Current attack surface metrics
    let current_assets: i32 = 5000;
    let _current_internet_facing: i32 = 250;
    let current_cloud_resources: i32 = 1200;
    let current_api_endpoints: i32 = 450;

    // Growth rates based on industry trends
    let asset_growth: f64 = 0.03; // 3% monthly
    let cloud_growth: f64 = 0.08; // 8% monthly (cloud adoption)
    let api_growth: f64 = 0.06; // 6% monthly (API proliferation)
    let _iot_growth: f64 = 0.10; // 10% monthly (IoT expansion)

    let months = horizon_days as f64 / 30.0;

    // Calculate weighted growth
    let projected_assets = current_assets as f64 * (1.0_f64 + asset_growth).powf(months);
    let projected_cloud = current_cloud_resources as f64 * (1.0_f64 + cloud_growth).powf(months);
    let projected_api = current_api_endpoints as f64 * (1.0_f64 + api_growth).powf(months);

    // Overall attack surface growth
    let current_total = current_assets as f64 + current_cloud_resources as f64 + current_api_endpoints as f64;
    let projected_total = projected_assets + projected_cloud + projected_api;

    let growth_percentage = ((projected_total - current_total) / current_total) * 100.0;

    Ok(growth_percentage)
}

/// Detailed attack surface forecast with breakdown
pub async fn forecast_attack_surface_detailed(horizon_days: i32) -> Result<AttackSurfaceForecast> {
    let months = horizon_days as f64 / 30.0;

    // Current state
    let current = AttackSurfaceState {
        total_assets: 5000,
        internet_facing: 250,
        cloud_resources: 1200,
        api_endpoints: 450,
        iot_devices: 300,
        mobile_apps: 25,
        third_party_integrations: 85,
    };

    // Growth rates
    let projected = AttackSurfaceState {
        total_assets: (current.total_assets as f64 * (1.03_f64).powf(months)) as i32,
        internet_facing: (current.internet_facing as f64 * (1.02_f64).powf(months)) as i32,
        cloud_resources: (current.cloud_resources as f64 * (1.08_f64).powf(months)) as i32,
        api_endpoints: (current.api_endpoints as f64 * (1.06_f64).powf(months)) as i32,
        iot_devices: (current.iot_devices as f64 * (1.10_f64).powf(months)) as i32,
        mobile_apps: (current.mobile_apps as f64 * (1.04_f64).powf(months)) as i32,
        third_party_integrations: (current.third_party_integrations as f64 * (1.05_f64).powf(months)) as i32,
    };

    // Calculate risk areas
    let mut high_risk_areas = Vec::new();

    if projected.cloud_resources - current.cloud_resources > 200 {
        high_risk_areas.push("Cloud infrastructure expanding rapidly".to_string());
    }

    if projected.iot_devices - current.iot_devices > 50 {
        high_risk_areas.push("IoT device proliferation increases attack surface".to_string());
    }

    if projected.api_endpoints - current.api_endpoints > 100 {
        high_risk_areas.push("API sprawl requires governance review".to_string());
    }

    if projected.third_party_integrations - current.third_party_integrations > 10 {
        high_risk_areas.push("Third-party risk increasing with new integrations".to_string());
    }

    // Generate recommendations
    let mut recommendations = Vec::new();

    recommendations.push(format!(
        "Cloud resources: {} → {} ({:.0}% growth)",
        current.cloud_resources,
        projected.cloud_resources,
        (projected.cloud_resources as f64 / current.cloud_resources as f64 - 1.0) * 100.0
    ));

    recommendations.push(format!(
        "API endpoints: {} → {} ({:.0}% growth)",
        current.api_endpoints,
        projected.api_endpoints,
        (projected.api_endpoints as f64 / current.api_endpoints as f64 - 1.0) * 100.0
    ));

    if projected.total_assets > current.total_assets * 12 / 10 {
        recommendations.push("Consider implementing asset discovery automation".to_string());
    }

    Ok(AttackSurfaceForecast {
        current,
        projected,
        horizon_days,
        high_risk_areas,
        recommendations,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceState {
    pub total_assets: i32,
    pub internet_facing: i32,
    pub cloud_resources: i32,
    pub api_endpoints: i32,
    pub iot_devices: i32,
    pub mobile_apps: i32,
    pub third_party_integrations: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceForecast {
    pub current: AttackSurfaceState,
    pub projected: AttackSurfaceState,
    pub horizon_days: i32,
    pub high_risk_areas: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Forecast compliance posture changes
pub async fn forecast_compliance_posture(horizon_days: i32) -> Result<ComplianceForecast> {
    // Current compliance scores by framework
    let mut current_scores = HashMap::new();
    current_scores.insert("PCI-DSS".to_string(), 0.92);
    current_scores.insert("HIPAA".to_string(), 0.88);
    current_scores.insert("SOC2".to_string(), 0.95);
    current_scores.insert("NIST-CSF".to_string(), 0.85);
    current_scores.insert("ISO-27001".to_string(), 0.90);

    // Upcoming audit dates
    let mut upcoming_audits = Vec::new();
    let now = Utc::now();

    upcoming_audits.push(AuditEvent {
        framework: "PCI-DSS".to_string(),
        audit_date: now + Duration::days(45),
        preparation_status: 0.85,
    });

    upcoming_audits.push(AuditEvent {
        framework: "SOC2".to_string(),
        audit_date: now + Duration::days(90),
        preparation_status: 0.70,
    });

    // Predict score changes
    let mut projected_scores = HashMap::new();

    for (framework, score) in &current_scores {
        // Factors: new requirements, control drift, remediation
        let drift = -0.02; // Natural drift
        let new_requirements = -0.03; // New compliance requirements
        let remediation = 0.04; // Active remediation efforts

        let months = horizon_days as f64 / 30.0;
        let change = (drift + new_requirements + remediation) * months / 12.0;
        let projected = (score + change).min(1.0).max(0.0);

        projected_scores.insert(framework.clone(), projected);
    }

    // Generate risk areas
    let mut risk_areas = Vec::new();

    for (framework, projected) in &projected_scores {
        if *projected < 0.85 {
            risk_areas.push(format!(
                "{} compliance at risk - projected {:.0}%",
                framework,
                projected * 100.0
            ));
        }
    }

    // Check upcoming audits
    let audit_window = now + Duration::days(horizon_days as i64);
    for audit in &upcoming_audits {
        if audit.audit_date <= audit_window && audit.preparation_status < 0.9 {
            risk_areas.push(format!(
                "{} audit in {} days - preparation at {:.0}%",
                audit.framework,
                (audit.audit_date - now).num_days(),
                audit.preparation_status * 100.0
            ));
        }
    }

    Ok(ComplianceForecast {
        current_scores,
        projected_scores,
        horizon_days,
        upcoming_audits,
        risk_areas,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceForecast {
    pub current_scores: HashMap<String, f64>,
    pub projected_scores: HashMap<String, f64>,
    pub horizon_days: i32,
    pub upcoming_audits: Vec<AuditEvent>,
    pub risk_areas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub framework: String,
    pub audit_date: chrono::DateTime<Utc>,
    pub preparation_status: f64,
}

/// Forecast security tool ROI
pub async fn forecast_tool_roi(tool_name: &str, investment: f64, horizon_months: i32) -> Result<RoiForecast> {
    // Tool effectiveness factors
    let (_efficiency_gain, risk_reduction, time_savings) = match tool_name.to_lowercase().as_str() {
        "siem" => (0.25, 0.30, 0.35),
        "edr" => (0.20, 0.40, 0.20),
        "soar" => (0.40, 0.20, 0.50),
        "vulnerability_scanner" => (0.15, 0.35, 0.25),
        "threat_intel" => (0.10, 0.25, 0.15),
        "dlp" => (0.15, 0.30, 0.10),
        _ => (0.10, 0.15, 0.10),
    };

    // Calculate benefits
    let avg_incident_cost = 50000.0;
    let incidents_per_year = 24.0;
    let hourly_analyst_cost = 75.0;
    let annual_analyst_hours = 2000.0;

    // Risk reduction benefit
    let annual_risk_benefit = avg_incident_cost * incidents_per_year * risk_reduction;

    // Efficiency benefit (time savings)
    let annual_efficiency_benefit = hourly_analyst_cost * annual_analyst_hours * time_savings;

    // Calculate ROI over horizon
    let years = horizon_months as f64 / 12.0;
    let total_benefit = (annual_risk_benefit + annual_efficiency_benefit) * years;
    let roi = (total_benefit - investment) / investment;

    // Payback period
    let monthly_benefit = (annual_risk_benefit + annual_efficiency_benefit) / 12.0;
    let payback_months = if monthly_benefit > 0.0 {
        (investment / monthly_benefit).ceil() as i32
    } else {
        999
    };

    Ok(RoiForecast {
        tool_name: tool_name.to_string(),
        investment,
        projected_benefit: total_benefit,
        roi_percentage: roi * 100.0,
        payback_months,
        risk_reduction_value: annual_risk_benefit * years,
        efficiency_value: annual_efficiency_benefit * years,
        recommendation: if roi > 1.0 {
            "Strong investment - recommended".to_string()
        } else if roi > 0.5 {
            "Positive ROI - consider implementation".to_string()
        } else if roi > 0.0 {
            "Marginal ROI - evaluate alternatives".to_string()
        } else {
            "Negative ROI - not recommended".to_string()
        },
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoiForecast {
    pub tool_name: String,
    pub investment: f64,
    pub projected_benefit: f64,
    pub roi_percentage: f64,
    pub payback_months: i32,
    pub risk_reduction_value: f64,
    pub efficiency_value: f64,
    pub recommendation: String,
}

// Helper functions

fn calculate_average_incidents(metrics: &[DailyMetric]) -> f64 {
    if metrics.is_empty() {
        return 40.0; // Default
    }

    let sum: f64 = metrics.iter().map(|m| m.value).sum();
    sum / metrics.len() as f64
}

fn calculate_incident_growth_rate(metrics: &[DailyMetric]) -> f64 {
    if metrics.len() < 30 {
        return 0.05; // Default 5% annual growth
    }

    // Compare recent 30 days to previous 30 days
    let recent: f64 = metrics.iter().rev().take(30).map(|m| m.value).sum();
    let older: f64 = metrics.iter().rev().skip(30).take(30).map(|m| m.value).sum();

    if older > 0.0 {
        (recent - older) / older
    } else {
        0.05
    }
}

fn calculate_forecast_confidence(data_points: usize, horizon_days: i32) -> f64 {
    // More data = higher confidence
    let data_factor = (data_points as f64 / 90.0).min(1.0);

    // Shorter horizon = higher confidence
    let horizon_factor = (1.0 - horizon_days as f64 / 365.0).max(0.3);

    (data_factor * 0.6 + horizon_factor * 0.4).min(0.95)
}

/// Update historical metrics with new data
pub async fn update_metrics(incident_count: i32, category: &str) -> Result<()> {
    let mut metrics = HISTORICAL_METRICS.write().unwrap();

    metrics.daily_incidents.push(DailyMetric {
        date: Utc::now(),
        value: incident_count as f64,
        category: category.to_string(),
    });

    // Keep only last 365 days
    if metrics.daily_incidents.len() > 365 {
        metrics.daily_incidents.drain(0..30);
    }

    Ok(())
}
