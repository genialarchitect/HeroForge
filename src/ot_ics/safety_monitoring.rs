use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyAlert {
    pub id: String,
    pub alert_type: SafetyAlertType,
    pub severity: SafetySeverity,
    pub description: String,
    pub affected_system: String,
    pub timestamp: DateTime<Utc>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafetyAlertType {
    SafetySystemBypass,
    ManualOverride,
    SILDegradation,
    ProcessAnomaly,
    SensorFailure,
    ActuatorMalfunction,
    CommunicationLoss,
    EmergencyShutdown,
    AlarmFlood,
    ConfigurationChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafetySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetySystemStatus {
    pub system_id: String,
    pub system_type: SafetySystemType,
    pub status: OperationalStatus,
    pub sil_level: u8,
    pub last_test_date: Option<DateTime<Utc>>,
    pub bypass_active: bool,
    pub override_active: bool,
    pub sensors: Vec<SensorStatus>,
    pub actuators: Vec<ActuatorStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafetySystemType {
    SIS,  // Safety Instrumented System
    ESD,  // Emergency Shutdown System
    FGS,  // Fire and Gas System
    HIPPS, // High Integrity Pressure Protection System
    BMS,  // Burner Management System
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationalStatus {
    Online,
    Degraded,
    Bypass,
    Maintenance,
    Offline,
    Faulted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorStatus {
    pub sensor_id: String,
    pub sensor_type: String,
    pub current_value: f64,
    pub unit: String,
    pub status: SensorState,
    pub last_calibration: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SensorState {
    Normal,
    HighAlarm,
    LowAlarm,
    HighHigh,
    LowLow,
    Failed,
    OutOfRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuatorStatus {
    pub actuator_id: String,
    pub actuator_type: String,
    pub position: f64,
    pub status: ActuatorState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActuatorState {
    Normal,
    Activated,
    Failed,
    Stuck,
    Maintenance,
}

/// Global safety monitoring state
static SAFETY_STATE: once_cell::sync::Lazy<Arc<RwLock<SafetyMonitoringState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(SafetyMonitoringState::default())));

#[derive(Debug, Default)]
struct SafetyMonitoringState {
    systems: HashMap<String, SafetySystemStatus>,
    alerts: Vec<SafetyAlert>,
    process_baselines: HashMap<String, ProcessBaseline>,
    alarm_history: Vec<AlarmEvent>,
}

#[derive(Debug, Clone)]
struct ProcessBaseline {
    parameter: String,
    min_value: f64,
    max_value: f64,
    normal_range_low: f64,
    normal_range_high: f64,
    rate_of_change_limit: f64,
}

#[derive(Debug, Clone)]
struct AlarmEvent {
    timestamp: DateTime<Utc>,
    alarm_id: String,
    severity: SafetySeverity,
}

/// Monitor Safety Instrumented System
pub async fn monitor_sis(system_id: &str) -> Result<Vec<SafetyAlert>> {
    info!("Monitoring SIS: {}", system_id);

    let mut alerts = Vec::new();
    let mut state = SAFETY_STATE.write().await;

    // Get or create system status
    let system = state.systems.entry(system_id.to_string())
        .or_insert_with(|| SafetySystemStatus {
            system_id: system_id.to_string(),
            system_type: SafetySystemType::SIS,
            status: OperationalStatus::Online,
            sil_level: 2,
            last_test_date: None,
            bypass_active: false,
            override_active: false,
            sensors: Vec::new(),
            actuators: Vec::new(),
        });

    // Check for bypass conditions
    if system.bypass_active {
        alerts.push(SafetyAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: SafetyAlertType::SafetySystemBypass,
            severity: SafetySeverity::Critical,
            description: format!("SIS {} is currently bypassed", system_id),
            affected_system: system_id.to_string(),
            timestamp: Utc::now(),
            recommendations: vec![
                "Remove bypass as soon as possible".to_string(),
                "Document bypass reason in MOC system".to_string(),
                "Implement compensating measures".to_string(),
            ],
        });
    }

    // Check sensor health
    for sensor in &system.sensors {
        match sensor.status {
            SensorState::Failed | SensorState::OutOfRange => {
                alerts.push(SafetyAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    alert_type: SafetyAlertType::SensorFailure,
                    severity: SafetySeverity::High,
                    description: format!("Sensor {} has failed or is out of range", sensor.sensor_id),
                    affected_system: system_id.to_string(),
                    timestamp: Utc::now(),
                    recommendations: vec![
                        "Check sensor wiring and connections".to_string(),
                        "Verify sensor calibration".to_string(),
                        "Replace sensor if necessary".to_string(),
                    ],
                });
            }
            SensorState::HighHigh | SensorState::LowLow => {
                alerts.push(SafetyAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    alert_type: SafetyAlertType::ProcessAnomaly,
                    severity: SafetySeverity::Critical,
                    description: format!("Sensor {} at critical alarm level: {:?}", sensor.sensor_id, sensor.status),
                    affected_system: system_id.to_string(),
                    timestamp: Utc::now(),
                    recommendations: vec![
                        "Investigate process condition immediately".to_string(),
                        "Prepare for possible emergency shutdown".to_string(),
                    ],
                });
            }
            _ => {}
        }
    }

    // Check actuator health
    for actuator in &system.actuators {
        if actuator.status == ActuatorState::Stuck || actuator.status == ActuatorState::Failed {
            alerts.push(SafetyAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: SafetyAlertType::ActuatorMalfunction,
                severity: SafetySeverity::High,
                description: format!("Actuator {} has malfunctioned: {:?}", actuator.actuator_id, actuator.status),
                affected_system: system_id.to_string(),
                timestamp: Utc::now(),
                recommendations: vec![
                    "Check actuator pneumatics/hydraulics".to_string(),
                    "Verify valve position feedback".to_string(),
                    "Consider manual intervention if safe".to_string(),
                ],
            });
        }
    }

    // Store alerts
    state.alerts.extend(alerts.clone());

    info!("SIS monitoring complete: {} alerts generated", alerts.len());
    Ok(alerts)
}

/// Monitor Emergency Shutdown System
pub async fn monitor_esd(system_id: &str) -> Result<Vec<SafetyAlert>> {
    info!("Monitoring ESD: {}", system_id);

    let mut alerts = Vec::new();
    let mut state = SAFETY_STATE.write().await;

    let system = state.systems.entry(system_id.to_string())
        .or_insert_with(|| SafetySystemStatus {
            system_id: system_id.to_string(),
            system_type: SafetySystemType::ESD,
            status: OperationalStatus::Online,
            sil_level: 3,
            last_test_date: None,
            bypass_active: false,
            override_active: false,
            sensors: Vec::new(),
            actuators: Vec::new(),
        });

    // Check ESD readiness
    if system.status == OperationalStatus::Faulted {
        alerts.push(SafetyAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: SafetyAlertType::EmergencyShutdown,
            severity: SafetySeverity::Critical,
            description: format!("ESD system {} is in faulted state", system_id),
            affected_system: system_id.to_string(),
            timestamp: Utc::now(),
            recommendations: vec![
                "Investigate fault cause immediately".to_string(),
                "Do not restart process until ESD is operational".to_string(),
                "Contact safety system vendor if necessary".to_string(),
            ],
        });
    }

    // Check for recent proof test
    if let Some(last_test) = system.last_test_date {
        let days_since_test = (Utc::now() - last_test).num_days();
        if days_since_test > 365 {
            alerts.push(SafetyAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: SafetyAlertType::SILDegradation,
                severity: SafetySeverity::Medium,
                description: format!("ESD {} proof test overdue by {} days", system_id, days_since_test - 365),
                affected_system: system_id.to_string(),
                timestamp: Utc::now(),
                recommendations: vec![
                    "Schedule proof test immediately".to_string(),
                    "Document in maintenance management system".to_string(),
                ],
            });
        }
    }

    // Check communication with field devices
    // Simulate communication check
    let comm_failure_count = system.sensors.iter()
        .filter(|s| s.status == SensorState::Failed)
        .count();

    if comm_failure_count > 0 {
        alerts.push(SafetyAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: SafetyAlertType::CommunicationLoss,
            severity: SafetySeverity::High,
            description: format!("ESD {} has lost communication with {} field devices", system_id, comm_failure_count),
            affected_system: system_id.to_string(),
            timestamp: Utc::now(),
            recommendations: vec![
                "Check field network connections".to_string(),
                "Verify I/O module status".to_string(),
                "Check for power supply issues".to_string(),
            ],
        });
    }

    state.alerts.extend(alerts.clone());

    info!("ESD monitoring complete: {} alerts generated", alerts.len());
    Ok(alerts)
}

/// Detect safety system bypass
pub async fn detect_bypass(system_id: &str) -> Result<Option<SafetyAlert>> {
    info!("Checking for bypass on system: {}", system_id);

    let state = SAFETY_STATE.read().await;

    if let Some(system) = state.systems.get(system_id) {
        if system.bypass_active {
            return Ok(Some(SafetyAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: SafetyAlertType::SafetySystemBypass,
                severity: SafetySeverity::Critical,
                description: format!("Safety system {} has active bypass", system_id),
                affected_system: system_id.to_string(),
                timestamp: Utc::now(),
                recommendations: vec![
                    "Verify bypass authorization".to_string(),
                    "Check bypass duration limit".to_string(),
                    "Ensure compensating measures are in place".to_string(),
                ],
            }));
        }
    }

    Ok(None)
}

/// Detect manual overrides
pub async fn detect_override(system_id: &str) -> Result<Option<SafetyAlert>> {
    info!("Checking for override on system: {}", system_id);

    let state = SAFETY_STATE.read().await;

    if let Some(system) = state.systems.get(system_id) {
        if system.override_active {
            return Ok(Some(SafetyAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: SafetyAlertType::ManualOverride,
                severity: SafetySeverity::High,
                description: format!("Safety system {} has active manual override", system_id),
                affected_system: system_id.to_string(),
                timestamp: Utc::now(),
                recommendations: vec![
                    "Document override reason".to_string(),
                    "Set time limit for override".to_string(),
                    "Monitor process closely during override".to_string(),
                ],
            }));
        }
    }

    Ok(None)
}

/// Validate Safety Integrity Level
pub async fn validate_sil_level(system_id: &str) -> Result<i32> {
    info!("Validating SIL level for system: {}", system_id);

    let state = SAFETY_STATE.read().await;

    if let Some(system) = state.systems.get(system_id) {
        let mut effective_sil = system.sil_level as i32;

        // Degrade SIL for various conditions
        if system.bypass_active {
            effective_sil -= 2; // Major degradation for bypass
            warn!("SIL degraded due to bypass on {}", system_id);
        }

        if system.override_active {
            effective_sil -= 1;
            warn!("SIL degraded due to override on {}", system_id);
        }

        // Check sensor degradation
        let failed_sensors = system.sensors.iter()
            .filter(|s| s.status == SensorState::Failed)
            .count();

        if failed_sensors > 0 {
            effective_sil -= 1;
            warn!("SIL degraded due to {} failed sensors on {}", failed_sensors, system_id);
        }

        // Check actuator degradation
        let failed_actuators = system.actuators.iter()
            .filter(|a| a.status == ActuatorState::Failed)
            .count();

        if failed_actuators > 0 {
            effective_sil -= 1;
            warn!("SIL degraded due to {} failed actuators on {}", failed_actuators, system_id);
        }

        return Ok(effective_sil.max(0));
    }

    // Default SIL if system not found
    Ok(2)
}

/// Monitor physical process parameters for anomalies
pub async fn monitor_process_parameters(sensor_data: &serde_json::Value) -> Result<Vec<SafetyAlert>> {
    info!("Monitoring process parameters");

    let mut alerts = Vec::new();
    let state = SAFETY_STATE.read().await;

    // Extract sensor readings from JSON
    if let Some(readings) = sensor_data.get("readings").and_then(|r| r.as_array()) {
        for reading in readings {
            let parameter = reading.get("parameter")
                .and_then(|p| p.as_str())
                .unwrap_or("unknown");

            let value = reading.get("value")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            let unit = reading.get("unit")
                .and_then(|u| u.as_str())
                .unwrap_or("");

            // Check against baseline if available
            if let Some(baseline) = state.process_baselines.get(parameter) {
                // Check absolute limits
                if value < baseline.min_value || value > baseline.max_value {
                    alerts.push(SafetyAlert {
                        id: uuid::Uuid::new_v4().to_string(),
                        alert_type: SafetyAlertType::ProcessAnomaly,
                        severity: SafetySeverity::Critical,
                        description: format!(
                            "{} at {} {} exceeds safety limits ({} - {} {})",
                            parameter, value, unit, baseline.min_value, baseline.max_value, unit
                        ),
                        affected_system: "process".to_string(),
                        timestamp: Utc::now(),
                        recommendations: vec![
                            format!("Reduce {} immediately", parameter),
                            "Prepare for emergency shutdown".to_string(),
                        ],
                    });
                }
                // Check normal operating range
                else if value < baseline.normal_range_low || value > baseline.normal_range_high {
                    alerts.push(SafetyAlert {
                        id: uuid::Uuid::new_v4().to_string(),
                        alert_type: SafetyAlertType::ProcessAnomaly,
                        severity: SafetySeverity::Medium,
                        description: format!(
                            "{} at {} {} is outside normal range ({} - {} {})",
                            parameter, value, unit, baseline.normal_range_low, baseline.normal_range_high, unit
                        ),
                        affected_system: "process".to_string(),
                        timestamp: Utc::now(),
                        recommendations: vec![
                            format!("Monitor {} closely", parameter),
                            "Investigate root cause".to_string(),
                        ],
                    });
                }
            }
        }
    }

    // Check for alarm flooding
    let recent_alarms = state.alarm_history.iter()
        .filter(|a| a.timestamp > Utc::now() - chrono::Duration::minutes(10))
        .count();

    if recent_alarms > 10 {
        alerts.push(SafetyAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: SafetyAlertType::AlarmFlood,
            severity: SafetySeverity::High,
            description: format!("{} alarms in last 10 minutes - alarm flooding detected", recent_alarms),
            affected_system: "alarm_system".to_string(),
            timestamp: Utc::now(),
            recommendations: vec![
                "Prioritize critical alarms".to_string(),
                "Suppress nuisance alarms".to_string(),
                "Investigate root cause of alarm surge".to_string(),
            ],
        });
    }

    info!("Process parameter monitoring complete: {} alerts generated", alerts.len());
    Ok(alerts)
}

/// Register a safety system for monitoring
pub async fn register_safety_system(system: SafetySystemStatus) {
    let mut state = SAFETY_STATE.write().await;
    info!("Registering safety system: {}", system.system_id);
    state.systems.insert(system.system_id.clone(), system);
}

/// Set process parameter baseline
pub async fn set_process_baseline(
    parameter: &str,
    min_value: f64,
    max_value: f64,
    normal_low: f64,
    normal_high: f64,
) {
    let mut state = SAFETY_STATE.write().await;
    state.process_baselines.insert(parameter.to_string(), ProcessBaseline {
        parameter: parameter.to_string(),
        min_value,
        max_value,
        normal_range_low: normal_low,
        normal_range_high: normal_high,
        rate_of_change_limit: (max_value - min_value) / 60.0, // Per minute
    });
}

/// Get all active alerts
pub async fn get_active_alerts() -> Vec<SafetyAlert> {
    let state = SAFETY_STATE.read().await;
    state.alerts.iter()
        .filter(|a| a.timestamp > Utc::now() - chrono::Duration::hours(24))
        .cloned()
        .collect()
}

/// Get safety system status
pub async fn get_system_status(system_id: &str) -> Option<SafetySystemStatus> {
    let state = SAFETY_STATE.read().await;
    state.systems.get(system_id).cloned()
}
