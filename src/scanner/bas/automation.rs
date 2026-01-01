//! Attack Simulation Automation Module
//!
//! This module provides comprehensive attack simulation automation capabilities:
//! - Attack chain execution (multi-step campaigns simulating real APT TTPs)
//! - Scheduled simulations with cron-like scheduling
//! - Continuous security validation
//! - Campaign templates based on real threat actors
//! - Automated reporting and trend analysis

use super::engine::BasEngine;
use super::types::*;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

// =============================================================================
// Attack Chain Types
// =============================================================================

/// An attack chain represents a sequence of techniques that simulate a real attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: String,
    pub name: String,
    pub description: String,
    pub threat_actor: Option<String>,
    pub campaign_type: CampaignType,
    pub steps: Vec<AttackChainStep>,
    pub success_criteria: SuccessCriteria,
    pub execution_options: ChainExecutionOptions,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A step in an attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainStep {
    pub order: u32,
    pub name: String,
    pub technique_id: String,
    pub description: String,
    pub required: bool,
    pub delay_after_ms: u64,
    pub depends_on: Vec<u32>,
    pub parameters: HashMap<String, String>,
    pub expected_detection: bool,
}

/// Type of attack campaign
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignType {
    InitialAccess,
    Persistence,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    Ransomware,
    Espionage,
    FullKillChain,
    Custom,
}

/// Criteria for determining chain success
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriteria {
    pub min_steps_succeeded: Option<u32>,
    pub required_steps: Vec<u32>,
    pub max_detection_rate: Option<f64>,
    pub timeout_seconds: u64,
}

/// Options for chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainExecutionOptions {
    pub parallel_independent_steps: bool,
    pub stop_on_detection: bool,
    pub stop_on_failure: bool,
    pub cleanup_on_complete: bool,
    pub randomize_delays: bool,
    pub max_retries: u32,
}

impl Default for ChainExecutionOptions {
    fn default() -> Self {
        Self {
            parallel_independent_steps: false,
            stop_on_detection: false,
            stop_on_failure: true,
            cleanup_on_complete: true,
            randomize_delays: true,
            max_retries: 1,
        }
    }
}

/// Result of an attack chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainResult {
    pub id: String,
    pub chain_id: String,
    pub chain_name: String,
    pub status: ChainExecutionStatus,
    pub step_results: Vec<ChainStepResult>,
    pub overall_detection_rate: f64,
    pub success_criteria_met: bool,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: u64,
    pub detection_gaps: Vec<DetectionGap>,
    pub recommendations: Vec<String>,
}

/// Status of chain execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChainExecutionStatus {
    Pending,
    Running,
    Completed,
    PartialSuccess,
    Failed,
    Aborted,
}

/// Result of a single step in the chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStepResult {
    pub step_order: u32,
    pub step_name: String,
    pub technique_id: String,
    pub status: TechniqueExecutionStatus,
    pub detected: bool,
    pub detection_time_ms: Option<u64>,
    pub detection_source: Option<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

// =============================================================================
// Scheduled Simulation Types
// =============================================================================

/// A scheduled simulation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledSimulation {
    pub id: String,
    pub name: String,
    pub description: String,
    pub schedule: SimulationSchedule,
    pub simulation_config: ScheduledSimConfig,
    pub notification_config: NotificationConfig,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub run_count: u64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// Schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationSchedule {
    pub schedule_type: ScheduleType,
    pub cron_expression: Option<String>,
    pub interval_minutes: Option<u32>,
    pub specific_times: Vec<String>,
    pub timezone: String,
    pub active_days: Vec<Weekday>,
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

/// Type of schedule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleType {
    Cron,
    Interval,
    Daily,
    Weekly,
    Monthly,
    OnDemand,
}

/// Days of the week
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Maintenance window when simulations should not run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    pub start_time: String,
    pub end_time: String,
    pub days: Vec<Weekday>,
    pub reason: String,
}

/// Configuration for scheduled simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledSimConfig {
    pub chain_ids: Vec<String>,
    pub technique_ids: Vec<String>,
    pub targets: Vec<String>,
    pub execution_mode: ExecutionMode,
    pub randomize_order: bool,
    pub subset_size: Option<usize>,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub notify_on_complete: bool,
    pub notify_on_failure: bool,
    pub notify_on_detection_gap: bool,
    pub email_recipients: Vec<String>,
    pub slack_channels: Vec<String>,
    pub webhook_urls: Vec<String>,
    pub include_report: bool,
}

// =============================================================================
// Continuous Validation Types
// =============================================================================

/// Continuous validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuousValidation {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub coverage_target: f64,
    pub techniques_per_cycle: usize,
    pub cycle_interval_hours: u32,
    pub priority_tactics: Vec<MitreTactic>,
    pub coverage_tracking: CoverageTracking,
    pub last_cycle_at: Option<DateTime<Utc>>,
    pub total_cycles: u64,
}

/// Coverage tracking for continuous validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTracking {
    pub techniques_tested: HashMap<String, DateTime<Utc>>,
    pub current_coverage: f64,
    pub detection_rates: HashMap<String, f64>,
    pub trend: Vec<CoverageTrendPoint>,
}

/// Point in coverage trend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageTrendPoint {
    pub timestamp: DateTime<Utc>,
    pub coverage: f64,
    pub detection_rate: f64,
    pub techniques_tested: usize,
}

// =============================================================================
// Campaign Templates
// =============================================================================

/// Pre-built campaign template based on real threat actors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub threat_actor: String,
    pub attribution: String,
    pub target_industries: Vec<String>,
    pub chain: AttackChain,
    pub references: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

// =============================================================================
// Attack Simulation Automation Engine
// =============================================================================

/// Main automation engine for attack simulations
pub struct AttackSimulationAutomation {
    engine: Arc<BasEngine>,
    chains: Arc<RwLock<HashMap<String, AttackChain>>>,
    schedules: Arc<RwLock<HashMap<String, ScheduledSimulation>>>,
    continuous_validations: Arc<RwLock<HashMap<String, ContinuousValidation>>>,
    templates: Vec<CampaignTemplate>,
    progress_tx: Option<broadcast::Sender<AutomationProgress>>,
}

/// Progress updates from automation
#[derive(Debug, Clone)]
pub enum AutomationProgress {
    ChainStarted { chain_id: String, chain_name: String },
    ChainStepStarted { chain_id: String, step_order: u32, step_name: String },
    ChainStepCompleted { chain_id: String, step_order: u32, detected: bool },
    ChainCompleted { chain_id: String, result: AttackChainResult },
    ScheduledRunStarted { schedule_id: String },
    ScheduledRunCompleted { schedule_id: String, success: bool },
    ContinuousValidationCycle { validation_id: String, coverage: f64 },
    DetectionGapFound { technique_id: String, description: String },
}

impl AttackSimulationAutomation {
    /// Create a new automation engine
    pub fn new(engine: BasEngine) -> Self {
        Self {
            engine: Arc::new(engine),
            chains: Arc::new(RwLock::new(HashMap::new())),
            schedules: Arc::new(RwLock::new(HashMap::new())),
            continuous_validations: Arc::new(RwLock::new(HashMap::new())),
            templates: Self::load_builtin_templates(),
            progress_tx: None,
        }
    }

    /// Set progress channel
    pub fn with_progress(mut self, tx: broadcast::Sender<AutomationProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Load built-in campaign templates
    fn load_builtin_templates() -> Vec<CampaignTemplate> {
        vec![
            Self::create_apt29_template(),
            Self::create_apt28_template(),
            Self::create_fin7_template(),
            Self::create_ransomware_template(),
            Self::create_insider_threat_template(),
        ]
    }

    /// Create APT29 (Cozy Bear) campaign template
    fn create_apt29_template() -> CampaignTemplate {
        CampaignTemplate {
            id: "apt29-supply-chain".to_string(),
            name: "APT29 Supply Chain Attack".to_string(),
            description: "Simulates APT29's supply chain compromise and post-exploitation TTPs".to_string(),
            threat_actor: "APT29 / Cozy Bear".to_string(),
            attribution: "Russia - SVR".to_string(),
            target_industries: vec!["Government".to_string(), "Technology".to_string(), "Healthcare".to_string()],
            chain: AttackChain {
                id: "apt29-chain".to_string(),
                name: "APT29 Kill Chain".to_string(),
                description: "Full APT29 attack simulation".to_string(),
                threat_actor: Some("APT29".to_string()),
                campaign_type: CampaignType::Espionage,
                steps: vec![
                    AttackChainStep {
                        order: 1,
                        name: "Initial Access via Trusted Relationship".to_string(),
                        technique_id: "T1199".to_string(),
                        description: "Compromise via trusted third party".to_string(),
                        required: true,
                        delay_after_ms: 5000,
                        depends_on: vec![],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 2,
                        name: "Execution via PowerShell".to_string(),
                        technique_id: "T1059.001".to_string(),
                        description: "Execute malicious PowerShell commands".to_string(),
                        required: true,
                        delay_after_ms: 3000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 3,
                        name: "Persistence via Scheduled Task".to_string(),
                        technique_id: "T1053.005".to_string(),
                        description: "Create scheduled task for persistence".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 4,
                        name: "Discovery - System Information".to_string(),
                        technique_id: "T1082".to_string(),
                        description: "Gather system information".to_string(),
                        required: false,
                        delay_after_ms: 1000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 5,
                        name: "Credential Access - LSASS".to_string(),
                        technique_id: "T1003.001".to_string(),
                        description: "Dump LSASS for credentials".to_string(),
                        required: true,
                        delay_after_ms: 5000,
                        depends_on: vec![3],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 6,
                        name: "Lateral Movement - WMI".to_string(),
                        technique_id: "T1047".to_string(),
                        description: "Move laterally using WMI".to_string(),
                        required: false,
                        delay_after_ms: 3000,
                        depends_on: vec![5],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 7,
                        name: "Exfiltration over HTTPS".to_string(),
                        technique_id: "T1041".to_string(),
                        description: "Exfiltrate data over encrypted channel".to_string(),
                        required: true,
                        delay_after_ms: 0,
                        depends_on: vec![4],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                ],
                success_criteria: SuccessCriteria {
                    min_steps_succeeded: Some(5),
                    required_steps: vec![1, 2, 3, 5],
                    max_detection_rate: None,
                    timeout_seconds: 600,
                },
                execution_options: ChainExecutionOptions::default(),
                tags: vec!["apt".to_string(), "nation-state".to_string(), "espionage".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            references: vec![
                "https://attack.mitre.org/groups/G0016/".to_string(),
                "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain.html".to_string(),
            ],
            last_updated: Utc::now(),
        }
    }

    /// Create APT28 (Fancy Bear) campaign template
    fn create_apt28_template() -> CampaignTemplate {
        CampaignTemplate {
            id: "apt28-spearphish".to_string(),
            name: "APT28 Spear Phishing Campaign".to_string(),
            description: "Simulates APT28's spear phishing and credential harvesting TTPs".to_string(),
            threat_actor: "APT28 / Fancy Bear".to_string(),
            attribution: "Russia - GRU".to_string(),
            target_industries: vec!["Government".to_string(), "Defense".to_string(), "Media".to_string()],
            chain: AttackChain {
                id: "apt28-chain".to_string(),
                name: "APT28 Kill Chain".to_string(),
                description: "APT28 spear phishing attack".to_string(),
                threat_actor: Some("APT28".to_string()),
                campaign_type: CampaignType::Espionage,
                steps: vec![
                    AttackChainStep {
                        order: 1,
                        name: "Spear Phishing Attachment".to_string(),
                        technique_id: "T1566.001".to_string(),
                        description: "Deliver malicious document via email".to_string(),
                        required: true,
                        delay_after_ms: 3000,
                        depends_on: vec![],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 2,
                        name: "User Execution - Malicious File".to_string(),
                        technique_id: "T1204.002".to_string(),
                        description: "User opens malicious document".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 3,
                        name: "Credential Harvesting".to_string(),
                        technique_id: "T1056.001".to_string(),
                        description: "Keylogger for credential capture".to_string(),
                        required: true,
                        delay_after_ms: 5000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 4,
                        name: "Data from Local System".to_string(),
                        technique_id: "T1005".to_string(),
                        description: "Collect sensitive files".to_string(),
                        required: false,
                        delay_after_ms: 3000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                ],
                success_criteria: SuccessCriteria {
                    min_steps_succeeded: Some(3),
                    required_steps: vec![1, 2, 3],
                    max_detection_rate: None,
                    timeout_seconds: 300,
                },
                execution_options: ChainExecutionOptions::default(),
                tags: vec!["apt".to_string(), "phishing".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            references: vec![
                "https://attack.mitre.org/groups/G0007/".to_string(),
            ],
            last_updated: Utc::now(),
        }
    }

    /// Create FIN7 campaign template
    fn create_fin7_template() -> CampaignTemplate {
        CampaignTemplate {
            id: "fin7-carbanak".to_string(),
            name: "FIN7 Carbanak Campaign".to_string(),
            description: "Simulates FIN7's financially-motivated attack TTPs".to_string(),
            threat_actor: "FIN7 / Carbanak".to_string(),
            attribution: "Cybercrime Group".to_string(),
            target_industries: vec!["Financial".to_string(), "Retail".to_string(), "Hospitality".to_string()],
            chain: AttackChain {
                id: "fin7-chain".to_string(),
                name: "FIN7 Kill Chain".to_string(),
                description: "FIN7 financial attack".to_string(),
                threat_actor: Some("FIN7".to_string()),
                campaign_type: CampaignType::DataExfiltration,
                steps: vec![
                    AttackChainStep {
                        order: 1,
                        name: "Spear Phishing Link".to_string(),
                        technique_id: "T1566.002".to_string(),
                        description: "Phishing email with malicious link".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 2,
                        name: "JavaScript Execution".to_string(),
                        technique_id: "T1059.007".to_string(),
                        description: "Execute JavaScript payload".to_string(),
                        required: true,
                        delay_after_ms: 3000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 3,
                        name: "Registry Run Keys".to_string(),
                        technique_id: "T1547.001".to_string(),
                        description: "Persistence via registry".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 4,
                        name: "Screen Capture".to_string(),
                        technique_id: "T1113".to_string(),
                        description: "Capture screenshots for recon".to_string(),
                        required: false,
                        delay_after_ms: 5000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 5,
                        name: "Payment Card Data Collection".to_string(),
                        technique_id: "T1005".to_string(),
                        description: "Collect payment card data".to_string(),
                        required: true,
                        delay_after_ms: 0,
                        depends_on: vec![3],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                ],
                success_criteria: SuccessCriteria {
                    min_steps_succeeded: Some(4),
                    required_steps: vec![1, 2, 3, 5],
                    max_detection_rate: None,
                    timeout_seconds: 400,
                },
                execution_options: ChainExecutionOptions::default(),
                tags: vec!["fin".to_string(), "financial".to_string(), "carbanak".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            references: vec![
                "https://attack.mitre.org/groups/G0046/".to_string(),
            ],
            last_updated: Utc::now(),
        }
    }

    /// Create ransomware campaign template
    fn create_ransomware_template() -> CampaignTemplate {
        CampaignTemplate {
            id: "ransomware-generic".to_string(),
            name: "Ransomware Attack Simulation".to_string(),
            description: "Simulates common ransomware attack patterns".to_string(),
            threat_actor: "Generic Ransomware".to_string(),
            attribution: "Various".to_string(),
            target_industries: vec!["Healthcare".to_string(), "Education".to_string(), "Manufacturing".to_string()],
            chain: AttackChain {
                id: "ransomware-chain".to_string(),
                name: "Ransomware Kill Chain".to_string(),
                description: "Ransomware attack simulation".to_string(),
                threat_actor: None,
                campaign_type: CampaignType::Ransomware,
                steps: vec![
                    AttackChainStep {
                        order: 1,
                        name: "Initial Access - RDP".to_string(),
                        technique_id: "T1133".to_string(),
                        description: "Exploit external RDP".to_string(),
                        required: true,
                        delay_after_ms: 3000,
                        depends_on: vec![],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 2,
                        name: "Disable Security Tools".to_string(),
                        technique_id: "T1562.001".to_string(),
                        description: "Disable AV/EDR".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 3,
                        name: "Network Share Discovery".to_string(),
                        technique_id: "T1135".to_string(),
                        description: "Find network shares".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 4,
                        name: "Delete Volume Shadow Copies".to_string(),
                        technique_id: "T1490".to_string(),
                        description: "Delete backups".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![2],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 5,
                        name: "Data Encrypted for Impact".to_string(),
                        technique_id: "T1486".to_string(),
                        description: "Encrypt files (simulated)".to_string(),
                        required: true,
                        delay_after_ms: 0,
                        depends_on: vec![3, 4],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                ],
                success_criteria: SuccessCriteria {
                    min_steps_succeeded: Some(4),
                    required_steps: vec![1, 4, 5],
                    max_detection_rate: Some(0.8),
                    timeout_seconds: 300,
                },
                execution_options: ChainExecutionOptions::default(),
                tags: vec!["ransomware".to_string(), "extortion".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            references: vec![
                "https://attack.mitre.org/techniques/T1486/".to_string(),
            ],
            last_updated: Utc::now(),
        }
    }

    /// Create insider threat template
    fn create_insider_threat_template() -> CampaignTemplate {
        CampaignTemplate {
            id: "insider-threat".to_string(),
            name: "Insider Threat Simulation".to_string(),
            description: "Simulates malicious insider data theft".to_string(),
            threat_actor: "Malicious Insider".to_string(),
            attribution: "Internal".to_string(),
            target_industries: vec!["All".to_string()],
            chain: AttackChain {
                id: "insider-chain".to_string(),
                name: "Insider Threat Kill Chain".to_string(),
                description: "Insider data theft simulation".to_string(),
                threat_actor: None,
                campaign_type: CampaignType::DataExfiltration,
                steps: vec![
                    AttackChainStep {
                        order: 1,
                        name: "Valid Accounts".to_string(),
                        technique_id: "T1078".to_string(),
                        description: "Use legitimate credentials".to_string(),
                        required: true,
                        delay_after_ms: 1000,
                        depends_on: vec![],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 2,
                        name: "Internal Spearphishing".to_string(),
                        technique_id: "T1534".to_string(),
                        description: "Phish colleagues for access".to_string(),
                        required: false,
                        delay_after_ms: 2000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                    AttackChainStep {
                        order: 3,
                        name: "Data from SharePoint".to_string(),
                        technique_id: "T1213.002".to_string(),
                        description: "Access sensitive SharePoint data".to_string(),
                        required: true,
                        delay_after_ms: 3000,
                        depends_on: vec![1],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 4,
                        name: "Archive Collected Data".to_string(),
                        technique_id: "T1560.001".to_string(),
                        description: "Compress data for exfil".to_string(),
                        required: true,
                        delay_after_ms: 2000,
                        depends_on: vec![3],
                        parameters: HashMap::new(),
                        expected_detection: false,
                    },
                    AttackChainStep {
                        order: 5,
                        name: "Exfil to Cloud Storage".to_string(),
                        technique_id: "T1567.002".to_string(),
                        description: "Upload to personal cloud".to_string(),
                        required: true,
                        delay_after_ms: 0,
                        depends_on: vec![4],
                        parameters: HashMap::new(),
                        expected_detection: true,
                    },
                ],
                success_criteria: SuccessCriteria {
                    min_steps_succeeded: Some(4),
                    required_steps: vec![1, 3, 4, 5],
                    max_detection_rate: None,
                    timeout_seconds: 300,
                },
                execution_options: ChainExecutionOptions::default(),
                tags: vec!["insider".to_string(), "data-theft".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            references: vec![
                "https://attack.mitre.org/matrices/enterprise/".to_string(),
            ],
            last_updated: Utc::now(),
        }
    }

    /// Get all available templates
    pub fn get_templates(&self) -> &[CampaignTemplate] {
        &self.templates
    }

    /// Get template by ID
    pub fn get_template(&self, id: &str) -> Option<&CampaignTemplate> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// Create a chain from a template
    pub fn create_chain_from_template(&self, template_id: &str) -> Option<AttackChain> {
        self.get_template(template_id).map(|t| {
            let mut chain = t.chain.clone();
            chain.id = Uuid::new_v4().to_string();
            chain.created_at = Utc::now();
            chain.updated_at = Utc::now();
            chain
        })
    }

    /// Register a new attack chain
    pub async fn register_chain(&self, chain: AttackChain) -> Result<String> {
        let id = chain.id.clone();
        let mut chains = self.chains.write().await;
        chains.insert(id.clone(), chain);
        Ok(id)
    }

    /// Get a registered chain
    pub async fn get_chain(&self, id: &str) -> Option<AttackChain> {
        let chains = self.chains.read().await;
        chains.get(id).cloned()
    }

    /// Execute an attack chain
    pub async fn execute_chain(
        &self,
        chain_id: &str,
        targets: Vec<String>,
        execution_mode: ExecutionMode,
    ) -> Result<AttackChainResult> {
        let chain = self.get_chain(chain_id).await
            .ok_or_else(|| anyhow!("Chain not found: {}", chain_id))?;

        self.execute_chain_internal(chain, targets, execution_mode).await
    }

    /// Execute a chain directly
    async fn execute_chain_internal(
        &self,
        chain: AttackChain,
        targets: Vec<String>,
        execution_mode: ExecutionMode,
    ) -> Result<AttackChainResult> {
        let result_id = Uuid::new_v4().to_string();
        let start_time = Utc::now();
        let start_instant = std::time::Instant::now();

        // Notify chain started
        if let Some(tx) = &self.progress_tx {
            let _ = tx.send(AutomationProgress::ChainStarted {
                chain_id: chain.id.clone(),
                chain_name: chain.name.clone(),
            });
        }

        let mut step_results = Vec::new();
        let mut completed_steps: HashMap<u32, bool> = HashMap::new();
        let mut total_detected = 0;
        let mut total_executed = 0;

        // Execute steps in dependency order
        for step in &chain.steps {
            // Check dependencies
            let deps_satisfied = step.depends_on.iter().all(|dep| {
                completed_steps.get(dep).copied().unwrap_or(false)
            });

            if !deps_satisfied {
                continue;
            }

            // Notify step started
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(AutomationProgress::ChainStepStarted {
                    chain_id: chain.id.clone(),
                    step_order: step.order,
                    step_name: step.name.clone(),
                });
            }

            let step_start = Utc::now();
            let step_instant = std::time::Instant::now();

            // Build scenario for this step
            let scenario = SimulationScenario {
                id: format!("{}-step-{}", result_id, step.order),
                name: step.name.clone(),
                description: step.description.clone(),
                user_id: "automation".to_string(),
                technique_ids: vec![step.technique_id.clone()],
                targets: targets.clone(),
                execution_mode,
                timeout_secs: 60,
                parallel_execution: false,
                continue_on_failure: true,
                tags: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                status: ScenarioStatus::Ready,
                payload_configs: HashMap::new(),
            };

            // Execute the technique
            let sim_result = self.engine.run_simulation(scenario, None).await?;

            let step_duration = step_instant.elapsed().as_millis() as u64;
            let step_end = Utc::now();

            let step_status = if let Some(exec) = sim_result.executions.first() {
                exec.status
            } else {
                TechniqueExecutionStatus::Failed
            };

            let detected = sim_result.executions.first()
                .map(|e| e.detection_observed)
                .unwrap_or(false);

            if detected {
                total_detected += 1;
            }
            total_executed += 1;

            let step_result = ChainStepResult {
                step_order: step.order,
                step_name: step.name.clone(),
                technique_id: step.technique_id.clone(),
                status: step_status,
                detected,
                detection_time_ms: if detected { Some(step_duration / 2) } else { None },
                detection_source: if detected { Some("EDR/SIEM".to_string()) } else { None },
                output: sim_result.executions.first().and_then(|e| e.output.clone()),
                error: sim_result.executions.first().and_then(|e| e.error.clone()),
                duration_ms: step_duration,
                started_at: step_start,
                completed_at: step_end,
            };

            let step_succeeded = step_status == TechniqueExecutionStatus::Success
                || step_status == TechniqueExecutionStatus::Detected;
            completed_steps.insert(step.order, step_succeeded);
            step_results.push(step_result);

            // Notify step completed
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(AutomationProgress::ChainStepCompleted {
                    chain_id: chain.id.clone(),
                    step_order: step.order,
                    detected,
                });
            }

            // Check stop conditions
            if chain.execution_options.stop_on_detection && detected {
                break;
            }

            if chain.execution_options.stop_on_failure && !step_succeeded && step.required {
                break;
            }

            // Add delay between steps
            if step.delay_after_ms > 0 {
                let delay = if chain.execution_options.randomize_delays {
                    let variance = step.delay_after_ms / 4;
                    step.delay_after_ms - variance + (rand::random::<u64>() % (variance * 2))
                } else {
                    step.delay_after_ms
                };
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
            }
        }

        // Calculate overall detection rate
        let detection_rate = if total_executed > 0 {
            total_detected as f64 / total_executed as f64
        } else {
            0.0
        };

        // Check success criteria
        let steps_succeeded = step_results.iter()
            .filter(|s| s.status == TechniqueExecutionStatus::Success || s.status == TechniqueExecutionStatus::Detected)
            .count() as u32;

        let success_criteria_met = chain.success_criteria.min_steps_succeeded
            .map(|min| steps_succeeded >= min)
            .unwrap_or(true)
            && chain.success_criteria.required_steps.iter().all(|req| {
                step_results.iter().any(|s| {
                    s.step_order == *req &&
                    (s.status == TechniqueExecutionStatus::Success || s.status == TechniqueExecutionStatus::Detected)
                })
            });

        let duration_ms = start_instant.elapsed().as_millis() as u64;

        // Identify detection gaps
        let detection_gaps: Vec<DetectionGap> = step_results.iter()
            .filter(|s| !s.detected && s.status == TechniqueExecutionStatus::Success)
            .map(|s| DetectionGap {
                id: Uuid::new_v4().to_string(),
                simulation_id: result_id.clone(),
                technique_id: s.technique_id.clone(),
                technique_name: s.step_name.clone(),
                tactics: vec![],
                expected_sources: vec!["EDR".to_string(), "SIEM".to_string()],
                reason: "Technique executed successfully without detection".to_string(),
                severity: 3, // Medium severity as u8
                recommendations: vec![
                    format!("Implement detection for {} ({})", s.step_name, s.technique_id),
                ],
                acknowledged: false,
                acknowledgement_notes: None,
                detected_at: Utc::now(),
            })
            .collect();

        // Generate recommendations
        let recommendations = self.generate_recommendations(&detection_gaps, detection_rate);

        let status = if success_criteria_met {
            ChainExecutionStatus::Completed
        } else if steps_succeeded > 0 {
            ChainExecutionStatus::PartialSuccess
        } else {
            ChainExecutionStatus::Failed
        };

        let result = AttackChainResult {
            id: result_id,
            chain_id: chain.id.clone(),
            chain_name: chain.name.clone(),
            status,
            step_results,
            overall_detection_rate: detection_rate,
            success_criteria_met,
            started_at: start_time,
            completed_at: Some(Utc::now()),
            duration_ms,
            detection_gaps: detection_gaps.clone(),
            recommendations,
        };

        // Notify chain completed
        if let Some(tx) = &self.progress_tx {
            let _ = tx.send(AutomationProgress::ChainCompleted {
                chain_id: chain.id.clone(),
                result: result.clone(),
            });

            // Notify detection gaps
            for gap in &detection_gaps {
                let _ = tx.send(AutomationProgress::DetectionGapFound {
                    technique_id: gap.technique_id.clone(),
                    description: format!("No detection for {} in chain {}", gap.technique_name, chain.name),
                });
            }
        }

        Ok(result)
    }

    /// Generate recommendations based on gaps
    fn generate_recommendations(&self, gaps: &[DetectionGap], detection_rate: f64) -> Vec<String> {
        let mut recommendations = Vec::new();

        if detection_rate < 0.5 {
            recommendations.push("Critical: Detection coverage is below 50%. Immediate security improvements required.".to_string());
        } else if detection_rate < 0.8 {
            recommendations.push("Warning: Detection coverage is below 80%. Consider implementing additional detection rules.".to_string());
        }

        for gap in gaps {
            recommendations.push(format!(
                "Implement detection for {} ({}) - see MITRE ATT&CK for detection guidance",
                gap.technique_name, gap.technique_id
            ));
        }

        if recommendations.is_empty() {
            recommendations.push("Excellent detection coverage! Continue monitoring for new techniques.".to_string());
        }

        recommendations
    }

    /// Register a scheduled simulation
    pub async fn register_schedule(&self, schedule: ScheduledSimulation) -> Result<String> {
        let id = schedule.id.clone();
        let mut schedules = self.schedules.write().await;
        schedules.insert(id.clone(), schedule);
        Ok(id)
    }

    /// Get all scheduled simulations
    pub async fn get_schedules(&self) -> Vec<ScheduledSimulation> {
        let schedules = self.schedules.read().await;
        schedules.values().cloned().collect()
    }

    /// Check and run due scheduled simulations
    pub async fn check_and_run_schedules(&self) -> Result<Vec<AttackChainResult>> {
        let now = Utc::now();
        let mut results = Vec::new();

        let schedules: Vec<ScheduledSimulation> = {
            let sched = self.schedules.read().await;
            sched.values().filter(|s| s.enabled).cloned().collect()
        };

        for schedule in schedules {
            if let Some(next_run) = &schedule.next_run_at {
                if *next_run <= now {
                    // Notify start
                    if let Some(tx) = &self.progress_tx {
                        let _ = tx.send(AutomationProgress::ScheduledRunStarted {
                            schedule_id: schedule.id.clone(),
                        });
                    }

                    // Run the scheduled chains
                    for chain_id in &schedule.simulation_config.chain_ids {
                        if let Ok(result) = self.execute_chain(
                            chain_id,
                            schedule.simulation_config.targets.clone(),
                            schedule.simulation_config.execution_mode,
                        ).await {
                            results.push(result);
                        }
                    }

                    // Update last run and calculate next run
                    let mut schedules = self.schedules.write().await;
                    if let Some(sched) = schedules.get_mut(&schedule.id) {
                        sched.last_run_at = Some(now);
                        sched.run_count += 1;
                        sched.next_run_at = self.calculate_next_run(&sched.schedule);
                    }

                    // Notify completion
                    if let Some(tx) = &self.progress_tx {
                        let _ = tx.send(AutomationProgress::ScheduledRunCompleted {
                            schedule_id: schedule.id.clone(),
                            success: true,
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    /// Calculate next run time based on schedule
    fn calculate_next_run(&self, schedule: &SimulationSchedule) -> Option<DateTime<Utc>> {
        let now = Utc::now();

        match schedule.schedule_type {
            ScheduleType::Interval => {
                schedule.interval_minutes.map(|mins| {
                    now + ChronoDuration::minutes(mins as i64)
                })
            }
            ScheduleType::Daily => {
                Some(now + ChronoDuration::days(1))
            }
            ScheduleType::Weekly => {
                Some(now + ChronoDuration::weeks(1))
            }
            ScheduleType::Monthly => {
                Some(now + ChronoDuration::days(30))
            }
            ScheduleType::OnDemand => None,
            ScheduleType::Cron => {
                // Simplified cron parsing - in production, use a cron parsing library
                schedule.interval_minutes.map(|mins| {
                    now + ChronoDuration::minutes(mins as i64)
                })
            }
        }
    }

    /// Register continuous validation
    pub async fn register_continuous_validation(&self, validation: ContinuousValidation) -> Result<String> {
        let id = validation.id.clone();
        let mut validations = self.continuous_validations.write().await;
        validations.insert(id.clone(), validation);
        Ok(id)
    }

    /// Run a continuous validation cycle
    pub async fn run_continuous_validation_cycle(&self, validation_id: &str) -> Result<CoverageTrendPoint> {
        let validation = {
            let validations = self.continuous_validations.read().await;
            validations.get(validation_id).cloned()
                .ok_or_else(|| anyhow!("Validation not found: {}", validation_id))?
        };

        // Get techniques to test this cycle (prioritize untested or stale)
        let library = self.engine.library();
        let all_techniques: Vec<_> = library.all_techniques();

        let mut techniques_to_test: Vec<String> = all_techniques.iter()
            .filter(|t| {
                // Filter by priority tactics if specified
                if !validation.priority_tactics.is_empty() {
                    t.tactics.iter().any(|tac| validation.priority_tactics.contains(tac))
                } else {
                    true
                }
            })
            .map(|t| t.technique_id.clone())
            .collect();

        // Sort by last tested (oldest first)
        techniques_to_test.sort_by(|a, b| {
            let a_time = validation.coverage_tracking.techniques_tested.get(a);
            let b_time = validation.coverage_tracking.techniques_tested.get(b);
            match (a_time, b_time) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(a_t), Some(b_t)) => a_t.cmp(b_t),
            }
        });

        // Take subset
        let techniques_to_test: Vec<String> = techniques_to_test
            .into_iter()
            .take(validation.techniques_per_cycle)
            .collect();

        // Run simulation
        let scenario = SimulationScenario {
            id: format!("continuous-{}-{}", validation_id, Utc::now().timestamp()),
            name: format!("Continuous Validation Cycle - {}", validation.name),
            description: "Automated continuous validation".to_string(),
            user_id: "system".to_string(),
            technique_ids: techniques_to_test.clone(),
            targets: vec!["localhost".to_string()],
            execution_mode: ExecutionMode::Simulation,
            timeout_secs: 300,
            parallel_execution: true,
            continue_on_failure: true,
            tags: vec!["continuous".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: ScenarioStatus::Ready,
            payload_configs: HashMap::new(),
        };

        let result = self.engine.run_simulation(scenario, None).await?;

        // Update tracking
        let now = Utc::now();
        let mut validations = self.continuous_validations.write().await;
        if let Some(val) = validations.get_mut(validation_id) {
            val.last_cycle_at = Some(now);
            val.total_cycles += 1;

            // Update techniques tested
            for tid in &techniques_to_test {
                val.coverage_tracking.techniques_tested.insert(tid.clone(), now);
            }

            // Update detection rates
            for exec in &result.executions {
                let rate = if exec.detection_observed { 1.0 } else { 0.0 };
                let entry = val.coverage_tracking.detection_rates
                    .entry(exec.technique_id.clone())
                    .or_insert(0.0);
                *entry = (*entry + rate) / 2.0; // Running average
            }

            // Calculate current coverage
            let total_techniques = all_techniques.len();
            let tested_techniques = val.coverage_tracking.techniques_tested.len();
            val.coverage_tracking.current_coverage = tested_techniques as f64 / total_techniques as f64;

            // Add trend point
            let trend_point = CoverageTrendPoint {
                timestamp: now,
                coverage: val.coverage_tracking.current_coverage,
                detection_rate: result.summary.detection_rate,
                techniques_tested: techniques_to_test.len(),
            };
            val.coverage_tracking.trend.push(trend_point.clone());

            // Notify
            if let Some(tx) = &self.progress_tx {
                let _ = tx.send(AutomationProgress::ContinuousValidationCycle {
                    validation_id: validation_id.to_string(),
                    coverage: val.coverage_tracking.current_coverage,
                });
            }

            return Ok(trend_point);
        }

        Err(anyhow!("Failed to update validation"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_execution_options_default() {
        let options = ChainExecutionOptions::default();
        assert!(!options.parallel_independent_steps);
        assert!(options.stop_on_failure);
        assert!(options.cleanup_on_complete);
    }

    #[test]
    fn test_automation_engine_creation() {
        let engine = BasEngine::default();
        let automation = AttackSimulationAutomation::new(engine);
        assert!(!automation.templates.is_empty());
    }

    #[test]
    fn test_get_templates() {
        let engine = BasEngine::default();
        let automation = AttackSimulationAutomation::new(engine);
        let templates = automation.get_templates();
        assert!(templates.len() >= 5);
    }

    #[test]
    fn test_create_chain_from_template() {
        let engine = BasEngine::default();
        let automation = AttackSimulationAutomation::new(engine);
        let chain = automation.create_chain_from_template("apt29-supply-chain");
        assert!(chain.is_some());
        let chain = chain.unwrap();
        assert!(!chain.steps.is_empty());
    }

    #[tokio::test]
    async fn test_register_chain() {
        let engine = BasEngine::default();
        let automation = AttackSimulationAutomation::new(engine);

        let chain = automation.create_chain_from_template("apt29-supply-chain").unwrap();
        let chain_id = chain.id.clone();

        let result = automation.register_chain(chain).await;
        assert!(result.is_ok());

        let retrieved = automation.get_chain(&chain_id).await;
        assert!(retrieved.is_some());
    }
}
