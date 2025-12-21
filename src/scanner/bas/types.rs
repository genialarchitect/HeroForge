#![allow(dead_code)]
//! Breach & Attack Simulation (BAS) Types
//!
//! Core types for the BAS engine including attack techniques, scenarios,
//! simulation results, and detection validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

// ============================================================================
// Execution Modes
// ============================================================================

/// Execution mode for simulation techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Dry run - only analyze, no execution
    DryRun,
    /// Simulation - execute safe payloads only
    Simulation,
    /// Controlled execution - execute with safety guardrails
    ControlledExec,
}

impl ExecutionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionMode::DryRun => "dry_run",
            ExecutionMode::Simulation => "simulation",
            ExecutionMode::ControlledExec => "controlled_exec",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dry_run" | "dryrun" => Some(ExecutionMode::DryRun),
            "simulation" | "sim" => Some(ExecutionMode::Simulation),
            "controlled_exec" | "controlled" => Some(ExecutionMode::ControlledExec),
            _ => None,
        }
    }
}

impl Default for ExecutionMode {
    fn default() -> Self {
        ExecutionMode::DryRun
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Payload Types
// ============================================================================

/// Types of safe payloads for BAS testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    /// File marker - creates identifiable marker files
    FileMarker,
    /// DNS beacon - performs DNS lookups for tracking
    DnsBeacon,
    /// HTTP beacon - sends HTTP requests for tracking
    HttpBeacon,
    /// Process marker - creates identifiable process activity
    ProcessMarker,
    /// Registry marker - creates registry entries (Windows)
    RegistryMarker,
    /// Network beacon - creates network traffic patterns
    NetworkBeacon,
    /// Memory marker - creates memory patterns
    MemoryMarker,
    /// Log injection - injects traceable log entries
    LogInjection,
}

impl PayloadType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadType::FileMarker => "file_marker",
            PayloadType::DnsBeacon => "dns_beacon",
            PayloadType::HttpBeacon => "http_beacon",
            PayloadType::ProcessMarker => "process_marker",
            PayloadType::RegistryMarker => "registry_marker",
            PayloadType::NetworkBeacon => "network_beacon",
            PayloadType::MemoryMarker => "memory_marker",
            PayloadType::LogInjection => "log_injection",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "file_marker" | "file" => Some(PayloadType::FileMarker),
            "dns_beacon" | "dns" => Some(PayloadType::DnsBeacon),
            "http_beacon" | "http" => Some(PayloadType::HttpBeacon),
            "process_marker" | "process" => Some(PayloadType::ProcessMarker),
            "registry_marker" | "registry" => Some(PayloadType::RegistryMarker),
            "network_beacon" | "network" => Some(PayloadType::NetworkBeacon),
            "memory_marker" | "memory" => Some(PayloadType::MemoryMarker),
            "log_injection" | "log" => Some(PayloadType::LogInjection),
            _ => None,
        }
    }
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// MITRE ATT&CK Tactics
// ============================================================================

/// MITRE ATT&CK Tactics (Enterprise)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MitreTactic {
    /// TA0043 - Reconnaissance
    Reconnaissance,
    /// TA0042 - Resource Development
    ResourceDevelopment,
    /// TA0001 - Initial Access
    InitialAccess,
    /// TA0002 - Execution
    Execution,
    /// TA0003 - Persistence
    Persistence,
    /// TA0004 - Privilege Escalation
    PrivilegeEscalation,
    /// TA0005 - Defense Evasion
    DefenseEvasion,
    /// TA0006 - Credential Access
    CredentialAccess,
    /// TA0007 - Discovery
    Discovery,
    /// TA0008 - Lateral Movement
    LateralMovement,
    /// TA0009 - Collection
    Collection,
    /// TA0011 - Command and Control
    CommandAndControl,
    /// TA0010 - Exfiltration
    Exfiltration,
    /// TA0040 - Impact
    Impact,
}

impl MitreTactic {
    pub fn id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "Reconnaissance",
            MitreTactic::ResourceDevelopment => "Resource Development",
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "Gathering information to plan future adversary operations",
            MitreTactic::ResourceDevelopment => "Establishing resources to support operations",
            MitreTactic::InitialAccess => "Trying to get into your network",
            MitreTactic::Execution => "Trying to run malicious code",
            MitreTactic::Persistence => "Trying to maintain their foothold",
            MitreTactic::PrivilegeEscalation => "Trying to gain higher-level permissions",
            MitreTactic::DefenseEvasion => "Trying to avoid being detected",
            MitreTactic::CredentialAccess => "Trying to steal account names and passwords",
            MitreTactic::Discovery => "Trying to figure out your environment",
            MitreTactic::LateralMovement => "Trying to move through your environment",
            MitreTactic::Collection => "Trying to gather data of interest",
            MitreTactic::CommandAndControl => "Trying to communicate with compromised systems",
            MitreTactic::Exfiltration => "Trying to steal data",
            MitreTactic::Impact => "Trying to manipulate, interrupt, or destroy systems and data",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_uppercase().as_str() {
            "TA0043" => Some(MitreTactic::Reconnaissance),
            "TA0042" => Some(MitreTactic::ResourceDevelopment),
            "TA0001" => Some(MitreTactic::InitialAccess),
            "TA0002" => Some(MitreTactic::Execution),
            "TA0003" => Some(MitreTactic::Persistence),
            "TA0004" => Some(MitreTactic::PrivilegeEscalation),
            "TA0005" => Some(MitreTactic::DefenseEvasion),
            "TA0006" => Some(MitreTactic::CredentialAccess),
            "TA0007" => Some(MitreTactic::Discovery),
            "TA0008" => Some(MitreTactic::LateralMovement),
            "TA0009" => Some(MitreTactic::Collection),
            "TA0011" => Some(MitreTactic::CommandAndControl),
            "TA0010" => Some(MitreTactic::Exfiltration),
            "TA0040" => Some(MitreTactic::Impact),
            _ => None,
        }
    }

    /// Get all tactics in kill chain order
    pub fn all() -> Vec<Self> {
        vec![
            MitreTactic::Reconnaissance,
            MitreTactic::ResourceDevelopment,
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
            MitreTactic::Exfiltration,
            MitreTactic::Impact,
        ]
    }
}

impl std::fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {}", self.id(), self.name())
    }
}

// ============================================================================
// Attack Technique
// ============================================================================

/// A MITRE ATT&CK technique that can be simulated
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttackTechnique {
    /// MITRE ATT&CK technique ID (e.g., T1059.001)
    pub technique_id: String,
    /// Technique name
    pub name: String,
    /// Description of the technique
    pub description: String,
    /// Associated tactics
    pub tactics: Vec<MitreTactic>,
    /// Platforms this technique applies to
    pub platforms: Vec<String>,
    /// Payload types that can simulate this technique
    pub payload_types: Vec<PayloadType>,
    /// Detection data sources
    pub detection_sources: Vec<String>,
    /// Minimum required execution mode
    pub min_execution_mode: ExecutionMode,
    /// Whether this technique is safe to simulate
    pub is_safe: bool,
    /// Risk level (1-10)
    pub risk_level: u8,
    /// Optional sub-technique parent ID
    pub parent_technique_id: Option<String>,
    /// External references
    pub references: Vec<String>,
}

impl AttackTechnique {
    pub fn new(
        technique_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        tactics: Vec<MitreTactic>,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            name: name.into(),
            description: description.into(),
            tactics,
            platforms: vec!["linux".to_string(), "windows".to_string(), "macos".to_string()],
            payload_types: Vec::new(),
            detection_sources: Vec::new(),
            min_execution_mode: ExecutionMode::Simulation,
            is_safe: true,
            risk_level: 3,
            parent_technique_id: None,
            references: Vec::new(),
        }
    }

    pub fn with_platforms(mut self, platforms: Vec<String>) -> Self {
        self.platforms = platforms;
        self
    }

    pub fn with_payload_types(mut self, payload_types: Vec<PayloadType>) -> Self {
        self.payload_types = payload_types;
        self
    }

    pub fn with_detection_sources(mut self, sources: Vec<String>) -> Self {
        self.detection_sources = sources;
        self
    }

    pub fn with_risk_level(mut self, level: u8) -> Self {
        self.risk_level = level.min(10);
        self
    }

    pub fn with_min_mode(mut self, mode: ExecutionMode) -> Self {
        self.min_execution_mode = mode;
        self
    }

    pub fn as_unsafe(mut self) -> Self {
        self.is_safe = false;
        self
    }
}

// ============================================================================
// Safe Payload
// ============================================================================

/// A safe payload for BAS testing
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SafePayload {
    /// Unique payload identifier
    pub id: String,
    /// Payload name
    pub name: String,
    /// Payload type
    pub payload_type: PayloadType,
    /// Description of what this payload does
    pub description: String,
    /// MITRE technique IDs this payload simulates
    pub technique_ids: Vec<String>,
    /// Payload configuration/parameters
    pub config: HashMap<String, serde_json::Value>,
    /// Whether this payload requires elevated privileges
    pub requires_elevation: bool,
    /// Cleanup instructions
    pub cleanup_steps: Vec<String>,
    /// Expected detection indicators
    pub expected_indicators: Vec<String>,
}

impl SafePayload {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        payload_type: PayloadType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            payload_type,
            description: description.into(),
            technique_ids: Vec::new(),
            config: HashMap::new(),
            requires_elevation: false,
            cleanup_steps: Vec::new(),
            expected_indicators: Vec::new(),
        }
    }

    pub fn with_techniques(mut self, ids: Vec<String>) -> Self {
        self.technique_ids = ids;
        self
    }

    pub fn with_config(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.config.insert(key.into(), value);
        self
    }

    pub fn requires_elevation(mut self) -> Self {
        self.requires_elevation = true;
        self
    }

    pub fn with_cleanup(mut self, steps: Vec<String>) -> Self {
        self.cleanup_steps = steps;
        self
    }

    pub fn with_indicators(mut self, indicators: Vec<String>) -> Self {
        self.expected_indicators = indicators;
        self
    }
}

// ============================================================================
// Simulation Scenario
// ============================================================================

/// Status of a simulation scenario
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Draft,
    Ready,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScenarioStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScenarioStatus::Draft => "draft",
            ScenarioStatus::Ready => "ready",
            ScenarioStatus::Running => "running",
            ScenarioStatus::Completed => "completed",
            ScenarioStatus::Failed => "failed",
            ScenarioStatus::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "draft" => Some(ScenarioStatus::Draft),
            "ready" => Some(ScenarioStatus::Ready),
            "running" => Some(ScenarioStatus::Running),
            "completed" => Some(ScenarioStatus::Completed),
            "failed" => Some(ScenarioStatus::Failed),
            "cancelled" => Some(ScenarioStatus::Cancelled),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScenarioStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A simulation scenario containing multiple techniques
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationScenario {
    /// Unique scenario identifier
    pub id: String,
    /// Scenario name
    pub name: String,
    /// Description
    pub description: String,
    /// Owner user ID
    pub user_id: String,
    /// Status
    pub status: ScenarioStatus,
    /// Execution mode
    pub execution_mode: ExecutionMode,
    /// Technique IDs to execute
    pub technique_ids: Vec<String>,
    /// Target hosts/networks
    pub targets: Vec<String>,
    /// Custom payload configurations
    pub payload_configs: HashMap<String, serde_json::Value>,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Whether to run techniques in parallel
    pub parallel_execution: bool,
    /// Whether to continue on technique failure
    pub continue_on_failure: bool,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl SimulationScenario {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            user_id: user_id.into(),
            status: ScenarioStatus::Draft,
            execution_mode: ExecutionMode::DryRun,
            technique_ids: Vec::new(),
            targets: Vec::new(),
            payload_configs: HashMap::new(),
            timeout_secs: 300,
            parallel_execution: false,
            continue_on_failure: true,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

// ============================================================================
// Technique Execution
// ============================================================================

/// Result status of a technique execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueExecutionStatus {
    Pending,
    Running,
    Success,
    Blocked,
    Detected,
    Failed,
    Skipped,
    TimedOut,
}

impl TechniqueExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TechniqueExecutionStatus::Pending => "pending",
            TechniqueExecutionStatus::Running => "running",
            TechniqueExecutionStatus::Success => "success",
            TechniqueExecutionStatus::Blocked => "blocked",
            TechniqueExecutionStatus::Detected => "detected",
            TechniqueExecutionStatus::Failed => "failed",
            TechniqueExecutionStatus::Skipped => "skipped",
            TechniqueExecutionStatus::TimedOut => "timed_out",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(TechniqueExecutionStatus::Pending),
            "running" => Some(TechniqueExecutionStatus::Running),
            "success" => Some(TechniqueExecutionStatus::Success),
            "blocked" => Some(TechniqueExecutionStatus::Blocked),
            "detected" => Some(TechniqueExecutionStatus::Detected),
            "failed" => Some(TechniqueExecutionStatus::Failed),
            "skipped" => Some(TechniqueExecutionStatus::Skipped),
            "timed_out" | "timedout" => Some(TechniqueExecutionStatus::TimedOut),
            _ => None,
        }
    }
}

impl std::fmt::Display for TechniqueExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Execution record for a single technique
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TechniqueExecution {
    /// Execution ID
    pub id: String,
    /// Simulation ID this belongs to
    pub simulation_id: String,
    /// Technique ID
    pub technique_id: String,
    /// Target host
    pub target: Option<String>,
    /// Payload type used
    pub payload_type: Option<PayloadType>,
    /// Execution status
    pub status: TechniqueExecutionStatus,
    /// Start time
    pub started_at: Option<DateTime<Utc>>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
    /// Output/logs from execution
    pub output: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether detection was observed
    pub detection_observed: bool,
    /// Detection details
    pub detection_details: Option<String>,
    /// Cleanup status
    pub cleanup_completed: bool,
}

impl TechniqueExecution {
    pub fn new(
        id: impl Into<String>,
        simulation_id: impl Into<String>,
        technique_id: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            simulation_id: simulation_id.into(),
            technique_id: technique_id.into(),
            target: None,
            payload_type: None,
            status: TechniqueExecutionStatus::Pending,
            started_at: None,
            completed_at: None,
            duration_ms: None,
            output: None,
            error: None,
            detection_observed: false,
            detection_details: None,
            cleanup_completed: false,
        }
    }

    pub fn mark_started(&mut self) {
        self.status = TechniqueExecutionStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn mark_completed(&mut self, status: TechniqueExecutionStatus) {
        let now = Utc::now();
        self.status = status;
        self.completed_at = Some(now);
        if let Some(started) = self.started_at {
            self.duration_ms = Some((now - started).num_milliseconds() as u64);
        }
    }
}

// ============================================================================
// Simulation Result
// ============================================================================

/// Overall status of a simulation run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SimulationStatus {
    Pending,
    Running,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

impl SimulationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SimulationStatus::Pending => "pending",
            SimulationStatus::Running => "running",
            SimulationStatus::Completed => "completed",
            SimulationStatus::PartiallyCompleted => "partially_completed",
            SimulationStatus::Failed => "failed",
            SimulationStatus::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(SimulationStatus::Pending),
            "running" => Some(SimulationStatus::Running),
            "completed" => Some(SimulationStatus::Completed),
            "partially_completed" => Some(SimulationStatus::PartiallyCompleted),
            "failed" => Some(SimulationStatus::Failed),
            "cancelled" => Some(SimulationStatus::Cancelled),
            _ => None,
        }
    }
}

impl std::fmt::Display for SimulationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Complete simulation result
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SimulationResult {
    /// Simulation run ID
    pub id: String,
    /// Scenario ID
    pub scenario_id: String,
    /// User ID who ran the simulation
    pub user_id: String,
    /// Execution mode used
    pub execution_mode: ExecutionMode,
    /// Overall status
    pub status: SimulationStatus,
    /// Technique executions
    pub executions: Vec<TechniqueExecution>,
    /// Summary statistics
    pub summary: SimulationSummary,
    /// Detection gaps identified
    pub detection_gaps: Vec<DetectionGap>,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Completion time
    pub completed_at: Option<DateTime<Utc>>,
    /// Total duration in milliseconds
    pub duration_ms: Option<u64>,
    /// Error message if overall simulation failed
    pub error: Option<String>,
}

impl SimulationResult {
    pub fn new(
        id: impl Into<String>,
        scenario_id: impl Into<String>,
        user_id: impl Into<String>,
        execution_mode: ExecutionMode,
    ) -> Self {
        Self {
            id: id.into(),
            scenario_id: scenario_id.into(),
            user_id: user_id.into(),
            execution_mode,
            status: SimulationStatus::Pending,
            executions: Vec::new(),
            summary: SimulationSummary::default(),
            detection_gaps: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            duration_ms: None,
            error: None,
        }
    }
}

/// Summary statistics for a simulation
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SimulationSummary {
    /// Total techniques attempted
    pub total_techniques: usize,
    /// Techniques that succeeded (executed without detection)
    pub succeeded: usize,
    /// Techniques that were blocked by controls
    pub blocked: usize,
    /// Techniques that were detected
    pub detected: usize,
    /// Techniques that failed to execute
    pub failed: usize,
    /// Techniques that were skipped
    pub skipped: usize,
    /// Techniques that timed out
    pub timed_out: usize,
    /// Detection rate (detected / total)
    pub detection_rate: f64,
    /// Block rate (blocked / total)
    pub block_rate: f64,
    /// Success rate (succeeded / total) - lower is better for security
    pub success_rate: f64,
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Tactics covered
    pub tactics_covered: Vec<MitreTactic>,
}

impl SimulationSummary {
    pub fn calculate(&mut self, executions: &[TechniqueExecution]) {
        self.total_techniques = executions.len();
        self.succeeded = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Success)
            .count();
        self.blocked = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Blocked)
            .count();
        self.detected = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Detected || e.detection_observed)
            .count();
        self.failed = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Failed)
            .count();
        self.skipped = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::Skipped)
            .count();
        self.timed_out = executions
            .iter()
            .filter(|e| e.status == TechniqueExecutionStatus::TimedOut)
            .count();

        let attempted = self.total_techniques - self.skipped;
        if attempted > 0 {
            self.detection_rate = self.detected as f64 / attempted as f64;
            self.block_rate = self.blocked as f64 / attempted as f64;
            self.success_rate = self.succeeded as f64 / attempted as f64;
            // Security score: higher detection + block rate = better
            self.security_score = ((self.detection_rate + self.block_rate) * 50.0).min(100.0) as u8;
        }
    }
}

// ============================================================================
// Detection Gap
// ============================================================================

/// A detection gap identified during simulation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DetectionGap {
    /// Gap ID
    pub id: String,
    /// Simulation ID
    pub simulation_id: String,
    /// Technique ID that was not detected
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Associated tactics
    pub tactics: Vec<MitreTactic>,
    /// Expected detection sources
    pub expected_sources: Vec<String>,
    /// Why detection was expected
    pub reason: String,
    /// Remediation recommendations
    pub recommendations: Vec<String>,
    /// Severity (1-5)
    pub severity: u8,
    /// Whether this has been acknowledged
    pub acknowledged: bool,
    /// Acknowledgement notes
    pub acknowledgement_notes: Option<String>,
    /// Detected timestamp
    pub detected_at: DateTime<Utc>,
}

impl DetectionGap {
    pub fn new(
        id: impl Into<String>,
        simulation_id: impl Into<String>,
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        tactics: Vec<MitreTactic>,
    ) -> Self {
        Self {
            id: id.into(),
            simulation_id: simulation_id.into(),
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            tactics,
            expected_sources: Vec::new(),
            reason: String::new(),
            recommendations: Vec::new(),
            severity: 3,
            acknowledged: false,
            acknowledgement_notes: None,
            detected_at: Utc::now(),
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.expected_sources = sources;
        self
    }

    pub fn with_recommendations(mut self, recs: Vec<String>) -> Self {
        self.recommendations = recs;
        self
    }

    pub fn with_severity(mut self, severity: u8) -> Self {
        self.severity = severity.min(5);
        self
    }
}

// ============================================================================
// Progress Messages
// ============================================================================

/// Progress message for real-time simulation updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimulationProgress {
    Started {
        simulation_id: String,
        scenario_name: String,
        total_techniques: usize,
    },
    TechniqueStarted {
        technique_id: String,
        technique_name: String,
        index: usize,
        total: usize,
    },
    TechniqueCompleted {
        technique_id: String,
        status: TechniqueExecutionStatus,
        detection_observed: bool,
        duration_ms: u64,
    },
    DetectionGapFound {
        technique_id: String,
        technique_name: String,
        severity: u8,
    },
    Completed {
        simulation_id: String,
        summary: SimulationSummary,
        duration_ms: u64,
    },
    Error {
        message: String,
    },
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the BAS engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasConfig {
    /// Default execution mode
    pub default_mode: ExecutionMode,
    /// Default timeout in seconds
    pub default_timeout_secs: u64,
    /// Maximum parallel technique executions
    pub max_parallel: usize,
    /// Whether to enable cleanup after execution
    pub enable_cleanup: bool,
    /// Whether to enable detection validation
    pub enable_detection_validation: bool,
    /// Detection validation timeout in seconds
    pub detection_timeout_secs: u64,
    /// Allowed execution modes
    pub allowed_modes: Vec<ExecutionMode>,
    /// Blocked technique IDs (safety blacklist)
    pub blocked_techniques: Vec<String>,
}

impl Default for BasConfig {
    fn default() -> Self {
        Self {
            default_mode: ExecutionMode::DryRun,
            default_timeout_secs: 300,
            max_parallel: 4,
            enable_cleanup: true,
            enable_detection_validation: true,
            detection_timeout_secs: 60,
            allowed_modes: vec![ExecutionMode::DryRun, ExecutionMode::Simulation],
            blocked_techniques: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_mode() {
        assert_eq!(ExecutionMode::DryRun.as_str(), "dry_run");
        assert_eq!(ExecutionMode::from_str("simulation"), Some(ExecutionMode::Simulation));
        assert_eq!(ExecutionMode::from_str("invalid"), None);
    }

    #[test]
    fn test_mitre_tactic() {
        assert_eq!(MitreTactic::Execution.id(), "TA0002");
        assert_eq!(MitreTactic::from_id("TA0001"), Some(MitreTactic::InitialAccess));
        assert_eq!(MitreTactic::all().len(), 14);
    }

    #[test]
    fn test_payload_type() {
        assert_eq!(PayloadType::FileMarker.as_str(), "file_marker");
        assert_eq!(PayloadType::from_str("dns_beacon"), Some(PayloadType::DnsBeacon));
    }

    #[test]
    fn test_simulation_summary() {
        let mut summary = SimulationSummary::default();
        let executions = vec![
            {
                let mut e = TechniqueExecution::new("1", "sim1", "T1059.001");
                e.status = TechniqueExecutionStatus::Detected;
                e.detection_observed = true;
                e
            },
            {
                let mut e = TechniqueExecution::new("2", "sim1", "T1059.002");
                e.status = TechniqueExecutionStatus::Success;
                e
            },
            {
                let mut e = TechniqueExecution::new("3", "sim1", "T1059.003");
                e.status = TechniqueExecutionStatus::Blocked;
                e
            },
        ];

        summary.calculate(&executions);

        assert_eq!(summary.total_techniques, 3);
        assert_eq!(summary.detected, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.blocked, 1);
        assert!((summary.detection_rate - 0.333).abs() < 0.01);
    }
}
