use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Timeline event representing a single point in an investigation
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TimelineEvent {
    pub id: String,
    pub investigation_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub severity: String,
    pub entities: Option<String>, // JSON array of entity IDs
    pub raw_data: Option<String>, // JSON of raw event data
    pub tags: Option<String>, // JSON array of tags
    pub created_at: DateTime<Utc>,
}

/// Temporal pattern detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPattern {
    pub pattern_type: String,
    pub description: String,
    pub events: Vec<String>, // Event IDs
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub confidence: f64,
}

/// Entity in a graph (IP, domain, user, file, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GraphEntity {
    pub id: String,
    pub investigation_id: String,
    pub entity_type: String, // IP, Domain, User, File, Process, etc.
    pub entity_value: String,
    pub properties: Option<String>, // JSON of additional properties
    pub risk_score: Option<f64>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Relationship between entities
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GraphRelationship {
    pub id: String,
    pub investigation_id: String,
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub relationship_type: String, // Connected, Communicated, Executed, Created, etc.
    pub properties: Option<String>, // JSON of additional properties
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: i64, // Number of times relationship observed
    pub created_at: DateTime<Utc>,
}

/// Attack graph analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    pub investigation_id: String,
    pub entry_point: String, // Entity ID
    pub target: String, // Entity ID
    pub paths: Vec<AttackPath>,
    pub pivot_points: Vec<String>, // Entity IDs
    pub blast_radius: Vec<String>, // Entity IDs
}

/// Single attack path in graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub entities: Vec<String>,
    pub relationships: Vec<String>,
    pub risk_score: f64,
    pub techniques: Vec<String>, // MITRE ATT&CK technique IDs
}

/// Memory forensics artifact
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MemoryArtifact {
    pub id: String,
    pub investigation_id: String,
    pub artifact_type: String, // Process, Network, Registry, File, Rootkit, etc.
    pub name: String,
    pub pid: Option<i64>,
    pub data: Option<String>, // JSON of artifact data
    pub suspicious: bool,
    pub indicators: Option<String>, // JSON array of suspicious indicators
    pub created_at: DateTime<Utc>,
}

/// Memory dump analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnalysisResult {
    pub investigation_id: String,
    pub dump_path: String,
    pub os_profile: String,
    pub artifacts: Vec<MemoryArtifact>,
    pub rootkits_detected: Vec<RootkitDetection>,
    pub injections_detected: Vec<InjectionDetection>,
    pub analysis_duration: f64,
}

/// Rootkit detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitDetection {
    pub detection_type: String,
    pub description: String,
    pub severity: String,
    pub evidence: Vec<String>,
}

/// Code injection detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionDetection {
    pub injection_type: String, // DLL, Process, Memory
    pub source_process: String,
    pub target_process: String,
    pub description: String,
    pub severity: String,
}

/// PCAP session analysis
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PcapSession {
    pub id: String,
    pub investigation_id: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub packets: i64,
    pub bytes: i64,
    pub suspicious: bool,
    pub indicators: Option<String>, // JSON array of suspicious indicators
    pub created_at: DateTime<Utc>,
}

/// Network forensics finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkForensicsFinding {
    pub finding_type: String, // C2, DataExfil, LateralMovement, etc.
    pub description: String,
    pub severity: String,
    pub sessions: Vec<String>, // Session IDs
    pub evidence: Vec<String>,
    pub iocs: Vec<String>,
}

/// Deep packet inspection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInspectionResult {
    pub packet_id: i64,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub payload_analysis: Option<PayloadAnalysis>,
    pub anomalies: Vec<String>,
}

/// Payload analysis details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysis {
    pub content_type: Option<String>,
    pub extracted_files: Vec<String>,
    pub credentials: Vec<CredentialExtraction>,
    pub malware_detected: bool,
    pub c2_patterns: Vec<String>,
}

/// Credential extracted from traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialExtraction {
    pub protocol: String,
    pub username: String,
    pub password_hash: Option<String>,
    pub source: String,
}

/// Investigation container
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Investigation {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub investigation_type: String, // Incident, Threat Hunt, Forensics, etc.
    pub status: String, // Active, Closed, Archived
    pub priority: String, // Low, Medium, High, Critical
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

/// Request to create a new investigation
#[derive(Debug, Clone, Deserialize)]
pub struct CreateInvestigationRequest {
    pub name: String,
    pub description: Option<String>,
    pub investigation_type: String,
    pub priority: String,
}

/// Request to add timeline event
#[derive(Debug, Clone, Deserialize)]
pub struct AddTimelineEventRequest {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub severity: String,
    pub entities: Option<Vec<String>>,
    pub raw_data: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
}

/// Request to add graph entity
#[derive(Debug, Clone, Deserialize)]
pub struct AddGraphEntityRequest {
    pub entity_type: String,
    pub entity_value: String,
    pub properties: Option<serde_json::Value>,
    pub risk_score: Option<f64>,
}

/// Request to add graph relationship
#[derive(Debug, Clone, Deserialize)]
pub struct AddGraphRelationshipRequest {
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub relationship_type: String,
    pub properties: Option<serde_json::Value>,
}
