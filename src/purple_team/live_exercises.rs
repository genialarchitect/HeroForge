//! Live Purple Team Exercises
//!
//! Provides real-time exercise dashboards with WebSocket updates for live collaboration
//! between red and blue teams.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Live exercise status for real-time monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveExercise {
    pub exercise_id: String,
    pub name: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub current_phase: ExercisePhase,
    pub progress: ExerciseProgress,
    pub live_timeline: Vec<TimelineEvent>,
    pub participants: Vec<Participant>,
    pub chat_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExercisePhase {
    Preparation,
    Execution,
    Detection,
    Analysis,
    Remediation,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseProgress {
    pub total_attacks: usize,
    pub attacks_executed: usize,
    pub attacks_detected: usize,
    pub attacks_missed: usize,
    pub current_attack: Option<String>,
    pub detection_latency_avg_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub team: String, // "red" or "blue"
    pub description: String,
    pub technique_id: Option<String>,
    pub detection_details: Option<LiveDetectionDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimelineEventType {
    AttackLaunched,
    AttackSucceeded,
    AttackFailed,
    AlertGenerated,
    ThreatDetected,
    ThreatMissed,
    PhaseChange,
    Comment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveDetectionDetails {
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub alert_severity: String,
    pub time_to_detect_ms: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub user_id: String,
    pub username: String,
    pub team: String, // "red" or "blue"
    pub role: String,
    pub online: bool,
}

/// Live exercise collaboration features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseCollaboration {
    pub exercise_id: String,
    pub annotations: Vec<Annotation>,
    pub chat_messages: Vec<ChatMessage>,
    pub shared_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub timeline_event_id: String,
    pub user_id: String,
    pub username: String,
    pub team: String,
    pub comment: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub team: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Detection latency metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLatencyMetrics {
    pub technique_id: String,
    pub technique_name: String,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub avg_latency_ms: u64,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub sample_count: usize,
}

/// Live exercise WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum LiveExerciseMessage {
    ExerciseStarted { exercise_id: String, name: String },
    PhaseChanged { phase: ExercisePhase },
    AttackLaunched { technique_id: String, technique_name: String, timestamp: DateTime<Utc> },
    AttackCompleted { technique_id: String, success: bool, timestamp: DateTime<Utc> },
    DetectionTriggered { technique_id: String, detection_details: LiveDetectionDetails, timestamp: DateTime<Utc> },
    DetectionMissed { technique_id: String, timestamp: DateTime<Utc> },
    ProgressUpdate { progress: ExerciseProgress },
    ParticipantJoined { participant: Participant },
    ParticipantLeft { user_id: String },
    ChatMessage { message: ChatMessage },
    Annotation { annotation: Annotation },
    ExerciseCompleted { summary: ExerciseSummary },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseSummary {
    pub exercise_id: String,
    pub duration_secs: u64,
    pub total_attacks: usize,
    pub successful_attacks: usize,
    pub detected_attacks: usize,
    pub missed_attacks: usize,
    pub detection_rate: f64,
    pub avg_detection_latency_ms: u64,
    pub gaps_identified: usize,
    pub coverage_score: f64,
}
