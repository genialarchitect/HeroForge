//! Fuzzing Types
//!
//! Core data structures for the fuzzing framework.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Fuzzing target type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzTargetType {
    Protocol,
    Http,
    File,
    Api,
    Custom,
}

impl std::fmt::Display for FuzzTargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => write!(f, "protocol"),
            Self::Http => write!(f, "http"),
            Self::File => write!(f, "file"),
            Self::Api => write!(f, "api"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Fuzzer type/strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerType {
    Mutation,
    Generation,
    Grammar,
    Template,
    Hybrid,
}

impl std::fmt::Display for FuzzerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mutation => write!(f, "mutation"),
            Self::Generation => write!(f, "generation"),
            Self::Grammar => write!(f, "grammar"),
            Self::Template => write!(f, "template"),
            Self::Hybrid => write!(f, "hybrid"),
        }
    }
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Created,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Crash type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrashType {
    Segfault,
    HeapOverflow,
    StackOverflow,
    UseAfterFree,
    DoubleFree,
    NullPointerDeref,
    IntegerOverflow,
    FormatString,
    BufferOverread,
    AssertionFailure,
    Timeout,
    Hang,
    MemoryLeak,
    Unknown,
}

impl std::fmt::Display for CrashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Segfault => write!(f, "segfault"),
            Self::HeapOverflow => write!(f, "heap_overflow"),
            Self::StackOverflow => write!(f, "stack_overflow"),
            Self::UseAfterFree => write!(f, "use_after_free"),
            Self::DoubleFree => write!(f, "double_free"),
            Self::NullPointerDeref => write!(f, "null_pointer_deref"),
            Self::IntegerOverflow => write!(f, "integer_overflow"),
            Self::FormatString => write!(f, "format_string"),
            Self::BufferOverread => write!(f, "buffer_overread"),
            Self::AssertionFailure => write!(f, "assertion_failure"),
            Self::Timeout => write!(f, "timeout"),
            Self::Hang => write!(f, "hang"),
            Self::MemoryLeak => write!(f, "memory_leak"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    Exploitable,
    ProbablyExploitable,
    ProbablyNotExploitable,
    NotExploitable,
    Unknown,
}

impl std::fmt::Display for Exploitability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exploitable => write!(f, "exploitable"),
            Self::ProbablyExploitable => write!(f, "probably_exploitable"),
            Self::ProbablyNotExploitable => write!(f, "probably_not_exploitable"),
            Self::NotExploitable => write!(f, "not_exploitable"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Mutation strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MutationStrategy {
    BitFlip,
    ByteFlip,
    ArithmeticAdd,
    ArithmeticSub,
    InterestingValues,
    BlockDuplication,
    BlockDeletion,
    BlockInsertion,
    BlockSwap,
    Havoc,
    Splice,
    Dictionary,
    Custom,
}

/// Fuzzing campaign configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingCampaign {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub target_type: FuzzTargetType,
    pub fuzzer_type: FuzzerType,
    pub target_config: TargetConfig,
    pub fuzzer_config: FuzzerConfig,
    pub status: CampaignStatus,
    pub total_iterations: u64,
    pub crashes_found: u32,
    pub unique_crashes: u32,
    pub coverage_percent: Option<f64>,
    pub execs_per_sec: Option<f64>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    /// Target URL, binary path, or connection string
    pub target: String,
    /// Port for protocol fuzzing
    pub port: Option<u16>,
    /// Protocol for protocol fuzzing (tcp, udp)
    pub protocol: Option<String>,
    /// HTTP method for HTTP fuzzing
    pub method: Option<String>,
    /// Headers for HTTP fuzzing
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// Input file for file fuzzing
    pub input_file: Option<String>,
    /// Command to execute for file fuzzing
    pub command: Option<String>,
    /// Arguments with @@ as placeholder for input file
    pub arguments: Option<Vec<String>>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Memory limit in MB
    pub memory_limit_mb: Option<u64>,
}

/// Fuzzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    /// Mutation strategies to use
    pub mutation_strategies: Option<Vec<MutationStrategy>>,
    /// Grammar definition for grammar-based fuzzing
    pub grammar: Option<String>,
    /// Template for template-based fuzzing
    pub template: Option<FuzzTemplate>,
    /// Dictionary words for dictionary-based mutations
    pub dictionary: Option<Vec<String>>,
    /// Seed inputs
    pub seeds: Option<Vec<Vec<u8>>>,
    /// Maximum input size in bytes
    pub max_input_size: Option<usize>,
    /// Minimum input size in bytes
    pub min_input_size: Option<usize>,
    /// Maximum iterations (0 = infinite)
    pub max_iterations: Option<u64>,
    /// Maximum runtime in seconds (0 = infinite)
    pub max_runtime_secs: Option<u64>,
    /// Enable coverage tracking
    pub enable_coverage: Option<bool>,
    /// Number of parallel workers
    pub workers: Option<u32>,
}

/// Fuzzing template for template-based fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTemplate {
    /// Template name
    pub name: String,
    /// Template content with fuzz markers
    pub content: String,
    /// Fuzz points in the template
    pub fuzz_points: Vec<FuzzPoint>,
}

/// A fuzz point in a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzPoint {
    /// Name of the fuzz point
    pub name: String,
    /// Type of data to generate
    pub data_type: FuzzDataType,
    /// Minimum length
    pub min_length: Option<usize>,
    /// Maximum length
    pub max_length: Option<usize>,
    /// Specific values to try
    pub values: Option<Vec<String>>,
}

/// Data types for fuzzing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FuzzDataType {
    String,
    Integer,
    Float,
    Binary,
    Email,
    Url,
    Path,
    SqlInjection,
    XssPayload,
    CommandInjection,
    FormatString,
    Unicode,
    Custom,
}

/// Crash record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingCrash {
    pub id: String,
    pub campaign_id: String,
    pub crash_type: CrashType,
    pub crash_hash: String,
    pub exploitability: Exploitability,
    pub input_data: Vec<u8>,
    pub input_size: usize,
    pub stack_trace: Option<String>,
    pub registers: Option<RegisterState>,
    pub signal: Option<i32>,
    pub exit_code: Option<i32>,
    pub stderr_output: Option<String>,
    pub reproduced: bool,
    pub reproduction_count: u32,
    pub minimized_input: Option<Vec<u8>>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Register state at crash time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    pub rax: Option<u64>,
    pub rbx: Option<u64>,
    pub rcx: Option<u64>,
    pub rdx: Option<u64>,
    pub rsi: Option<u64>,
    pub rdi: Option<u64>,
    pub rbp: Option<u64>,
    pub rsp: Option<u64>,
    pub rip: Option<u64>,
    pub r8: Option<u64>,
    pub r9: Option<u64>,
    pub r10: Option<u64>,
    pub r11: Option<u64>,
    pub r12: Option<u64>,
    pub r13: Option<u64>,
    pub r14: Option<u64>,
    pub r15: Option<u64>,
    pub eflags: Option<u64>,
}

/// Coverage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageInfo {
    pub campaign_id: String,
    pub timestamp: DateTime<Utc>,
    pub total_edges: u64,
    pub covered_edges: u64,
    pub coverage_percent: f64,
    pub new_edges_this_session: u64,
    pub total_blocks: Option<u64>,
    pub covered_blocks: Option<u64>,
    pub edge_hits: Option<std::collections::HashMap<u64, u64>>,
}

/// Campaign statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignStats {
    pub campaign_id: String,
    pub total_execs: u64,
    pub execs_per_sec: f64,
    pub total_crashes: u32,
    pub unique_crashes: u32,
    pub hangs: u32,
    pub coverage_percent: f64,
    pub new_edges: u64,
    pub pending_inputs: u32,
    pub stability: f64,
    pub runtime_secs: u64,
    pub last_crash_at: Option<DateTime<Utc>>,
    pub last_new_edge_at: Option<DateTime<Utc>>,
}

/// HTTP fuzzer payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFuzzPayload {
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query_params: Option<std::collections::HashMap<String, String>>,
}

/// HTTP fuzzer response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFuzzResponse {
    pub status_code: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
    pub response_time_ms: u64,
    pub is_error: bool,
    pub error_message: Option<String>,
}

/// Protocol fuzzer message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    pub data: Vec<u8>,
    pub is_request: bool,
    pub timestamp: DateTime<Utc>,
}

/// Grammar rule for grammar-based fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarRule {
    pub name: String,
    pub productions: Vec<GrammarProduction>,
    pub weight: Option<f64>,
}

/// Grammar production
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarProduction {
    pub elements: Vec<GrammarElement>,
    pub weight: Option<f64>,
}

/// Grammar element
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GrammarElement {
    Terminal { value: String },
    NonTerminal { name: String },
    Range { min: u8, max: u8 },
    Repeat { element: Box<GrammarElement>, min: usize, max: usize },
    Optional { element: Box<GrammarElement> },
    Choice { elements: Vec<GrammarElement> },
}

/// Fuzzing session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingSession {
    pub session_id: String,
    pub campaign_id: String,
    pub worker_id: u32,
    pub started_at: DateTime<Utc>,
    pub iterations: u64,
    pub crashes: u32,
    pub is_active: bool,
}

/// Create campaign request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub target_type: FuzzTargetType,
    pub fuzzer_type: FuzzerType,
    pub target_config: TargetConfig,
    pub fuzzer_config: FuzzerConfig,
}

/// Update campaign request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub fuzzer_config: Option<FuzzerConfig>,
}
