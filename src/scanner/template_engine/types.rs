//! Template Engine Types
//!
//! Core data structures for the vulnerability template scanner.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Template severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
            Severity::Unknown => write!(f, "unknown"),
        }
    }
}

/// Template classification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Classification {
    #[serde(default, rename = "cve-id")]
    pub cve_id: Option<String>,
    #[serde(default, rename = "cwe-id")]
    pub cwe_id: Option<String>,
    #[serde(default)]
    pub cvss_metrics: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f32>,
}

/// Template metadata/info section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub reference: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub classification: Option<Classification>,
    #[serde(default)]
    pub remediation: Option<String>,
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    #[serde(rename = "CONNECT")]
    Connect,
    #[serde(rename = "TRACE")]
    Trace,
}

impl Default for HttpMethod {
    fn default() -> Self {
        Self::Get
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Connect => write!(f, "CONNECT"),
            HttpMethod::Trace => write!(f, "TRACE"),
        }
    }
}

/// Matcher type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherType {
    Word,
    Regex,
    Binary,
    Status,
    Size,
    Dsl,
}

impl Default for MatcherType {
    fn default() -> Self {
        Self::Word
    }
}

/// Matcher condition (AND/OR)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherCondition {
    And,
    Or,
}

impl Default for MatcherCondition {
    fn default() -> Self {
        Self::Or
    }
}

/// Match part (where to look for matches)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchPart {
    Body,
    Header,
    All,
    #[serde(rename = "interactsh_protocol")]
    InteractshProtocol,
    #[serde(rename = "interactsh_request")]
    InteractshRequest,
}

impl Default for MatchPart {
    fn default() -> Self {
        Self::Body
    }
}

/// Matcher definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type", default)]
    pub matcher_type: MatcherType,
    #[serde(default)]
    pub part: MatchPart,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub size: Vec<usize>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub condition: MatcherCondition,
    #[serde(default)]
    pub negative: bool,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub name: Option<String>,
}

/// Extractor type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractorType {
    Regex,
    Kval,
    Xpath,
    Json,
    Dsl,
}

impl Default for ExtractorType {
    fn default() -> Self {
        Self::Regex
    }
}

/// Extractor definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Extractor {
    #[serde(rename = "type", default)]
    pub extractor_type: ExtractorType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub part: MatchPart,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub group: Option<usize>,
    #[serde(default)]
    pub kval: Vec<String>,
    #[serde(default)]
    pub json: Vec<String>,
    #[serde(default)]
    pub xpath: Vec<String>,
    #[serde(default)]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub case_insensitive: bool,
}

/// HTTP request definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default)]
    pub method: HttpMethod,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub raw: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default, rename = "stop-at-first-match")]
    pub stop_at_first_match: bool,
    #[serde(default, rename = "cookie-reuse")]
    pub cookie_reuse: bool,
    #[serde(default, rename = "redirects")]
    pub follow_redirects: bool,
    #[serde(default, rename = "max-redirects")]
    pub max_redirects: Option<u32>,
    #[serde(default, rename = "host-redirects")]
    pub host_redirects: bool,
    #[serde(default, rename = "unsafe")]
    pub unsafe_request: bool,
    #[serde(default, rename = "req-condition")]
    pub req_condition: bool,
    #[serde(default)]
    pub pipeline: bool,
    #[serde(default, rename = "race")]
    pub race_condition: bool,
    #[serde(default, rename = "race_count")]
    pub race_count: Option<u32>,
    #[serde(default, rename = "threads")]
    pub threads: Option<u32>,
    #[serde(default, rename = "attack")]
    pub attack_type: Option<String>,
    #[serde(default)]
    pub payloads: HashMap<String, Vec<String>>,
}

/// TCP request definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpRequest {
    #[serde(default)]
    pub inputs: Vec<TcpInput>,
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub read_size: Option<usize>,
    #[serde(default, rename = "read-all")]
    pub read_all: bool,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: MatcherCondition,
}

/// TCP input
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpInput {
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default, rename = "type")]
    pub input_type: Option<String>,
    #[serde(default)]
    pub read: Option<usize>,
    #[serde(default)]
    pub name: Option<String>,
}

/// DNS request definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub query_type: String,
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub recursion: bool,
    #[serde(default)]
    pub resolvers: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: MatcherCondition,
}

/// File request (for local file analysis)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileRequest {
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default, rename = "denylist")]
    pub deny_list: Vec<String>,
    #[serde(default)]
    pub archive: bool,
    #[serde(default, rename = "max-size")]
    pub max_size: Option<usize>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: MatcherCondition,
}

/// Headless browser request
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeadlessRequest {
    #[serde(default)]
    pub steps: Vec<HeadlessStep>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: MatcherCondition,
    #[serde(default, rename = "disable-cookie")]
    pub disable_cookie: bool,
}

/// Headless browser step
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeadlessStep {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub args: HashMap<String, String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Complete template definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default, rename = "http")]
    pub http_requests: Vec<HttpRequest>,
    #[serde(default, rename = "tcp")]
    pub tcp_requests: Vec<TcpRequest>,
    #[serde(default, rename = "dns")]
    pub dns_requests: Vec<DnsRequest>,
    #[serde(default, rename = "file")]
    pub file_requests: Vec<FileRequest>,
    #[serde(default, rename = "headless")]
    pub headless_requests: Vec<HeadlessRequest>,
    #[serde(default, rename = "self-contained")]
    pub self_contained: bool,
    #[serde(default, rename = "stop-at-first-match")]
    pub stop_at_first_match: bool,
    #[serde(skip)]
    pub source_path: Option<String>,
}

impl Template {
    /// Check if template has any requests
    pub fn has_requests(&self) -> bool {
        !self.http_requests.is_empty()
            || !self.tcp_requests.is_empty()
            || !self.dns_requests.is_empty()
            || !self.file_requests.is_empty()
            || !self.headless_requests.is_empty()
    }

    /// Get all tags
    pub fn tags(&self) -> &[String] {
        &self.info.tags
    }

    /// Check if template matches a tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.info.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }
}

/// Template execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateResult {
    pub template_id: String,
    pub template_name: String,
    pub severity: Severity,
    pub matched: bool,
    pub extracted: HashMap<String, Vec<String>>,
    pub matched_at: String,
    pub matcher_name: Option<String>,
    pub request_url: Option<String>,
    pub request_method: Option<String>,
    pub response_status: Option<u16>,
    pub response_time: Duration,
    pub curl_command: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl TemplateResult {
    pub fn new(template: &Template, target: &str) -> Self {
        Self {
            template_id: template.id.clone(),
            template_name: template.info.name.clone(),
            severity: template.info.severity,
            matched: false,
            extracted: HashMap::new(),
            matched_at: target.to_string(),
            matcher_name: None,
            request_url: None,
            request_method: None,
            response_status: None,
            response_time: Duration::ZERO,
            curl_command: None,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Template execution options
#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub timeout: Duration,
    pub retries: u32,
    pub rate_limit: Option<u32>,
    pub concurrency: u32,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub proxy: Option<String>,
    pub headers: HashMap<String, String>,
    pub variables: HashMap<String, String>,
    pub debug: bool,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            retries: 1,
            rate_limit: None,
            concurrency: 25,
            follow_redirects: true,
            max_redirects: 10,
            proxy: None,
            headers: HashMap::new(),
            variables: HashMap::new(),
            debug: false,
        }
    }
}

/// Template engine error
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Execution error: {0}")]
    Execution(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("HTTP error: {0}")]
    Http(String),
}

pub type TemplateResult2 = Result<TemplateResult, TemplateError>;
