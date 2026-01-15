//! Intelligence API
//!
//! Comprehensive API for intelligence platform including:
//! - RESTful API for intelligence queries
//! - GraphQL API for flexible data fetching
//! - Webhooks for real-time notifications
//! - Streaming API for continuous intelligence feed
//! - Intelligence-as-a-Service (IaaS)

use super::types::*;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

// ============================================================================
// REST API Types
// ============================================================================

/// RESTful API client for intelligence queries
#[derive(Debug, Clone)]
pub struct IntelligenceRestApi {
    /// API base URL
    base_url: String,
    /// API key for authentication
    api_key: String,
    /// Rate limiter configuration
    rate_limit_rps: usize,
    /// Request count for rate limiting
    request_count: Arc<RwLock<RequestCounter>>,
}

#[derive(Debug, Default)]
struct RequestCounter {
    count: usize,
    window_start: Option<DateTime<Utc>>,
}

/// Query parameters for indicator search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorQuery {
    /// Indicator value to search for
    pub value: Option<String>,
    /// Indicator type (ip, domain, hash, url, email)
    pub indicator_type: Option<IndicatorType>,
    /// Minimum confidence score (0.0 - 1.0)
    pub min_confidence: Option<f64>,
    /// Tags to filter by
    pub tags: Option<Vec<String>>,
    /// Source to filter by
    pub source: Option<String>,
    /// Date range start
    pub from_date: Option<DateTime<Utc>>,
    /// Date range end
    pub to_date: Option<DateTime<Utc>>,
    /// Pagination offset
    pub offset: Option<usize>,
    /// Pagination limit
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    IPv4,
    IPv6,
    Domain,
    URL,
    MD5,
    SHA1,
    SHA256,
    Email,
    CVE,
    MITRE,
    Custom(String),
}

/// Indicator of Compromise (IOC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub context: HashMap<String, serde_json::Value>,
}

/// Enrichment result for an IOC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub indicator: Indicator,
    pub enrichments: Vec<Enrichment>,
    pub related_indicators: Vec<Indicator>,
    pub threat_actors: Vec<ThreatActorInfo>,
    pub campaigns: Vec<CampaignInfo>,
    pub malware_families: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    pub source: String,
    pub enrichment_type: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorInfo {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub motivation: String,
    pub sophistication: String,
    pub country: Option<String>,
    pub ttps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub targets: Vec<String>,
    pub indicators: Vec<String>,
}

/// Intelligence submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSubmission {
    pub indicators: Vec<SubmittedIndicator>,
    pub source: String,
    pub tlp: SharingLevel,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmittedIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: Option<f64>,
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Query response with pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

impl IntelligenceRestApi {
    pub fn new(base_url: &str, api_key: &str, rate_limit_rps: usize) -> Self {
        Self {
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
            rate_limit_rps,
            request_count: Arc::new(RwLock::new(RequestCounter::default())),
        }
    }

    /// Check and update rate limit
    async fn check_rate_limit(&self) -> Result<()> {
        let mut counter = self.request_count.write().await;
        let now = Utc::now();

        match counter.window_start {
            Some(start) if (now - start).num_seconds() < 1 => {
                if counter.count >= self.rate_limit_rps {
                    return Err(anyhow!("Rate limit exceeded: {} requests per second", self.rate_limit_rps));
                }
                counter.count += 1;
            }
            _ => {
                counter.window_start = Some(now);
                counter.count = 1;
            }
        }

        Ok(())
    }

    /// Query indicators with filters
    pub async fn query_indicators(&self, query: &IndicatorQuery) -> Result<QueryResponse<Indicator>> {
        self.check_rate_limit().await?;

        // Build indicators based on query parameters
        let mut indicators = self.get_sample_indicators();

        // Apply filters
        if let Some(ref value) = query.value {
            indicators.retain(|i| i.value.contains(value));
        }

        if let Some(ref indicator_type) = query.indicator_type {
            indicators.retain(|i| &i.indicator_type == indicator_type);
        }

        if let Some(min_conf) = query.min_confidence {
            indicators.retain(|i| i.confidence >= min_conf);
        }

        if let Some(ref tags) = query.tags {
            indicators.retain(|i| tags.iter().any(|t| i.tags.contains(t)));
        }

        if let Some(ref source) = query.source {
            indicators.retain(|i| i.source.to_lowercase().contains(&source.to_lowercase()));
        }

        // Apply pagination
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(50).min(1000);
        let total = indicators.len();

        let paginated: Vec<_> = indicators
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();

        Ok(QueryResponse {
            has_more: offset + paginated.len() < total,
            data: paginated,
            total,
            offset,
            limit,
        })
    }

    /// Enrich an IOC with additional context
    pub async fn enrich_ioc(&self, indicator_type: &IndicatorType, value: &str) -> Result<EnrichmentResult> {
        self.check_rate_limit().await?;

        let indicator = Indicator {
            id: format!("ioc-{}", uuid::Uuid::new_v4()),
            indicator_type: indicator_type.clone(),
            value: value.to_string(),
            confidence: 0.85,
            severity: self.determine_severity(indicator_type, value),
            tags: self.auto_tag(indicator_type, value),
            source: "enrichment".to_string(),
            first_seen: Utc::now() - chrono::Duration::days(30),
            last_seen: Utc::now(),
            context: HashMap::new(),
        };

        let enrichments = vec![
            Enrichment {
                source: "WHOIS".to_string(),
                enrichment_type: "domain_info".to_string(),
                data: serde_json::json!({
                    "registrar": "Example Registrar",
                    "creation_date": "2020-01-15",
                    "country": "US"
                }),
                timestamp: Utc::now(),
            },
            Enrichment {
                source: "VirusTotal".to_string(),
                enrichment_type: "reputation".to_string(),
                data: serde_json::json!({
                    "positives": 5,
                    "total": 70,
                    "scan_date": Utc::now().format("%Y-%m-%d").to_string()
                }),
                timestamp: Utc::now(),
            },
            Enrichment {
                source: "Shodan".to_string(),
                enrichment_type: "host_info".to_string(),
                data: serde_json::json!({
                    "ports": [22, 80, 443],
                    "org": "Example ISP",
                    "asn": "AS12345"
                }),
                timestamp: Utc::now(),
            },
        ];

        let threat_actors = if self.is_known_threat_actor_ioc(value) {
            vec![ThreatActorInfo {
                id: "ta-001".to_string(),
                name: "APT-Example".to_string(),
                aliases: vec!["Dark Horde".to_string(), "Shadow Group".to_string()],
                motivation: "Espionage".to_string(),
                sophistication: "Advanced".to_string(),
                country: Some("Unknown".to_string()),
                ttps: vec!["T1566".to_string(), "T1059".to_string()],
            }]
        } else {
            vec![]
        };

        let risk_score = self.calculate_risk_score(&indicator, &enrichments, &threat_actors);

        Ok(EnrichmentResult {
            indicator,
            enrichments,
            related_indicators: vec![],
            threat_actors,
            campaigns: vec![],
            malware_families: vec![],
            risk_score,
        })
    }

    /// Submit new intelligence
    pub async fn submit_intel(&self, submission: &IntelSubmission) -> Result<SubmissionResult> {
        self.check_rate_limit().await?;

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        for indicator in &submission.indicators {
            if self.validate_indicator(indicator) {
                accepted.push(IndicatorAccepted {
                    id: format!("ioc-{}", uuid::Uuid::new_v4()),
                    value: indicator.value.clone(),
                    indicator_type: indicator.indicator_type.clone(),
                });
            } else {
                rejected.push(IndicatorRejected {
                    value: indicator.value.clone(),
                    reason: "Invalid format or duplicate".to_string(),
                });
            }
        }

        let status = if rejected.is_empty() { "complete" } else { "partial" }.to_string();

        Ok(SubmissionResult {
            submission_id: format!("sub-{}", uuid::Uuid::new_v4()),
            accepted,
            rejected,
            status,
            timestamp: Utc::now(),
        })
    }

    /// Get threat actors
    pub async fn get_threat_actors(&self, filter: Option<&str>) -> Result<Vec<ThreatActorInfo>> {
        self.check_rate_limit().await?;

        let actors = vec![
            ThreatActorInfo {
                id: "ta-001".to_string(),
                name: "APT-28".to_string(),
                aliases: vec!["Fancy Bear".to_string(), "Sofacy".to_string()],
                motivation: "Espionage".to_string(),
                sophistication: "Advanced".to_string(),
                country: Some("Russia".to_string()),
                ttps: vec!["T1566.001".to_string(), "T1059.001".to_string(), "T1003.001".to_string()],
            },
            ThreatActorInfo {
                id: "ta-002".to_string(),
                name: "Lazarus Group".to_string(),
                aliases: vec!["Hidden Cobra".to_string(), "Zinc".to_string()],
                motivation: "Financial".to_string(),
                sophistication: "Advanced".to_string(),
                country: Some("North Korea".to_string()),
                ttps: vec!["T1566.002".to_string(), "T1027".to_string(), "T1486".to_string()],
            },
            ThreatActorInfo {
                id: "ta-003".to_string(),
                name: "APT-41".to_string(),
                aliases: vec!["Double Dragon".to_string(), "Winnti".to_string()],
                motivation: "Financial/Espionage".to_string(),
                sophistication: "Advanced".to_string(),
                country: Some("China".to_string()),
                ttps: vec!["T1195.002".to_string(), "T1059.001".to_string()],
            },
        ];

        if let Some(f) = filter {
            Ok(actors.into_iter()
                .filter(|a| a.name.to_lowercase().contains(&f.to_lowercase())
                    || a.aliases.iter().any(|al| al.to_lowercase().contains(&f.to_lowercase())))
                .collect())
        } else {
            Ok(actors)
        }
    }

    /// Get campaigns
    pub async fn get_campaigns(&self, active_only: bool) -> Result<Vec<CampaignInfo>> {
        self.check_rate_limit().await?;

        let campaigns = vec![
            CampaignInfo {
                id: "camp-001".to_string(),
                name: "Operation SolarStorm".to_string(),
                description: "Supply chain attack targeting software vendors".to_string(),
                start_date: Some(Utc::now() - chrono::Duration::days(180)),
                end_date: None,
                targets: vec!["Technology".to_string(), "Government".to_string()],
                indicators: vec!["ioc-001".to_string(), "ioc-002".to_string()],
            },
            CampaignInfo {
                id: "camp-002".to_string(),
                name: "PhishNet".to_string(),
                description: "Credential harvesting campaign targeting financial sector".to_string(),
                start_date: Some(Utc::now() - chrono::Duration::days(60)),
                end_date: if active_only { None } else { Some(Utc::now() - chrono::Duration::days(10)) },
                targets: vec!["Financial".to_string(), "Banking".to_string()],
                indicators: vec!["ioc-003".to_string(), "ioc-004".to_string()],
            },
        ];

        if active_only {
            Ok(campaigns.into_iter().filter(|c| c.end_date.is_none()).collect())
        } else {
            Ok(campaigns)
        }
    }

    // Helper methods

    fn get_sample_indicators(&self) -> Vec<Indicator> {
        vec![
            Indicator {
                id: "ioc-001".to_string(),
                indicator_type: IndicatorType::IPv4,
                value: "192.168.1.100".to_string(),
                confidence: 0.95,
                severity: Severity::High,
                tags: vec!["c2".to_string(), "apt".to_string()],
                source: "Internal".to_string(),
                first_seen: Utc::now() - chrono::Duration::days(7),
                last_seen: Utc::now(),
                context: HashMap::new(),
            },
            Indicator {
                id: "ioc-002".to_string(),
                indicator_type: IndicatorType::Domain,
                value: "malware-distribution.example.com".to_string(),
                confidence: 0.90,
                severity: Severity::Critical,
                tags: vec!["malware".to_string(), "distribution".to_string()],
                source: "OSINT".to_string(),
                first_seen: Utc::now() - chrono::Duration::days(14),
                last_seen: Utc::now() - chrono::Duration::hours(2),
                context: HashMap::new(),
            },
            Indicator {
                id: "ioc-003".to_string(),
                indicator_type: IndicatorType::SHA256,
                value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                confidence: 0.99,
                severity: Severity::Critical,
                tags: vec!["ransomware".to_string(), "lockbit".to_string()],
                source: "Commercial".to_string(),
                first_seen: Utc::now() - chrono::Duration::days(1),
                last_seen: Utc::now(),
                context: HashMap::new(),
            },
        ]
    }

    fn determine_severity(&self, indicator_type: &IndicatorType, _value: &str) -> Severity {
        match indicator_type {
            IndicatorType::SHA256 | IndicatorType::SHA1 | IndicatorType::MD5 => Severity::High,
            IndicatorType::Domain | IndicatorType::URL => Severity::Medium,
            IndicatorType::IPv4 | IndicatorType::IPv6 => Severity::Medium,
            IndicatorType::CVE => Severity::High,
            _ => Severity::Low,
        }
    }

    fn auto_tag(&self, indicator_type: &IndicatorType, value: &str) -> Vec<String> {
        let mut tags = vec![];

        match indicator_type {
            IndicatorType::IPv4 | IndicatorType::IPv6 => tags.push("network".to_string()),
            IndicatorType::Domain | IndicatorType::URL => tags.push("web".to_string()),
            IndicatorType::SHA256 | IndicatorType::SHA1 | IndicatorType::MD5 => tags.push("file".to_string()),
            IndicatorType::Email => tags.push("email".to_string()),
            IndicatorType::CVE => tags.push("vulnerability".to_string()),
            _ => {}
        }

        // Pattern-based tagging
        if value.contains("tor") || value.contains("onion") {
            tags.push("tor".to_string());
        }
        if value.contains("c2") || value.contains("command") {
            tags.push("c2".to_string());
        }

        tags
    }

    fn is_known_threat_actor_ioc(&self, value: &str) -> bool {
        // Check against known threat actor indicators
        let known_patterns = ["apt", "lazarus", "fancy", "cozy"];
        known_patterns.iter().any(|p| value.to_lowercase().contains(p))
    }

    fn calculate_risk_score(&self, indicator: &Indicator, enrichments: &[Enrichment], threat_actors: &[ThreatActorInfo]) -> f64 {
        let mut score: f64 = indicator.confidence * 0.4;

        // Add severity weight
        score += match indicator.severity {
            Severity::Critical => 0.3,
            Severity::High => 0.2,
            Severity::Medium => 0.1,
            Severity::Low => 0.05,
            Severity::Info => 0.0,
        };

        // Add enrichment weight
        let enrichment_score: f64 = enrichments.len() as f64 * 0.05;
        score += enrichment_score.min(0.15);

        // Add threat actor association weight
        if !threat_actors.is_empty() {
            score += 0.2;
        }

        score.min(1.0)
    }

    fn validate_indicator(&self, indicator: &SubmittedIndicator) -> bool {
        match &indicator.indicator_type {
            IndicatorType::IPv4 => {
                indicator.value.parse::<std::net::Ipv4Addr>().is_ok()
            }
            IndicatorType::IPv6 => {
                indicator.value.parse::<std::net::Ipv6Addr>().is_ok()
            }
            IndicatorType::MD5 => {
                indicator.value.len() == 32 && indicator.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IndicatorType::SHA1 => {
                indicator.value.len() == 40 && indicator.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IndicatorType::SHA256 => {
                indicator.value.len() == 64 && indicator.value.chars().all(|c| c.is_ascii_hexdigit())
            }
            IndicatorType::Domain => {
                !indicator.value.is_empty() && indicator.value.contains('.')
            }
            IndicatorType::URL => {
                indicator.value.starts_with("http://") || indicator.value.starts_with("https://")
            }
            IndicatorType::Email => {
                indicator.value.contains('@') && indicator.value.contains('.')
            }
            IndicatorType::CVE => {
                indicator.value.starts_with("CVE-")
            }
            _ => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionResult {
    pub submission_id: String,
    pub accepted: Vec<IndicatorAccepted>,
    pub rejected: Vec<IndicatorRejected>,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorAccepted {
    pub id: String,
    pub value: String,
    pub indicator_type: IndicatorType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorRejected {
    pub value: String,
    pub reason: String,
}

// ============================================================================
// GraphQL API
// ============================================================================

/// GraphQL API for flexible intelligence queries
#[derive(Debug, Clone)]
pub struct IntelligenceGraphQLApi {
    /// REST API for underlying queries
    rest_api: IntelligenceRestApi,
    /// Schema definition
    schema: GraphQLSchema,
}

#[derive(Debug, Clone)]
pub struct GraphQLSchema {
    /// Available types
    types: Vec<GraphQLType>,
    /// Available queries
    queries: Vec<GraphQLQuery>,
    /// Available mutations
    mutations: Vec<GraphQLMutation>,
}

#[derive(Debug, Clone)]
pub struct GraphQLType {
    pub name: String,
    pub fields: Vec<GraphQLField>,
}

#[derive(Debug, Clone)]
pub struct GraphQLField {
    pub name: String,
    pub field_type: String,
    pub nullable: bool,
}

#[derive(Debug, Clone)]
pub struct GraphQLQuery {
    pub name: String,
    pub arguments: Vec<GraphQLArgument>,
    pub return_type: String,
}

#[derive(Debug, Clone)]
pub struct GraphQLMutation {
    pub name: String,
    pub arguments: Vec<GraphQLArgument>,
    pub return_type: String,
}

#[derive(Debug, Clone)]
pub struct GraphQLArgument {
    pub name: String,
    pub arg_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    pub query: String,
    pub variables: Option<HashMap<String, serde_json::Value>>,
    pub operation_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    pub errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    pub locations: Option<Vec<GraphQLLocation>>,
    pub path: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLLocation {
    pub line: usize,
    pub column: usize,
}

impl IntelligenceGraphQLApi {
    pub fn new(rest_api: IntelligenceRestApi) -> Self {
        let schema = Self::build_schema();
        Self { rest_api, schema }
    }

    fn build_schema() -> GraphQLSchema {
        GraphQLSchema {
            types: vec![
                GraphQLType {
                    name: "Indicator".to_string(),
                    fields: vec![
                        GraphQLField { name: "id".to_string(), field_type: "ID!".to_string(), nullable: false },
                        GraphQLField { name: "type".to_string(), field_type: "IndicatorType!".to_string(), nullable: false },
                        GraphQLField { name: "value".to_string(), field_type: "String!".to_string(), nullable: false },
                        GraphQLField { name: "confidence".to_string(), field_type: "Float!".to_string(), nullable: false },
                        GraphQLField { name: "severity".to_string(), field_type: "Severity!".to_string(), nullable: false },
                        GraphQLField { name: "tags".to_string(), field_type: "[String!]!".to_string(), nullable: false },
                        GraphQLField { name: "source".to_string(), field_type: "String!".to_string(), nullable: false },
                        GraphQLField { name: "firstSeen".to_string(), field_type: "DateTime!".to_string(), nullable: false },
                        GraphQLField { name: "lastSeen".to_string(), field_type: "DateTime!".to_string(), nullable: false },
                    ],
                },
                GraphQLType {
                    name: "ThreatActor".to_string(),
                    fields: vec![
                        GraphQLField { name: "id".to_string(), field_type: "ID!".to_string(), nullable: false },
                        GraphQLField { name: "name".to_string(), field_type: "String!".to_string(), nullable: false },
                        GraphQLField { name: "aliases".to_string(), field_type: "[String!]!".to_string(), nullable: false },
                        GraphQLField { name: "motivation".to_string(), field_type: "String!".to_string(), nullable: false },
                        GraphQLField { name: "sophistication".to_string(), field_type: "String!".to_string(), nullable: false },
                        GraphQLField { name: "country".to_string(), field_type: "String".to_string(), nullable: true },
                        GraphQLField { name: "ttps".to_string(), field_type: "[String!]!".to_string(), nullable: false },
                    ],
                },
            ],
            queries: vec![
                GraphQLQuery {
                    name: "indicators".to_string(),
                    arguments: vec![
                        GraphQLArgument { name: "type".to_string(), arg_type: "IndicatorType".to_string(), required: false },
                        GraphQLArgument { name: "value".to_string(), arg_type: "String".to_string(), required: false },
                        GraphQLArgument { name: "minConfidence".to_string(), arg_type: "Float".to_string(), required: false },
                        GraphQLArgument { name: "limit".to_string(), arg_type: "Int".to_string(), required: false },
                    ],
                    return_type: "[Indicator!]!".to_string(),
                },
                GraphQLQuery {
                    name: "indicator".to_string(),
                    arguments: vec![
                        GraphQLArgument { name: "id".to_string(), arg_type: "ID!".to_string(), required: true },
                    ],
                    return_type: "Indicator".to_string(),
                },
                GraphQLQuery {
                    name: "enrichIndicator".to_string(),
                    arguments: vec![
                        GraphQLArgument { name: "type".to_string(), arg_type: "IndicatorType!".to_string(), required: true },
                        GraphQLArgument { name: "value".to_string(), arg_type: "String!".to_string(), required: true },
                    ],
                    return_type: "EnrichmentResult!".to_string(),
                },
                GraphQLQuery {
                    name: "threatActors".to_string(),
                    arguments: vec![
                        GraphQLArgument { name: "filter".to_string(), arg_type: "String".to_string(), required: false },
                    ],
                    return_type: "[ThreatActor!]!".to_string(),
                },
            ],
            mutations: vec![
                GraphQLMutation {
                    name: "submitIndicators".to_string(),
                    arguments: vec![
                        GraphQLArgument { name: "input".to_string(), arg_type: "IndicatorSubmissionInput!".to_string(), required: true },
                    ],
                    return_type: "SubmissionResult!".to_string(),
                },
            ],
        }
    }

    /// Execute a GraphQL query
    pub async fn execute(&self, request: &GraphQLRequest) -> Result<GraphQLResponse> {
        // Parse and execute the query
        let query = &request.query;

        // Simple query parsing (in production, use a proper GraphQL parser)
        if query.contains("indicators") {
            let limit = request.variables
                .as_ref()
                .and_then(|v| v.get("limit"))
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);

            let ioc_query = IndicatorQuery {
                value: None,
                indicator_type: None,
                min_confidence: None,
                tags: None,
                source: None,
                from_date: None,
                to_date: None,
                offset: None,
                limit,
            };

            let response = self.rest_api.query_indicators(&ioc_query).await?;

            Ok(GraphQLResponse {
                data: Some(serde_json::json!({
                    "indicators": response.data
                })),
                errors: None,
            })
        } else if query.contains("threatActors") {
            let filter = request.variables
                .as_ref()
                .and_then(|v| v.get("filter"))
                .and_then(|v| v.as_str());

            let actors = self.rest_api.get_threat_actors(filter).await?;

            Ok(GraphQLResponse {
                data: Some(serde_json::json!({
                    "threatActors": actors
                })),
                errors: None,
            })
        } else {
            Ok(GraphQLResponse {
                data: None,
                errors: Some(vec![GraphQLError {
                    message: "Unknown query".to_string(),
                    locations: None,
                    path: None,
                }]),
            })
        }
    }

    /// Get schema for introspection
    pub fn get_schema(&self) -> &GraphQLSchema {
        &self.schema
    }
}

// ============================================================================
// Webhooks API
// ============================================================================

/// Webhook manager for real-time intelligence notifications
#[derive(Debug)]
pub struct WebhookManager {
    /// Registered webhooks
    webhooks: Arc<RwLock<HashMap<String, WebhookRegistration>>>,
    /// Event queue
    event_queue: Arc<RwLock<Vec<WebhookEvent>>>,
    /// Delivery statistics
    stats: Arc<RwLock<WebhookStats>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    pub id: String,
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub secret: String,
    pub enabled: bool,
    pub filters: Option<WebhookFilter>,
    pub created_at: DateTime<Utc>,
    pub last_triggered: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebhookEventType {
    NewIndicator,
    IndicatorUpdate,
    ThreatActorUpdate,
    CampaignUpdate,
    HighSeverityAlert,
    NewThreatBrief,
    EnrichmentComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookFilter {
    pub severity: Option<Vec<Severity>>,
    pub indicator_types: Option<Vec<IndicatorType>>,
    pub tags: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    pub event_type: WebhookEventType,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub webhook_id: String,
    pub event_id: String,
    pub status: DeliveryStatus,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WebhookStats {
    pub total_deliveries: usize,
    pub successful_deliveries: usize,
    pub failed_deliveries: usize,
    pub average_response_time_ms: f64,
}

impl WebhookManager {
    pub fn new() -> Self {
        Self {
            webhooks: Arc::new(RwLock::new(HashMap::new())),
            event_queue: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(WebhookStats::default())),
        }
    }

    /// Register a new webhook
    pub async fn register(&self, url: &str, events: Vec<WebhookEventType>, filters: Option<WebhookFilter>) -> Result<WebhookRegistration> {
        let registration = WebhookRegistration {
            id: format!("wh-{}", uuid::Uuid::new_v4()),
            url: url.to_string(),
            events,
            secret: self.generate_secret(),
            enabled: true,
            filters,
            created_at: Utc::now(),
            last_triggered: None,
        };

        let mut webhooks = self.webhooks.write().await;
        webhooks.insert(registration.id.clone(), registration.clone());

        Ok(registration)
    }

    /// Unregister a webhook
    pub async fn unregister(&self, webhook_id: &str) -> Result<()> {
        let mut webhooks = self.webhooks.write().await;
        webhooks.remove(webhook_id)
            .ok_or_else(|| anyhow!("Webhook not found: {}", webhook_id))?;
        Ok(())
    }

    /// Update a webhook
    pub async fn update(&self, webhook_id: &str, enabled: Option<bool>, events: Option<Vec<WebhookEventType>>) -> Result<WebhookRegistration> {
        let mut webhooks = self.webhooks.write().await;
        let webhook = webhooks.get_mut(webhook_id)
            .ok_or_else(|| anyhow!("Webhook not found: {}", webhook_id))?;

        if let Some(e) = enabled {
            webhook.enabled = e;
        }
        if let Some(ev) = events {
            webhook.events = ev;
        }

        Ok(webhook.clone())
    }

    /// Queue an event for delivery
    pub async fn queue_event(&self, event_type: WebhookEventType, payload: serde_json::Value) -> Result<String> {
        let event = WebhookEvent {
            id: format!("evt-{}", uuid::Uuid::new_v4()),
            event_type,
            payload,
            timestamp: Utc::now(),
        };

        let mut queue = self.event_queue.write().await;
        queue.push(event.clone());

        Ok(event.id)
    }

    /// Deliver pending events
    pub async fn deliver_events(&self) -> Result<Vec<WebhookDelivery>> {
        let queue = {
            let mut q = self.event_queue.write().await;
            std::mem::take(&mut *q)
        };

        let webhooks = self.webhooks.read().await;
        let mut deliveries = Vec::new();

        for event in queue {
            for (_, webhook) in webhooks.iter() {
                if !webhook.enabled || !webhook.events.contains(&event.event_type) {
                    continue;
                }

                if let Some(ref filters) = webhook.filters {
                    if !self.matches_filters(&event, filters) {
                        continue;
                    }
                }

                let delivery = self.deliver_to_webhook(webhook, &event).await;
                deliveries.push(delivery);
            }
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_deliveries += deliveries.len();
        stats.successful_deliveries += deliveries.iter().filter(|d| d.status == DeliveryStatus::Delivered).count();
        stats.failed_deliveries += deliveries.iter().filter(|d| d.status == DeliveryStatus::Failed).count();

        Ok(deliveries)
    }

    /// Get webhook statistics
    pub async fn get_stats(&self) -> WebhookStats {
        self.stats.read().await.clone()
    }

    /// List registered webhooks
    pub async fn list(&self) -> Vec<WebhookRegistration> {
        self.webhooks.read().await.values().cloned().collect()
    }

    async fn deliver_to_webhook(&self, webhook: &WebhookRegistration, event: &WebhookEvent) -> WebhookDelivery {
        let start = std::time::Instant::now();

        // Prepare payload with signature
        let payload = serde_json::json!({
            "event_id": event.id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "payload": event.payload
        });

        let signature = self.compute_signature(&payload, &webhook.secret);

        // Simulate HTTP delivery (in production, use reqwest or similar)
        let (status, status_code, error) = if webhook.url.starts_with("https://") {
            (DeliveryStatus::Delivered, Some(200_u16), None)
        } else if webhook.url.starts_with("http://") {
            (DeliveryStatus::Delivered, Some(200_u16), None)
        } else {
            (DeliveryStatus::Failed, None, Some("Invalid URL scheme".to_string()))
        };

        let response_time_ms = start.elapsed().as_millis() as u64;

        // Update last triggered
        if status == DeliveryStatus::Delivered {
            if let Ok(mut webhooks) = self.webhooks.try_write() {
                if let Some(wh) = webhooks.get_mut(&webhook.id) {
                    wh.last_triggered = Some(Utc::now());
                }
            }
        }

        WebhookDelivery {
            webhook_id: webhook.id.clone(),
            event_id: event.id.clone(),
            status,
            status_code,
            response_time_ms: Some(response_time_ms),
            error,
            timestamp: Utc::now(),
        }
    }

    fn generate_secret(&self) -> String {
        use std::iter;
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
        let mut rng = rand::thread_rng();
        use rand::Rng;
        iter::repeat(())
            .take(32)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    }

    fn compute_signature(&self, payload: &serde_json::Value, secret: &str) -> String {
        use sha2::{Sha256, Digest};
        let payload_str = serde_json::to_string(payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(payload_str.as_bytes());
        format!("sha256={:x}", hasher.finalize())
    }

    fn matches_filters(&self, event: &WebhookEvent, filters: &WebhookFilter) -> bool {
        // Check severity filter
        if let Some(ref severities) = filters.severity {
            if let Some(severity) = event.payload.get("severity").and_then(|s| {
                serde_json::from_value::<Severity>(s.clone()).ok()
            }) {
                if !severities.contains(&severity) {
                    return false;
                }
            }
        }

        // Check indicator type filter
        if let Some(ref types) = filters.indicator_types {
            if let Some(ioc_type) = event.payload.get("indicator_type").and_then(|t| {
                serde_json::from_value::<IndicatorType>(t.clone()).ok()
            }) {
                if !types.contains(&ioc_type) {
                    return false;
                }
            }
        }

        true
    }
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Streaming API
// ============================================================================

/// Streaming API for continuous intelligence feed
#[derive(Debug)]
pub struct IntelligenceStream {
    /// Broadcast channel sender
    sender: broadcast::Sender<StreamEvent>,
    /// Subscriber count
    subscriber_count: Arc<RwLock<usize>>,
    /// Stream configuration
    config: StreamConfig,
}

#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Maximum events per second
    pub max_events_per_second: usize,
    /// Event buffer size
    pub buffer_size: usize,
    /// Enable heartbeats
    pub heartbeat_enabled: bool,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_seconds: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_events_per_second: 100,
            buffer_size: 1000,
            heartbeat_enabled: true,
            heartbeat_interval_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    pub event_id: String,
    pub event_type: StreamEventType,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StreamEventType {
    Indicator,
    ThreatActor,
    Campaign,
    Alert,
    Enrichment,
    Heartbeat,
}

#[derive(Debug)]
pub struct StreamSubscription {
    /// Subscription ID
    pub id: String,
    /// Event filter
    pub filter: Option<StreamFilter>,
    /// Receiver channel
    pub receiver: broadcast::Receiver<StreamEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamFilter {
    pub event_types: Option<Vec<StreamEventType>>,
    pub severity: Option<Vec<Severity>>,
    pub sources: Option<Vec<String>>,
}

impl IntelligenceStream {
    pub fn new(config: StreamConfig) -> Self {
        let (sender, _) = broadcast::channel(config.buffer_size);
        Self {
            sender,
            subscriber_count: Arc::new(RwLock::new(0)),
            config,
        }
    }

    /// Subscribe to the intelligence stream
    pub async fn subscribe(&self, filter: Option<StreamFilter>) -> StreamSubscription {
        let receiver = self.sender.subscribe();

        let mut count = self.subscriber_count.write().await;
        *count += 1;

        StreamSubscription {
            id: format!("sub-{}", uuid::Uuid::new_v4()),
            filter,
            receiver,
        }
    }

    /// Publish an event to the stream
    pub async fn publish(&self, event_type: StreamEventType, data: serde_json::Value) -> Result<()> {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let event = StreamEvent {
            event_id: format!("se-{}", uuid::Uuid::new_v4()),
            event_type,
            data,
            timestamp: Utc::now(),
            sequence: SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        };

        // Send to all subscribers (ignore errors for subscribers that have dropped)
        let _ = self.sender.send(event);

        Ok(())
    }

    /// Publish an indicator event
    pub async fn publish_indicator(&self, indicator: &Indicator) -> Result<()> {
        self.publish(
            StreamEventType::Indicator,
            serde_json::to_value(indicator)?,
        ).await
    }

    /// Publish a heartbeat
    pub async fn publish_heartbeat(&self) -> Result<()> {
        self.publish(
            StreamEventType::Heartbeat,
            serde_json::json!({
                "subscribers": *self.subscriber_count.read().await,
                "timestamp": Utc::now()
            }),
        ).await
    }

    /// Get subscriber count
    pub async fn subscriber_count(&self) -> usize {
        *self.subscriber_count.read().await
    }

    /// Get stream configuration
    pub fn config(&self) -> &StreamConfig {
        &self.config
    }
}

impl Default for IntelligenceStream {
    fn default() -> Self {
        Self::new(StreamConfig::default())
    }
}

// ============================================================================
// Intelligence-as-a-Service
// ============================================================================

/// Intelligence-as-a-Service (IaaS) manager
#[derive(Debug)]
pub struct IntelligenceService {
    /// REST API client
    pub rest_api: IntelligenceRestApi,
    /// GraphQL API
    pub graphql_api: IntelligenceGraphQLApi,
    /// Webhook manager
    pub webhooks: WebhookManager,
    /// Streaming API
    pub stream: IntelligenceStream,
    /// Service configuration
    config: IaaSConfig,
    /// Service statistics
    stats: Arc<RwLock<ServiceStats>>,
}

#[derive(Debug, Clone)]
pub struct IaaSConfig {
    pub service_id: String,
    pub tier: ServiceTier,
    pub rate_limits: RateLimits,
    pub features: EnabledFeatures,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServiceTier {
    Free,
    Professional,
    Enterprise,
    Unlimited,
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    pub queries_per_minute: usize,
    pub enrichments_per_day: usize,
    pub submissions_per_day: usize,
    pub webhook_events_per_hour: usize,
}

#[derive(Debug, Clone)]
pub struct EnabledFeatures {
    pub rest_api: bool,
    pub graphql_api: bool,
    pub webhooks: bool,
    pub streaming: bool,
    pub bulk_operations: bool,
    pub historical_data: bool,
    pub custom_feeds: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServiceStats {
    pub total_queries: usize,
    pub total_enrichments: usize,
    pub total_submissions: usize,
    pub active_subscriptions: usize,
    pub uptime_seconds: u64,
}

impl IntelligenceService {
    pub fn new(config: IaaSConfig) -> Self {
        let rate_limit = config.rate_limits.queries_per_minute / 60;
        let rest_api = IntelligenceRestApi::new(
            "https://api.intelligence.example.com",
            "api-key-placeholder",
            rate_limit.max(1),
        );
        let graphql_api = IntelligenceGraphQLApi::new(rest_api.clone());
        let webhooks = WebhookManager::new();
        let stream = IntelligenceStream::new(StreamConfig::default());

        Self {
            rest_api,
            graphql_api,
            webhooks,
            stream,
            config,
            stats: Arc::new(RwLock::new(ServiceStats::default())),
        }
    }

    /// Create service with tier-based configuration
    pub fn with_tier(tier: ServiceTier) -> Self {
        let config = match tier {
            ServiceTier::Free => IaaSConfig {
                service_id: format!("svc-{}", uuid::Uuid::new_v4()),
                tier: ServiceTier::Free,
                rate_limits: RateLimits {
                    queries_per_minute: 10,
                    enrichments_per_day: 100,
                    submissions_per_day: 10,
                    webhook_events_per_hour: 100,
                },
                features: EnabledFeatures {
                    rest_api: true,
                    graphql_api: false,
                    webhooks: false,
                    streaming: false,
                    bulk_operations: false,
                    historical_data: false,
                    custom_feeds: false,
                },
            },
            ServiceTier::Professional => IaaSConfig {
                service_id: format!("svc-{}", uuid::Uuid::new_v4()),
                tier: ServiceTier::Professional,
                rate_limits: RateLimits {
                    queries_per_minute: 100,
                    enrichments_per_day: 10000,
                    submissions_per_day: 1000,
                    webhook_events_per_hour: 10000,
                },
                features: EnabledFeatures {
                    rest_api: true,
                    graphql_api: true,
                    webhooks: true,
                    streaming: false,
                    bulk_operations: true,
                    historical_data: false,
                    custom_feeds: false,
                },
            },
            ServiceTier::Enterprise => IaaSConfig {
                service_id: format!("svc-{}", uuid::Uuid::new_v4()),
                tier: ServiceTier::Enterprise,
                rate_limits: RateLimits {
                    queries_per_minute: 1000,
                    enrichments_per_day: 100000,
                    submissions_per_day: 10000,
                    webhook_events_per_hour: 100000,
                },
                features: EnabledFeatures {
                    rest_api: true,
                    graphql_api: true,
                    webhooks: true,
                    streaming: true,
                    bulk_operations: true,
                    historical_data: true,
                    custom_feeds: true,
                },
            },
            ServiceTier::Unlimited => IaaSConfig {
                service_id: format!("svc-{}", uuid::Uuid::new_v4()),
                tier: ServiceTier::Unlimited,
                rate_limits: RateLimits {
                    queries_per_minute: usize::MAX,
                    enrichments_per_day: usize::MAX,
                    submissions_per_day: usize::MAX,
                    webhook_events_per_hour: usize::MAX,
                },
                features: EnabledFeatures {
                    rest_api: true,
                    graphql_api: true,
                    webhooks: true,
                    streaming: true,
                    bulk_operations: true,
                    historical_data: true,
                    custom_feeds: true,
                },
            },
        };

        Self::new(config)
    }

    /// Check if a feature is enabled
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "rest" => self.config.features.rest_api,
            "graphql" => self.config.features.graphql_api,
            "webhooks" => self.config.features.webhooks,
            "streaming" => self.config.features.streaming,
            "bulk" => self.config.features.bulk_operations,
            "historical" => self.config.features.historical_data,
            "custom_feeds" => self.config.features.custom_feeds,
            _ => false,
        }
    }

    /// Get service tier
    pub fn tier(&self) -> &ServiceTier {
        &self.config.tier
    }

    /// Get rate limits
    pub fn rate_limits(&self) -> &RateLimits {
        &self.config.rate_limits
    }

    /// Get service statistics
    pub async fn get_stats(&self) -> ServiceStats {
        self.stats.read().await.clone()
    }

    /// Update statistics
    pub async fn increment_stat(&self, stat: &str) {
        let mut stats = self.stats.write().await;
        match stat {
            "queries" => stats.total_queries += 1,
            "enrichments" => stats.total_enrichments += 1,
            "submissions" => stats.total_submissions += 1,
            _ => {}
        }
    }
}

// ============================================================================
// Setup Function
// ============================================================================

/// Setup intelligence API and return available endpoints
pub async fn setup_api(config: &APIConfig) -> Result<Vec<String>> {
    let mut endpoints = Vec::new();

    if config.enable_rest {
        endpoints.push("/api/intelligence/query".to_string());
        endpoints.push("/api/intelligence/enrich".to_string());
        endpoints.push("/api/intelligence/submit".to_string());
        endpoints.push("/api/intelligence/threat-actors".to_string());
        endpoints.push("/api/intelligence/campaigns".to_string());
        endpoints.push("/api/intelligence/indicators".to_string());
        endpoints.push("/api/intelligence/indicators/{id}".to_string());
        endpoints.push("/api/intelligence/bulk/query".to_string());
        endpoints.push("/api/intelligence/bulk/enrich".to_string());
    }

    if config.enable_graphql {
        endpoints.push("/graphql/intelligence".to_string());
        endpoints.push("/graphql/intelligence/schema".to_string());
        endpoints.push("/graphql/intelligence/playground".to_string());
    }

    if config.enable_webhooks {
        endpoints.push("/api/intelligence/webhooks".to_string());
        endpoints.push("/api/intelligence/webhooks/{id}".to_string());
        endpoints.push("/api/intelligence/webhooks/{id}/test".to_string());
        endpoints.push("/api/intelligence/webhooks/stats".to_string());
    }

    if config.enable_streaming {
        endpoints.push("/api/intelligence/stream".to_string());
        endpoints.push("/api/intelligence/stream/subscribe".to_string());
        endpoints.push("ws://api/intelligence/stream/live".to_string());
    }

    Ok(endpoints)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rest_api_query() {
        let api = IntelligenceRestApi::new("https://example.com", "test-key", 100);
        let query = IndicatorQuery {
            value: None,
            indicator_type: Some(IndicatorType::IPv4),
            min_confidence: Some(0.5),
            tags: None,
            source: None,
            from_date: None,
            to_date: None,
            offset: None,
            limit: Some(10),
        };

        let result = api.query_indicators(&query).await.unwrap();
        assert!(result.limit <= 10);
    }

    #[tokio::test]
    async fn test_enrichment() {
        let api = IntelligenceRestApi::new("https://example.com", "test-key", 100);
        let result = api.enrich_ioc(&IndicatorType::IPv4, "192.168.1.1").await.unwrap();
        assert!(!result.enrichments.is_empty());
        assert!(result.risk_score > 0.0 && result.risk_score <= 1.0);
    }

    #[tokio::test]
    async fn test_intel_submission() {
        let api = IntelligenceRestApi::new("https://example.com", "test-key", 100);
        let submission = IntelSubmission {
            indicators: vec![
                SubmittedIndicator {
                    indicator_type: IndicatorType::IPv4,
                    value: "10.0.0.1".to_string(),
                    confidence: Some(0.8),
                    context: None,
                },
                SubmittedIndicator {
                    indicator_type: IndicatorType::SHA256,
                    value: "invalid-hash".to_string(),
                    confidence: None,
                    context: None,
                },
            ],
            source: "test".to_string(),
            tlp: SharingLevel::TlpGreen,
            description: None,
            tags: None,
        };

        let result = api.submit_intel(&submission).await.unwrap();
        assert_eq!(result.accepted.len(), 1);
        assert_eq!(result.rejected.len(), 1);
    }

    #[tokio::test]
    async fn test_threat_actors() {
        let api = IntelligenceRestApi::new("https://example.com", "test-key", 100);
        let actors = api.get_threat_actors(Some("lazarus")).await.unwrap();
        assert!(!actors.is_empty());
        assert!(actors.iter().any(|a| a.name.to_lowercase().contains("lazarus")));
    }

    #[tokio::test]
    async fn test_graphql_query() {
        let rest_api = IntelligenceRestApi::new("https://example.com", "test-key", 100);
        let graphql = IntelligenceGraphQLApi::new(rest_api);

        let request = GraphQLRequest {
            query: "query { indicators { id value } }".to_string(),
            variables: None,
            operation_name: None,
        };

        let response = graphql.execute(&request).await.unwrap();
        assert!(response.data.is_some());
        assert!(response.errors.is_none());
    }

    #[tokio::test]
    async fn test_webhook_registration() {
        let manager = WebhookManager::new();

        let webhook = manager.register(
            "https://example.com/webhook",
            vec![WebhookEventType::NewIndicator, WebhookEventType::HighSeverityAlert],
            None,
        ).await.unwrap();

        assert!(!webhook.id.is_empty());
        assert!(webhook.enabled);

        let webhooks = manager.list().await;
        assert_eq!(webhooks.len(), 1);
    }

    #[tokio::test]
    async fn test_webhook_event_delivery() {
        let manager = WebhookManager::new();

        manager.register(
            "https://example.com/webhook",
            vec![WebhookEventType::NewIndicator],
            None,
        ).await.unwrap();

        manager.queue_event(
            WebhookEventType::NewIndicator,
            serde_json::json!({ "test": "data" }),
        ).await.unwrap();

        let deliveries = manager.deliver_events().await.unwrap();
        assert_eq!(deliveries.len(), 1);
    }

    #[tokio::test]
    async fn test_streaming_api() {
        let stream = IntelligenceStream::new(StreamConfig::default());

        let subscription = stream.subscribe(None).await;
        assert!(!subscription.id.is_empty());
        assert_eq!(stream.subscriber_count().await, 1);

        stream.publish_heartbeat().await.unwrap();
    }

    #[tokio::test]
    async fn test_intelligence_service_tiers() {
        let free_service = IntelligenceService::with_tier(ServiceTier::Free);
        assert!(!free_service.is_feature_enabled("graphql"));
        assert!(!free_service.is_feature_enabled("streaming"));

        let enterprise_service = IntelligenceService::with_tier(ServiceTier::Enterprise);
        assert!(enterprise_service.is_feature_enabled("graphql"));
        assert!(enterprise_service.is_feature_enabled("streaming"));
        assert!(enterprise_service.is_feature_enabled("custom_feeds"));
    }

    #[tokio::test]
    async fn test_setup_api() {
        let config = APIConfig {
            enable_rest: true,
            enable_graphql: true,
            enable_webhooks: true,
            enable_streaming: true,
            rate_limit_rps: 100,
        };

        let endpoints = setup_api(&config).await.unwrap();
        assert!(endpoints.iter().any(|e| e.contains("/query")));
        assert!(endpoints.iter().any(|e| e.contains("/graphql")));
        assert!(endpoints.iter().any(|e| e.contains("/webhooks")));
        assert!(endpoints.iter().any(|e| e.contains("/stream")));
    }

    #[test]
    fn test_indicator_validation() {
        let api = IntelligenceRestApi::new("https://example.com", "test-key", 100);

        // Valid IPv4
        let valid_ip = SubmittedIndicator {
            indicator_type: IndicatorType::IPv4,
            value: "192.168.1.1".to_string(),
            confidence: None,
            context: None,
        };
        assert!(api.validate_indicator(&valid_ip));

        // Invalid IPv4
        let invalid_ip = SubmittedIndicator {
            indicator_type: IndicatorType::IPv4,
            value: "not-an-ip".to_string(),
            confidence: None,
            context: None,
        };
        assert!(!api.validate_indicator(&invalid_ip));

        // Valid SHA256
        let valid_hash = SubmittedIndicator {
            indicator_type: IndicatorType::SHA256,
            value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            confidence: None,
            context: None,
        };
        assert!(api.validate_indicator(&valid_hash));

        // Invalid SHA256
        let invalid_hash = SubmittedIndicator {
            indicator_type: IndicatorType::SHA256,
            value: "not-a-hash".to_string(),
            confidence: None,
            context: None,
        };
        assert!(!api.validate_indicator(&invalid_hash));
    }
}
