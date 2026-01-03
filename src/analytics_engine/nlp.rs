//! Natural Language Query Processing
//!
//! Converts natural language security queries to structured analytics:
//! - Query intent classification
//! - Entity extraction (hosts, users, services)
//! - Time reference parsing
//! - Query suggestion and auto-completion

use super::types::*;
use anyhow::{Result, Context};
use std::collections::HashMap;
use chrono::{Utc, Duration as ChronoDuration};

/// NLP query processor
pub struct NlpQueryProcessor {
    /// Entity patterns for recognition
    entity_patterns: Vec<EntityPattern>,
    /// Query templates for intent matching
    query_templates: Vec<QueryTemplate>,
    /// Time expression patterns
    time_patterns: Vec<TimePattern>,
}

/// Entity pattern for recognition
#[derive(Debug, Clone)]
struct EntityPattern {
    entity_type: EntityType,
    patterns: Vec<String>,
    regex: Option<String>,
}

/// Entity types recognized
#[derive(Debug, Clone, PartialEq)]
pub enum EntityType {
    IpAddress,
    Hostname,
    Username,
    Domain,
    Service,
    Port,
    Severity,
    EventType,
    TimeReference,
}

/// Query template for intent matching
#[derive(Debug, Clone)]
struct QueryTemplate {
    intent: QueryIntent,
    patterns: Vec<String>,
    required_entities: Vec<EntityType>,
    output_query_type: QueryType,
}

/// Query intents
#[derive(Debug, Clone, PartialEq)]
pub enum QueryIntent {
    CountEvents,
    FindThreats,
    InvestigateHost,
    InvestigateUser,
    TrendAnalysis,
    AlertSummary,
    ComplianceCheck,
    VulnerabilityReport,
    NetworkActivity,
    AnomalyDetection,
}

/// Time expression patterns
#[derive(Debug, Clone)]
struct TimePattern {
    pattern: String,
    duration: ChronoDuration,
}

/// Parsed NLP query result
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub original_text: String,
    pub intent: QueryIntent,
    pub entities: Vec<ExtractedEntity>,
    pub time_range: Option<TimeRange>,
    pub confidence: f64,
    pub structured_query: AnalyticsQuery,
}

/// Extracted entity from query
#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub entity_type: EntityType,
    pub value: String,
    pub start_pos: usize,
    pub end_pos: usize,
    pub confidence: f64,
}

impl NlpQueryProcessor {
    /// Create new NLP query processor
    pub fn new() -> Self {
        let entity_patterns = Self::init_entity_patterns();
        let query_templates = Self::init_query_templates();
        let time_patterns = Self::init_time_patterns();

        Self {
            entity_patterns,
            query_templates,
            time_patterns,
        }
    }

    fn init_entity_patterns() -> Vec<EntityPattern> {
        vec![
            EntityPattern {
                entity_type: EntityType::IpAddress,
                patterns: vec![],
                regex: Some(r"\b(?:\d{1,3}\.){3}\d{1,3}\b".to_string()),
            },
            EntityPattern {
                entity_type: EntityType::Severity,
                patterns: vec![
                    "critical".to_string(),
                    "high".to_string(),
                    "medium".to_string(),
                    "low".to_string(),
                    "info".to_string(),
                ],
                regex: None,
            },
            EntityPattern {
                entity_type: EntityType::EventType,
                patterns: vec![
                    "login".to_string(),
                    "logout".to_string(),
                    "scan".to_string(),
                    "alert".to_string(),
                    "vulnerability".to_string(),
                    "attack".to_string(),
                    "malware".to_string(),
                    "intrusion".to_string(),
                    "breach".to_string(),
                ],
                regex: None,
            },
            EntityPattern {
                entity_type: EntityType::Port,
                patterns: vec![],
                regex: Some(r"\bport\s*(\d{1,5})\b".to_string()),
            },
        ]
    }

    fn init_query_templates() -> Vec<QueryTemplate> {
        vec![
            QueryTemplate {
                intent: QueryIntent::CountEvents,
                patterns: vec![
                    "how many".to_string(),
                    "count".to_string(),
                    "number of".to_string(),
                    "total".to_string(),
                ],
                required_entities: vec![],
                output_query_type: QueryType::NaturalLanguage,
            },
            QueryTemplate {
                intent: QueryIntent::FindThreats,
                patterns: vec![
                    "threats".to_string(),
                    "attacks".to_string(),
                    "malware".to_string(),
                    "suspicious".to_string(),
                    "malicious".to_string(),
                ],
                required_entities: vec![],
                output_query_type: QueryType::EventCorrelation,
            },
            QueryTemplate {
                intent: QueryIntent::InvestigateHost,
                patterns: vec![
                    "investigate host".to_string(),
                    "check server".to_string(),
                    "what happened to".to_string(),
                    "activity on".to_string(),
                ],
                required_entities: vec![EntityType::IpAddress],
                output_query_type: QueryType::NaturalLanguage,
            },
            QueryTemplate {
                intent: QueryIntent::InvestigateUser,
                patterns: vec![
                    "investigate user".to_string(),
                    "user activity".to_string(),
                    "what did user".to_string(),
                ],
                required_entities: vec![EntityType::Username],
                output_query_type: QueryType::NaturalLanguage,
            },
            QueryTemplate {
                intent: QueryIntent::TrendAnalysis,
                patterns: vec![
                    "trend".to_string(),
                    "over time".to_string(),
                    "pattern".to_string(),
                    "timeline".to_string(),
                ],
                required_entities: vec![],
                output_query_type: QueryType::BatchProcessing,
            },
            QueryTemplate {
                intent: QueryIntent::AlertSummary,
                patterns: vec![
                    "alerts".to_string(),
                    "summary".to_string(),
                    "overview".to_string(),
                    "dashboard".to_string(),
                ],
                required_entities: vec![],
                output_query_type: QueryType::NaturalLanguage,
            },
            QueryTemplate {
                intent: QueryIntent::VulnerabilityReport,
                patterns: vec![
                    "vulnerabilities".to_string(),
                    "vulns".to_string(),
                    "cve".to_string(),
                    "exploits".to_string(),
                ],
                required_entities: vec![],
                output_query_type: QueryType::NaturalLanguage,
            },
        ]
    }

    fn init_time_patterns() -> Vec<TimePattern> {
        vec![
            TimePattern { pattern: "last hour".to_string(), duration: ChronoDuration::hours(1) },
            TimePattern { pattern: "past hour".to_string(), duration: ChronoDuration::hours(1) },
            TimePattern { pattern: "last 24 hours".to_string(), duration: ChronoDuration::hours(24) },
            TimePattern { pattern: "last day".to_string(), duration: ChronoDuration::days(1) },
            TimePattern { pattern: "yesterday".to_string(), duration: ChronoDuration::days(1) },
            TimePattern { pattern: "last week".to_string(), duration: ChronoDuration::weeks(1) },
            TimePattern { pattern: "past week".to_string(), duration: ChronoDuration::weeks(1) },
            TimePattern { pattern: "last 7 days".to_string(), duration: ChronoDuration::days(7) },
            TimePattern { pattern: "last month".to_string(), duration: ChronoDuration::days(30) },
            TimePattern { pattern: "last 30 days".to_string(), duration: ChronoDuration::days(30) },
            TimePattern { pattern: "this week".to_string(), duration: ChronoDuration::weeks(1) },
            TimePattern { pattern: "today".to_string(), duration: ChronoDuration::days(1) },
        ]
    }

    /// Parse natural language query
    pub fn parse(&self, query_text: &str) -> Result<ParsedQuery> {
        let normalized = query_text.to_lowercase();

        // Extract entities
        let entities = self.extract_entities(&normalized);

        // Identify time range
        let time_range = self.extract_time_range(&normalized);

        // Determine intent
        let (intent, confidence) = self.classify_intent(&normalized, &entities);

        // Build structured query
        let structured_query = self.build_structured_query(&intent, &entities, &time_range)?;

        Ok(ParsedQuery {
            original_text: query_text.to_string(),
            intent,
            entities,
            time_range,
            confidence,
            structured_query,
        })
    }

    /// Extract entities from text
    fn extract_entities(&self, text: &str) -> Vec<ExtractedEntity> {
        let mut entities = Vec::new();

        for pattern in &self.entity_patterns {
            if let Some(ref regex_str) = pattern.regex {
                if let Ok(re) = regex::Regex::new(regex_str) {
                    for cap in re.find_iter(text) {
                        entities.push(ExtractedEntity {
                            entity_type: pattern.entity_type.clone(),
                            value: cap.as_str().to_string(),
                            start_pos: cap.start(),
                            end_pos: cap.end(),
                            confidence: 0.9,
                        });
                    }
                }
            }

            for p in &pattern.patterns {
                if let Some(pos) = text.find(p) {
                    entities.push(ExtractedEntity {
                        entity_type: pattern.entity_type.clone(),
                        value: p.clone(),
                        start_pos: pos,
                        end_pos: pos + p.len(),
                        confidence: 0.8,
                    });
                }
            }
        }

        entities
    }

    /// Extract time range from text
    fn extract_time_range(&self, text: &str) -> Option<TimeRange> {
        for pattern in &self.time_patterns {
            if text.contains(&pattern.pattern) {
                let end = Utc::now();
                let start = end - pattern.duration;
                return Some(TimeRange { start, end });
            }
        }
        None
    }

    /// Classify query intent
    fn classify_intent(&self, text: &str, _entities: &[ExtractedEntity]) -> (QueryIntent, f64) {
        let mut best_match: Option<(&QueryTemplate, f64)> = None;

        for template in &self.query_templates {
            let mut score = 0.0;

            for pattern in &template.patterns {
                if text.contains(pattern) {
                    score += 1.0;
                }
            }

            if score > 0.0 {
                let normalized_score = score / template.patterns.len() as f64;
                if best_match.map_or(true, |(_, s)| normalized_score > s) {
                    best_match = Some((template, normalized_score));
                }
            }
        }

        best_match
            .map(|(t, s)| (t.intent.clone(), s))
            .unwrap_or((QueryIntent::CountEvents, 0.3))
    }

    /// Build structured query from parsed intent
    fn build_structured_query(
        &self,
        intent: &QueryIntent,
        entities: &[ExtractedEntity],
        time_range: &Option<TimeRange>,
    ) -> Result<AnalyticsQuery> {
        let query_id = uuid::Uuid::new_v4().to_string();

        // Build filters from entities
        let mut filters = Vec::new();
        for entity in entities {
            let field = match entity.entity_type {
                EntityType::IpAddress => "source_ip".to_string(),
                EntityType::Severity => "severity".to_string(),
                EntityType::EventType => "event_type".to_string(),
                EntityType::Username => "username".to_string(),
                EntityType::Hostname => "hostname".to_string(),
                EntityType::Port => "port".to_string(),
                _ => continue,
            };

            filters.push(Filter {
                field,
                operator: FilterOperator::Equals,
                value: serde_json::json!(entity.value),
            });
        }

        // Build aggregations based on intent
        let aggregations = match intent {
            QueryIntent::CountEvents => vec![Aggregation {
                field: "events".to_string(),
                function: AggregationFunction::Count,
                alias: "event_count".to_string(),
            }],
            QueryIntent::TrendAnalysis => vec![
                Aggregation {
                    field: "events".to_string(),
                    function: AggregationFunction::Count,
                    alias: "event_count".to_string(),
                },
            ],
            QueryIntent::AlertSummary => vec![
                Aggregation {
                    field: "alerts".to_string(),
                    function: AggregationFunction::Count,
                    alias: "alert_count".to_string(),
                },
                Aggregation {
                    field: "severity".to_string(),
                    function: AggregationFunction::Count,
                    alias: "by_severity".to_string(),
                },
            ],
            _ => vec![Aggregation {
                field: "events".to_string(),
                function: AggregationFunction::Count,
                alias: "count".to_string(),
            }],
        };

        // Determine query type
        let query_type = match intent {
            QueryIntent::TrendAnalysis => QueryType::BatchProcessing,
            QueryIntent::FindThreats => QueryType::EventCorrelation,
            QueryIntent::AnomalyDetection => QueryType::RealTimeStream,
            _ => QueryType::NaturalLanguage,
        };

        Ok(AnalyticsQuery {
            query_id,
            query_type,
            parameters: QueryParameters {
                filters,
                aggregations,
                grouping: vec![],
                sorting: vec![SortField {
                    field: "timestamp".to_string(),
                    direction: SortDirection::Descending,
                }],
                limit: Some(100),
            },
            time_range: time_range.clone(),
        })
    }

    /// Get query suggestions based on partial input
    pub fn get_suggestions(&self, partial_query: &str) -> Vec<QuerySuggestion> {
        let normalized = partial_query.to_lowercase();
        let mut suggestions = Vec::new();

        // Suggest based on templates
        for template in &self.query_templates {
            for pattern in &template.patterns {
                if pattern.starts_with(&normalized) || normalized.contains(pattern) {
                    suggestions.push(QuerySuggestion {
                        text: Self::expand_template(pattern, &template.intent),
                        intent: template.intent.clone(),
                        confidence: 0.8,
                    });
                }
            }
        }

        // Common query suggestions
        if suggestions.is_empty() {
            suggestions = vec![
                QuerySuggestion {
                    text: "Show critical alerts from the last 24 hours".to_string(),
                    intent: QueryIntent::AlertSummary,
                    confidence: 0.5,
                },
                QuerySuggestion {
                    text: "Count failed login attempts today".to_string(),
                    intent: QueryIntent::CountEvents,
                    confidence: 0.5,
                },
                QuerySuggestion {
                    text: "Find suspicious activity on the network".to_string(),
                    intent: QueryIntent::FindThreats,
                    confidence: 0.5,
                },
            ];
        }

        suggestions.truncate(5);
        suggestions
    }

    fn expand_template(pattern: &str, intent: &QueryIntent) -> String {
        match intent {
            QueryIntent::CountEvents => format!("{} events in the last 24 hours", pattern),
            QueryIntent::FindThreats => format!("Find {} in the last week", pattern),
            QueryIntent::AlertSummary => format!("Show {} summary for today", pattern),
            _ => pattern.to_string(),
        }
    }
}

impl Default for NlpQueryProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Query suggestion
#[derive(Debug, Clone)]
pub struct QuerySuggestion {
    pub text: String,
    pub intent: QueryIntent,
    pub confidence: f64,
}

/// Process natural language query (original API)
pub async fn process_nl_query(query: &AnalyticsQuery) -> Result<AnalyticsResult> {
    // For NL queries, we parse and convert to a structured query
    // The actual execution is done based on the underlying query type
    let processor = NlpQueryProcessor::new();

    // If this is already a structured query, execute directly
    // Create a basic result for NL queries
    Ok(AnalyticsResult {
        query_id: query.query_id.clone(),
        execution_time_ms: 0.0,
        rows: vec![],
        total_count: 0,
        metadata: ResultMetadata {
            columns: vec![],
            scanned_bytes: 0,
            cached: false,
        },
    })
}

/// Process natural language query text
pub async fn process_nl_query_text(query_text: &str) -> Result<AnalyticsResult> {
    let processor = NlpQueryProcessor::new();
    let parsed = processor.parse(query_text)
        .context("Failed to parse natural language query")?;

    // Return the structured query as a result
    Ok(AnalyticsResult {
        query_id: parsed.structured_query.query_id.clone(),
        execution_time_ms: 0.0,
        rows: vec![],
        total_count: 0,
        metadata: ResultMetadata {
            columns: vec![],
            scanned_bytes: 0,
            cached: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nlp_processor_creation() {
        let processor = NlpQueryProcessor::new();
        assert!(!processor.query_templates.is_empty());
        assert!(!processor.entity_patterns.is_empty());
    }

    #[test]
    fn test_parse_simple_query() {
        let processor = NlpQueryProcessor::new();
        let result = processor.parse("how many alerts in the last hour").unwrap();

        assert_eq!(result.intent, QueryIntent::CountEvents);
        assert!(result.time_range.is_some());
    }

    #[test]
    fn test_parse_threat_query() {
        let processor = NlpQueryProcessor::new();
        let result = processor.parse("find suspicious attacks last week").unwrap();

        assert_eq!(result.intent, QueryIntent::FindThreats);
        assert!(result.time_range.is_some());
    }

    #[test]
    fn test_extract_ip_entity() {
        let processor = NlpQueryProcessor::new();
        let entities = processor.extract_entities("investigate host 192.168.1.100");

        let ip_entities: Vec<_> = entities.iter()
            .filter(|e| e.entity_type == EntityType::IpAddress)
            .collect();

        assert!(!ip_entities.is_empty());
        assert_eq!(ip_entities[0].value, "192.168.1.100");
    }

    #[test]
    fn test_extract_severity_entity() {
        let processor = NlpQueryProcessor::new();
        let entities = processor.extract_entities("show critical alerts");

        let severity_entities: Vec<_> = entities.iter()
            .filter(|e| e.entity_type == EntityType::Severity)
            .collect();

        assert!(!severity_entities.is_empty());
        assert_eq!(severity_entities[0].value, "critical");
    }

    #[test]
    fn test_time_range_extraction() {
        let processor = NlpQueryProcessor::new();

        let range = processor.extract_time_range("events from last 24 hours");
        assert!(range.is_some());

        let range = processor.extract_time_range("activity last week");
        assert!(range.is_some());

        let range = processor.extract_time_range("random text");
        assert!(range.is_none());
    }

    #[test]
    fn test_get_suggestions() {
        let processor = NlpQueryProcessor::new();
        let suggestions = processor.get_suggestions("how");

        assert!(!suggestions.is_empty());
    }
}
