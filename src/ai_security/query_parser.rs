//! Natural Language Query Parser
//!
//! Parses natural language security queries into structured filters and intents.
//! Uses pattern matching and entity extraction to understand user queries.

use anyhow::Result;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{AIQueryType, ExtractedEntity, ParsedIntent, QueryFilter, TimeRange};

/// Entity type for extraction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    IpAddress,
    CveId,
    Hostname,
    Port,
    Service,
    Severity,
    Status,
    Date,
    Username,
    AssetTag,
    Vulnerability,
    Protocol,
    Country,
    Number,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::IpAddress => "ip_address",
            EntityType::CveId => "cve_id",
            EntityType::Hostname => "hostname",
            EntityType::Port => "port",
            EntityType::Service => "service",
            EntityType::Severity => "severity",
            EntityType::Status => "status",
            EntityType::Date => "date",
            EntityType::Username => "username",
            EntityType::AssetTag => "asset_tag",
            EntityType::Vulnerability => "vulnerability",
            EntityType::Protocol => "protocol",
            EntityType::Country => "country",
            EntityType::Number => "number",
        }
    }
}

/// Query intent patterns
struct IntentPattern {
    intent: AIQueryType,
    patterns: Vec<&'static str>,
}

/// Natural Language Query Parser
pub struct QueryParser {
    intent_patterns: Vec<IntentPattern>,
    entity_patterns: HashMap<EntityType, Regex>,
    severity_keywords: HashMap<String, String>,
    status_keywords: HashMap<String, String>,
    time_keywords: HashMap<String, Duration>,
}

impl QueryParser {
    /// Create a new query parser
    pub fn new() -> Self {
        let intent_patterns = vec![
            IntentPattern {
                intent: AIQueryType::Search,
                patterns: vec![
                    "find", "show", "list", "get", "display", "search",
                    "what", "which", "where", "look for", "give me",
                ],
            },
            IntentPattern {
                intent: AIQueryType::Analysis,
                patterns: vec![
                    "analyze", "explain", "why", "how many", "count",
                    "statistics", "summary", "breakdown", "distribution",
                    "compare", "trend", "pattern", "correlation",
                ],
            },
            IntentPattern {
                intent: AIQueryType::Report,
                patterns: vec![
                    "report", "generate report", "create report",
                    "export", "document", "pdf", "csv",
                ],
            },
            IntentPattern {
                intent: AIQueryType::Remediation,
                patterns: vec![
                    "fix", "remediate", "patch", "resolve",
                    "how to fix", "solution", "mitigation",
                    "steps to", "recommend",
                ],
            },
            IntentPattern {
                intent: AIQueryType::Investigation,
                patterns: vec![
                    "investigate", "trace", "correlate", "timeline",
                    "attack path", "root cause", "what happened",
                    "incident", "breach", "compromise",
                ],
            },
        ];

        let mut entity_patterns = HashMap::new();

        // IP address pattern (IPv4)
        entity_patterns.insert(
            EntityType::IpAddress,
            Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
        );

        // CVE ID pattern
        entity_patterns.insert(
            EntityType::CveId,
            Regex::new(r"(?i)\bCVE-\d{4}-\d{4,7}\b").unwrap(),
        );

        // Port number pattern (within context)
        entity_patterns.insert(
            EntityType::Port,
            Regex::new(r"(?i)\bport\s*(\d{1,5})\b|\b(\d{1,5})/(?:tcp|udp)\b").unwrap(),
        );

        // Hostname pattern
        entity_patterns.insert(
            EntityType::Hostname,
            Regex::new(r"(?i)\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b").unwrap(),
        );

        // Date patterns (ISO, common formats)
        entity_patterns.insert(
            EntityType::Date,
            Regex::new(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{2}/\d{2}/\d{4}\b").unwrap(),
        );

        // Number pattern
        entity_patterns.insert(
            EntityType::Number,
            Regex::new(r"\b\d+\b").unwrap(),
        );

        // Severity keywords
        let mut severity_keywords = HashMap::new();
        severity_keywords.insert("critical".to_string(), "critical".to_string());
        severity_keywords.insert("crit".to_string(), "critical".to_string());
        severity_keywords.insert("high".to_string(), "high".to_string());
        severity_keywords.insert("severe".to_string(), "high".to_string());
        severity_keywords.insert("medium".to_string(), "medium".to_string());
        severity_keywords.insert("med".to_string(), "medium".to_string());
        severity_keywords.insert("moderate".to_string(), "medium".to_string());
        severity_keywords.insert("low".to_string(), "low".to_string());
        severity_keywords.insert("minor".to_string(), "low".to_string());
        severity_keywords.insert("info".to_string(), "info".to_string());
        severity_keywords.insert("informational".to_string(), "info".to_string());

        // Status keywords
        let mut status_keywords = HashMap::new();
        status_keywords.insert("open".to_string(), "open".to_string());
        status_keywords.insert("new".to_string(), "open".to_string());
        status_keywords.insert("active".to_string(), "open".to_string());
        status_keywords.insert("closed".to_string(), "closed".to_string());
        status_keywords.insert("resolved".to_string(), "resolved".to_string());
        status_keywords.insert("fixed".to_string(), "resolved".to_string());
        status_keywords.insert("in progress".to_string(), "in_progress".to_string());
        status_keywords.insert("working on".to_string(), "in_progress".to_string());
        status_keywords.insert("pending".to_string(), "pending".to_string());
        status_keywords.insert("awaiting".to_string(), "pending".to_string());
        status_keywords.insert("false positive".to_string(), "false_positive".to_string());
        status_keywords.insert("fp".to_string(), "false_positive".to_string());
        status_keywords.insert("accepted".to_string(), "accepted".to_string());
        status_keywords.insert("risk accepted".to_string(), "risk_accepted".to_string());

        // Time keywords
        let mut time_keywords = HashMap::new();
        time_keywords.insert("today".to_string(), Duration::days(1));
        time_keywords.insert("yesterday".to_string(), Duration::days(2));
        time_keywords.insert("last hour".to_string(), Duration::hours(1));
        time_keywords.insert("past hour".to_string(), Duration::hours(1));
        time_keywords.insert("last 24 hours".to_string(), Duration::hours(24));
        time_keywords.insert("past 24 hours".to_string(), Duration::hours(24));
        time_keywords.insert("last week".to_string(), Duration::weeks(1));
        time_keywords.insert("past week".to_string(), Duration::weeks(1));
        time_keywords.insert("this week".to_string(), Duration::weeks(1));
        time_keywords.insert("last month".to_string(), Duration::days(30));
        time_keywords.insert("past month".to_string(), Duration::days(30));
        time_keywords.insert("this month".to_string(), Duration::days(30));
        time_keywords.insert("last 30 days".to_string(), Duration::days(30));
        time_keywords.insert("past 30 days".to_string(), Duration::days(30));
        time_keywords.insert("last 90 days".to_string(), Duration::days(90));
        time_keywords.insert("past 90 days".to_string(), Duration::days(90));
        time_keywords.insert("last quarter".to_string(), Duration::days(90));
        time_keywords.insert("last year".to_string(), Duration::days(365));
        time_keywords.insert("past year".to_string(), Duration::days(365));
        time_keywords.insert("this year".to_string(), Duration::days(365));

        Self {
            intent_patterns,
            entity_patterns,
            severity_keywords,
            status_keywords,
            time_keywords,
        }
    }

    /// Parse a natural language query
    pub fn parse(&self, query: &str) -> Result<ParsedIntent> {
        let query_lower = query.to_lowercase();

        // Detect intent
        let (query_type, intent_confidence) = self.detect_intent(&query_lower);

        // Extract entities
        let entities = self.extract_entities(query);

        // Build filters
        let filters = self.build_filters(&query_lower, &entities);

        // Extract time range
        let time_range = self.extract_time_range(&query_lower);

        // Calculate overall confidence
        let confidence = self.calculate_confidence(&query_lower, &entities, intent_confidence);

        Ok(ParsedIntent {
            query_type,
            entities,
            filters,
            time_range,
            confidence,
        })
    }

    /// Detect the intent of the query
    fn detect_intent(&self, query: &str) -> (AIQueryType, f64) {
        let mut best_match: Option<(AIQueryType, usize)> = None;

        for intent_pattern in &self.intent_patterns {
            for pattern in &intent_pattern.patterns {
                if let Some(pos) = query.find(pattern) {
                    // Prefer patterns at the start of the query
                    let score = if pos < 20 { 2 } else { 1 };
                    if let Some((_, best_score)) = best_match {
                        if score > best_score || (score == best_score && pos < 10) {
                            best_match = Some((intent_pattern.intent, score));
                        }
                    } else {
                        best_match = Some((intent_pattern.intent, score));
                    }
                }
            }
        }

        match best_match {
            Some((intent, score)) => {
                let confidence = if score >= 2 { 0.85 } else { 0.70 };
                (intent, confidence)
            }
            None => (AIQueryType::Search, 0.50), // Default to search
        }
    }

    /// Extract entities from the query
    fn extract_entities(&self, query: &str) -> Vec<ExtractedEntity> {
        let mut entities = Vec::new();

        // Extract IP addresses
        if let Some(regex) = self.entity_patterns.get(&EntityType::IpAddress) {
            for cap in regex.find_iter(query) {
                entities.push(ExtractedEntity {
                    entity_type: EntityType::IpAddress.as_str().to_string(),
                    value: cap.as_str().to_string(),
                    start_pos: cap.start(),
                    end_pos: cap.end(),
                    confidence: 0.95,
                });
            }
        }

        // Extract CVE IDs
        if let Some(regex) = self.entity_patterns.get(&EntityType::CveId) {
            for cap in regex.find_iter(query) {
                entities.push(ExtractedEntity {
                    entity_type: EntityType::CveId.as_str().to_string(),
                    value: cap.as_str().to_uppercase(),
                    start_pos: cap.start(),
                    end_pos: cap.end(),
                    confidence: 0.98,
                });
            }
        }

        // Extract ports
        if let Some(regex) = self.entity_patterns.get(&EntityType::Port) {
            for cap in regex.captures_iter(query) {
                if let Some(port_match) = cap.get(1).or_else(|| cap.get(2)) {
                    if let Ok(port) = port_match.as_str().parse::<u16>() {
                        if port > 0 && port <= 65535 {
                            entities.push(ExtractedEntity {
                                entity_type: EntityType::Port.as_str().to_string(),
                                value: port.to_string(),
                                start_pos: port_match.start(),
                                end_pos: port_match.end(),
                                confidence: 0.90,
                            });
                        }
                    }
                }
            }
        }

        // Extract hostnames
        if let Some(regex) = self.entity_patterns.get(&EntityType::Hostname) {
            for cap in regex.find_iter(query) {
                let hostname = cap.as_str();
                // Avoid matching common words that look like hostnames
                if !["example.com", "domain.com", "test.com"].contains(&hostname.to_lowercase().as_str()) {
                    entities.push(ExtractedEntity {
                        entity_type: EntityType::Hostname.as_str().to_string(),
                        value: hostname.to_string(),
                        start_pos: cap.start(),
                        end_pos: cap.end(),
                        confidence: 0.80,
                    });
                }
            }
        }

        // Extract severity keywords
        let query_lower = query.to_lowercase();
        for (keyword, severity) in &self.severity_keywords {
            if let Some(pos) = query_lower.find(keyword.as_str()) {
                entities.push(ExtractedEntity {
                    entity_type: EntityType::Severity.as_str().to_string(),
                    value: severity.clone(),
                    start_pos: pos,
                    end_pos: pos + keyword.len(),
                    confidence: 0.85,
                });
            }
        }

        // Extract status keywords
        for (keyword, status) in &self.status_keywords {
            if let Some(pos) = query_lower.find(keyword.as_str()) {
                entities.push(ExtractedEntity {
                    entity_type: EntityType::Status.as_str().to_string(),
                    value: status.clone(),
                    start_pos: pos,
                    end_pos: pos + keyword.len(),
                    confidence: 0.85,
                });
            }
        }

        // Extract service names
        let services = [
            "ssh", "http", "https", "ftp", "smtp", "mysql", "postgres",
            "mongodb", "redis", "elasticsearch", "nginx", "apache",
            "tomcat", "iis", "rdp", "smb", "dns", "ldap", "kerberos",
        ];
        for service in services {
            if let Some(pos) = query_lower.find(service) {
                // Check it's not part of a larger word
                let before_ok = pos == 0 || !query_lower.chars().nth(pos - 1).unwrap().is_alphanumeric();
                let after_ok = pos + service.len() >= query_lower.len()
                    || !query_lower.chars().nth(pos + service.len()).unwrap().is_alphanumeric();

                if before_ok && after_ok {
                    entities.push(ExtractedEntity {
                        entity_type: EntityType::Service.as_str().to_string(),
                        value: service.to_string(),
                        start_pos: pos,
                        end_pos: pos + service.len(),
                        confidence: 0.85,
                    });
                }
            }
        }

        entities
    }

    /// Build filters from extracted entities
    fn build_filters(&self, query: &str, entities: &[ExtractedEntity]) -> Vec<QueryFilter> {
        let mut filters = Vec::new();

        for entity in entities {
            let filter = match entity.entity_type.as_str() {
                "ip_address" => Some(QueryFilter {
                    field: "target_ip".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                "cve_id" => Some(QueryFilter {
                    field: "cve_id".to_string(),
                    operator: "contains".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                "port" => Some(QueryFilter {
                    field: "port".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::json!(entity.value.parse::<u16>().unwrap_or(0)),
                }),
                "severity" => Some(QueryFilter {
                    field: "severity".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                "status" => Some(QueryFilter {
                    field: "status".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                "service" => Some(QueryFilter {
                    field: "service".to_string(),
                    operator: "eq".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                "hostname" => Some(QueryFilter {
                    field: "hostname".to_string(),
                    operator: "contains".to_string(),
                    value: serde_json::json!(entity.value),
                }),
                _ => None,
            };

            if let Some(f) = filter {
                // Avoid duplicate filters
                if !filters.iter().any(|existing: &QueryFilter| existing.field == f.field && existing.value == f.value) {
                    filters.push(f);
                }
            }
        }

        // Add limit filter if mentioned
        if let Some(regex) = self.entity_patterns.get(&EntityType::Number) {
            if query.contains("top ") || query.contains("first ") {
                if let Some(cap) = regex.find(query) {
                    if let Ok(num) = cap.as_str().parse::<u32>() {
                        if num > 0 && num <= 1000 {
                            filters.push(QueryFilter {
                                field: "limit".to_string(),
                                operator: "eq".to_string(),
                                value: serde_json::json!(num),
                            });
                        }
                    }
                }
            }
        }

        filters
    }

    /// Extract time range from the query
    fn extract_time_range(&self, query: &str) -> Option<TimeRange> {
        // Check for relative time keywords
        for (keyword, duration) in &self.time_keywords {
            if query.contains(keyword.as_str()) {
                let now = Utc::now();
                return Some(TimeRange {
                    start: Some(now - *duration),
                    end: Some(now),
                    relative: Some(keyword.clone()),
                });
            }
        }

        // Check for date pattern matches
        if let Some(regex) = self.entity_patterns.get(&EntityType::Date) {
            let dates: Vec<_> = regex.find_iter(query).collect();

            if dates.len() == 1 {
                // Single date - search for that specific day
                if let Ok(date) = NaiveDate::parse_from_str(dates[0].as_str(), "%Y-%m-%d") {
                    let start = date.and_hms_opt(0, 0, 0).unwrap().and_utc();
                    let end = date.and_hms_opt(23, 59, 59).unwrap().and_utc();
                    return Some(TimeRange {
                        start: Some(start),
                        end: Some(end),
                        relative: None,
                    });
                }
            } else if dates.len() >= 2 {
                // Date range
                if let (Ok(start_date), Ok(end_date)) = (
                    NaiveDate::parse_from_str(dates[0].as_str(), "%Y-%m-%d"),
                    NaiveDate::parse_from_str(dates[1].as_str(), "%Y-%m-%d"),
                ) {
                    let start = start_date.and_hms_opt(0, 0, 0).unwrap().and_utc();
                    let end = end_date.and_hms_opt(23, 59, 59).unwrap().and_utc();
                    return Some(TimeRange {
                        start: Some(start),
                        end: Some(end),
                        relative: None,
                    });
                }
            }
        }

        None
    }

    /// Calculate overall confidence in the parsing
    fn calculate_confidence(&self, query: &str, entities: &[ExtractedEntity], intent_confidence: f64) -> f64 {
        let mut confidence = intent_confidence;

        // Boost confidence if we extracted entities
        if !entities.is_empty() {
            confidence += 0.10;
        }

        // Boost for specific entity types
        for entity in entities {
            match entity.entity_type.as_str() {
                "cve_id" => confidence += 0.05,
                "ip_address" => confidence += 0.05,
                "severity" => confidence += 0.03,
                _ => {}
            }
        }

        // Reduce confidence for very short or very long queries
        let word_count = query.split_whitespace().count();
        if word_count < 2 {
            confidence -= 0.10;
        } else if word_count > 30 {
            confidence -= 0.15;
        }

        confidence.min(1.0).max(0.0)
    }
}

impl Default for QueryParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Query result suggestion
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QuerySuggestion {
    pub original_query: String,
    pub suggested_query: String,
    pub explanation: String,
    pub confidence: f64,
}

impl QueryParser {
    /// Generate query suggestions for better results
    pub fn suggest_improvements(&self, query: &str, parsed: &ParsedIntent) -> Vec<QuerySuggestion> {
        let mut suggestions = Vec::new();

        // Suggest adding severity filter if not present
        let has_severity = parsed.entities.iter()
            .any(|e| e.entity_type == "severity");

        if !has_severity && parsed.query_type == AIQueryType::Search {
            suggestions.push(QuerySuggestion {
                original_query: query.to_string(),
                suggested_query: format!("{} severity critical", query),
                explanation: "Try filtering by severity for more focused results".to_string(),
                confidence: 0.70,
            });
        }

        // Suggest adding time range if not present
        if parsed.time_range.is_none() {
            suggestions.push(QuerySuggestion {
                original_query: query.to_string(),
                suggested_query: format!("{} last 30 days", query),
                explanation: "Consider adding a time range to narrow results".to_string(),
                confidence: 0.65,
            });
        }

        // Suggest analysis if just searching
        if parsed.query_type == AIQueryType::Search && query.len() > 20 {
            suggestions.push(QuerySuggestion {
                original_query: query.to_string(),
                suggested_query: format!("analyze {}", query),
                explanation: "Use 'analyze' for statistical insights".to_string(),
                confidence: 0.60,
            });
        }

        suggestions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        let parser = QueryParser::new();
        let result = parser.parse("show critical vulnerabilities").unwrap();

        assert_eq!(result.query_type, AIQueryType::Search);
        assert!(result.entities.iter().any(|e| e.entity_type == "severity" && e.value == "critical"));
    }

    #[test]
    fn test_parse_cve_query() {
        let parser = QueryParser::new();
        let result = parser.parse("find all hosts affected by CVE-2024-1234").unwrap();

        assert!(result.entities.iter().any(|e| e.entity_type == "cve_id" && e.value == "CVE-2024-1234"));
    }

    #[test]
    fn test_parse_ip_query() {
        let parser = QueryParser::new();
        let result = parser.parse("show vulnerabilities for 192.168.1.100").unwrap();

        assert!(result.entities.iter().any(|e| e.entity_type == "ip_address" && e.value == "192.168.1.100"));
    }

    #[test]
    fn test_parse_time_range() {
        let parser = QueryParser::new();
        let result = parser.parse("show critical issues from last week").unwrap();

        assert!(result.time_range.is_some());
        let time_range = result.time_range.unwrap();
        assert_eq!(time_range.relative, Some("last week".to_string()));
    }

    #[test]
    fn test_intent_detection() {
        let parser = QueryParser::new();

        let search_result = parser.parse("find all ssh servers").unwrap();
        assert_eq!(search_result.query_type, AIQueryType::Search);

        let analysis_result = parser.parse("how many critical vulnerabilities do we have").unwrap();
        assert_eq!(analysis_result.query_type, AIQueryType::Analysis);

        let remediation_result = parser.parse("how to fix CVE-2024-1234").unwrap();
        assert_eq!(remediation_result.query_type, AIQueryType::Remediation);
    }

    #[test]
    fn test_service_extraction() {
        let parser = QueryParser::new();
        let result = parser.parse("show vulnerabilities on ssh and mysql services").unwrap();

        let services: Vec<_> = result.entities.iter()
            .filter(|e| e.entity_type == "service")
            .map(|e| e.value.as_str())
            .collect();

        assert!(services.contains(&"ssh"));
        assert!(services.contains(&"mysql"));
    }
}
