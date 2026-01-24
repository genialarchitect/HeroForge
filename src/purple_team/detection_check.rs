//! SIEM detection checking and alert correlation

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use uuid;

use super::types::*;
use crate::db::models::SiemSettings;

/// Checks SIEM for detection of attacks
pub struct DetectionChecker {
    pool: SqlitePool,
}

impl DetectionChecker {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Check if an attack was detected by the SIEM
    pub async fn check_detection(
        &self,
        siem_integration_id: &str,
        attack_result: &PurpleAttackResult,
        timeout_secs: u64,
    ) -> Result<DetectionStatus> {
        // Get SIEM settings
        let siem_settings = self.get_siem_settings(siem_integration_id).await?;

        // Wait for detection window
        tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)).await;

        // Query SIEM for alerts matching this attack
        let alerts = self.query_siem_alerts(
            &siem_settings,
            &attack_result.technique_id,
            attack_result.executed_at,
            attack_result.target.clone(),
        ).await?;

        // Determine detection status based on alerts found
        if alerts.is_empty() {
            Ok(DetectionStatus::NotDetected)
        } else if self.is_full_detection(&alerts, attack_result) {
            Ok(DetectionStatus::Detected)
        } else {
            Ok(DetectionStatus::PartiallyDetected)
        }
    }

    /// Get detection details including matched alerts
    pub async fn get_detection_details(
        &self,
        siem_integration_id: &str,
        attack_result: &PurpleAttackResult,
    ) -> Result<DetectionDetails> {
        let siem_settings = self.get_siem_settings(siem_integration_id).await?;

        let alerts = self.query_siem_alerts(
            &siem_settings,
            &attack_result.technique_id,
            attack_result.executed_at,
            attack_result.target.clone(),
        ).await?;

        let detection_time = alerts.first().map(|a| a.timestamp);
        let confidence = self.calculate_confidence(&alerts, attack_result);

        let log_sources: Vec<String> = alerts.iter()
            .filter_map(|a| Some(a.rule_name.clone()))
            .collect();

        Ok(DetectionDetails {
            alerts_matched: alerts,
            log_sources,
            detection_time,
            confidence,
        })
    }

    async fn get_siem_settings(&self, integration_id: &str) -> Result<SiemSettings> {
        // Query SIEM settings from database
        let settings: Option<SiemSettings> = sqlx::query_as(
            "SELECT * FROM siem_settings WHERE id = ?"
        )
        .bind(integration_id)
        .fetch_optional(&self.pool)
        .await?;

        settings.ok_or_else(|| anyhow::anyhow!("SIEM integration not found"))
    }

    async fn query_siem_alerts(
        &self,
        siem_settings: &SiemSettings,
        technique_id: &str,
        start_time: DateTime<Utc>,
        target: String,
    ) -> Result<Vec<MatchedAlert>> {
        let end_time = Utc::now();

        match siem_settings.siem_type.as_str() {
            "splunk" => {
                self.query_splunk(siem_settings, technique_id, start_time, end_time, &target).await
            }
            "elasticsearch" => {
                self.query_elasticsearch(siem_settings, technique_id, start_time, end_time, &target).await
            }
            "syslog" | _ => {
                // Syslog doesn't support querying - return empty
                Ok(vec![])
            }
        }
    }

    async fn query_splunk(
        &self,
        settings: &SiemSettings,
        technique_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        target: &str,
    ) -> Result<Vec<MatchedAlert>> {
        if !settings.enabled {
            return Ok(vec![]);
        }

        let query = format!(
            r#"search index=* earliest="{}" latest="{}" (mitre_attack_id="{}" OR technique_id="{}" OR dest="{}" OR src="{}") | table _time, rule_name, severity, description"#,
            start_time.format("%Y-%m-%dT%H:%M:%S"),
            end_time.format("%Y-%m-%dT%H:%M:%S"),
            technique_id,
            technique_id,
            target,
            target,
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Create search job via Splunk REST API
        let search_url = format!("{}/services/search/jobs", settings.endpoint_url.trim_end_matches('/'));

        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(ref api_key) = settings.api_key {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_key))
                    .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
            );
        }
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let response = client
            .post(&search_url)
            .headers(headers.clone())
            .form(&[
                ("search", query.as_str()),
                ("output_mode", "json"),
                ("exec_mode", "oneshot"),
                ("count", "50"),
            ])
            .send()
            .await;

        let response = match response {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to query Splunk at {}: {}", search_url, e);
                return Ok(vec![]);
            }
        };

        if !response.status().is_success() {
            log::warn!("Splunk query returned status {}", response.status());
            return Ok(vec![]);
        }

        let body: serde_json::Value = response.json().await.unwrap_or_default();

        // Parse Splunk JSON response
        let mut alerts = Vec::new();
        if let Some(results) = body.get("results").and_then(|r| r.as_array()) {
            for result in results {
                let timestamp_str = result.get("_time").and_then(|t| t.as_str()).unwrap_or("");
                let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                alerts.push(MatchedAlert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    rule_name: result.get("rule_name").and_then(|r| r.as_str()).unwrap_or("unknown").to_string(),
                    severity: result.get("severity").and_then(|s| s.as_str()).unwrap_or("medium").to_string(),
                    timestamp,
                    description: result.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                });
            }
        }

        log::info!("Splunk query returned {} alerts for technique {}", alerts.len(), technique_id);
        Ok(alerts)
    }

    async fn query_elasticsearch(
        &self,
        settings: &SiemSettings,
        technique_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        target: &str,
    ) -> Result<Vec<MatchedAlert>> {
        if !settings.enabled {
            return Ok(vec![]);
        }

        let query = serde_json::json!({
            "size": 50,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.to_rfc3339(),
                                    "lte": end_time.to_rfc3339()
                                }
                            }
                        }
                    ],
                    "should": [
                        { "match": { "mitre.technique.id": technique_id } },
                        { "match": { "threat.technique.id": technique_id } },
                        { "match": { "destination.ip": target } },
                        { "match": { "source.ip": target } }
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{ "@timestamp": { "order": "desc" } }]
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let search_url = format!("{}/_search", settings.endpoint_url.trim_end_matches('/'));

        let mut request = client.post(&search_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&query);

        if let Some(ref api_key) = settings.api_key {
            request = request.header(reqwest::header::AUTHORIZATION, format!("ApiKey {}", api_key));
        }

        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Failed to query Elasticsearch at {}: {}", search_url, e);
                return Ok(vec![]);
            }
        };

        if !response.status().is_success() {
            log::warn!("Elasticsearch query returned status {}", response.status());
            return Ok(vec![]);
        }

        let body: serde_json::Value = response.json().await.unwrap_or_default();

        // Parse Elasticsearch response
        let mut alerts = Vec::new();
        if let Some(hits) = body.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
            for hit in hits {
                let source = hit.get("_source").unwrap_or(&serde_json::Value::Null);

                let timestamp_str = source.get("@timestamp")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                let rule_name = source.get("rule")
                    .and_then(|r| r.get("name"))
                    .and_then(|n| n.as_str())
                    .or_else(|| source.get("event").and_then(|e| e.get("action")).and_then(|a| a.as_str()))
                    .unwrap_or("unknown")
                    .to_string();

                let severity = source.get("event")
                    .and_then(|e| e.get("severity"))
                    .and_then(|s| s.as_str())
                    .or_else(|| source.get("log").and_then(|l| l.get("level")).and_then(|l| l.as_str()))
                    .unwrap_or("medium")
                    .to_string();

                let description = source.get("message")
                    .and_then(|m| m.as_str())
                    .or_else(|| source.get("event").and_then(|e| e.get("original")).and_then(|o| o.as_str()))
                    .unwrap_or("")
                    .to_string();

                alerts.push(MatchedAlert {
                    alert_id: hit.get("_id").and_then(|i| i.as_str()).unwrap_or("").to_string(),
                    rule_name,
                    severity,
                    timestamp,
                    description,
                });
            }
        }

        log::info!("Elasticsearch query returned {} alerts for technique {}", alerts.len(), technique_id);
        Ok(alerts)
    }

    fn is_full_detection(&self, alerts: &[MatchedAlert], attack_result: &PurpleAttackResult) -> bool {
        // Check if alerts indicate full detection of the attack
        // This is a simplified check - in production would be more sophisticated

        if alerts.is_empty() {
            return false;
        }

        // Check if any alert has high severity
        let has_high_severity = alerts.iter().any(|a| {
            a.severity.to_lowercase() == "high" ||
            a.severity.to_lowercase() == "critical"
        });

        // Check if alert description mentions the technique
        let mentions_technique = alerts.iter().any(|a| {
            a.description.to_lowercase().contains(&attack_result.technique_name.to_lowercase()) ||
            a.rule_name.to_lowercase().contains(&attack_result.technique_id.to_lowercase())
        });

        has_high_severity || mentions_technique
    }

    fn calculate_confidence(&self, alerts: &[MatchedAlert], _attack_result: &PurpleAttackResult) -> f32 {
        if alerts.is_empty() {
            return 0.0;
        }

        let mut confidence = 0.0;

        // Base confidence from number of alerts
        confidence += (alerts.len() as f32 * 0.2).min(0.6);

        // Bonus for high severity alerts
        let high_severity_count = alerts.iter().filter(|a| {
            a.severity.to_lowercase() == "high" ||
            a.severity.to_lowercase() == "critical"
        }).count();
        confidence += (high_severity_count as f32 * 0.15).min(0.3);

        // Bonus for quick detection (within 60 seconds)
        if alerts.first().map_or(false, |a| {
            (Utc::now() - a.timestamp) < Duration::seconds(60)
        }) {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }
}

/// Generate detection rules for a technique
pub fn generate_sigma_rule(technique: &MitreTechnique, attack_type: &str) -> String {
    let rule = format!(
        r#"title: Detection for {name}
id: {id}
status: experimental
description: Detects {name} ({technique_id})
references:
    - https://attack.mitre.org/techniques/{technique_id}/
author: HeroForge Purple Team
date: {date}
tags:
    - attack.{tactic}
    - attack.{technique_id}
logsource:
    category: {category}
    product: windows
detection:
    selection:
        {detection_logic}
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: medium
"#,
        name = technique.name,
        id = uuid::Uuid::new_v4(),
        technique_id = technique.id,
        date = Utc::now().format("%Y/%m/%d"),
        tactic = format!("{:?}", technique.tactic).to_lowercase(),
        category = get_log_category(attack_type),
        detection_logic = get_detection_logic(attack_type),
    );

    rule
}

/// Generate Splunk SPL query for a technique
pub fn generate_splunk_query(technique: &MitreTechnique, attack_type: &str) -> String {
    match attack_type {
        "kerberoast" => format!(
            r#"index=windows EventCode=4769 ServiceName!="krbtgt" ServiceName!="*$" TicketEncryptionType=0x17
| stats count by Account_Name, ServiceName, Client_Address
| where count > 1
| eval mitre_attack_id="{}"
| table _time, Account_Name, ServiceName, Client_Address, mitre_attack_id"#,
            technique.id
        ),
        "asrep_roast" => format!(
            r#"index=windows EventCode=4768 PreAuthType=0
| stats count by Account_Name, Client_Address
| eval mitre_attack_id="{}"
| table _time, Account_Name, Client_Address, mitre_attack_id"#,
            technique.id
        ),
        "password_spray" => format!(
            r#"index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, TargetUserName, IpAddress
| where count > 5
| eval mitre_attack_id="{}"
| table _time, TargetUserName, IpAddress, count, mitre_attack_id"#,
            technique.id
        ),
        "dcsync" => format!(
            r#"index=windows EventCode=4662 AccessMask=0x100
Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| eval mitre_attack_id="{}"
| table _time, SubjectUserName, ObjectName, mitre_attack_id"#,
            technique.id
        ),
        _ => format!(
            r#"index=* mitre_attack_id="{}" OR technique_id="{}"
| table _time, src, dest, action, mitre_attack_id"#,
            technique.id, technique.id
        ),
    }
}

/// Generate Elasticsearch query for a technique
pub fn generate_elastic_query(technique: &MitreTechnique, attack_type: &str) -> String {
    let query = match attack_type {
        "kerberoast" => serde_json::json!({
            "query": {
                "bool": {
                    "must": [
                        { "match": { "event.code": "4769" } },
                        { "match": { "winlog.event_data.TicketEncryptionType": "0x17" } }
                    ],
                    "must_not": [
                        { "wildcard": { "winlog.event_data.ServiceName": "*$" } },
                        { "match": { "winlog.event_data.ServiceName": "krbtgt" } }
                    ]
                }
            },
            "aggs": {
                "by_account": {
                    "terms": { "field": "winlog.event_data.TargetUserName.keyword" }
                }
            }
        }),
        "password_spray" => serde_json::json!({
            "query": {
                "bool": {
                    "must": [
                        { "match": { "event.code": "4625" } },
                        { "range": { "@timestamp": { "gte": "now-5m" } } }
                    ]
                }
            },
            "aggs": {
                "by_source": {
                    "terms": { "field": "source.ip" },
                    "aggs": {
                        "unique_users": {
                            "cardinality": { "field": "user.name.keyword" }
                        }
                    }
                }
            }
        }),
        _ => serde_json::json!({
            "query": {
                "bool": {
                    "should": [
                        { "match": { "threat.technique.id": technique.id } },
                        { "match": { "mitre.technique.id": technique.id } }
                    ]
                }
            }
        }),
    };

    serde_json::to_string_pretty(&query).unwrap_or_default()
}

fn get_log_category(attack_type: &str) -> &'static str {
    match attack_type {
        "kerberoast" | "asrep_roast" | "dcsync" => "authentication",
        "password_spray" => "authentication",
        "credential_dump" => "process_creation",
        "lateral_movement" | "pass_the_hash" => "network_connection",
        "persistence" | "scheduled_task" => "process_creation",
        _ => "process_creation",
    }
}

fn get_detection_logic(attack_type: &str) -> &'static str {
    match attack_type {
        "kerberoast" => "EventID: 4769\n        TicketEncryptionType: 0x17",
        "asrep_roast" => "EventID: 4768\n        PreAuthType: 0",
        "password_spray" => "EventID: 4625\n        # Multiple failed logins from same source",
        "dcsync" => "EventID: 4662\n        AccessMask: 0x100",
        "credential_dump" => "TargetImage|endswith: 'lsass.exe'\n        GrantedAccess|contains: '0x1010'",
        "pass_the_hash" => "LogonType: 9\n        LogonProcessName: 'seclogo'",
        _ => "# Add detection logic for this technique",
    }
}
