use crate::investigation::types::{TimelineEvent, TemporalPattern};
use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

/// Reconstruct attack timeline from events
pub async fn reconstruct_attack_timeline(
    events: Vec<TimelineEvent>,
) -> Result<Vec<TimelineEvent>> {
    // Sort events by timestamp
    let mut sorted_events = events;
    sorted_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Group and correlate related events using ML-based correlation
    let correlated_events = correlate_events(&sorted_events).await?;

    // Identify attack phases and enrich events with phase information
    let enriched_events = identify_attack_phases(&correlated_events).await?;

    Ok(enriched_events)
}

/// Correlate events based on similarity, timing, and entity relationships
async fn correlate_events(events: &[TimelineEvent]) -> Result<Vec<TimelineEvent>> {
    let mut correlated = events.to_vec();

    // Build entity index for quick lookups
    let mut entity_events: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, event) in events.iter().enumerate() {
        if let Some(entities_json) = &event.entities {
            if let Ok(entities) = serde_json::from_str::<Vec<String>>(entities_json) {
                for entity in entities {
                    entity_events.entry(entity).or_default().push(idx);
                }
            }
        }
    }

    // Calculate correlation scores between events
    for i in 0..correlated.len() {
        let mut correlation_tags = Vec::new();

        // Time-based correlation: events within 5 minutes are likely related
        for j in 0..correlated.len() {
            if i == j {
                continue;
            }

            let time_diff = (correlated[i].timestamp - correlated[j].timestamp).num_seconds().abs();

            // Events within 5 minutes
            if time_diff < 300 {
                // Check for shared entities
                if let (Some(entities_i), Some(entities_j)) = (&correlated[i].entities, &correlated[j].entities) {
                    if let (Ok(e_i), Ok(e_j)) = (
                        serde_json::from_str::<Vec<String>>(entities_i),
                        serde_json::from_str::<Vec<String>>(entities_j),
                    ) {
                        let shared: Vec<_> = e_i.iter().filter(|e| e_j.contains(e)).collect();
                        if !shared.is_empty() {
                            correlation_tags.push(format!("correlated_with:{}", correlated[j].id));
                        }
                    }
                }

                // Same event type within time window suggests a pattern
                if correlated[i].event_type == correlated[j].event_type {
                    correlation_tags.push("repeated_activity".to_string());
                }
            }
        }

        // Update tags with correlation information
        if !correlation_tags.is_empty() {
            let existing_tags: Vec<String> = correlated[i].tags
                .as_ref()
                .and_then(|t| serde_json::from_str(t).ok())
                .unwrap_or_default();

            let mut all_tags = existing_tags;
            all_tags.extend(correlation_tags);
            all_tags.dedup();

            correlated[i].tags = Some(serde_json::to_string(&all_tags)?);
        }
    }

    Ok(correlated)
}

/// Identify attack phases (Reconnaissance, Initial Access, Execution, etc.)
async fn identify_attack_phases(events: &[TimelineEvent]) -> Result<Vec<TimelineEvent>> {
    let mut enriched = events.to_vec();

    for event in enriched.iter_mut() {
        let phase = determine_attack_phase(&event.event_type, &event.description);

        // Add phase to tags
        let mut tags: Vec<String> = event.tags
            .as_ref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or_default();

        tags.push(format!("phase:{}", phase));
        event.tags = Some(serde_json::to_string(&tags)?);
    }

    Ok(enriched)
}

/// Determine attack phase based on event characteristics
fn determine_attack_phase(event_type: &str, description: &str) -> &'static str {
    let event_lower = event_type.to_lowercase();
    let desc_lower = description.to_lowercase();

    if event_lower.contains("scan") || event_lower.contains("recon") ||
       desc_lower.contains("enumeration") || desc_lower.contains("discovery") {
        "reconnaissance"
    } else if event_lower.contains("exploit") || desc_lower.contains("initial access") ||
              desc_lower.contains("phishing") || desc_lower.contains("spearphish") {
        "initial_access"
    } else if event_lower.contains("exec") || desc_lower.contains("command") ||
              desc_lower.contains("powershell") || desc_lower.contains("script") {
        "execution"
    } else if event_lower.contains("persist") || desc_lower.contains("registry") ||
              desc_lower.contains("scheduled task") || desc_lower.contains("service") {
        "persistence"
    } else if event_lower.contains("priv") || desc_lower.contains("escalat") ||
              desc_lower.contains("sudo") || desc_lower.contains("admin") {
        "privilege_escalation"
    } else if event_lower.contains("evasi") || desc_lower.contains("obfuscat") ||
              desc_lower.contains("disable") || desc_lower.contains("clear log") {
        "defense_evasion"
    } else if event_lower.contains("cred") || desc_lower.contains("password") ||
              desc_lower.contains("dump") || desc_lower.contains("mimikatz") {
        "credential_access"
    } else if event_lower.contains("lateral") || desc_lower.contains("rdp") ||
              desc_lower.contains("ssh") || desc_lower.contains("psexec") {
        "lateral_movement"
    } else if event_lower.contains("collect") || desc_lower.contains("archive") ||
              desc_lower.contains("stage") || desc_lower.contains("compress") {
        "collection"
    } else if event_lower.contains("c2") || event_lower.contains("beacon") ||
              desc_lower.contains("command and control") || desc_lower.contains("callback") {
        "command_and_control"
    } else if event_lower.contains("exfil") || desc_lower.contains("upload") ||
              desc_lower.contains("transfer") || desc_lower.contains("steal") {
        "exfiltration"
    } else if event_lower.contains("impact") || desc_lower.contains("ransom") ||
              desc_lower.contains("encrypt") || desc_lower.contains("wipe") {
        "impact"
    } else {
        "unknown"
    }
}

/// Generate timeline visualization data
pub fn generate_timeline_visualization(
    events: &[TimelineEvent],
) -> Result<serde_json::Value> {
    // Generate swim lane visualization data
    let mut lanes: std::collections::HashMap<String, Vec<&TimelineEvent>> =
        std::collections::HashMap::new();

    for event in events {
        lanes.entry(event.event_type.clone())
            .or_insert_with(Vec::new)
            .push(event);
    }

    Ok(serde_json::json!({
        "lanes": lanes.into_iter().map(|(lane, events)| {
            serde_json::json!({
                "name": lane,
                "events": events.iter().map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "description": e.description,
                        "severity": e.severity
                    })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    }))
}

/// Export timeline to MITRE ATT&CK Navigator format
pub fn export_to_attack_navigator(
    events: &[TimelineEvent],
) -> Result<serde_json::Value> {
    // Map events to MITRE ATT&CK techniques
    let mut techniques: Vec<serde_json::Value> = Vec::new();
    let mut technique_counts: HashMap<&str, (u32, String)> = HashMap::new();

    for event in events {
        // Map event to ATT&CK techniques
        let mapped_techniques = map_event_to_techniques(&event.event_type, &event.description);

        for (technique_id, technique_name) in mapped_techniques {
            let entry = technique_counts.entry(technique_id).or_insert((0, technique_name.to_string()));
            entry.0 += 1;
        }
    }

    // Generate Navigator technique entries
    for (technique_id, (count, name)) in technique_counts {
        // Color intensity based on frequency (higher count = more red)
        let color = match count {
            1 => "#ffe766", // Yellow - single occurrence
            2..=3 => "#ff8c00", // Orange - few occurrences
            4..=10 => "#ff6666", // Light red - moderate
            _ => "#ff0000", // Red - many occurrences
        };

        techniques.push(serde_json::json!({
            "techniqueID": technique_id,
            "tactic": get_tactic_for_technique(technique_id),
            "color": color,
            "comment": format!("{} - Observed {} times", name, count),
            "enabled": true,
            "metadata": [],
            "links": [],
            "showSubtechniques": false
        }));
    }

    Ok(serde_json::json!({
        "name": "Investigation Timeline",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": format!("Attack timeline with {} events mapped to {} techniques",
                               events.len(), techniques.len()),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": true,
            "showName": true
        },
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff8c00", "#ff0000"],
            "minValue": 1,
            "maxValue": 10
        },
        "legendItems": [
            {"label": "Low frequency (1)", "color": "#ffe766"},
            {"label": "Medium frequency (2-3)", "color": "#ff8c00"},
            {"label": "High frequency (4+)", "color": "#ff0000"}
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": true,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": true,
        "selectSubtechniquesWithParent": false
    }))
}

/// Map event type and description to MITRE ATT&CK techniques
fn map_event_to_techniques<'a>(event_type: &str, description: &str) -> Vec<(&'a str, &'a str)> {
    let event_lower = event_type.to_lowercase();
    let desc_lower = description.to_lowercase();
    let mut techniques = Vec::new();

    // Reconnaissance
    if event_lower.contains("scan") || desc_lower.contains("port scan") {
        techniques.push(("T1046", "Network Service Scanning"));
    }
    if desc_lower.contains("whois") || desc_lower.contains("dns") {
        techniques.push(("T1596.002", "WHOIS"));
    }

    // Initial Access
    if desc_lower.contains("phish") || desc_lower.contains("spearphish") {
        techniques.push(("T1566", "Phishing"));
    }
    if desc_lower.contains("exploit") && desc_lower.contains("public") {
        techniques.push(("T1190", "Exploit Public-Facing Application"));
    }

    // Execution
    if desc_lower.contains("powershell") {
        techniques.push(("T1059.001", "PowerShell"));
    }
    if desc_lower.contains("cmd") || desc_lower.contains("command line") {
        techniques.push(("T1059.003", "Windows Command Shell"));
    }
    if desc_lower.contains("wmi") {
        techniques.push(("T1047", "Windows Management Instrumentation"));
    }
    if desc_lower.contains("python") || desc_lower.contains("script") {
        techniques.push(("T1059", "Command and Scripting Interpreter"));
    }

    // Persistence
    if desc_lower.contains("registry") && desc_lower.contains("run") {
        techniques.push(("T1547.001", "Registry Run Keys"));
    }
    if desc_lower.contains("scheduled task") || desc_lower.contains("cron") {
        techniques.push(("T1053", "Scheduled Task/Job"));
    }
    if desc_lower.contains("service") && (desc_lower.contains("create") || desc_lower.contains("install")) {
        techniques.push(("T1543", "Create or Modify System Process"));
    }

    // Privilege Escalation
    if desc_lower.contains("sudo") || desc_lower.contains("privilege") {
        techniques.push(("T1548", "Abuse Elevation Control Mechanism"));
    }
    if desc_lower.contains("token") && desc_lower.contains("impersonat") {
        techniques.push(("T1134", "Access Token Manipulation"));
    }

    // Defense Evasion
    if desc_lower.contains("obfuscat") || desc_lower.contains("encod") {
        techniques.push(("T1027", "Obfuscated Files or Information"));
    }
    if desc_lower.contains("disable") && (desc_lower.contains("antivirus") || desc_lower.contains("defender")) {
        techniques.push(("T1562.001", "Disable or Modify Tools"));
    }
    if desc_lower.contains("clear") && desc_lower.contains("log") {
        techniques.push(("T1070", "Indicator Removal"));
    }

    // Credential Access
    if desc_lower.contains("mimikatz") || desc_lower.contains("lsass") {
        techniques.push(("T1003.001", "LSASS Memory"));
    }
    if desc_lower.contains("keylog") {
        techniques.push(("T1056.001", "Keylogging"));
    }
    if desc_lower.contains("brute") || desc_lower.contains("password spray") {
        techniques.push(("T1110", "Brute Force"));
    }

    // Discovery
    if desc_lower.contains("system info") || desc_lower.contains("hostname") {
        techniques.push(("T1082", "System Information Discovery"));
    }
    if desc_lower.contains("process list") || desc_lower.contains("tasklist") {
        techniques.push(("T1057", "Process Discovery"));
    }
    if desc_lower.contains("domain") && desc_lower.contains("trust") {
        techniques.push(("T1482", "Domain Trust Discovery"));
    }

    // Lateral Movement
    if desc_lower.contains("rdp") || desc_lower.contains("remote desktop") {
        techniques.push(("T1021.001", "Remote Desktop Protocol"));
    }
    if desc_lower.contains("smb") || desc_lower.contains("psexec") {
        techniques.push(("T1021.002", "SMB/Windows Admin Shares"));
    }
    if desc_lower.contains("ssh") {
        techniques.push(("T1021.004", "SSH"));
    }
    if desc_lower.contains("wmi") && desc_lower.contains("remote") {
        techniques.push(("T1021.003", "Distributed Component Object Model"));
    }

    // Collection
    if desc_lower.contains("screenshot") {
        techniques.push(("T1113", "Screen Capture"));
    }
    if desc_lower.contains("clipboard") {
        techniques.push(("T1115", "Clipboard Data"));
    }
    if desc_lower.contains("archive") || desc_lower.contains("zip") || desc_lower.contains("rar") {
        techniques.push(("T1560", "Archive Collected Data"));
    }

    // Command and Control
    if desc_lower.contains("beacon") || desc_lower.contains("c2") {
        techniques.push(("T1071", "Application Layer Protocol"));
    }
    if desc_lower.contains("dns") && desc_lower.contains("tunnel") {
        techniques.push(("T1071.004", "DNS"));
    }
    if desc_lower.contains("proxy") || desc_lower.contains("tor") {
        techniques.push(("T1090", "Proxy"));
    }

    // Exfiltration
    if desc_lower.contains("exfil") {
        techniques.push(("T1041", "Exfiltration Over C2 Channel"));
    }
    if desc_lower.contains("cloud") && desc_lower.contains("storage") {
        techniques.push(("T1567.002", "Exfiltration to Cloud Storage"));
    }

    // Impact
    if desc_lower.contains("ransom") || desc_lower.contains("encrypt") {
        techniques.push(("T1486", "Data Encrypted for Impact"));
    }
    if desc_lower.contains("wipe") || desc_lower.contains("destruct") {
        techniques.push(("T1485", "Data Destruction"));
    }
    if desc_lower.contains("defac") {
        techniques.push(("T1491", "Defacement"));
    }

    // Return at least one generic technique if nothing matched
    if techniques.is_empty() {
        techniques.push(("T1204", "User Execution"));
    }

    techniques
}

/// Get the primary tactic for a technique ID
fn get_tactic_for_technique(technique_id: &str) -> &'static str {
    // Map technique IDs to their primary tactics
    match technique_id {
        t if t.starts_with("T1595") || t.starts_with("T1596") || t.starts_with("T1046") => "reconnaissance",
        t if t.starts_with("T1190") || t.starts_with("T1566") || t.starts_with("T1133") => "initial-access",
        t if t.starts_with("T1059") || t.starts_with("T1047") || t.starts_with("T1204") => "execution",
        t if t.starts_with("T1547") || t.starts_with("T1053") || t.starts_with("T1543") => "persistence",
        t if t.starts_with("T1548") || t.starts_with("T1134") => "privilege-escalation",
        t if t.starts_with("T1027") || t.starts_with("T1562") || t.starts_with("T1070") => "defense-evasion",
        t if t.starts_with("T1003") || t.starts_with("T1056") || t.starts_with("T1110") => "credential-access",
        t if t.starts_with("T1082") || t.starts_with("T1057") || t.starts_with("T1482") => "discovery",
        t if t.starts_with("T1021") => "lateral-movement",
        t if t.starts_with("T1113") || t.starts_with("T1115") || t.starts_with("T1560") => "collection",
        t if t.starts_with("T1071") || t.starts_with("T1090") => "command-and-control",
        t if t.starts_with("T1041") || t.starts_with("T1567") => "exfiltration",
        t if t.starts_with("T1486") || t.starts_with("T1485") || t.starts_with("T1491") => "impact",
        _ => "execution",
    }
}

/// Filter timeline events by criteria
pub fn filter_timeline(
    events: &[TimelineEvent],
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    event_types: Option<Vec<String>>,
    severity: Option<String>,
) -> Vec<TimelineEvent> {
    events.iter()
        .filter(|e| {
            if let Some(start) = start_time {
                if e.timestamp < start {
                    return false;
                }
            }
            if let Some(end) = end_time {
                if e.timestamp > end {
                    return false;
                }
            }
            if let Some(ref types) = event_types {
                if !types.contains(&e.event_type) {
                    return false;
                }
            }
            if let Some(ref sev) = severity {
                if &e.severity != sev {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}
