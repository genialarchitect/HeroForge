use crate::investigation::types::MemoryArtifact;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

/// Extract all artifacts from memory analysis
pub fn extract_artifacts(
    investigation_id: &str,
    processes: &[serde_json::Value],
    network: &[serde_json::Value],
) -> Result<Vec<MemoryArtifact>> {
    let mut artifacts = Vec::new();

    // Process artifacts
    for process in processes {
        artifacts.push(MemoryArtifact {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            artifact_type: "Process".to_string(),
            name: process.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            pid: process.get("pid").and_then(|v| v.as_i64()),
            data: Some(process.to_string()),
            suspicious: false,
            indicators: None,
            created_at: Utc::now(),
        });
    }

    // Network artifacts
    for conn in network {
        artifacts.push(MemoryArtifact {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            artifact_type: "Network".to_string(),
            name: format!("Connection to {}", conn.get("remote_addr").and_then(|v| v.as_str()).unwrap_or("Unknown")),
            pid: conn.get("pid").and_then(|v| v.as_i64()),
            data: Some(conn.to_string()),
            suspicious: false,
            indicators: None,
            created_at: Utc::now(),
        });
    }

    Ok(artifacts)
}

/// Analyze artifacts for suspicious indicators
pub fn analyze_artifacts(artifacts: &mut [MemoryArtifact]) -> Result<()> {
    for artifact in artifacts.iter_mut() {
        let mut indicators = Vec::new();

        match artifact.artifact_type.as_str() {
            "Process" => {
                // Check for suspicious process characteristics
                if artifact.name.ends_with(".tmp.exe") {
                    indicators.push("Temporary executable name".to_string());
                    artifact.suspicious = true;
                }
                if artifact.name.contains("powershell") && artifact.name.contains("-enc") {
                    indicators.push("Encoded PowerShell command".to_string());
                    artifact.suspicious = true;
                }
            }
            "Network" => {
                // Check for suspicious network activity
                if let Some(data) = &artifact.data {
                    if data.contains("443") || data.contains("8443") {
                        indicators.push("HTTPS connection".to_string());
                    }
                }
            }
            _ => {}
        }

        if !indicators.is_empty() {
            artifact.indicators = Some(serde_json::to_string(&indicators)?);
        }
    }

    Ok(())
}
