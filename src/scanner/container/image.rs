//! Docker Image Vulnerability Scanner
//!
//! This module provides functionality to scan Docker images for:
//! - Known vulnerabilities (CVEs) in packages
//! - Outdated base images
//! - Package versioning issues
//!
//! For real scanning, it integrates with trivy or grype if available.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::process::Command;
use uuid::Uuid;

use super::types::{
    ContainerFinding, ContainerFindingSeverity, ContainerFindingType, ContainerImage,
    ContainerScanConfig, FindingStatus,
};

/// Scan Docker images for vulnerabilities (real implementation)
pub async fn scan_images(
    config: &ContainerScanConfig,
) -> Result<(Vec<ContainerImage>, Vec<ContainerFinding>)> {
    let mut images = Vec::new();
    let mut findings = Vec::new();

    for image_ref in &config.images {
        log::info!("Scanning image: {}", image_ref);

        // Try to use trivy first, fall back to grype, then to basic inspection
        let (image, image_findings) = if is_trivy_available() {
            scan_with_trivy(image_ref).await?
        } else if is_grype_available() {
            scan_with_grype(image_ref).await?
        } else {
            // Basic inspection using docker inspect
            scan_with_docker_inspect(image_ref).await?
        };

        images.push(image);
        findings.extend(image_findings);
    }

    Ok((images, findings))
}


/// Check if trivy is available
fn is_trivy_available() -> bool {
    Command::new("trivy")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if grype is available
fn is_grype_available() -> bool {
    Command::new("grype")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Scan image using Trivy
async fn scan_with_trivy(
    image_ref: &str,
) -> Result<(ContainerImage, Vec<ContainerFinding>)> {
    log::info!("Using Trivy to scan: {}", image_ref);

    let scan_id = Uuid::new_v4().to_string();
    let image_id = Uuid::new_v4().to_string();

    // Run trivy with JSON output
    let output = Command::new("trivy")
        .args([
            "image",
            "--format", "json",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            image_ref,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Trivy scan failed: {}", stderr);
        // Return empty results
        let (repo, tag) = parse_image_ref(image_ref);
        return Ok((
            ContainerImage {
                id: image_id,
                scan_id,
                image_ref: image_ref.to_string(),
                digest: None,
                registry: None,
                repository: repo,
                tag,
                os: None,
                architecture: None,
                created: None,
                size_bytes: None,
                layer_count: 0,
                labels: HashMap::new(),
                vuln_count: 0,
                critical_count: 0,
                high_count: 0,
                discovered_at: Utc::now(),
            },
            Vec::new(),
        ));
    }

    // Parse trivy JSON output
    let trivy_result: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    let (repo, tag) = parse_image_ref(image_ref);
    let mut findings = Vec::new();

    // Extract metadata
    let metadata = trivy_result.get("Metadata").and_then(|m| m.as_object());
    let os = metadata
        .and_then(|m| m.get("OS"))
        .and_then(|o| o.get("Family"))
        .and_then(|f| f.as_str())
        .map(String::from);
    let digest = metadata
        .and_then(|m| m.get("RepoDigests"))
        .and_then(|d| d.as_array())
        .and_then(|a| a.first())
        .and_then(|d| d.as_str())
        .map(String::from);

    // Parse vulnerabilities
    if let Some(results) = trivy_result.get("Results").and_then(|r| r.as_array()) {
        for result in results {
            if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    let finding = parse_trivy_vulnerability(&image_id, &scan_id, vuln);
                    findings.push(finding);
                }
            }
        }
    }

    let mut critical_count = 0;
    let mut high_count = 0;
    for f in &findings {
        match f.severity {
            ContainerFindingSeverity::Critical => critical_count += 1,
            ContainerFindingSeverity::High => high_count += 1,
            _ => {}
        }
    }

    let image = ContainerImage {
        id: image_id,
        scan_id,
        image_ref: image_ref.to_string(),
        digest,
        registry: None,
        repository: repo,
        tag,
        os,
        architecture: Some("amd64".to_string()),
        created: None,
        size_bytes: None,
        layer_count: 0,
        labels: HashMap::new(),
        vuln_count: findings.len() as i32,
        critical_count,
        high_count,
        discovered_at: Utc::now(),
    };

    Ok((image, findings))
}

/// Parse a Trivy vulnerability into our finding format
fn parse_trivy_vulnerability(
    image_id: &str,
    scan_id: &str,
    vuln: &serde_json::Value,
) -> ContainerFinding {
    let cve_id = vuln.get("VulnerabilityID")
        .and_then(|v| v.as_str())
        .map(String::from);

    let severity_str = vuln.get("Severity")
        .and_then(|s| s.as_str())
        .unwrap_or("UNKNOWN");

    let severity = match severity_str.to_uppercase().as_str() {
        "CRITICAL" => ContainerFindingSeverity::Critical,
        "HIGH" => ContainerFindingSeverity::High,
        "MEDIUM" => ContainerFindingSeverity::Medium,
        "LOW" => ContainerFindingSeverity::Low,
        _ => ContainerFindingSeverity::Info,
    };

    let cvss_score = vuln.get("CVSS")
        .and_then(|c| c.as_object())
        .and_then(|c| c.values().next())
        .and_then(|v| v.get("V3Score"))
        .and_then(|s| s.as_f64());

    let package_name = vuln.get("PkgName")
        .and_then(|p| p.as_str())
        .map(String::from);

    let package_version = vuln.get("InstalledVersion")
        .and_then(|v| v.as_str())
        .map(String::from);

    let fixed_version = vuln.get("FixedVersion")
        .and_then(|v| v.as_str())
        .map(String::from);

    let title = vuln.get("Title")
        .and_then(|t| t.as_str())
        .unwrap_or(&cve_id.clone().unwrap_or_default())
        .to_string();

    let description = vuln.get("Description")
        .and_then(|d| d.as_str())
        .unwrap_or("No description available")
        .to_string();

    let references: Vec<String> = vuln.get("References")
        .and_then(|r| r.as_array())
        .map(|refs| refs.iter().filter_map(|r| r.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let cwe_ids: Vec<String> = vuln.get("CweIDs")
        .and_then(|c| c.as_array())
        .map(|cwes| cwes.iter().filter_map(|c| c.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let remediation = Some(format!(
        "Update the affected package to version {} or later",
        fixed_version.clone().unwrap_or_else(|| "latest".to_string())
    ));

    ContainerFinding {
        id: Uuid::new_v4().to_string(),
        scan_id: scan_id.to_string(),
        image_id: Some(image_id.to_string()),
        resource_id: None,
        finding_type: ContainerFindingType::Vulnerability,
        severity,
        title,
        description,
        cve_id,
        cvss_score,
        cwe_ids,
        package_name,
        package_version,
        fixed_version,
        file_path: None,
        line_number: None,
        remediation,
        references,
        status: FindingStatus::Open,
        created_at: Utc::now(),
    }
}

/// Scan image using Grype
async fn scan_with_grype(
    image_ref: &str,
) -> Result<(ContainerImage, Vec<ContainerFinding>)> {
    log::info!("Using Grype to scan: {}", image_ref);

    let scan_id = Uuid::new_v4().to_string();
    let image_id = Uuid::new_v4().to_string();

    let output = Command::new("grype")
        .args([image_ref, "-o", "json"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Grype scan failed: {}", stderr);
        let (repo, tag) = parse_image_ref(image_ref);
        return Ok((
            ContainerImage {
                id: image_id,
                scan_id,
                image_ref: image_ref.to_string(),
                digest: None,
                registry: None,
                repository: repo,
                tag,
                os: None,
                architecture: None,
                created: None,
                size_bytes: None,
                layer_count: 0,
                labels: HashMap::new(),
                vuln_count: 0,
                critical_count: 0,
                high_count: 0,
                discovered_at: Utc::now(),
            },
            Vec::new(),
        ));
    }

    let grype_result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let (repo, tag) = parse_image_ref(image_ref);
    let mut findings = Vec::new();

    // Parse grype matches
    if let Some(matches) = grype_result.get("matches").and_then(|m| m.as_array()) {
        for m in matches {
            let finding = parse_grype_match(&image_id, &scan_id, m);
            findings.push(finding);
        }
    }

    let mut critical_count = 0;
    let mut high_count = 0;
    for f in &findings {
        match f.severity {
            ContainerFindingSeverity::Critical => critical_count += 1,
            ContainerFindingSeverity::High => high_count += 1,
            _ => {}
        }
    }

    let image = ContainerImage {
        id: image_id,
        scan_id,
        image_ref: image_ref.to_string(),
        digest: None,
        registry: None,
        repository: repo,
        tag,
        os: None,
        architecture: None,
        created: None,
        size_bytes: None,
        layer_count: 0,
        labels: HashMap::new(),
        vuln_count: findings.len() as i32,
        critical_count,
        high_count,
        discovered_at: Utc::now(),
    };

    Ok((image, findings))
}

/// Parse a Grype match into our finding format
fn parse_grype_match(
    image_id: &str,
    scan_id: &str,
    m: &serde_json::Value,
) -> ContainerFinding {
    let vulnerability = m.get("vulnerability").unwrap_or(m);

    let cve_id = vulnerability.get("id")
        .and_then(|v| v.as_str())
        .map(String::from);

    let severity_str = vulnerability.get("severity")
        .and_then(|s| s.as_str())
        .unwrap_or("Unknown");

    let severity = match severity_str.to_lowercase().as_str() {
        "critical" => ContainerFindingSeverity::Critical,
        "high" => ContainerFindingSeverity::High,
        "medium" => ContainerFindingSeverity::Medium,
        "low" => ContainerFindingSeverity::Low,
        _ => ContainerFindingSeverity::Info,
    };

    let artifact = m.get("artifact");
    let package_name = artifact
        .and_then(|a| a.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from);
    let package_version = artifact
        .and_then(|a| a.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let fixed_version = vulnerability.get("fix")
        .and_then(|f| f.get("versions"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(String::from);

    let description = vulnerability.get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("No description available")
        .to_string();

    let urls: Vec<String> = vulnerability.get("urls")
        .and_then(|u| u.as_array())
        .map(|urls| urls.iter().filter_map(|u| u.as_str().map(String::from)).collect())
        .unwrap_or_default();

    ContainerFinding {
        id: Uuid::new_v4().to_string(),
        scan_id: scan_id.to_string(),
        image_id: Some(image_id.to_string()),
        resource_id: None,
        finding_type: ContainerFindingType::Vulnerability,
        severity,
        title: cve_id.clone().unwrap_or_else(|| "Unknown Vulnerability".to_string()),
        description,
        cve_id,
        cvss_score: None,
        cwe_ids: Vec::new(),
        package_name,
        package_version,
        fixed_version: fixed_version.clone(),
        file_path: None,
        line_number: None,
        remediation: Some(format!(
            "Update to version {} or later",
            fixed_version.unwrap_or_else(|| "latest".to_string())
        )),
        references: urls,
        status: FindingStatus::Open,
        created_at: Utc::now(),
    }
}

/// Basic scanning using docker inspect
async fn scan_with_docker_inspect(
    image_ref: &str,
) -> Result<(ContainerImage, Vec<ContainerFinding>)> {
    log::info!("Using docker inspect for: {}", image_ref);

    let scan_id = Uuid::new_v4().to_string();
    let image_id = Uuid::new_v4().to_string();
    let (repo, tag) = parse_image_ref(image_ref);

    // Try to get image info
    let output = Command::new("docker")
        .args(["inspect", image_ref])
        .output();

    let (os, architecture, created, size_bytes, digest) = match output {
        Ok(o) if o.status.success() => {
            let info: serde_json::Value = serde_json::from_slice(&o.stdout)?;
            if let Some(first) = info.as_array().and_then(|a| a.first()) {
                let os = first.get("Os").and_then(|v| v.as_str()).map(String::from);
                let arch = first.get("Architecture").and_then(|v| v.as_str()).map(String::from);
                let created = first.get("Created").and_then(|v| v.as_str()).and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
                });
                let size = first.get("Size").and_then(|v| v.as_i64());
                let digest = first.get("RepoDigests")
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.first())
                    .and_then(|d| d.as_str())
                    .map(String::from);
                (os, arch, created, size, digest)
            } else {
                (None, None, None, None, None)
            }
        }
        _ => (None, None, None, None, None),
    };

    let image = ContainerImage {
        id: image_id,
        scan_id,
        image_ref: image_ref.to_string(),
        digest,
        registry: None,
        repository: repo,
        tag,
        os,
        architecture,
        created,
        size_bytes,
        layer_count: 0,
        labels: HashMap::new(),
        vuln_count: 0,
        critical_count: 0,
        high_count: 0,
        discovered_at: Utc::now(),
    };

    // Without trivy/grype, we can't detect vulnerabilities
    // Just return the image info
    Ok((image, Vec::new()))
}

/// Parse image reference into repository and tag
fn parse_image_ref(image_ref: &str) -> (String, String) {
    if let Some(idx) = image_ref.rfind(':') {
        // Check if this is a port number (registry:port/image)
        let after_colon = &image_ref[idx + 1..];
        if !after_colon.contains('/') && !after_colon.parse::<u16>().is_ok() {
            return (
                image_ref[..idx].to_string(),
                after_colon.to_string(),
            );
        }
    }
    (image_ref.to_string(), "latest".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_ref() {
        assert_eq!(
            parse_image_ref("nginx:1.21.0"),
            ("nginx".to_string(), "1.21.0".to_string())
        );
        assert_eq!(
            parse_image_ref("nginx"),
            ("nginx".to_string(), "latest".to_string())
        );
    }

    #[test]
    fn test_trivy_check() {
        // Just verify the function doesn't panic
        let _ = is_trivy_available();
    }
}
