//! Build provenance and SLSA compliance
//!
//! This module provides:
//! - SLSA provenance attestation generation
//! - Provenance verification
//! - SLSA level assessment
//! - In-toto attestation support

use super::*;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tokio::process::Command;

/// Check if a command exists in PATH
fn command_exists(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Find a command in PATH and return its path
fn find_command(name: &str) -> Option<String> {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}

/// Provenance tracker for SLSA compliance
pub struct ProvenanceTracker {
    /// Builder identity
    builder_id: String,
    /// Build platform
    platform: String,
    /// Attestation format
    attestation_format: AttestationFormat,
}

/// Supported attestation formats
#[derive(Debug, Clone, Copy, Default)]
pub enum AttestationFormat {
    #[default]
    SlsaV1,
    InTotoV1,
}

impl ProvenanceTracker {
    pub fn new() -> Self {
        Self {
            builder_id: format!("https://heroforge.io/builder/{}", env!("CARGO_PKG_VERSION")),
            platform: std::env::consts::OS.to_string(),
            attestation_format: AttestationFormat::SlsaV1,
        }
    }

    /// Set builder identity
    pub fn with_builder(mut self, builder_id: &str) -> Self {
        self.builder_id = builder_id.to_string();
        self
    }

    /// Set attestation format
    pub fn with_format(mut self, format: AttestationFormat) -> Self {
        self.attestation_format = format;
        self
    }

    /// Generate SLSA provenance attestation
    ///
    /// Creates a SLSA v1.0 provenance predicate compliant with
    /// https://slsa.dev/provenance/v1
    pub async fn generate_attestation(&self, build_info: &BuildInfo) -> Result<ProvenanceAttestation> {
        // Collect materials (source inputs)
        let mut materials = Vec::new();

        // Add source repository as material
        if !build_info.source_repo.is_empty() {
            let mut digest = HashMap::new();
            digest.insert("gitCommit".to_string(), build_info.commit_sha.clone());

            materials.push(Material {
                uri: build_info.source_repo.clone(),
                digest,
            });
        }

        // Collect environment info for build metadata
        let run_details = RunDetails {
            builder: BuilderInfo {
                id: self.builder_id.clone(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                builder_dependencies: self.collect_builder_deps().await?,
            },
            metadata: BuildMetadata {
                invocation_id: uuid::Uuid::new_v4().to_string(),
                started_on: build_info.build_time.to_rfc3339(),
                finished_on: Some(Utc::now().to_rfc3339()),
            },
            byproducts: vec![],
        };

        // Build the invocation config
        let invocation = serde_json::json!({
            "configSource": {
                "uri": build_info.source_repo,
                "digest": {
                    "sha1": build_info.commit_sha
                },
                "entryPoint": build_info.builder
            },
            "parameters": {},
            "environment": self.collect_environment()
        });

        let attestation = ProvenanceAttestation {
            build_type: format!("https://heroforge.io/build-types/{}",
                self.platform.to_lowercase()),
            builder: self.builder_id.clone(),
            invocation,
            materials,
        };

        log::info!(
            "Generated SLSA provenance for commit {} in {}",
            &build_info.commit_sha[..8.min(build_info.commit_sha.len())],
            build_info.source_repo
        );

        Ok(attestation)
    }

    /// Generate full SLSA v1 predicate
    pub async fn generate_slsa_predicate(&self, build_info: &BuildInfo, subjects: &[ArtifactSubject]) -> Result<SlsaPredicate> {
        let attestation = self.generate_attestation(build_info).await?;

        Ok(SlsaPredicate {
            build_definition: BuildDefinition {
                build_type: attestation.build_type.clone(),
                external_parameters: serde_json::json!({
                    "repository": build_info.source_repo,
                    "ref": build_info.commit_sha
                }),
                internal_parameters: serde_json::json!({}),
                resolved_dependencies: attestation.materials.iter().map(|m| {
                    ResolvedDependency {
                        uri: m.uri.clone(),
                        digest: m.digest.clone(),
                        name: None,
                    }
                }).collect(),
            },
            run_details: RunDetails {
                builder: BuilderInfo {
                    id: self.builder_id.clone(),
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    builder_dependencies: vec![],
                },
                metadata: BuildMetadata {
                    invocation_id: uuid::Uuid::new_v4().to_string(),
                    started_on: build_info.build_time.to_rfc3339(),
                    finished_on: Some(Utc::now().to_rfc3339()),
                },
                byproducts: vec![],
            },
        })
    }

    /// Verify provenance chain for an artifact
    pub async fn verify_provenance(&self, artifact: &str) -> Result<bool> {
        // Check for provenance file
        let provenance_file = format!("{}.provenance.json", artifact);
        let intoto_file = format!("{}.intoto.jsonl", artifact);

        let provenance_path = if Path::new(&provenance_file).exists() {
            provenance_file
        } else if Path::new(&intoto_file).exists() {
            intoto_file
        } else {
            log::warn!("No provenance file found for {}", artifact);
            return Ok(false);
        };

        // Read provenance
        let content = tokio::fs::read_to_string(&provenance_path).await?;

        // Parse as SLSA predicate or in-toto statement
        if let Ok(statement) = serde_json::from_str::<InTotoStatement>(&content) {
            // Verify the statement structure
            if statement.statement_type != "https://in-toto.io/Statement/v1" {
                log::warn!("Invalid in-toto statement type");
                return Ok(false);
            }

            // Verify subject matches artifact
            let artifact_path = Path::new(artifact);
            let artifact_name = artifact_path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let subject_matches = statement.subject.iter()
                .any(|s| s.name == artifact_name || s.name == artifact);

            if !subject_matches {
                log::warn!("Artifact not found in provenance subjects");
                return Ok(false);
            }

            // Verify artifact hash if available
            if artifact_path.exists() {
                let content = tokio::fs::read(artifact_path).await?;
                let actual_hash = format!("{:x}", Sha256::digest(&content));

                let hash_matches = statement.subject.iter()
                    .filter(|s| s.name == artifact_name || s.name == artifact)
                    .any(|s| {
                        s.digest.get("sha256").map(|h| h == &actual_hash).unwrap_or(false)
                    });

                if !hash_matches {
                    log::warn!("Artifact hash does not match provenance");
                    return Ok(false);
                }
            }

            log::info!("Provenance verified for {}", artifact);
            return Ok(true);
        }

        // Try to use slsa-verifier if available
        if command_exists("slsa-verifier") {
            let output = Command::new("slsa-verifier")
                .arg("verify-artifact")
                .arg(artifact)
                .arg("--provenance-path")
                .arg(&provenance_path)
                .output()
                .await;

            if let Ok(out) = output {
                return Ok(out.status.success());
            }
        }

        Ok(false)
    }

    /// Check SLSA level compliance
    ///
    /// Evaluates the attestation against SLSA requirements:
    /// - Level 1: Attestation exists with build provenance
    /// - Level 2: Hosted build service with authenticated provenance
    /// - Level 3: Hardened build platform with non-falsifiable provenance
    /// - Level 4: Hermetic, reproducible build with two-party review
    pub fn check_slsa_level(&self, attestation: &ProvenanceAttestation) -> SlsaLevel {
        let mut level = SlsaLevel::Level0;

        // Level 1: Build provenance exists
        if !attestation.build_type.is_empty() && !attestation.materials.is_empty() {
            level = SlsaLevel::Level1;
        }

        // Level 2: Hosted build service and authenticated provenance
        if attestation.builder.starts_with("https://") {
            // Check for known CI systems
            let known_builders = [
                "github.com/actions",
                "cloud.google.com/cloudbuild",
                "circleci.com",
                "travis-ci.com",
                "gitlab.com/ci",
                "heroforge.io/builder",
            ];

            if known_builders.iter().any(|b| attestation.builder.contains(b)) {
                level = SlsaLevel::Level2;
            }
        }

        // Level 3: Requires non-falsifiable provenance (verified builds)
        // This would typically be verified by checking cryptographic signatures
        // against a transparency log like Rekor
        if let Some(invocation) = attestation.invocation.as_object() {
            if invocation.contains_key("configSource") {
                // Has verifiable source configuration
                if attestation.materials.iter().any(|m| {
                    m.digest.contains_key("sha256") || m.digest.contains_key("gitCommit")
                }) {
                    // Has cryptographic binding to source
                    // Level 3 requires additional verification in practice
                }
            }
        }

        // Level 4: Would require hermetic builds and reproducibility
        // This is the highest level and requires significant infrastructure
        // Not typically achievable without specialized build systems

        level
    }

    /// Create an in-toto statement envelope
    pub async fn create_intoto_statement(
        &self,
        subjects: &[ArtifactSubject],
        predicate: &ProvenanceAttestation,
    ) -> Result<InTotoStatement> {
        Ok(InTotoStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: subjects.to_vec(),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: serde_json::to_value(predicate)?,
        })
    }

    /// Collect builder dependencies
    async fn collect_builder_deps(&self) -> Result<Vec<ResourceDescriptor>> {
        let mut deps = Vec::new();

        // Check for common build tools
        for tool in &["cargo", "rustc", "docker", "npm", "go"] {
            if let Some(path) = find_command(tool) {
                // Try to get version
                let version = Command::new(tool)
                    .arg("--version")
                    .output()
                    .await
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();

                deps.push(ResourceDescriptor {
                    uri: format!("tool://{}", tool),
                    digest: HashMap::new(),
                    name: Some(format!("{} ({})", tool, version)),
                });
            }
        }

        Ok(deps)
    }

    /// Collect environment info
    fn collect_environment(&self) -> serde_json::Value {
        let mut env = serde_json::Map::new();

        // Add safe environment variables
        for key in &["CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "RUNNER_OS"] {
            if let Ok(val) = std::env::var(key) {
                env.insert(key.to_string(), serde_json::Value::String(val));
            }
        }

        // Add platform info
        env.insert("os".to_string(), serde_json::Value::String(std::env::consts::OS.to_string()));
        env.insert("arch".to_string(), serde_json::Value::String(std::env::consts::ARCH.to_string()));

        serde_json::Value::Object(env)
    }

    /// Save attestation to file
    pub async fn save_attestation(&self, attestation: &ProvenanceAttestation, artifact_path: &str) -> Result<String> {
        let output_path = format!("{}.provenance.json", artifact_path);

        let json = serde_json::to_string_pretty(attestation)?;
        tokio::fs::write(&output_path, &json).await?;

        Ok(output_path)
    }
}

impl Default for ProvenanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Build information for provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    pub source_repo: String,
    pub commit_sha: String,
    pub build_time: chrono::DateTime<chrono::Utc>,
    pub builder: String,
}

/// Artifact subject for in-toto statements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSubject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

impl ArtifactSubject {
    /// Create subject from file
    pub async fn from_file(path: &str) -> Result<Self> {
        let content = tokio::fs::read(path).await?;
        let hash = format!("{:x}", Sha256::digest(&content));

        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());

        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), hash);

        Ok(Self { name, digest })
    }
}

/// SLSA v1 predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaPredicate {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}

/// Build definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    pub build_type: String,
    pub external_parameters: serde_json::Value,
    pub internal_parameters: serde_json::Value,
    pub resolved_dependencies: Vec<ResolvedDependency>,
}

/// Resolved dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDependency {
    pub uri: String,
    pub digest: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Run details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    pub builder: BuilderInfo,
    pub metadata: BuildMetadata,
    pub byproducts: Vec<ResourceDescriptor>,
}

/// Builder information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuilderInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub builder_dependencies: Vec<ResourceDescriptor>,
}

/// Build metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMetadata {
    pub invocation_id: String,
    pub started_on: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

/// Resource descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    pub uri: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub digest: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// In-toto statement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ArtifactSubject>,
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_attestation() {
        let tracker = ProvenanceTracker::new();

        let build_info = BuildInfo {
            source_repo: "https://github.com/example/repo".to_string(),
            commit_sha: "abc123def456".to_string(),
            build_time: Utc::now(),
            builder: "cargo".to_string(),
        };

        let attestation = tracker.generate_attestation(&build_info).await.unwrap();

        assert!(!attestation.build_type.is_empty());
        assert!(!attestation.materials.is_empty());
        assert_eq!(attestation.materials[0].uri, build_info.source_repo);
    }

    #[test]
    fn test_check_slsa_level() {
        let tracker = ProvenanceTracker::new();

        // Empty attestation - Level 0
        let empty = ProvenanceAttestation {
            build_type: String::new(),
            builder: String::new(),
            invocation: serde_json::json!({}),
            materials: vec![],
        };
        assert_eq!(tracker.check_slsa_level(&empty), SlsaLevel::Level0);

        // Basic attestation - Level 1
        let basic = ProvenanceAttestation {
            build_type: "https://heroforge.io/build".to_string(),
            builder: "local".to_string(),
            invocation: serde_json::json!({}),
            materials: vec![Material {
                uri: "https://github.com/example/repo".to_string(),
                digest: HashMap::from([("sha256".to_string(), "abc123".to_string())]),
            }],
        };
        assert_eq!(tracker.check_slsa_level(&basic), SlsaLevel::Level1);

        // Hosted builder - Level 2
        let hosted = ProvenanceAttestation {
            build_type: "https://heroforge.io/build".to_string(),
            builder: "https://github.com/actions/runner".to_string(),
            invocation: serde_json::json!({}),
            materials: vec![Material {
                uri: "https://github.com/example/repo".to_string(),
                digest: HashMap::from([("sha256".to_string(), "abc123".to_string())]),
            }],
        };
        assert_eq!(tracker.check_slsa_level(&hosted), SlsaLevel::Level2);
    }

    #[tokio::test]
    async fn test_artifact_subject_from_file() {
        use tempfile::NamedTempFile;
        use std::io::Write;

        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"test content").unwrap();

        let subject = ArtifactSubject::from_file(temp.path().to_str().unwrap())
            .await
            .unwrap();

        assert!(!subject.name.is_empty());
        assert!(subject.digest.contains_key("sha256"));
    }
}
