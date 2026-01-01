//! Software Bill of Materials (SBOM) generation and management
//!
//! This module provides:
//! - CycloneDX SBOM generation (industry standard)
//! - SPDX SBOM generation (Linux Foundation standard)
//! - SBOM comparison and diffing
//! - SBOM signing with Sigstore/Cosign

use super::*;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use uuid::Uuid;

/// Check if a command exists in PATH
fn command_exists(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// SBOM Generator supporting multiple formats
pub struct SbomGenerator {
    /// Tool name and version for metadata
    tool_name: String,
    tool_version: String,
    /// Organization info for SPDX
    organization: Option<String>,
}

impl SbomGenerator {
    pub fn new() -> Self {
        Self {
            tool_name: "HeroForge".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            organization: None,
        }
    }

    /// Set organization for SPDX creator info
    pub fn with_organization(mut self, org: String) -> Self {
        self.organization = Some(org);
        self
    }

    /// Generate SBOM in CycloneDX format (JSON)
    pub async fn generate_cyclonedx(&self, project_path: &str) -> Result<String> {
        let path = Path::new(project_path);

        if !path.exists() {
            anyhow::bail!("Project path does not exist: {}", project_path);
        }

        // Detect project type and extract dependencies
        let components = self.extract_dependencies(path).await?;

        // Build CycloneDX structure
        let cyclonedx = CycloneDxBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: Utc::now().to_rfc3339(),
                tools: vec![CycloneDxTool {
                    vendor: "HeroForge".to_string(),
                    name: self.tool_name.clone(),
                    version: self.tool_version.clone(),
                }],
                component: None,
            },
            components: components.iter().map(|c| CycloneDxComponent {
                component_type: "library".to_string(),
                bom_ref: c.purl.clone(),
                name: c.name.clone(),
                version: c.version.clone(),
                purl: Some(c.purl.clone()),
                licenses: c.license.as_ref().map(|l| vec![CycloneDxLicense {
                    license: CycloneDxLicenseInfo {
                        id: Some(l.clone()),
                        name: None,
                    },
                }]),
                hashes: c.hashes.iter().map(|(alg, hash)| CycloneDxHash {
                    alg: alg.clone(),
                    content: hash.clone(),
                }).collect(),
                external_references: vec![],
            }).collect(),
            dependencies: self.build_dependency_graph(&components),
        };

        let json = serde_json::to_string_pretty(&cyclonedx)
            .context("Failed to serialize CycloneDX SBOM")?;

        log::info!(
            "Generated CycloneDX SBOM with {} components",
            components.len()
        );

        Ok(json)
    }

    /// Generate SBOM in SPDX format (JSON)
    pub async fn generate_spdx(&self, project_path: &str) -> Result<String> {
        let path = Path::new(project_path);

        if !path.exists() {
            anyhow::bail!("Project path does not exist: {}", project_path);
        }

        // Detect project type and extract dependencies
        let components = self.extract_dependencies(path).await?;

        let doc_id = format!("SPDXRef-DOCUMENT-{}", Uuid::new_v4().to_string().replace("-", "")[..8].to_uppercase());
        let doc_namespace = format!(
            "https://heroforge.io/spdxdocs/{}",
            Uuid::new_v4()
        );

        // Build SPDX structure
        let spdx = SpdxDocument {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            document_namespace: doc_namespace,
            creation_info: SpdxCreationInfo {
                created: Utc::now().to_rfc3339(),
                creators: vec![
                    format!("Tool: {}-{}", self.tool_name, self.tool_version),
                    self.organization.as_ref()
                        .map(|o| format!("Organization: {}", o))
                        .unwrap_or_else(|| "Organization: Unknown".to_string()),
                ],
                license_list_version: Some("3.19".to_string()),
            },
            packages: components.iter().enumerate().map(|(i, c)| SpdxPackage {
                spdx_id: format!("SPDXRef-Package-{}", i + 1),
                name: c.name.clone(),
                version_info: Some(c.version.clone()),
                download_location: c.download_url.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
                files_analyzed: false,
                license_concluded: c.license.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
                license_declared: c.license.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
                copyright_text: "NOASSERTION".to_string(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: c.purl.clone(),
                }],
                checksums: c.hashes.iter().map(|(alg, hash)| SpdxChecksum {
                    algorithm: match alg.as_str() {
                        "SHA-256" => "SHA256".to_string(),
                        "SHA-512" => "SHA512".to_string(),
                        "MD5" => "MD5".to_string(),
                        _ => alg.clone(),
                    },
                    checksum_value: hash.clone(),
                }).collect(),
            }).collect(),
            relationships: self.build_spdx_relationships(&components),
        };

        let json = serde_json::to_string_pretty(&spdx)
            .context("Failed to serialize SPDX SBOM")?;

        log::info!(
            "Generated SPDX SBOM with {} packages",
            components.len()
        );

        Ok(json)
    }

    /// Compare two SBOMs and return differences
    pub fn compare_sboms(&self, sbom1: &str, sbom2: &str) -> Result<SbomDiff> {
        // Try to parse as CycloneDX first, then SPDX
        let components1 = self.extract_components_from_sbom(sbom1)?;
        let components2 = self.extract_components_from_sbom(sbom2)?;

        let set1: HashSet<_> = components1.iter().map(|c| format!("{}@{}", c.name, c.version)).collect();
        let set2: HashSet<_> = components2.iter().map(|c| format!("{}@{}", c.name, c.version)).collect();

        // Find additions (in sbom2 but not in sbom1)
        let added: Vec<_> = set2.difference(&set1).cloned().collect();

        // Find removals (in sbom1 but not in sbom2)
        let removed: Vec<_> = set1.difference(&set2).cloned().collect();

        // Find version changes (same name, different version)
        let names1: HashMap<_, _> = components1.iter().map(|c| (c.name.clone(), c.version.clone())).collect();
        let names2: HashMap<_, _> = components2.iter().map(|c| (c.name.clone(), c.version.clone())).collect();

        let modified: Vec<_> = names1.iter()
            .filter_map(|(name, v1)| {
                names2.get(name).and_then(|v2| {
                    if v1 != v2 {
                        Some(format!("{}: {} -> {}", name, v1, v2))
                    } else {
                        None
                    }
                })
            })
            .collect();

        Ok(SbomDiff {
            added,
            removed,
            modified,
        })
    }

    /// Sign SBOM with Sigstore/Cosign
    pub async fn sign_sbom(&self, sbom: &str) -> Result<String> {
        // Calculate SBOM hash
        let sbom_hash = format!("{:x}", Sha256::digest(sbom.as_bytes()));

        // Check if cosign is available
        if command_exists("cosign") {
            // Use cosign for keyless signing
            let temp_file = std::env::temp_dir().join(format!("sbom-{}.json", Uuid::new_v4()));
            tokio::fs::write(&temp_file, sbom).await?;

            let output = tokio::process::Command::new("cosign")
                .arg("sign-blob")
                .arg("--yes")
                .arg("--output-signature")
                .arg("-")
                .arg(&temp_file)
                .output()
                .await;

            // Clean up temp file
            let _ = tokio::fs::remove_file(&temp_file).await;

            if let Ok(out) = output {
                if out.status.success() {
                    let signature = String::from_utf8_lossy(&out.stdout).to_string();
                    return Ok(self.wrap_signed_sbom(sbom, &signature, &sbom_hash));
                }
            }
        }

        // Fallback: Create a simple signed wrapper
        let signed = SignedSbom {
            sbom: serde_json::from_str(sbom).unwrap_or(serde_json::json!(sbom)),
            signature: SbomSignature {
                algorithm: "SHA256".to_string(),
                digest: sbom_hash.clone(),
                timestamp: Utc::now().to_rfc3339(),
                signer: self.tool_name.clone(),
                signature_value: None, // No actual signature without cosign
            },
        };

        serde_json::to_string_pretty(&signed)
            .context("Failed to create signed SBOM wrapper")
    }

    /// Extract dependencies from project based on detected ecosystem
    async fn extract_dependencies(&self, project_path: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();

        // Check for Cargo.toml (Rust)
        let cargo_toml = project_path.join("Cargo.toml");
        if cargo_toml.exists() {
            components.extend(self.extract_cargo_dependencies(&cargo_toml).await?);
        }

        // Check for package.json (Node.js)
        let package_json = project_path.join("package.json");
        if package_json.exists() {
            components.extend(self.extract_npm_dependencies(&package_json).await?);
        }

        // Check for requirements.txt (Python)
        let requirements_txt = project_path.join("requirements.txt");
        if requirements_txt.exists() {
            components.extend(self.extract_pip_dependencies(&requirements_txt).await?);
        }

        // Check for go.mod (Go)
        let go_mod = project_path.join("go.mod");
        if go_mod.exists() {
            components.extend(self.extract_go_dependencies(&go_mod).await?);
        }

        // Check for pom.xml (Maven/Java)
        let pom_xml = project_path.join("pom.xml");
        if pom_xml.exists() {
            components.extend(self.extract_maven_dependencies(&pom_xml).await?);
        }

        Ok(components)
    }

    /// Extract dependencies from Cargo.toml/Cargo.lock
    async fn extract_cargo_dependencies(&self, cargo_toml: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();

        // Prefer Cargo.lock for exact versions
        let cargo_lock = cargo_toml.parent().unwrap().join("Cargo.lock");

        if cargo_lock.exists() {
            let lock_content = tokio::fs::read_to_string(&cargo_lock).await?;

            // Parse Cargo.lock
            for section in lock_content.split("\n[[package]]") {
                if section.trim().is_empty() {
                    continue;
                }

                let mut name = String::new();
                let mut version = String::new();
                let mut checksum = String::new();

                for line in section.lines() {
                    let line = line.trim();
                    if line.starts_with("name = ") {
                        name = line.trim_start_matches("name = ").trim_matches('"').to_string();
                    } else if line.starts_with("version = ") {
                        version = line.trim_start_matches("version = ").trim_matches('"').to_string();
                    } else if line.starts_with("checksum = ") {
                        checksum = line.trim_start_matches("checksum = ").trim_matches('"').to_string();
                    }
                }

                if !name.is_empty() && !version.is_empty() {
                    let mut hashes = HashMap::new();
                    if !checksum.is_empty() {
                        hashes.insert("SHA-256".to_string(), checksum);
                    }

                    components.push(ExtendedComponent {
                        name: name.clone(),
                        version: version.clone(),
                        purl: format!("pkg:cargo/{}@{}", name, version),
                        license: None,
                        hashes,
                        download_url: Some(format!("https://crates.io/crates/{}/{}", name, version)),
                        dependencies: vec![],
                    });
                }
            }
        }

        Ok(components)
    }

    /// Extract dependencies from package.json/package-lock.json
    async fn extract_npm_dependencies(&self, package_json: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();

        // Prefer package-lock.json for exact versions
        let package_lock = package_json.parent().unwrap().join("package-lock.json");

        if package_lock.exists() {
            let content = tokio::fs::read_to_string(&package_lock).await?;
            let lock: serde_json::Value = serde_json::from_str(&content)?;

            if let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) {
                for (path, pkg) in packages {
                    // Skip root package
                    if path.is_empty() {
                        continue;
                    }

                    let name = path.trim_start_matches("node_modules/").to_string();
                    let version = pkg.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let mut hashes = HashMap::new();
                    if let Some(integrity) = pkg.get("integrity").and_then(|i| i.as_str()) {
                        if integrity.starts_with("sha512-") {
                            hashes.insert("SHA-512".to_string(), integrity.trim_start_matches("sha512-").to_string());
                        } else if integrity.starts_with("sha256-") {
                            hashes.insert("SHA-256".to_string(), integrity.trim_start_matches("sha256-").to_string());
                        }
                    }

                    components.push(ExtendedComponent {
                        name: name.clone(),
                        version: version.clone(),
                        purl: format!("pkg:npm/{}@{}", name, version),
                        license: pkg.get("license").and_then(|l| l.as_str()).map(String::from),
                        hashes,
                        download_url: Some(format!("https://registry.npmjs.org/{}/-/{}-{}.tgz", name, name.split('/').last().unwrap_or(&name), version)),
                        dependencies: vec![],
                    });
                }
            }
        }

        Ok(components)
    }

    /// Extract dependencies from requirements.txt
    async fn extract_pip_dependencies(&self, requirements_txt: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();
        let content = tokio::fs::read_to_string(requirements_txt).await?;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse package==version or package>=version
            let (name, version) = if let Some(idx) = line.find("==") {
                (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
            } else if let Some(idx) = line.find(">=") {
                (line[..idx].trim().to_string(), line[idx + 2..].split(',').next().unwrap_or("").trim().to_string())
            } else if let Some(idx) = line.find("~=") {
                (line[..idx].trim().to_string(), line[idx + 2..].trim().to_string())
            } else {
                (line.to_string(), "unknown".to_string())
            };

            if !name.is_empty() {
                components.push(ExtendedComponent {
                    name: name.clone(),
                    version: version.clone(),
                    purl: format!("pkg:pypi/{}@{}", name.to_lowercase(), version),
                    license: None,
                    hashes: HashMap::new(),
                    download_url: Some(format!("https://pypi.org/project/{}/", name)),
                    dependencies: vec![],
                });
            }
        }

        Ok(components)
    }

    /// Extract dependencies from go.mod
    async fn extract_go_dependencies(&self, go_mod: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();
        let content = tokio::fs::read_to_string(go_mod).await?;

        let mut in_require = false;

        for line in content.lines() {
            let line = line.trim();

            if line == "require (" {
                in_require = true;
                continue;
            }

            if line == ")" {
                in_require = false;
                continue;
            }

            if in_require || line.starts_with("require ") {
                let parts: Vec<&str> = line
                    .trim_start_matches("require ")
                    .split_whitespace()
                    .collect();

                if parts.len() >= 2 {
                    let name = parts[0].to_string();
                    let version = parts[1].to_string();

                    components.push(ExtendedComponent {
                        name: name.clone(),
                        version: version.clone(),
                        purl: format!("pkg:golang/{}@{}", name, version),
                        license: None,
                        hashes: HashMap::new(),
                        download_url: Some(format!("https://pkg.go.dev/{}@{}", name, version)),
                        dependencies: vec![],
                    });
                }
            }
        }

        Ok(components)
    }

    /// Extract dependencies from pom.xml
    async fn extract_maven_dependencies(&self, pom_xml: &Path) -> Result<Vec<ExtendedComponent>> {
        let mut components = Vec::new();
        let content = tokio::fs::read_to_string(pom_xml).await?;

        // Simple XML parsing for dependencies
        let mut in_dependency = false;
        let mut group_id = String::new();
        let mut artifact_id = String::new();
        let mut version = String::new();

        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("<dependency>") {
                in_dependency = true;
                group_id.clear();
                artifact_id.clear();
                version.clear();
            } else if line.starts_with("</dependency>") && in_dependency {
                if !artifact_id.is_empty() && !version.is_empty() {
                    let name = if !group_id.is_empty() {
                        format!("{}:{}", group_id, artifact_id)
                    } else {
                        artifact_id.clone()
                    };

                    components.push(ExtendedComponent {
                        name: name.clone(),
                        version: version.clone(),
                        purl: format!("pkg:maven/{}@{}", name.replace(':', "/"), version),
                        license: None,
                        hashes: HashMap::new(),
                        download_url: Some(format!(
                            "https://repo1.maven.org/maven2/{}/{}/{}",
                            group_id.replace('.', "/"),
                            artifact_id,
                            version
                        )),
                        dependencies: vec![],
                    });
                }
                in_dependency = false;
            } else if in_dependency {
                if line.starts_with("<groupId>") && line.ends_with("</groupId>") {
                    group_id = line.trim_start_matches("<groupId>").trim_end_matches("</groupId>").to_string();
                } else if line.starts_with("<artifactId>") && line.ends_with("</artifactId>") {
                    artifact_id = line.trim_start_matches("<artifactId>").trim_end_matches("</artifactId>").to_string();
                } else if line.starts_with("<version>") && line.ends_with("</version>") {
                    version = line.trim_start_matches("<version>").trim_end_matches("</version>").to_string();
                }
            }
        }

        Ok(components)
    }

    /// Build CycloneDX dependency graph
    fn build_dependency_graph(&self, components: &[ExtendedComponent]) -> Vec<CycloneDxDependency> {
        components.iter().map(|c| CycloneDxDependency {
            dep_ref: c.purl.clone(),
            depends_on: c.dependencies.clone(),
        }).collect()
    }

    /// Build SPDX relationships
    fn build_spdx_relationships(&self, components: &[ExtendedComponent]) -> Vec<SpdxRelationship> {
        let mut relationships = vec![
            // Document describes the root package
            SpdxRelationship {
                spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
                relationship_type: "DESCRIBES".to_string(),
                related_spdx_element: "SPDXRef-Package-1".to_string(),
            }
        ];

        // Add DEPENDS_ON relationships
        for (i, comp) in components.iter().enumerate() {
            for dep in &comp.dependencies {
                // Find the dependency's index
                if let Some(dep_idx) = components.iter().position(|c| c.purl == *dep) {
                    relationships.push(SpdxRelationship {
                        spdx_element_id: format!("SPDXRef-Package-{}", i + 1),
                        relationship_type: "DEPENDS_ON".to_string(),
                        related_spdx_element: format!("SPDXRef-Package-{}", dep_idx + 1),
                    });
                }
            }
        }

        relationships
    }

    /// Extract components from an existing SBOM (for comparison)
    fn extract_components_from_sbom(&self, sbom: &str) -> Result<Vec<SbomComponent>> {
        let json: serde_json::Value = serde_json::from_str(sbom)?;

        let mut components = Vec::new();

        // Check if CycloneDX
        if json.get("bomFormat").is_some() {
            if let Some(comps) = json.get("components").and_then(|c| c.as_array()) {
                for comp in comps {
                    components.push(SbomComponent {
                        name: comp.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        version: comp.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        purl: comp.get("purl").and_then(|p| p.as_str()).unwrap_or("").to_string(),
                        license: comp.get("licenses")
                            .and_then(|l| l.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|lic| lic.get("license"))
                            .and_then(|l| l.get("id"))
                            .and_then(|id| id.as_str())
                            .map(String::from),
                    });
                }
            }
        }
        // Check if SPDX
        else if json.get("spdxVersion").is_some() {
            if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
                for pkg in packages {
                    let purl = pkg.get("externalRefs")
                        .and_then(|r| r.as_array())
                        .and_then(|arr| arr.iter().find(|r| {
                            r.get("referenceType").and_then(|t| t.as_str()) == Some("purl")
                        }))
                        .and_then(|r| r.get("referenceLocator"))
                        .and_then(|l| l.as_str())
                        .unwrap_or("")
                        .to_string();

                    components.push(SbomComponent {
                        name: pkg.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        version: pkg.get("versionInfo").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        purl,
                        license: pkg.get("licenseConcluded").and_then(|l| l.as_str()).map(String::from),
                    });
                }
            }
        }

        Ok(components)
    }

    /// Wrap SBOM with signature
    fn wrap_signed_sbom(&self, sbom: &str, signature: &str, digest: &str) -> String {
        let signed = SignedSbom {
            sbom: serde_json::from_str(sbom).unwrap_or(serde_json::json!(sbom)),
            signature: SbomSignature {
                algorithm: "SHA256".to_string(),
                digest: digest.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                signer: self.tool_name.clone(),
                signature_value: Some(signature.to_string()),
            },
        };

        serde_json::to_string_pretty(&signed).unwrap_or_default()
    }
}

impl Default for SbomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended component with hash info
#[derive(Debug, Clone)]
struct ExtendedComponent {
    name: String,
    version: String,
    purl: String,
    license: Option<String>,
    hashes: HashMap<String, String>,
    download_url: Option<String>,
    dependencies: Vec<String>,
}

/// SBOM diff result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SbomDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

/// Signed SBOM wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedSbom {
    sbom: serde_json::Value,
    signature: SbomSignature,
}

/// SBOM signature info
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SbomSignature {
    algorithm: String,
    digest: String,
    timestamp: String,
    signer: String,
    signature_value: Option<String>,
}

// CycloneDX structures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: String,
    spec_version: String,
    serial_number: String,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
    dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
    component: Option<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxTool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    purl: Option<String>,
    licenses: Option<Vec<CycloneDxLicense>>,
    hashes: Vec<CycloneDxHash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<CycloneDxExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxLicense {
    license: CycloneDxLicenseInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxLicenseInfo {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxHash {
    alg: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxExternalRef {
    url: String,
    #[serde(rename = "type")]
    ref_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    dep_ref: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
}

// SPDX structures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    document_namespace: String,
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
    license_list_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: Option<String>,
    download_location: String,
    files_analyzed: bool,
    license_concluded: String,
    license_declared: String,
    copyright_text: String,
    external_refs: Vec<SpdxExternalRef>,
    checksums: Vec<SpdxChecksum>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxChecksum {
    algorithm: String,
    checksum_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxRelationship {
    spdx_element_id: String,
    relationship_type: String,
    related_spdx_element: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_extract_cargo_deps() {
        let temp = TempDir::new().unwrap();

        // Create minimal Cargo.lock
        let cargo_lock = r#"
[[package]]
name = "serde"
version = "1.0.0"
checksum = "abc123"

[[package]]
name = "tokio"
version = "1.0.0"
"#;

        tokio::fs::write(temp.path().join("Cargo.toml"), "[package]\nname = \"test\"").await.unwrap();
        tokio::fs::write(temp.path().join("Cargo.lock"), cargo_lock).await.unwrap();

        let generator = SbomGenerator::new();
        let sbom = generator.generate_cyclonedx(temp.path().to_str().unwrap()).await.unwrap();

        assert!(sbom.contains("CycloneDX"));
        assert!(sbom.contains("serde"));
        assert!(sbom.contains("tokio"));
    }

    #[test]
    fn test_sbom_diff() {
        let generator = SbomGenerator::new();

        let sbom1 = r#"{
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "pkg1", "version": "1.0.0", "purl": "pkg:npm/pkg1@1.0.0"},
                {"name": "pkg2", "version": "1.0.0", "purl": "pkg:npm/pkg2@1.0.0"}
            ]
        }"#;

        let sbom2 = r#"{
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "pkg1", "version": "1.1.0", "purl": "pkg:npm/pkg1@1.1.0"},
                {"name": "pkg3", "version": "1.0.0", "purl": "pkg:npm/pkg3@1.0.0"}
            ]
        }"#;

        let diff = generator.compare_sboms(sbom1, sbom2).unwrap();

        assert!(diff.added.contains(&"pkg3@1.0.0".to_string()));
        assert!(diff.removed.contains(&"pkg2@1.0.0".to_string()));
        assert!(!diff.modified.is_empty());
    }
}
