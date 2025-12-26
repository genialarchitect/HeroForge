//! CycloneDX 1.5 SBOM format generator

use crate::yellow_team::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::SbomGenerator;

/// CycloneDX BOM (Bill of Materials)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    /// BOM format
    pub bom_format: String,
    /// Specification version
    pub spec_version: String,
    /// Serial number (URN UUID)
    pub serial_number: String,
    /// BOM version
    pub version: i32,
    /// Metadata
    pub metadata: CycloneDxMetadata,
    /// Components
    pub components: Vec<CycloneDxComponent>,
    /// Dependencies
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<CycloneDxDependency>,
    /// Vulnerabilities (optional)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<CycloneDxVulnerability>,
}

/// CycloneDX Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxMetadata {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Tools used to generate
    pub tools: Vec<CycloneDxTool>,
    /// Component being described (root project)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<CycloneDxComponent>,
}

/// CycloneDX Tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

/// CycloneDX Component
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxComponent {
    /// Component type
    #[serde(rename = "type")]
    pub component_type: String,
    /// BOM reference (unique ID within BOM)
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Component name
    pub name: String,
    /// Version
    pub version: String,
    /// Package URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// CPE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Licenses
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<CycloneDxLicense>,
    /// External references
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<CycloneDxExternalReference>,
    /// Hashes
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<CycloneDxHash>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Scope (required, optional, excluded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// CycloneDX License
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicense {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<CycloneDxLicenseInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

/// CycloneDX License Info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicenseInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// CycloneDX External Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxExternalReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// CycloneDX Hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

/// CycloneDX Dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxDependency {
    #[serde(rename = "ref")]
    pub dependency_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// CycloneDX Vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxVulnerability {
    /// Vulnerability ID
    pub id: String,
    /// Source
    pub source: CycloneDxVulnSource,
    /// References
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<CycloneDxVulnReference>,
    /// Ratings
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ratings: Vec<CycloneDxVulnRating>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Recommendation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    /// Affected components
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub affects: Vec<CycloneDxAffected>,
}

/// CycloneDX Vulnerability Source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxVulnSource {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// CycloneDX Vulnerability Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxVulnReference {
    pub id: String,
    pub source: CycloneDxVulnSource,
}

/// CycloneDX Vulnerability Rating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxVulnRating {
    pub source: CycloneDxVulnSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

/// CycloneDX Affected Component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxAffected {
    #[serde(rename = "ref")]
    pub component_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<CycloneDxAffectedVersion>,
}

/// CycloneDX Affected Version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxAffectedVersion {
    pub version: String,
    pub status: String,
}

impl CycloneDxBom {
    /// Create a new CycloneDX BOM
    pub fn new() -> Self {
        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: Utc::now(),
                tools: vec![CycloneDxTool {
                    vendor: "HeroForge".to_string(),
                    name: "HeroForge SBOM Generator".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
                component: None,
            },
            components: Vec::new(),
            dependencies: Vec::new(),
            vulnerabilities: Vec::new(),
        }
    }

    /// Create from SBOM Generator
    pub fn from_sbom(sbom: &SbomGenerator) -> Self {
        let mut bom = Self::new();
        
        // Set root component
        bom.metadata.component = Some(CycloneDxComponent {
            component_type: "application".to_string(),
            bom_ref: sbom.project.id.clone(),
            name: sbom.project.name.clone(),
            version: sbom.project.version.clone().unwrap_or_else(|| "0.0.0".to_string()),
            purl: None,
            cpe: None,
            licenses: Vec::new(),
            external_references: Vec::new(),
            hashes: Vec::new(),
            description: None,
            scope: None,
        });
        
        // Add components
        for component in &sbom.components {
            bom.components.push(CycloneDxComponent {
                component_type: "library".to_string(),
                bom_ref: component.id.clone(),
                name: component.name.clone(),
                version: component.version.clone(),
                purl: if component.purl.is_empty() { None } else { Some(component.purl.clone()) },
                cpe: component.cpe.clone(),
                licenses: component.license().as_ref().map(|l| {
                    vec![CycloneDxLicense {
                        license: Some(CycloneDxLicenseInfo {
                            id: Some(l.clone()),
                            name: None,
                            url: None,
                        }),
                        expression: None,
                    }]
                }).unwrap_or_default(),
                external_references: Vec::new(),
                hashes: Vec::new(),
                description: None,
                scope: if component.is_direct() { Some("required".to_string()) } else { Some("optional".to_string()) },
            });
        }
        
        // Add dependencies
        for (parent, children) in &sbom.dependencies {
            bom.dependencies.push(CycloneDxDependency {
                dependency_ref: parent.clone(),
                depends_on: children.clone(),
            });
        }
        
        // Add vulnerabilities for components that have them
        for component in &sbom.components {
            for vuln_id in &component.vulnerabilities {
                bom.vulnerabilities.push(CycloneDxVulnerability {
                    id: vuln_id.clone(),
                    source: CycloneDxVulnSource {
                        name: "NVD".to_string(),
                        url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", vuln_id)),
                    },
                    references: Vec::new(),
                    ratings: Vec::new(),
                    description: None,
                    recommendation: None,
                    affects: vec![CycloneDxAffected {
                        component_ref: component.id.clone(),
                        versions: vec![CycloneDxAffectedVersion {
                            version: component.version.clone(),
                            status: "affected".to_string(),
                        }],
                    }],
                });
            }
        }
        
        bom
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export to XML string
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\" ");
        xml.push_str(&format!("serialNumber=\"{}\" version=\"{}\">\n", self.serial_number, self.version));
        
        // Metadata
        xml.push_str("  <metadata>\n");
        xml.push_str(&format!("    <timestamp>{}</timestamp>\n", self.metadata.timestamp.to_rfc3339()));
        xml.push_str("    <tools>\n");
        for tool in &self.metadata.tools {
            xml.push_str("      <tool>\n");
            xml.push_str(&format!("        <vendor>{}</vendor>\n", tool.vendor));
            xml.push_str(&format!("        <name>{}</name>\n", tool.name));
            xml.push_str(&format!("        <version>{}</version>\n", tool.version));
            xml.push_str("      </tool>\n");
        }
        xml.push_str("    </tools>\n");
        xml.push_str("  </metadata>\n");
        
        // Components
        xml.push_str("  <components>\n");
        for comp in &self.components {
            xml.push_str(&format!("    <component type=\"{}\" bom-ref=\"{}\">\n", comp.component_type, comp.bom_ref));
            xml.push_str(&format!("      <name>{}</name>\n", escape_xml(&comp.name)));
            xml.push_str(&format!("      <version>{}</version>\n", escape_xml(&comp.version)));
            if let Some(ref purl) = comp.purl {
                xml.push_str(&format!("      <purl>{}</purl>\n", escape_xml(purl)));
            }
            xml.push_str("    </component>\n");
        }
        xml.push_str("  </components>\n");
        
        // Dependencies
        if !self.dependencies.is_empty() {
            xml.push_str("  <dependencies>\n");
            for dep in &self.dependencies {
                xml.push_str(&format!("    <dependency ref=\"{}\">\n", dep.dependency_ref));
                for child in &dep.depends_on {
                    xml.push_str(&format!("      <dependency ref=\"{}\"/>\n", child));
                }
                xml.push_str("    </dependency>\n");
            }
            xml.push_str("  </dependencies>\n");
        }
        
        xml.push_str("</bom>\n");
        xml
    }
}

impl Default for CycloneDxBom {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyclonedx_new() {
        let bom = CycloneDxBom::new();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert!(bom.serial_number.starts_with("urn:uuid:"));
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("<test>"), "&lt;test&gt;");
        assert_eq!(escape_xml("a & b"), "a &amp; b");
    }

    #[test]
    fn test_cyclonedx_to_json() {
        let bom = CycloneDxBom::new();
        let json = bom.to_json().unwrap();
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("1.5"));
    }
}
