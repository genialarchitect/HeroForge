//! SPDX 2.3 SBOM format generator

use crate::yellow_team::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::SbomGenerator;

/// SPDX Document
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxDocument {
    /// SPDX version
    pub spdx_version: String,
    /// Data license
    pub data_license: String,
    /// SPDX identifier
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Document name
    pub name: String,
    /// Document namespace
    pub document_namespace: String,
    /// Creation info
    pub creation_info: SpdxCreationInfo,
    /// Packages
    pub packages: Vec<SpdxPackage>,
    /// Relationships
    pub relationships: Vec<SpdxRelationship>,
    /// External document references
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_document_refs: Vec<SpdxExternalDocRef>,
    /// Extracted licensing info
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub has_extracted_licensing_infos: Vec<SpdxExtractedLicense>,
}

/// SPDX Creation Info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxCreationInfo {
    /// Created timestamp
    pub created: String,
    /// Creators
    pub creators: Vec<String>,
    /// License list version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_list_version: Option<String>,
    /// Comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// SPDX Package
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxPackage {
    /// SPDX identifier
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Package name
    pub name: String,
    /// Version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<String>,
    /// Package file name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_file_name: Option<String>,
    /// Supplier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,
    /// Originator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub originator: Option<String>,
    /// Download location
    pub download_location: String,
    /// Files analyzed
    pub files_analyzed: bool,
    /// Package verification code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_verification_code: Option<SpdxVerificationCode>,
    /// Checksums
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<SpdxChecksum>,
    /// Home page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Source info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_info: Option<String>,
    /// License concluded
    pub license_concluded: String,
    /// All licenses info from files
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub license_info_from_files: Vec<String>,
    /// License declared
    pub license_declared: String,
    /// License comments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_comments: Option<String>,
    /// Copyright text
    pub copyright_text: String,
    /// Summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// External references
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_refs: Vec<SpdxExternalRef>,
    /// Primary package purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_package_purpose: Option<String>,
    /// Release date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    /// Built date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub built_date: Option<String>,
    /// Valid until date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until_date: Option<String>,
}

/// SPDX Verification Code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxVerificationCode {
    pub package_verification_code_value: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub package_verification_code_excluded_files: Vec<String>,
}

/// SPDX Checksum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxChecksum {
    pub algorithm: String,
    pub checksum_value: String,
}

/// SPDX External Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExternalRef {
    pub reference_category: String,
    pub reference_type: String,
    pub reference_locator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// SPDX Relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: String,
    pub related_spdx_element: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// SPDX External Document Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExternalDocRef {
    pub external_document_id: String,
    pub spdx_document: String,
    pub checksum: SpdxChecksum,
}

/// SPDX Extracted License
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpdxExtractedLicense {
    pub license_id: String,
    pub extracted_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cross_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// SPDX Relationship types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdxRelationshipType {
    Describes,
    DescribedBy,
    Contains,
    ContainedBy,
    DependsOn,
    DependencyOf,
    DevDependencyOf,
    OptionalDependencyOf,
    BuildToolOf,
    DevToolOf,
    TestToolOf,
    DocumentationOf,
    OptionalComponentOf,
    PackageOf,
    GeneratedFrom,
    Generates,
    AncestorOf,
    DescendantOf,
    VariantOf,
    BuildDependencyOf,
    RuntimeDependencyOf,
    ProvidedDependencyOf,
    Other,
}

impl SpdxRelationshipType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Describes => "DESCRIBES",
            Self::DescribedBy => "DESCRIBED_BY",
            Self::Contains => "CONTAINS",
            Self::ContainedBy => "CONTAINED_BY",
            Self::DependsOn => "DEPENDS_ON",
            Self::DependencyOf => "DEPENDENCY_OF",
            Self::DevDependencyOf => "DEV_DEPENDENCY_OF",
            Self::OptionalDependencyOf => "OPTIONAL_DEPENDENCY_OF",
            Self::BuildToolOf => "BUILD_TOOL_OF",
            Self::DevToolOf => "DEV_TOOL_OF",
            Self::TestToolOf => "TEST_TOOL_OF",
            Self::DocumentationOf => "DOCUMENTATION_OF",
            Self::OptionalComponentOf => "OPTIONAL_COMPONENT_OF",
            Self::PackageOf => "PACKAGE_OF",
            Self::GeneratedFrom => "GENERATED_FROM",
            Self::Generates => "GENERATES",
            Self::AncestorOf => "ANCESTOR_OF",
            Self::DescendantOf => "DESCENDANT_OF",
            Self::VariantOf => "VARIANT_OF",
            Self::BuildDependencyOf => "BUILD_DEPENDENCY_OF",
            Self::RuntimeDependencyOf => "RUNTIME_DEPENDENCY_OF",
            Self::ProvidedDependencyOf => "PROVIDED_DEPENDENCY_OF",
            Self::Other => "OTHER",
        }
    }
}

impl SpdxDocument {
    /// Create a new SPDX document
    pub fn new(name: &str) -> Self {
        let doc_id = Uuid::new_v4();
        Self {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: name.to_string(),
            document_namespace: format!("https://heroforge.io/spdx/{}", doc_id),
            creation_info: SpdxCreationInfo {
                created: Utc::now().to_rfc3339(),
                creators: vec![
                    format!("Tool: HeroForge-{}", env!("CARGO_PKG_VERSION")),
                    "Organization: Genial Architect".to_string(),
                ],
                license_list_version: Some("3.21".to_string()),
                comment: None,
            },
            packages: Vec::new(),
            relationships: Vec::new(),
            external_document_refs: Vec::new(),
            has_extracted_licensing_infos: Vec::new(),
        }
    }

    /// Create from SBOM Generator
    pub fn from_sbom(sbom: &SbomGenerator) -> Self {
        let mut doc = Self::new(&sbom.project.name);
        
        // Create root package
        let root_spdx_id = "SPDXRef-Package-root".to_string();
        doc.packages.push(SpdxPackage {
            spdx_id: root_spdx_id.clone(),
            name: sbom.project.name.clone(),
            version_info: sbom.project.version.clone(),
            package_file_name: None,
            supplier: None,
            originator: None,
            download_location: "NOASSERTION".to_string(),
            files_analyzed: false,
            package_verification_code: None,
            checksums: Vec::new(),
            homepage: None,
            source_info: None,
            license_concluded: "NOASSERTION".to_string(),
            license_info_from_files: Vec::new(),
            license_declared: "NOASSERTION".to_string(),
            license_comments: None,
            copyright_text: "NOASSERTION".to_string(),
            summary: None,
            description: None,
            comment: None,
            external_refs: Vec::new(),
            primary_package_purpose: Some("APPLICATION".to_string()),
            release_date: None,
            built_date: None,
            valid_until_date: None,
        });
        
        // Document describes root package
        doc.relationships.push(SpdxRelationship {
            spdx_element_id: "SPDXRef-DOCUMENT".to_string(),
            relationship_type: SpdxRelationshipType::Describes.as_str().to_string(),
            related_spdx_element: root_spdx_id.clone(),
            comment: None,
        });
        
        // Add components as packages
        for component in &sbom.components {
            let pkg_spdx_id = format!("SPDXRef-Package-{}", sanitize_spdx_id(&component.id));

            let mut external_refs = Vec::new();
            if !component.purl.is_empty() {
                external_refs.push(SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: component.purl.clone(),
                    comment: None,
                });
            }
            
            let license = component.license().unwrap_or_else(|| "NOASSERTION".to_string());
            
            doc.packages.push(SpdxPackage {
                spdx_id: pkg_spdx_id.clone(),
                name: component.name.clone(),
                version_info: Some(component.version.clone()),
                package_file_name: None,
                supplier: None,
                originator: None,
                download_location: "NOASSERTION".to_string(),
                files_analyzed: false,
                package_verification_code: None,
                checksums: Vec::new(),
                homepage: None,
                source_info: None,
                license_concluded: license.clone(),
                license_info_from_files: Vec::new(),
                license_declared: license,
                license_comments: None,
                copyright_text: "NOASSERTION".to_string(),
                summary: None,
                description: None,
                comment: None,
                external_refs,
                primary_package_purpose: Some("LIBRARY".to_string()),
                release_date: None,
                built_date: None,
                valid_until_date: None,
            });
            
            // Add dependency relationship
            if component.is_direct() {
                doc.relationships.push(SpdxRelationship {
                    spdx_element_id: root_spdx_id.clone(),
                    relationship_type: SpdxRelationshipType::DependsOn.as_str().to_string(),
                    related_spdx_element: pkg_spdx_id,
                    comment: None,
                });
            }
        }
        
        doc
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export to tag-value format
    pub fn to_tag_value(&self) -> String {
        let mut output = String::new();
        
        // Document header
        output.push_str(&format!("SPDXVersion: {}\n", self.spdx_version));
        output.push_str(&format!("DataLicense: {}\n", self.data_license));
        output.push_str(&format!("SPDXID: {}\n", self.spdx_id));
        output.push_str(&format!("DocumentName: {}\n", self.name));
        output.push_str(&format!("DocumentNamespace: {}\n", self.document_namespace));
        output.push_str("\n");
        
        // Creation info
        output.push_str("## Creation Information\n");
        for creator in &self.creation_info.creators {
            output.push_str(&format!("Creator: {}\n", creator));
        }
        output.push_str(&format!("Created: {}\n", self.creation_info.created));
        if let Some(ref version) = self.creation_info.license_list_version {
            output.push_str(&format!("LicenseListVersion: {}\n", version));
        }
        output.push_str("\n");
        
        // Packages
        for pkg in &self.packages {
            output.push_str("## Package\n");
            output.push_str(&format!("PackageName: {}\n", pkg.name));
            output.push_str(&format!("SPDXID: {}\n", pkg.spdx_id));
            if let Some(ref version) = pkg.version_info {
                output.push_str(&format!("PackageVersion: {}\n", version));
            }
            output.push_str(&format!("PackageDownloadLocation: {}\n", pkg.download_location));
            output.push_str(&format!("FilesAnalyzed: {}\n", pkg.files_analyzed));
            output.push_str(&format!("PackageLicenseConcluded: {}\n", pkg.license_concluded));
            output.push_str(&format!("PackageLicenseDeclared: {}\n", pkg.license_declared));
            output.push_str(&format!("PackageCopyrightText: {}\n", pkg.copyright_text));
            
            for ext_ref in &pkg.external_refs {
                output.push_str(&format!(
                    "ExternalRef: {} {} {}\n",
                    ext_ref.reference_category, ext_ref.reference_type, ext_ref.reference_locator
                ));
            }
            output.push_str("\n");
        }
        
        // Relationships
        output.push_str("## Relationships\n");
        for rel in &self.relationships {
            output.push_str(&format!(
                "Relationship: {} {} {}\n",
                rel.spdx_element_id, rel.relationship_type, rel.related_spdx_element
            ));
        }
        
        output
    }
}

/// Sanitize a string for use as SPDX ID
fn sanitize_spdx_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spdx_new() {
        let doc = SpdxDocument::new("test-project");
        assert_eq!(doc.spdx_version, "SPDX-2.3");
        assert_eq!(doc.name, "test-project");
        assert_eq!(doc.spdx_id, "SPDXRef-DOCUMENT");
    }

    #[test]
    fn test_sanitize_spdx_id() {
        assert_eq!(sanitize_spdx_id("test-123"), "test-123");
        assert_eq!(sanitize_spdx_id("test/package"), "test-package");
        assert_eq!(sanitize_spdx_id("@scope/pkg"), "-scope-pkg");
    }

    #[test]
    fn test_relationship_type() {
        assert_eq!(SpdxRelationshipType::DependsOn.as_str(), "DEPENDS_ON");
        assert_eq!(SpdxRelationshipType::Describes.as_str(), "DESCRIBES");
    }

    #[test]
    fn test_spdx_to_json() {
        let doc = SpdxDocument::new("test");
        let json = doc.to_json().unwrap();
        assert!(json.contains("SPDX-2.3"));
    }
}
