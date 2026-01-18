//! Custom Report Templates
//!
//! Provides support for user-defined report templates with:
//! - Custom section ordering and visibility
//! - Custom branding (logo, colors, fonts)
//! - Custom content blocks and text
//! - Template versioning and sharing

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Custom report template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomTemplate {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_public: bool,
    pub version: i32,
    pub sections: Vec<TemplateSectionConfig>,
    pub branding: TemplateBranding,
    pub settings: TemplateSettings,
}

impl CustomTemplate {
    /// Create a new custom template
    pub fn new(name: &str, created_by: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: None,
            created_by: created_by.to_string(),
            created_at: now,
            updated_at: now,
            is_public: false,
            version: 1,
            sections: Self::default_sections(),
            branding: TemplateBranding::default(),
            settings: TemplateSettings::default(),
        }
    }

    /// Default section configuration
    pub fn default_sections() -> Vec<TemplateSectionConfig> {
        vec![
            TemplateSectionConfig {
                section_type: SectionType::CoverPage,
                order: 0,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::TableOfContents,
                order: 1,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::ExecutiveSummary,
                order: 2,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::RiskOverview,
                order: 3,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::VulnerabilityFindings,
                order: 4,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::HostInventory,
                order: 5,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::RemediationRecommendations,
                order: 6,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
            TemplateSectionConfig {
                section_type: SectionType::Appendix,
                order: 7,
                enabled: true,
                custom_title: None,
                custom_content: None,
                settings: SectionSettings::default(),
            },
        ]
    }
}

/// Section configuration in a template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSectionConfig {
    pub section_type: SectionType,
    pub order: i32,
    pub enabled: bool,
    pub custom_title: Option<String>,
    pub custom_content: Option<String>,
    pub settings: SectionSettings,
}

/// Available section types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionType {
    CoverPage,
    TableOfContents,
    ExecutiveSummary,
    RiskOverview,
    MethodologySection,
    ScopeSection,
    VulnerabilityFindings,
    HostInventory,
    PortAnalysis,
    ServiceEnumeration,
    SecretFindings,
    ComplianceResults,
    Screenshots,
    RemediationRecommendations,
    Timeline,
    OperatorNotes,
    Appendix,
    CustomContent,
    Disclaimer,
    Glossary,
}

impl SectionType {
    pub fn title(&self) -> &'static str {
        match self {
            Self::CoverPage => "Cover Page",
            Self::TableOfContents => "Table of Contents",
            Self::ExecutiveSummary => "Executive Summary",
            Self::RiskOverview => "Risk Overview",
            Self::MethodologySection => "Methodology",
            Self::ScopeSection => "Scope",
            Self::VulnerabilityFindings => "Vulnerability Findings",
            Self::HostInventory => "Host Inventory",
            Self::PortAnalysis => "Port Analysis",
            Self::ServiceEnumeration => "Service Enumeration",
            Self::SecretFindings => "Secret Findings",
            Self::ComplianceResults => "Compliance Results",
            Self::Screenshots => "Visual Evidence",
            Self::RemediationRecommendations => "Remediation Recommendations",
            Self::Timeline => "Timeline",
            Self::OperatorNotes => "Operator Notes",
            Self::Appendix => "Appendix",
            Self::CustomContent => "Custom Content",
            Self::Disclaimer => "Disclaimer",
            Self::Glossary => "Glossary",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CoverPage => "The report cover page with title, client info, and dates",
            Self::TableOfContents => "Auto-generated table of contents",
            Self::ExecutiveSummary => "High-level summary for executives and stakeholders",
            Self::RiskOverview => "Charts and statistics showing risk distribution",
            Self::MethodologySection => "Description of testing methodology used",
            Self::ScopeSection => "Scope and boundaries of the assessment",
            Self::VulnerabilityFindings => "Detailed vulnerability findings with evidence",
            Self::HostInventory => "List of discovered hosts and their details",
            Self::PortAnalysis => "Open ports and services analysis",
            Self::ServiceEnumeration => "Detailed service enumeration results",
            Self::SecretFindings => "Discovered secrets, credentials, and sensitive data",
            Self::ComplianceResults => "Compliance framework mapping and results",
            Self::Screenshots => "Visual evidence and screenshots",
            Self::RemediationRecommendations => "Prioritized remediation recommendations",
            Self::Timeline => "Timeline of assessment activities",
            Self::OperatorNotes => "Operator notes and observations",
            Self::Appendix => "Supplementary information and raw data",
            Self::CustomContent => "User-defined custom content block",
            Self::Disclaimer => "Legal disclaimers and limitations",
            Self::Glossary => "Glossary of terms and abbreviations",
        }
    }

    /// Get all available section types
    pub fn all() -> Vec<Self> {
        vec![
            Self::CoverPage,
            Self::TableOfContents,
            Self::ExecutiveSummary,
            Self::RiskOverview,
            Self::MethodologySection,
            Self::ScopeSection,
            Self::VulnerabilityFindings,
            Self::HostInventory,
            Self::PortAnalysis,
            Self::ServiceEnumeration,
            Self::SecretFindings,
            Self::ComplianceResults,
            Self::Screenshots,
            Self::RemediationRecommendations,
            Self::Timeline,
            Self::OperatorNotes,
            Self::Appendix,
            Self::CustomContent,
            Self::Disclaimer,
            Self::Glossary,
        ]
    }
}

/// Section-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSettings {
    /// Include page break before section
    pub page_break_before: bool,
    /// Show section in table of contents
    pub show_in_toc: bool,
    /// Severity filter for vulnerability sections
    pub severity_filter: Option<Vec<String>>,
    /// Maximum items to show (0 = unlimited)
    pub max_items: usize,
    /// Custom CSS class for styling
    pub css_class: Option<String>,
    /// Chart type for risk/stats sections
    pub chart_type: Option<ChartType>,
    /// Custom fields to include
    pub include_fields: Option<Vec<String>>,
    /// Fields to exclude
    pub exclude_fields: Option<Vec<String>>,
}

impl Default for SectionSettings {
    fn default() -> Self {
        Self {
            page_break_before: true,
            show_in_toc: true,
            severity_filter: None,
            max_items: 0,
            css_class: None,
            chart_type: None,
            include_fields: None,
            exclude_fields: None,
        }
    }
}

/// Chart types for visualization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChartType {
    Bar,
    Pie,
    Donut,
    Line,
    Radar,
    HorizontalBar,
    Stacked,
}

/// Branding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBranding {
    /// Company/organization name
    pub company_name: Option<String>,
    /// Logo image (base64 encoded)
    pub logo_base64: Option<String>,
    /// Logo position on cover
    pub logo_position: LogoPosition,
    /// Primary brand color (hex)
    pub primary_color: String,
    /// Secondary brand color (hex)
    pub secondary_color: String,
    /// Accent color for highlights (hex)
    pub accent_color: String,
    /// Header font
    pub header_font: String,
    /// Body font
    pub body_font: String,
    /// Footer text
    pub footer_text: Option<String>,
    /// Header text
    pub header_text: Option<String>,
    /// Watermark text
    pub watermark: Option<String>,
    /// Classification label (Confidential, Internal, etc.)
    pub classification: Option<String>,
}

impl Default for TemplateBranding {
    fn default() -> Self {
        Self {
            company_name: None,
            logo_base64: None,
            logo_position: LogoPosition::TopRight,
            primary_color: "#1a365d".to_string(), // Dark blue
            secondary_color: "#2c5282".to_string(), // Medium blue
            accent_color: "#e53e3e".to_string(), // Red for critical
            header_font: "Arial".to_string(),
            body_font: "Arial".to_string(),
            footer_text: None,
            header_text: None,
            watermark: None,
            classification: None,
        }
    }
}

/// Logo position options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogoPosition {
    TopLeft,
    TopCenter,
    TopRight,
    BottomLeft,
    BottomCenter,
    BottomRight,
}

/// Template generation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSettings {
    /// Paper size
    pub paper_size: PaperSize,
    /// Page orientation
    pub orientation: PageOrientation,
    /// Margin sizes in inches
    pub margins: PageMargins,
    /// Include page numbers
    pub page_numbers: bool,
    /// Page number position
    pub page_number_position: PageNumberPosition,
    /// Date format
    pub date_format: String,
    /// Show confidentiality notice on each page
    pub show_confidentiality: bool,
    /// Include raw scan data in appendix
    pub include_raw_data: bool,
    /// Generate AI narrative sections
    pub ai_narrative: bool,
    /// Language for the report
    pub language: String,
}

impl Default for TemplateSettings {
    fn default() -> Self {
        Self {
            paper_size: PaperSize::Letter,
            orientation: PageOrientation::Portrait,
            margins: PageMargins::default(),
            page_numbers: true,
            page_number_position: PageNumberPosition::BottomCenter,
            date_format: "%B %d, %Y".to_string(),
            show_confidentiality: true,
            include_raw_data: false,
            ai_narrative: false,
            language: "en".to_string(),
        }
    }
}

/// Paper size options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaperSize {
    Letter,
    Legal,
    A4,
    A3,
}

impl PaperSize {
    pub fn dimensions(&self) -> (f32, f32) {
        match self {
            Self::Letter => (8.5, 11.0),
            Self::Legal => (8.5, 14.0),
            Self::A4 => (8.27, 11.69),
            Self::A3 => (11.69, 16.54),
        }
    }
}

/// Page orientation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PageOrientation {
    Portrait,
    Landscape,
}

/// Page margins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageMargins {
    pub top: f32,
    pub bottom: f32,
    pub left: f32,
    pub right: f32,
}

impl Default for PageMargins {
    fn default() -> Self {
        Self {
            top: 1.0,
            bottom: 1.0,
            left: 1.0,
            right: 1.0,
        }
    }
}

/// Page number position
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageNumberPosition {
    TopLeft,
    TopCenter,
    TopRight,
    BottomLeft,
    BottomCenter,
    BottomRight,
}

// ============================================================================
// Database Operations
// ============================================================================

/// Save a custom template to the database
pub async fn save_template(pool: &SqlitePool, template: &CustomTemplate) -> Result<()> {
    let sections_json = serde_json::to_string(&template.sections)?;
    let branding_json = serde_json::to_string(&template.branding)?;
    let settings_json = serde_json::to_string(&template.settings)?;

    sqlx::query(
        r#"INSERT INTO custom_report_templates
           (id, name, description, created_by, created_at, updated_at, is_public, version, sections, branding, settings)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
           name = excluded.name,
           description = excluded.description,
           updated_at = excluded.updated_at,
           is_public = excluded.is_public,
           version = version + 1,
           sections = excluded.sections,
           branding = excluded.branding,
           settings = excluded.settings"#
    )
    .bind(&template.id)
    .bind(&template.name)
    .bind(&template.description)
    .bind(&template.created_by)
    .bind(template.created_at.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .bind(template.is_public)
    .bind(template.version)
    .bind(&sections_json)
    .bind(&branding_json)
    .bind(&settings_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a custom template by ID
pub async fn get_template(pool: &SqlitePool, id: &str) -> Result<Option<CustomTemplate>> {
    let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, String, bool, i32, String, String, String)>(
        r#"SELECT id, name, description, created_by, created_at, updated_at, is_public, version, sections, branding, settings
           FROM custom_report_templates WHERE id = ?"#
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((id, name, description, created_by, created_at, updated_at, is_public, version, sections, branding, settings)) => {
            Ok(Some(CustomTemplate {
                id,
                name,
                description,
                created_by,
                created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
                is_public,
                version,
                sections: serde_json::from_str(&sections)?,
                branding: serde_json::from_str(&branding)?,
                settings: serde_json::from_str(&settings)?,
            }))
        }
        None => Ok(None),
    }
}

/// List templates for a user (including public templates)
pub async fn list_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<CustomTemplate>> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, String, String, String, bool, i32, String, String, String)>(
        r#"SELECT id, name, description, created_by, created_at, updated_at, is_public, version, sections, branding, settings
           FROM custom_report_templates
           WHERE created_by = ? OR is_public = 1
           ORDER BY updated_at DESC"#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut templates = Vec::new();
    for (id, name, description, created_by, created_at, updated_at, is_public, version, sections, branding, settings) in rows {
        templates.push(CustomTemplate {
            id,
            name,
            description,
            created_by,
            created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
            is_public,
            version,
            sections: serde_json::from_str(&sections)?,
            branding: serde_json::from_str(&branding)?,
            settings: serde_json::from_str(&settings)?,
        });
    }

    Ok(templates)
}

/// Delete a custom template
pub async fn delete_template(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM custom_report_templates WHERE id = ? AND created_by = ?"
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Duplicate a template
pub async fn duplicate_template(pool: &SqlitePool, template_id: &str, new_name: &str, user_id: &str) -> Result<CustomTemplate> {
    let original = get_template(pool, template_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Template not found"))?;

    let mut new_template = original.clone();
    new_template.id = Uuid::new_v4().to_string();
    new_template.name = new_name.to_string();
    new_template.created_by = user_id.to_string();
    new_template.created_at = Utc::now();
    new_template.updated_at = Utc::now();
    new_template.is_public = false;
    new_template.version = 1;

    save_template(pool, &new_template).await?;

    Ok(new_template)
}

// ============================================================================
// Built-in Templates
// ============================================================================

/// Get built-in template definitions
pub fn get_builtin_templates() -> Vec<CustomTemplate> {
    vec![
        executive_brief_template(),
        full_technical_template(),
        compliance_report_template(),
        quick_summary_template(),
    ]
}

fn executive_brief_template() -> CustomTemplate {
    let mut template = CustomTemplate::new("Executive Brief", "system");
    template.id = "builtin-executive".to_string();
    template.description = Some("Concise summary for executive stakeholders".to_string());
    template.is_public = true;
    template.sections = vec![
        TemplateSectionConfig {
            section_type: SectionType::CoverPage,
            order: 0,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::ExecutiveSummary,
            order: 1,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::RiskOverview,
            order: 2,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings {
                chart_type: Some(ChartType::Pie),
                ..Default::default()
            },
        },
        TemplateSectionConfig {
            section_type: SectionType::VulnerabilityFindings,
            order: 3,
            enabled: true,
            custom_title: Some("Critical and High Findings".to_string()),
            custom_content: None,
            settings: SectionSettings {
                severity_filter: Some(vec!["critical".to_string(), "high".to_string()]),
                max_items: 10,
                ..Default::default()
            },
        },
        TemplateSectionConfig {
            section_type: SectionType::RemediationRecommendations,
            order: 4,
            enabled: true,
            custom_title: Some("Key Recommendations".to_string()),
            custom_content: None,
            settings: SectionSettings {
                max_items: 5,
                ..Default::default()
            },
        },
    ];
    template
}

fn full_technical_template() -> CustomTemplate {
    let mut template = CustomTemplate::new("Full Technical Report", "system");
    template.id = "builtin-technical".to_string();
    template.description = Some("Comprehensive technical report with all details".to_string());
    template.is_public = true;
    template.sections = CustomTemplate::default_sections();
    template
}

fn compliance_report_template() -> CustomTemplate {
    let mut template = CustomTemplate::new("Compliance Report", "system");
    template.id = "builtin-compliance".to_string();
    template.description = Some("Report focused on compliance mapping".to_string());
    template.is_public = true;
    template.sections = vec![
        TemplateSectionConfig {
            section_type: SectionType::CoverPage,
            order: 0,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::TableOfContents,
            order: 1,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::ExecutiveSummary,
            order: 2,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::ScopeSection,
            order: 3,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::ComplianceResults,
            order: 4,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::VulnerabilityFindings,
            order: 5,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::RemediationRecommendations,
            order: 6,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
        TemplateSectionConfig {
            section_type: SectionType::Disclaimer,
            order: 7,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings::default(),
        },
    ];
    template
}

fn quick_summary_template() -> CustomTemplate {
    let mut template = CustomTemplate::new("Quick Summary", "system");
    template.id = "builtin-quick".to_string();
    template.description = Some("Brief one-page summary".to_string());
    template.is_public = true;
    template.sections = vec![
        TemplateSectionConfig {
            section_type: SectionType::ExecutiveSummary,
            order: 0,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings {
                page_break_before: false,
                ..Default::default()
            },
        },
        TemplateSectionConfig {
            section_type: SectionType::RiskOverview,
            order: 1,
            enabled: true,
            custom_title: None,
            custom_content: None,
            settings: SectionSettings {
                page_break_before: false,
                chart_type: Some(ChartType::HorizontalBar),
                ..Default::default()
            },
        },
    ];
    template.settings.page_numbers = false;
    template
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_types() {
        let types = SectionType::all();
        assert!(types.len() >= 10);

        for section_type in types {
            assert!(!section_type.title().is_empty());
            assert!(!section_type.description().is_empty());
        }
    }

    #[test]
    fn test_default_template() {
        let template = CustomTemplate::new("Test", "user123");
        assert!(!template.sections.is_empty());
        assert!(template.sections.iter().all(|s| s.enabled));
    }

    #[test]
    fn test_builtin_templates() {
        let templates = get_builtin_templates();
        assert!(templates.len() >= 3);

        for template in templates {
            assert!(template.is_public);
            assert!(template.id.starts_with("builtin-"));
        }
    }

    #[test]
    fn test_paper_sizes() {
        assert_eq!(PaperSize::Letter.dimensions(), (8.5, 11.0));
        assert_eq!(PaperSize::A4.dimensions(), (8.27, 11.69));
    }
}
