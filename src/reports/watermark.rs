//! Report Watermark and Classification Module
//!
//! Adds watermarks and classification markings to reports for:
//! - Document classification (TLP, confidentiality levels)
//! - Document tracking (watermarks with user/date info)
//! - Distribution control

use serde::{Deserialize, Serialize};

/// Document classification levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClassificationLevel {
    /// Public - No restrictions
    Public,
    /// Internal - For internal use only
    Internal,
    /// Confidential - Restricted distribution
    Confidential,
    /// Secret - Highly restricted
    Secret,
    /// Custom classification
    Custom(String),
}

impl ClassificationLevel {
    /// Get display name
    pub fn display_name(&self) -> &str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::Custom(s) => s,
        }
    }

    /// Get color (hex)
    pub fn color(&self) -> &str {
        match self {
            Self::Public => "#22c55e",    // Green
            Self::Internal => "#3b82f6",   // Blue
            Self::Confidential => "#f97316", // Orange
            Self::Secret => "#dc2626",     // Red
            Self::Custom(_) => "#6b7280",  // Gray
        }
    }

    /// Get background color (hex)
    pub fn background_color(&self) -> &str {
        match self {
            Self::Public => "#dcfce7",
            Self::Internal => "#dbeafe",
            Self::Confidential => "#ffedd5",
            Self::Secret => "#fee2e2",
            Self::Custom(_) => "#f3f4f6",
        }
    }
}

/// Traffic Light Protocol (TLP) marking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TlpMarking {
    /// TLP:CLEAR - For public disclosure
    Clear,
    /// TLP:GREEN - Community-wide sharing
    Green,
    /// TLP:AMBER - Limited sharing
    Amber,
    /// TLP:AMBER+STRICT - Restricted to organization only
    AmberStrict,
    /// TLP:RED - Named recipients only
    Red,
}

impl TlpMarking {
    /// Get display name
    pub fn display_name(&self) -> &str {
        match self {
            Self::Clear => "TLP:CLEAR",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::AmberStrict => "TLP:AMBER+STRICT",
            Self::Red => "TLP:RED",
        }
    }

    /// Get color (hex)
    pub fn color(&self) -> &str {
        match self {
            Self::Clear => "#ffffff",
            Self::Green => "#22c55e",
            Self::Amber => "#f59e0b",
            Self::AmberStrict => "#f59e0b",
            Self::Red => "#dc2626",
        }
    }

    /// Get description
    pub fn description(&self) -> &str {
        match self {
            Self::Clear => "Disclosure is not limited",
            Self::Green => "May be shared with the community",
            Self::Amber => "May be shared with organization members",
            Self::AmberStrict => "Restricted to organization only",
            Self::Red => "Named recipients only",
        }
    }
}

/// Watermark configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkConfig {
    /// Enable watermark
    pub enabled: bool,
    /// Watermark text (e.g., "DRAFT", "CONFIDENTIAL")
    pub text: Option<String>,
    /// Include recipient info in watermark
    pub include_recipient: bool,
    /// Include date in watermark
    pub include_date: bool,
    /// Include tracking ID
    pub include_tracking_id: bool,
    /// Watermark opacity (0.0 - 1.0)
    pub opacity: f32,
    /// Watermark angle in degrees
    pub angle: i32,
    /// Watermark color
    pub color: String,
}

impl Default for WatermarkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            text: None,
            include_recipient: true,
            include_date: true,
            include_tracking_id: true,
            opacity: 0.1,
            angle: -45,
            color: "#6b7280".to_string(),
        }
    }
}

/// Full classification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationConfig {
    /// Classification level
    pub level: Option<ClassificationLevel>,
    /// TLP marking
    pub tlp: Option<TlpMarking>,
    /// Watermark configuration
    pub watermark: WatermarkConfig,
    /// Distribution statement
    pub distribution_statement: Option<String>,
    /// Handling caveats
    pub caveats: Vec<String>,
    /// Expiration date for classification
    pub declassify_on: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for ClassificationConfig {
    fn default() -> Self {
        Self {
            level: None,
            tlp: None,
            watermark: WatermarkConfig::default(),
            distribution_statement: None,
            caveats: Vec::new(),
            declassify_on: None,
        }
    }
}

/// Generate classification header HTML
pub fn generate_classification_header(config: &ClassificationConfig) -> String {
    let mut html = String::new();

    // Classification banner
    if let Some(ref level) = config.level {
        html.push_str(&format!(
            r#"<div style="background: {}; color: {}; padding: 8px; text-align: center; font-weight: bold; border-bottom: 2px solid {}; font-size: 14px;">{}</div>"#,
            level.background_color(),
            level.color(),
            level.color(),
            level.display_name(),
        ));
    }

    // TLP banner
    if let Some(ref tlp) = config.tlp {
        html.push_str(&format!(
            r#"<div style="background: {}; color: white; padding: 6px; text-align: center; font-weight: bold; font-size: 12px;">{}</div>"#,
            tlp.color(),
            tlp.display_name(),
        ));
    }

    html
}

/// Generate classification footer HTML
pub fn generate_classification_footer(config: &ClassificationConfig) -> String {
    let mut html = String::new();

    // Distribution statement
    if let Some(ref statement) = config.distribution_statement {
        html.push_str(&format!(
            r#"<div style="margin-top: 20px; padding: 10px; border: 1px solid #ddd; background: #f9fafb; font-size: 11px;">{}</div>"#,
            statement,
        ));
    }

    // Caveats
    if !config.caveats.is_empty() {
        html.push_str(r#"<div style="margin-top: 10px; font-size: 10px; color: #6b7280;">"#);
        html.push_str("<strong>Handling Caveats:</strong> ");
        html.push_str(&config.caveats.join(" | "));
        html.push_str("</div>");
    }

    // Classification footer banner
    if let Some(ref level) = config.level {
        html.push_str(&format!(
            r#"<div style="margin-top: 20px; background: {}; color: {}; padding: 8px; text-align: center; font-weight: bold; border-top: 2px solid {}; font-size: 14px;">{}</div>"#,
            level.background_color(),
            level.color(),
            level.color(),
            level.display_name(),
        ));
    }

    html
}

/// Generate CSS for watermark overlay
pub fn generate_watermark_css(config: &WatermarkConfig, recipient: Option<&str>, tracking_id: Option<&str>) -> String {
    if !config.enabled {
        return String::new();
    }

    let mut watermark_parts: Vec<String> = Vec::new();

    if let Some(ref text) = config.text {
        watermark_parts.push(text.clone());
    }

    if config.include_recipient {
        if let Some(recipient) = recipient {
            watermark_parts.push(recipient.to_string());
        }
    }

    if config.include_date {
        watermark_parts.push(chrono::Utc::now().format("%Y-%m-%d").to_string());
    }

    if config.include_tracking_id {
        if let Some(id) = tracking_id {
            watermark_parts.push(id.to_string());
        }
    }

    if watermark_parts.is_empty() {
        return String::new();
    }

    let watermark_text = watermark_parts.join(" | ");

    format!(
        r#"
@media print, screen {{
    body::after {{
        content: "{}";
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%) rotate({}deg);
        font-size: 72px;
        color: {};
        opacity: {};
        white-space: nowrap;
        pointer-events: none;
        z-index: 9999;
        user-select: none;
    }}
}}
"#,
        watermark_text,
        config.angle,
        config.color,
        config.opacity,
    )
}

/// Generate watermark SVG for PDF embedding
pub fn generate_watermark_svg(config: &WatermarkConfig, recipient: Option<&str>, tracking_id: Option<&str>) -> String {
    if !config.enabled {
        return String::new();
    }

    let mut watermark_parts: Vec<String> = Vec::new();

    if let Some(ref text) = config.text {
        watermark_parts.push(text.clone());
    }

    if config.include_recipient {
        if let Some(recipient) = recipient {
            watermark_parts.push(recipient.to_string());
        }
    }

    if config.include_date {
        watermark_parts.push(chrono::Utc::now().format("%Y-%m-%d").to_string());
    }

    if config.include_tracking_id {
        if let Some(id) = tracking_id {
            watermark_parts.push(id.to_string());
        }
    }

    if watermark_parts.is_empty() {
        return String::new();
    }

    let watermark_text = watermark_parts.join(" | ");

    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600" viewBox="0 0 800 600">
    <text
        x="400"
        y="300"
        text-anchor="middle"
        font-family="Arial, sans-serif"
        font-size="48"
        fill="{}"
        fill-opacity="{}"
        transform="rotate({} 400 300)">
        {}
    </text>
</svg>"#,
        config.color,
        config.opacity,
        config.angle,
        watermark_text,
    )
}

/// Generate DOCX watermark paragraph
pub fn generate_docx_watermark_xml(config: &WatermarkConfig, recipient: Option<&str>, tracking_id: Option<&str>) -> String {
    if !config.enabled {
        return String::new();
    }

    let mut watermark_parts: Vec<String> = Vec::new();

    if let Some(ref text) = config.text {
        watermark_parts.push(text.clone());
    }

    if config.include_recipient {
        if let Some(recipient) = recipient {
            watermark_parts.push(recipient.to_string());
        }
    }

    if config.include_date {
        watermark_parts.push(chrono::Utc::now().format("%Y-%m-%d").to_string());
    }

    if config.include_tracking_id {
        if let Some(id) = tracking_id {
            watermark_parts.push(id.to_string());
        }
    }

    if watermark_parts.is_empty() {
        return String::new();
    }

    let watermark_text = watermark_parts.join(" | ");

    // Return simplified VML shape for DOCX watermark
    let mut xml = String::new();
    xml.push_str("<w:pict xmlns:v=\"urn:schemas-microsoft-com:vml\">\n");
    xml.push_str("<v:shapetype id=\"_x0000_t136\" coordsize=\"21600,21600\"/>\n");
    xml.push_str(&format!(
        "<v:shape type=\"#_x0000_t136\" style=\"position:absolute;rotation:{}\" fillcolor=\"{}\">\n",
        config.angle, config.color
    ));
    xml.push_str(&format!("<v:fill opacity=\"{}\"/>\n", config.opacity));
    xml.push_str(&format!("<v:textpath string=\"{}\"/>\n", watermark_text));
    xml.push_str("</v:shape>\n");
    xml.push_str("</w:pict>");
    xml
}

/// Common classification presets
pub struct ClassificationPresets;

impl ClassificationPresets {
    /// DoD FOUO (For Official Use Only)
    pub fn dod_fouo() -> ClassificationConfig {
        ClassificationConfig {
            level: Some(ClassificationLevel::Custom("FOR OFFICIAL USE ONLY".to_string())),
            tlp: Some(TlpMarking::Amber),
            watermark: WatermarkConfig {
                enabled: true,
                text: Some("FOUO".to_string()),
                include_recipient: true,
                include_date: true,
                include_tracking_id: true,
                opacity: 0.08,
                angle: -30,
                color: "#9ca3af".to_string(),
            },
            distribution_statement: Some(
                "Distribution Statement D: Distribution authorized to DoD and U.S. DoD contractors only.".to_string()
            ),
            caveats: vec!["NOFORN".to_string(), "PROPIN".to_string()],
            declassify_on: None,
        }
    }

    /// Commercial Confidential
    pub fn commercial_confidential() -> ClassificationConfig {
        ClassificationConfig {
            level: Some(ClassificationLevel::Confidential),
            tlp: Some(TlpMarking::Amber),
            watermark: WatermarkConfig {
                enabled: true,
                text: Some("CONFIDENTIAL".to_string()),
                include_recipient: true,
                include_date: true,
                include_tracking_id: false,
                opacity: 0.1,
                angle: -45,
                color: "#f97316".to_string(),
            },
            distribution_statement: Some(
                "This document contains confidential and proprietary information. Unauthorized disclosure is prohibited.".to_string()
            ),
            caveats: vec![],
            declassify_on: None,
        }
    }

    /// Public release
    pub fn public_release() -> ClassificationConfig {
        ClassificationConfig {
            level: Some(ClassificationLevel::Public),
            tlp: Some(TlpMarking::Clear),
            watermark: WatermarkConfig::default(),
            distribution_statement: Some(
                "Approved for public release. Distribution unlimited.".to_string()
            ),
            caveats: vec![],
            declassify_on: None,
        }
    }

    /// Internal draft
    pub fn internal_draft() -> ClassificationConfig {
        ClassificationConfig {
            level: Some(ClassificationLevel::Internal),
            tlp: Some(TlpMarking::Green),
            watermark: WatermarkConfig {
                enabled: true,
                text: Some("DRAFT".to_string()),
                include_recipient: false,
                include_date: true,
                include_tracking_id: false,
                opacity: 0.15,
                angle: -45,
                color: "#3b82f6".to_string(),
            },
            distribution_statement: None,
            caveats: vec!["DRAFT - NOT FOR DISTRIBUTION".to_string()],
            declassify_on: None,
        }
    }

    /// Client-specific (red team report)
    pub fn client_specific(client_name: &str) -> ClassificationConfig {
        ClassificationConfig {
            level: Some(ClassificationLevel::Confidential),
            tlp: Some(TlpMarking::Red),
            watermark: WatermarkConfig {
                enabled: true,
                text: Some("CONFIDENTIAL".to_string()),
                include_recipient: true,
                include_date: true,
                include_tracking_id: true,
                opacity: 0.08,
                angle: -45,
                color: "#dc2626".to_string(),
            },
            distribution_statement: Some(format!(
                "This document is prepared exclusively for {} and contains sensitive security assessment findings. \
                Unauthorized disclosure, reproduction, or distribution is strictly prohibited.",
                client_name
            )),
            caveats: vec!["CLIENT PROPRIETARY".to_string(), "SECURITY SENSITIVE".to_string()],
            declassify_on: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_levels() {
        assert_eq!(ClassificationLevel::Public.display_name(), "PUBLIC");
        assert_eq!(ClassificationLevel::Confidential.color(), "#f97316");
        assert_eq!(ClassificationLevel::Custom("TEST".to_string()).display_name(), "TEST");
    }

    #[test]
    fn test_tlp_markings() {
        assert_eq!(TlpMarking::Red.display_name(), "TLP:RED");
        assert_eq!(TlpMarking::Amber.color(), "#f59e0b");
    }

    #[test]
    fn test_watermark_css_generation() {
        let config = WatermarkConfig {
            enabled: true,
            text: Some("CONFIDENTIAL".to_string()),
            include_recipient: true,
            include_date: false,
            include_tracking_id: false,
            opacity: 0.1,
            angle: -45,
            color: "#ff0000".to_string(),
        };

        let css = generate_watermark_css(&config, Some("John Doe"), None);
        assert!(css.contains("CONFIDENTIAL"));
        assert!(css.contains("John Doe"));
        assert!(css.contains("rotate(-45deg)"));
    }

    #[test]
    fn test_watermark_disabled() {
        let config = WatermarkConfig::default();
        let css = generate_watermark_css(&config, Some("Test"), Some("123"));
        assert!(css.is_empty());
    }

    #[test]
    fn test_classification_presets() {
        let fouo = ClassificationPresets::dod_fouo();
        assert!(fouo.watermark.enabled);
        assert!(fouo.caveats.contains(&"NOFORN".to_string()));

        let public = ClassificationPresets::public_release();
        assert!(!public.watermark.enabled);
        assert_eq!(public.tlp, Some(TlpMarking::Clear));
    }

    #[test]
    fn test_generate_classification_header() {
        let config = ClassificationConfig {
            level: Some(ClassificationLevel::Secret),
            tlp: Some(TlpMarking::Red),
            ..Default::default()
        };

        let header = generate_classification_header(&config);
        assert!(header.contains("SECRET"));
        assert!(header.contains("TLP:RED"));
    }
}
