//! CPE 2.3 Types

use serde::{Deserialize, Serialize};

/// CPE 2.3 Naming Specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cpe {
    pub part: CpePart,
    pub vendor: WfnAttribute,
    pub product: WfnAttribute,
    pub version: WfnAttribute,
    pub update: WfnAttribute,
    pub edition: WfnAttribute,
    pub language: WfnAttribute,
    pub sw_edition: WfnAttribute,
    pub target_sw: WfnAttribute,
    pub target_hw: WfnAttribute,
    pub other: WfnAttribute,
}

impl Cpe {
    /// Create a new CPE with all attributes set to ANY
    pub fn new(part: CpePart) -> Self {
        Self {
            part,
            vendor: WfnAttribute::Any,
            product: WfnAttribute::Any,
            version: WfnAttribute::Any,
            update: WfnAttribute::Any,
            edition: WfnAttribute::Any,
            language: WfnAttribute::Any,
            sw_edition: WfnAttribute::Any,
            target_sw: WfnAttribute::Any,
            target_hw: WfnAttribute::Any,
            other: WfnAttribute::Any,
        }
    }

    /// Parse from CPE 2.3 URI format
    pub fn from_uri(uri: &str) -> Result<Self, CpeParseError> {
        super::parser::CpeParser::parse_uri(uri)
    }

    /// Parse from CPE 2.3 formatted string
    pub fn from_formatted_string(fs: &str) -> Result<Self, CpeParseError> {
        super::parser::CpeParser::parse_formatted_string(fs)
    }

    /// Convert to CPE 2.3 URI format
    pub fn to_uri(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part.as_char(),
            self.vendor.to_uri_component(),
            self.product.to_uri_component(),
            self.version.to_uri_component(),
            self.update.to_uri_component(),
            self.edition.to_uri_component(),
            self.language.to_uri_component(),
            self.sw_edition.to_uri_component(),
            self.target_sw.to_uri_component(),
            self.target_hw.to_uri_component(),
            self.other.to_uri_component(),
        )
    }
}

impl Default for Cpe {
    fn default() -> Self {
        Self::new(CpePart::Application)
    }
}

/// CPE Part type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpePart {
    /// Application ('a')
    Application,
    /// Operating System ('o')
    OperatingSystem,
    /// Hardware ('h')
    Hardware,
}

impl CpePart {
    pub fn as_char(&self) -> char {
        match self {
            CpePart::Application => 'a',
            CpePart::OperatingSystem => 'o',
            CpePart::Hardware => 'h',
        }
    }

    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'a' => Some(CpePart::Application),
            'o' => Some(CpePart::OperatingSystem),
            'h' => Some(CpePart::Hardware),
            _ => None,
        }
    }
}

/// Well-Formed Name attribute value
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WfnAttribute {
    /// Matches any value ('*')
    Any,
    /// Not applicable ('-')
    NotApplicable,
    /// Specific value
    Value(String),
}

impl WfnAttribute {
    pub fn to_uri_component(&self) -> &str {
        match self {
            WfnAttribute::Any => "*",
            WfnAttribute::NotApplicable => "-",
            WfnAttribute::Value(v) => v.as_str(),
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, WfnAttribute::Any)
    }

    pub fn is_na(&self) -> bool {
        matches!(self, WfnAttribute::NotApplicable)
    }
}

impl Default for WfnAttribute {
    fn default() -> Self {
        WfnAttribute::Any
    }
}

/// CPE parsing error
#[derive(Debug, Clone)]
pub struct CpeParseError {
    pub message: String,
}

impl std::fmt::Display for CpeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CPE parse error: {}", self.message)
    }
}

impl std::error::Error for CpeParseError {}

/// CPE Dictionary entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeDictionaryItem {
    pub cpe: Cpe,
    pub title: Vec<super::super::LocalizedText>,
    pub notes: Vec<super::super::LocalizedText>,
    pub references: Vec<super::super::Reference>,
    pub deprecated: bool,
    pub deprecated_by: Option<String>,
}

/// CPE Platform specification for applicability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpePlatform {
    pub id: String,
    pub title: Option<super::super::LocalizedText>,
    pub logical_test: CpeLogicalTest,
}

/// Logical test for CPE platform matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpeLogicalTest {
    FactRef(CpeFactRef),
    And(Vec<CpeLogicalTest>),
    Or(Vec<CpeLogicalTest>),
    Negate(Box<CpeLogicalTest>),
}

/// Reference to a CPE fact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeFactRef {
    pub cpe: Cpe,
    pub check_existence: bool,
}
