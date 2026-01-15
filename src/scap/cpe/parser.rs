//! CPE Parser

use super::types::*;

/// Parser for CPE strings
pub struct CpeParser;

impl CpeParser {
    /// Parse a CPE 2.3 URI (e.g., "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
    pub fn parse_uri(uri: &str) -> Result<Cpe, CpeParseError> {
        if !uri.starts_with("cpe:2.3:") {
            return Err(CpeParseError {
                message: "Invalid CPE URI: must start with 'cpe:2.3:'".to_string(),
            });
        }

        let parts: Vec<&str> = uri[8..].split(':').collect();
        if parts.len() != 11 {
            return Err(CpeParseError {
                message: format!("Invalid CPE URI: expected 11 components, got {}", parts.len()),
            });
        }

        let part = CpePart::from_char(parts[0].chars().next().unwrap_or('a'))
            .ok_or_else(|| CpeParseError {
                message: format!("Invalid CPE part: {}", parts[0]),
            })?;

        Ok(Cpe {
            part,
            vendor: Self::parse_attribute(parts[1]),
            product: Self::parse_attribute(parts[2]),
            version: Self::parse_attribute(parts[3]),
            update: Self::parse_attribute(parts[4]),
            edition: Self::parse_attribute(parts[5]),
            language: Self::parse_attribute(parts[6]),
            sw_edition: Self::parse_attribute(parts[7]),
            target_sw: Self::parse_attribute(parts[8]),
            target_hw: Self::parse_attribute(parts[9]),
            other: Self::parse_attribute(parts[10]),
        })
    }

    /// Parse a CPE 2.3 formatted string
    pub fn parse_formatted_string(fs: &str) -> Result<Cpe, CpeParseError> {
        // Formatted string uses different delimiters
        // For now, treat as URI
        Self::parse_uri(fs)
    }

    fn parse_attribute(s: &str) -> WfnAttribute {
        match s {
            "*" => WfnAttribute::Any,
            "-" => WfnAttribute::NotApplicable,
            _ => WfnAttribute::Value(s.to_string()),
        }
    }
}
