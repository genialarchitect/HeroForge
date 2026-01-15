//! XCCDF Parser
//!
//! Parses XCCDF 1.2 benchmark XML files into typed Rust structures.

use anyhow::{Result, Context, bail};
use quick_xml::events::{Event, BytesStart};
use quick_xml::reader::Reader;

use super::types::*;
use crate::scap::{ScapSeverity, StigCategory, LocalizedText, Reference};

/// Parser for XCCDF XML content
pub struct XccdfParser;

impl XccdfParser {
    /// Parse XCCDF benchmark from XML
    pub fn parse(xml: &str) -> Result<XccdfBenchmark> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut benchmark = XccdfBenchmark::default();
        let mut buf = Vec::new();
        let mut current_path: Vec<String> = Vec::new();
        let mut current_group: Option<XccdfGroup> = None;
        let mut current_rule: Option<XccdfRule> = None;
        let mut current_profile: Option<XccdfProfile> = None;
        let mut current_text = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = Self::local_name(e);
                    current_path.push(name.clone());

                    match name.as_str() {
                        "Benchmark" => {
                            Self::parse_benchmark_attrs(e, &mut benchmark)?;
                        }
                        "Profile" => {
                            current_profile = Some(Self::parse_profile_start(e)?);
                        }
                        "Group" => {
                            current_group = Some(Self::parse_group_start(e)?);
                        }
                        "Rule" => {
                            current_rule = Some(Self::parse_rule_start(e)?);
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = Self::local_name_end(e);

                    match name.as_str() {
                        "Profile" => {
                            if let Some(profile) = current_profile.take() {
                                benchmark.profiles.push(profile);
                            }
                        }
                        "Group" => {
                            if let Some(group) = current_group.take() {
                                benchmark.groups.push(group);
                            }
                        }
                        "Rule" => {
                            if let Some(rule) = current_rule.take() {
                                // Add rule to current group or benchmark
                                if let Some(ref mut group) = current_group {
                                    group.rules.push(rule.id.clone());
                                }
                                benchmark.rules.push(rule);
                            }
                        }
                        "title" => {
                            let title = std::mem::take(&mut current_text);
                            if let Some(ref mut rule) = current_rule {
                                rule.title = LocalizedText::new(&title);
                            } else if let Some(ref mut group) = current_group {
                                group.title = LocalizedText::new(&title);
                            } else if let Some(ref mut profile) = current_profile {
                                profile.title = LocalizedText::new(&title);
                            } else if current_path.len() <= 2 {
                                benchmark.title = LocalizedText::new(&title);
                            }
                        }
                        "description" => {
                            let desc = std::mem::take(&mut current_text);
                            if let Some(ref mut rule) = current_rule {
                                rule.description = Some(LocalizedText::new(&desc));
                            } else if let Some(ref mut group) = current_group {
                                group.description = Some(LocalizedText::new(&desc));
                            } else if let Some(ref mut profile) = current_profile {
                                profile.description = Some(LocalizedText::new(&desc));
                            } else if current_path.len() <= 2 {
                                benchmark.description = Some(LocalizedText::new(&desc));
                            }
                        }
                        "version" => {
                            if current_path.len() <= 2 {
                                benchmark.version = std::mem::take(&mut current_text);
                            }
                        }
                        "rationale" => {
                            if let Some(ref mut rule) = current_rule {
                                rule.rationale = Some(LocalizedText::new(&std::mem::take(&mut current_text)));
                            }
                        }
                        "fixtext" => {
                            if let Some(ref mut rule) = current_rule {
                                let text = std::mem::take(&mut current_text);
                                rule.fixtext = Some(Fixtext {
                                    text,
                                    fixref: None,
                                    reboot: false,
                                    strategy: None,
                                    disruption: None,
                                    complexity: None,
                                });
                            }
                        }
                        _ => {}
                    }

                    current_path.pop();
                }
                Ok(Event::Text(ref e)) => {
                    current_text = String::from_utf8_lossy(e.as_ref()).to_string();
                }
                Ok(Event::Eof) => break,
                Err(e) => bail!("Error parsing XCCDF XML: {:?}", e),
                _ => {}
            }
            buf.clear();
        }

        Ok(benchmark)
    }

    /// Parse XCCDF from file
    pub async fn parse_file(path: &str) -> Result<XccdfBenchmark> {
        let content = tokio::fs::read_to_string(path).await
            .with_context(|| format!("Failed to read XCCDF file: {}", path))?;
        Self::parse(&content)
    }

    fn local_name(e: &BytesStart) -> String {
        let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        if let Some(pos) = full_name.rfind(':') {
            full_name[pos + 1..].to_string()
        } else {
            full_name
        }
    }

    fn local_name_end(e: &quick_xml::events::BytesEnd) -> String {
        let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
        if let Some(pos) = full_name.rfind(':') {
            full_name[pos + 1..].to_string()
        } else {
            full_name
        }
    }

    fn parse_benchmark_attrs(e: &BytesStart, benchmark: &mut XccdfBenchmark) -> Result<()> {
        for attr in e.attributes().flatten() {
            if attr.key.as_ref() == b"id" {
                benchmark.id = String::from_utf8_lossy(&attr.value).to_string();
            }
        }
        Ok(())
    }

    fn parse_profile_start(e: &BytesStart) -> Result<XccdfProfile> {
        let mut id = String::new();
        let mut extends = None;

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"extends" => {
                    extends = Some(String::from_utf8_lossy(&attr.value).to_string());
                }
                _ => {}
            }
        }

        Ok(XccdfProfile {
            id,
            title: LocalizedText::default(),
            description: None,
            extends,
            selects: Vec::new(),
            set_values: Vec::new(),
            refine_values: Vec::new(),
            refine_rules: Vec::new(),
        })
    }

    fn parse_group_start(e: &BytesStart) -> Result<XccdfGroup> {
        let mut id = String::new();

        for attr in e.attributes().flatten() {
            if attr.key.as_ref() == b"id" {
                id = String::from_utf8_lossy(&attr.value).to_string();
            }
        }

        Ok(XccdfGroup {
            id,
            title: LocalizedText::default(),
            description: None,
            rules: Vec::new(),
            groups: Vec::new(),
        })
    }

    fn parse_rule_start(e: &BytesStart) -> Result<XccdfRule> {
        let mut rule = XccdfRule::default();

        for attr in e.attributes().flatten() {
            match attr.key.as_ref() {
                b"id" => {
                    rule.id = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"severity" => {
                    rule.severity = Self::parse_severity(&String::from_utf8_lossy(&attr.value));
                }
                b"weight" => {
                    rule.weight = String::from_utf8_lossy(&attr.value)
                        .parse()
                        .unwrap_or(1.0);
                }
                _ => {}
            }
        }

        Ok(rule)
    }

    fn parse_severity(s: &str) -> ScapSeverity {
        match s.to_lowercase().as_str() {
            "critical" | "very high" | "cat i" | "cat_i" => ScapSeverity::Critical,
            "high" => ScapSeverity::High,
            "medium" | "cat ii" | "cat_ii" | "moderate" => ScapSeverity::Medium,
            "low" | "cat iii" | "cat_iii" => ScapSeverity::Low,
            "info" | "informational" => ScapSeverity::Info,
            _ => ScapSeverity::Medium,
        }
    }
}

/// XCCDF profile selector for determining which rules to evaluate
pub struct ProfileSelector<'a> {
    benchmark: &'a XccdfBenchmark,
    profile: Option<&'a XccdfProfile>,
}

impl<'a> ProfileSelector<'a> {
    pub fn new(benchmark: &'a XccdfBenchmark, profile_id: Option<&str>) -> Self {
        let profile = profile_id.and_then(|id| {
            benchmark.profiles.iter().find(|p| p.id == id)
        });
        Self { benchmark, profile }
    }

    /// Get all rules that should be evaluated based on profile selection
    pub fn get_selected_rules(&self) -> Vec<&'a XccdfRule> {
        let mut selected = Vec::new();

        for rule in &self.benchmark.rules {
            if self.is_rule_selected(&rule.id) {
                selected.push(rule);
            }
        }

        selected
    }

    fn is_rule_selected(&self, rule_id: &str) -> bool {
        if let Some(profile) = self.profile {
            // Check profile-specific selection
            for select in &profile.selects {
                if select.id_ref == rule_id {
                    return select.selected;
                }
            }
        }

        // By default, all rules are selected
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_benchmark() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <Benchmark id="test-benchmark" xmlns="http://checklists.nist.gov/xccdf/1.2">
            <title>Test Benchmark</title>
            <version>1.0</version>
            <description>A test benchmark</description>
            <Profile id="profile1">
                <title>Test Profile</title>
            </Profile>
            <Rule id="rule1" severity="high">
                <title>Test Rule</title>
                <description>Test rule description</description>
            </Rule>
        </Benchmark>"#;

        let benchmark = XccdfParser::parse(xml).unwrap();
        assert_eq!(benchmark.id, "test-benchmark");
        assert_eq!(benchmark.profiles.len(), 1);
        assert_eq!(benchmark.rules.len(), 1);
    }

    #[test]
    fn test_parse_severity() {
        assert!(matches!(XccdfParser::parse_severity("high"), ScapSeverity::High));
        assert!(matches!(XccdfParser::parse_severity("medium"), ScapSeverity::Medium));
        assert!(matches!(XccdfParser::parse_severity("low"), ScapSeverity::Low));
        assert!(matches!(XccdfParser::parse_severity("CAT I"), ScapSeverity::Critical));
        assert!(matches!(XccdfParser::parse_severity("cat_ii"), ScapSeverity::Medium));
    }
}
