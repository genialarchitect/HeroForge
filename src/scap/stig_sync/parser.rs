//! STIG Bundle Parser
//!
//! Parses downloaded STIG ZIP bundles and extracts XCCDF/OVAL content.

use anyhow::{Result, Context, bail};
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

use crate::scap::content::ContentLoader;
use crate::scap::xccdf::XccdfBenchmark;
use crate::scap::oval::OvalDefinitions;
use super::types::{StigEntry, ParsedStig};

/// Parser for STIG ZIP bundles
pub struct StigParser {
    content_loader: ContentLoader,
}

impl StigParser {
    /// Create a new STIG parser
    pub fn new() -> Self {
        Self {
            content_loader: ContentLoader::new(),
        }
    }

    /// Parse a downloaded STIG bundle
    pub async fn parse_bundle(&self, bundle_path: &str, entry: &StigEntry) -> Result<ParsedStig> {
        log::info!("Parsing STIG bundle: {}", bundle_path);

        let file = std::fs::File::open(bundle_path)
            .with_context(|| format!("Failed to open bundle: {}", bundle_path))?;

        let mut archive = ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        // Find and parse XCCDF/OVAL files
        let mut benchmarks = Vec::new();
        let mut all_oval_defs = OvalDefinitions::new();
        let mut xccdf_files = Vec::new();
        let mut oval_files = Vec::new();

        // First pass: identify relevant files
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name().to_lowercase();

            if name.ends_with(".xml") {
                if name.contains("xccdf") || name.contains("benchmark") || name.contains("manual-xccdf") {
                    xccdf_files.push(i);
                } else if name.contains("oval") {
                    oval_files.push(i);
                }
            }
        }

        // If no specifically named files, check content
        if xccdf_files.is_empty() && oval_files.is_empty() {
            for i in 0..archive.len() {
                let file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.to_lowercase().ends_with(".xml") {
                    let mut content = Vec::new();
                    file.take(2048).read_to_end(&mut content)?;
                    let preview = String::from_utf8_lossy(&content);

                    if preview.contains("<Benchmark") || preview.contains("<xccdf:Benchmark") {
                        xccdf_files.push(i);
                    } else if preview.contains("<oval_definitions") || preview.contains("<oval-def:oval_definitions") {
                        oval_files.push(i);
                    }
                }
            }
        }

        // Parse XCCDF files
        for idx in xccdf_files {
            let mut file = archive.by_index(idx)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            match crate::scap::xccdf::XccdfParser::parse(&content) {
                Ok(benchmark) => {
                    log::debug!("Parsed XCCDF benchmark: {} ({})", benchmark.title.text, benchmark.id);
                    benchmarks.push(benchmark);
                }
                Err(e) => {
                    log::warn!("Failed to parse XCCDF file {}: {}", file.name(), e);
                }
            }
        }

        // Parse OVAL files
        for idx in oval_files {
            let mut file = archive.by_index(idx)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            match crate::scap::oval::OvalParser::parse(&content) {
                Ok(oval_defs) => {
                    log::debug!("Parsed {} OVAL definitions", oval_defs.definitions.len());
                    // Merge into all_oval_defs
                    for (id, def) in oval_defs.definitions {
                        all_oval_defs.definitions.insert(id, def);
                    }
                    for (id, test) in oval_defs.tests {
                        all_oval_defs.tests.insert(id, test);
                    }
                    for (id, obj) in oval_defs.objects {
                        all_oval_defs.objects.insert(id, obj);
                    }
                    for (id, state) in oval_defs.states {
                        all_oval_defs.states.insert(id, state);
                    }
                    for (id, var) in oval_defs.variables {
                        all_oval_defs.variables.insert(id, var);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse OVAL file {}: {}", file.name(), e);
                }
            }
        }

        // Count total rules across all benchmarks
        let rule_count: usize = benchmarks
            .iter()
            .map(|b| count_rules(b))
            .sum();

        let benchmark_ids: Vec<String> = benchmarks.iter().map(|b| b.id.clone()).collect();

        log::info!(
            "Parsed STIG bundle: {} benchmarks, {} OVAL definitions, {} rules",
            benchmarks.len(),
            all_oval_defs.definitions.len(),
            rule_count
        );

        Ok(ParsedStig {
            entry: entry.clone(),
            bundle_path: bundle_path.to_string(),
            benchmark_ids,
            oval_definition_count: all_oval_defs.definitions.len(),
            rule_count,
        })
    }

    /// Extract a specific file from the bundle
    pub fn extract_file(&self, bundle_path: &str, file_name: &str) -> Result<Vec<u8>> {
        let file = std::fs::File::open(bundle_path)
            .with_context(|| format!("Failed to open bundle: {}", bundle_path))?;

        let mut archive = ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if entry.name().ends_with(file_name) || entry.name() == file_name {
                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;
                return Ok(content);
            }
        }

        bail!("File {} not found in bundle", file_name);
    }

    /// List all files in a STIG bundle
    pub fn list_files(&self, bundle_path: &str) -> Result<Vec<String>> {
        let file = std::fs::File::open(bundle_path)
            .with_context(|| format!("Failed to open bundle: {}", bundle_path))?;

        let mut archive = ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        let mut files = Vec::new();
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            files.push(entry.name().to_string());
        }

        Ok(files)
    }

    /// Validate a STIG bundle
    pub fn validate_bundle(&self, bundle_path: &str) -> Result<BundleValidation> {
        let file = std::fs::File::open(bundle_path)
            .with_context(|| format!("Failed to open bundle: {}", bundle_path))?;

        let mut archive = ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        let mut validation = BundleValidation {
            is_valid: true,
            has_xccdf: false,
            has_oval: false,
            has_manual: false,
            file_count: archive.len(),
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            let name = entry.name().to_lowercase();

            if name.contains("xccdf") && name.ends_with(".xml") {
                validation.has_xccdf = true;
            }
            if name.contains("oval") && name.ends_with(".xml") {
                validation.has_oval = true;
            }
            if name.contains("manual") && name.ends_with(".xml") {
                validation.has_manual = true;
            }
        }

        if !validation.has_xccdf && !validation.has_oval {
            validation.is_valid = false;
            validation.errors.push("No XCCDF or OVAL files found in bundle".to_string());
        }

        if !validation.has_xccdf {
            validation.warnings.push("No XCCDF benchmark file found".to_string());
        }

        if !validation.has_oval {
            validation.warnings.push("No OVAL definitions file found (automated checks may not work)".to_string());
        }

        Ok(validation)
    }
}

impl Default for StigParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of bundle validation
#[derive(Debug, Clone)]
pub struct BundleValidation {
    /// Whether the bundle is valid for import
    pub is_valid: bool,
    /// Whether the bundle contains XCCDF content
    pub has_xccdf: bool,
    /// Whether the bundle contains OVAL definitions
    pub has_oval: bool,
    /// Whether the bundle contains manual check content
    pub has_manual: bool,
    /// Total number of files in the bundle
    pub file_count: usize,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

/// Count rules in a benchmark (including nested groups)
fn count_rules(benchmark: &XccdfBenchmark) -> usize {
    fn count_in_group(group: &crate::scap::xccdf::XccdfGroup) -> usize {
        let rule_count = group.rules.len();
        let nested_count: usize = group.groups.iter().map(count_in_group).sum();
        rule_count + nested_count
    }

    let top_level_rules = benchmark.groups.iter().map(count_in_group).sum::<usize>();
    top_level_rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let _parser = StigParser::new();
        // Parser should be created successfully without panicking
    }
}
