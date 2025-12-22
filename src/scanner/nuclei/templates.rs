// Nuclei Template Management
// List, browse, and manage Nuclei templates

use super::runner::get_templates_path;
use super::types::*;
use anyhow::{anyhow, Result};
use log::{debug, info};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use walkdir::WalkDir;

/// YAML template structure (partial, for metadata extraction)
#[derive(Debug, Deserialize)]
struct TemplateYaml {
    id: String,
    info: TemplateInfoYaml,
}

#[derive(Debug, Deserialize)]
struct TemplateInfoYaml {
    name: String,
    #[serde(default)]
    author: StringOrVec,
    severity: Option<String>,
    description: Option<String>,
    #[serde(default)]
    tags: StringOrVec,
    #[serde(default)]
    reference: StringOrVec,
    classification: Option<ClassificationYaml>,
}

#[derive(Debug, Deserialize)]
struct ClassificationYaml {
    #[serde(rename = "cve-id")]
    cve_id: Option<String>,
    #[serde(rename = "cwe-id")]
    cwe_id: Option<String>,
    #[serde(rename = "cvss-metrics")]
    cvss_metrics: Option<String>,
    #[serde(rename = "cvss-score")]
    cvss_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl Default for StringOrVec {
    fn default() -> Self {
        StringOrVec::Vec(Vec::new())
    }
}

impl StringOrVec {
    fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrVec::String(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
            StringOrVec::Vec(v) => v.clone(),
        }
    }
}

/// List all available templates
pub async fn list_templates() -> Result<Vec<NucleiTemplate>> {
    let templates_path = get_templates_path();

    if !templates_path.exists() {
        return Err(anyhow!(
            "Templates directory not found at {:?}. Run 'nuclei -ut' to download templates.",
            templates_path
        ));
    }

    let mut templates = Vec::new();

    for entry in WalkDir::new(&templates_path)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        // Only process YAML files
        if path.extension().map_or(false, |ext| ext == "yaml" || ext == "yml") {
            match parse_template_file(path).await {
                Ok(template) => templates.push(template),
                Err(e) => {
                    debug!("Failed to parse template {:?}: {}", path, e);
                }
            }
        }
    }

    info!("Loaded {} templates from {:?}", templates.len(), templates_path);
    Ok(templates)
}

/// Parse a single template file
async fn parse_template_file(path: &Path) -> Result<NucleiTemplate> {
    let content = fs::read_to_string(path).await?;

    // Parse YAML
    let yaml: TemplateYaml = serde_yaml::from_str(&content)?;

    let severity = yaml
        .info
        .severity
        .as_ref()
        .map(|s| NucleiSeverity::from(s.as_str()))
        .unwrap_or(NucleiSeverity::Info);

    let classification = yaml.info.classification.map(|c| TemplateClassification {
        cve_id: c.cve_id,
        cwe_id: c.cwe_id,
        cvss_metrics: c.cvss_metrics,
        cvss_score: c.cvss_score,
    });

    Ok(NucleiTemplate {
        id: yaml.id,
        name: yaml.info.name,
        author: yaml.info.author.to_vec(),
        severity,
        description: yaml.info.description,
        tags: yaml.info.tags.to_vec(),
        reference: yaml.info.reference.to_vec(),
        classification,
        path: path.to_string_lossy().to_string(),
    })
}

/// Get template statistics
pub async fn get_template_stats() -> Result<TemplateStats> {
    let templates = list_templates().await?;

    let mut stats = TemplateStats {
        total: templates.len(),
        ..Default::default()
    };

    let mut tag_counts: HashMap<String, usize> = HashMap::new();

    for template in &templates {
        // Count by severity
        match template.severity {
            NucleiSeverity::Critical => stats.critical += 1,
            NucleiSeverity::High => stats.high += 1,
            NucleiSeverity::Medium => stats.medium += 1,
            NucleiSeverity::Low => stats.low += 1,
            NucleiSeverity::Info => stats.info += 1,
            NucleiSeverity::Unknown => {}
        }

        // Count tags
        for tag in &template.tags {
            *tag_counts.entry(tag.clone()).or_insert(0) += 1;
        }
    }

    // Sort tags by count and take top 20
    let mut tag_vec: Vec<_> = tag_counts.into_iter().collect();
    tag_vec.sort_by(|a, b| b.1.cmp(&a.1));
    stats.tags = tag_vec.into_iter().take(20).collect();

    // Get last modified time of templates directory
    let templates_path = get_templates_path();
    if let Ok(metadata) = fs::metadata(&templates_path).await {
        if let Ok(modified) = metadata.modified() {
            stats.last_updated = Some(chrono::DateTime::from(modified));
        }
    }

    Ok(stats)
}

/// Search templates by various criteria
pub async fn search_templates(
    query: Option<&str>,
    tags: Option<&[String]>,
    severity: Option<&[NucleiSeverity]>,
    limit: Option<usize>,
) -> Result<Vec<NucleiTemplate>> {
    let all_templates = list_templates().await?;

    let filtered: Vec<_> = all_templates
        .into_iter()
        .filter(|t| {
            // Filter by query (search in id, name, description)
            if let Some(q) = query {
                let q_lower = q.to_lowercase();
                let matches = t.id.to_lowercase().contains(&q_lower)
                    || t.name.to_lowercase().contains(&q_lower)
                    || t.description
                        .as_ref()
                        .map_or(false, |d| d.to_lowercase().contains(&q_lower));
                if !matches {
                    return false;
                }
            }

            // Filter by tags
            if let Some(filter_tags) = tags {
                let has_tag = filter_tags.iter().any(|ft| t.tags.contains(ft));
                if !has_tag {
                    return false;
                }
            }

            // Filter by severity
            if let Some(severities) = severity {
                if !severities.contains(&t.severity) {
                    return false;
                }
            }

            true
        })
        .collect();

    // Apply limit
    if let Some(l) = limit {
        Ok(filtered.into_iter().take(l).collect())
    } else {
        Ok(filtered)
    }
}

/// Get a specific template by ID
pub async fn get_template(template_id: &str) -> Result<NucleiTemplate> {
    let templates = list_templates().await?;

    templates
        .into_iter()
        .find(|t| t.id == template_id)
        .ok_or_else(|| anyhow!("Template not found: {}", template_id))
}

/// Get template content (the raw YAML)
pub async fn get_template_content(template_id: &str) -> Result<String> {
    let template = get_template(template_id).await?;
    fs::read_to_string(&template.path).await.map_err(Into::into)
}

/// List all available template tags
pub async fn list_tags() -> Result<Vec<(String, usize)>> {
    let templates = list_templates().await?;

    let mut tag_counts: HashMap<String, usize> = HashMap::new();

    for template in &templates {
        for tag in &template.tags {
            *tag_counts.entry(tag.clone()).or_insert(0) += 1;
        }
    }

    let mut tags: Vec<_> = tag_counts.into_iter().collect();
    tags.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(tags)
}

/// Get templates for a specific CVE
pub async fn get_templates_for_cve(cve_id: &str) -> Result<Vec<NucleiTemplate>> {
    let templates = list_templates().await?;

    Ok(templates
        .into_iter()
        .filter(|t| {
            // Check in ID
            t.id.to_lowercase().contains(&cve_id.to_lowercase())
            // Check in classification
            || t.classification
                .as_ref()
                .and_then(|c| c.cve_id.as_ref())
                .map_or(false, |c| c.eq_ignore_ascii_case(cve_id))
            // Check in tags
            || t.tags.iter().any(|tag| tag.eq_ignore_ascii_case(cve_id))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_or_vec() {
        let single = StringOrVec::String("one,two,three".to_string());
        assert_eq!(single.to_vec(), vec!["one", "two", "three"]);

        let vec = StringOrVec::Vec(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.to_vec(), vec!["a", "b"]);
    }

    #[test]
    fn test_severity_conversion() {
        assert_eq!(NucleiSeverity::from("critical"), NucleiSeverity::Critical);
        assert_eq!(NucleiSeverity::from("HIGH"), NucleiSeverity::High);
        assert_eq!(NucleiSeverity::from("unknown_value"), NucleiSeverity::Unknown);
    }
}
