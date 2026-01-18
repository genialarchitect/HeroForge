//! SCAP Content Loader
//!
//! Handles loading SCAP content from ZIP files (DISA STIGs), SCAP DataStreams,
//! and individual XCCDF/OVAL XML files.

use anyhow::{Result, Context, bail};
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::io::{Read, Cursor};
use std::path::Path;
use zip::ZipArchive;

use crate::scap::{
    ScapContentBundle, ScapContentSource, ContentStatus, generate_scap_id,
    xccdf::{XccdfBenchmark, XccdfParser},
    oval::{OvalDefinitions, OvalParser},
};

/// Loader for SCAP content bundles
pub struct ContentLoader {
    /// Maximum file size to process (default 500MB)
    max_file_size: usize,
}

impl ContentLoader {
    pub fn new() -> Self {
        Self {
            max_file_size: 500 * 1024 * 1024, // 500MB
        }
    }

    /// Set maximum file size for processing
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    /// Load SCAP content from a file path
    pub async fn load_from_file(
        &self,
        path: &str,
        source: ScapContentSource,
    ) -> Result<ScapContentBundle> {
        let data = tokio::fs::read(path).await
            .with_context(|| format!("Failed to read file: {}", path))?;

        if data.len() > self.max_file_size {
            bail!("File size {} exceeds maximum allowed size {}", data.len(), self.max_file_size);
        }

        let name = Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        self.load_from_bytes(&data, &name, source, Some(path.to_string())).await
    }

    /// Load SCAP content from bytes (main entry point)
    pub async fn load_from_bytes(
        &self,
        data: &[u8],
        name: &str,
        source: ScapContentSource,
        source_path: Option<String>,
    ) -> Result<ScapContentBundle> {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let file_hash = format!("{:x}", hasher.finalize());

        // Detect content type and parse
        let content_type = self.detect_content_type(data);

        let mut bundle = ScapContentBundle {
            id: generate_scap_id(),
            name: name.to_string(),
            version: "1.0".to_string(),
            source,
            source_url: source_path,
            file_hash,
            imported_at: Utc::now(),
            imported_by: None,
            status: ContentStatus::Active,
            metadata: HashMap::new(),
            benchmark_count: 0,
            oval_definition_count: 0,
        };

        match content_type {
            ContentType::Zip => {
                let (benchmarks, oval_defs) = self.parse_zip_content(data).await?;
                bundle.benchmark_count = benchmarks.len();
                bundle.oval_definition_count = oval_defs.definitions.len();
                bundle.metadata.insert("content_type".to_string(), "zip".to_string());
                bundle.metadata.insert("benchmarks".to_string(),
                    serde_json::to_string(&benchmarks.iter().map(|b| &b.id).collect::<Vec<_>>())?);
            }
            ContentType::XccdfXml => {
                let benchmark = self.parse_xccdf_content(data)?;
                bundle.benchmark_count = 1;
                bundle.version = benchmark.version.clone();
                bundle.metadata.insert("content_type".to_string(), "xccdf".to_string());
                bundle.metadata.insert("benchmark_id".to_string(), benchmark.id.clone());
            }
            ContentType::OvalXml => {
                let oval_defs = self.parse_oval_content(data)?;
                bundle.oval_definition_count = oval_defs.definitions.len();
                bundle.metadata.insert("content_type".to_string(), "oval".to_string());
            }
            ContentType::ScapDataStream => {
                let (benchmarks, oval_defs) = self.parse_datastream_content(data)?;
                bundle.benchmark_count = benchmarks.len();
                bundle.oval_definition_count = oval_defs.definitions.len();
                bundle.metadata.insert("content_type".to_string(), "datastream".to_string());
            }
            ContentType::Unknown => {
                bail!("Unknown content type - expected ZIP, XCCDF XML, OVAL XML, or SCAP DataStream");
            }
        }

        Ok(bundle)
    }

    /// Detect content type from file contents
    fn detect_content_type(&self, data: &[u8]) -> ContentType {
        // Check for ZIP magic number
        if data.len() >= 4 && data[0..4] == [0x50, 0x4B, 0x03, 0x04] {
            return ContentType::Zip;
        }

        // Check for XML content
        let xml_start = String::from_utf8_lossy(&data[..data.len().min(1000)]);

        if xml_start.contains("<Benchmark") || xml_start.contains("<xccdf:Benchmark") {
            return ContentType::XccdfXml;
        }

        if xml_start.contains("<oval_definitions") || xml_start.contains("<oval-def:oval_definitions") {
            return ContentType::OvalXml;
        }

        if xml_start.contains("<data-stream-collection") || xml_start.contains("<ds:data-stream-collection") {
            return ContentType::ScapDataStream;
        }

        ContentType::Unknown
    }

    /// Parse ZIP file containing SCAP content (DISA STIG format)
    async fn parse_zip_content(&self, data: &[u8]) -> Result<(Vec<XccdfBenchmark>, OvalDefinitions)> {
        let cursor = Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .context("Failed to open ZIP archive")?;

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

        // If no specifically named files found, check XML content
        if xccdf_files.is_empty() && oval_files.is_empty() {
            for i in 0..archive.len() {
                let file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.to_lowercase().ends_with(".xml") {
                    let mut content = Vec::new();
                    // Read up to 2KB to detect type
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

            match XccdfParser::parse(&content) {
                Ok(benchmark) => {
                    log::info!("Parsed XCCDF benchmark: {} ({})", benchmark.title.text, benchmark.id);
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

            match OvalParser::parse(&content) {
                Ok(oval_defs) => {
                    log::info!("Parsed OVAL definitions: {} definitions", oval_defs.definitions.len());
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

        Ok((benchmarks, all_oval_defs))
    }

    /// Parse standalone XCCDF XML content
    fn parse_xccdf_content(&self, data: &[u8]) -> Result<XccdfBenchmark> {
        let content = std::str::from_utf8(data)
            .context("Invalid UTF-8 in XCCDF content")?;
        XccdfParser::parse(content)
    }

    /// Parse standalone OVAL XML content
    fn parse_oval_content(&self, data: &[u8]) -> Result<OvalDefinitions> {
        let content = std::str::from_utf8(data)
            .context("Invalid UTF-8 in OVAL content")?;
        OvalParser::parse(content)
    }

    /// Parse SCAP 1.2/1.3 DataStream content
    fn parse_datastream_content(&self, data: &[u8]) -> Result<(Vec<XccdfBenchmark>, OvalDefinitions)> {
        let content = std::str::from_utf8(data)
            .context("Invalid UTF-8 in DataStream content")?;

        // DataStream format combines XCCDF and OVAL in a single XML
        // We need to extract components from <component> elements
        let mut benchmarks = Vec::new();
        let mut all_oval_defs = OvalDefinitions::new();

        // Extract XCCDF components - handle both namespaced and non-namespaced
        // Patterns: <Benchmark, <xccdf:Benchmark, <cdf:Benchmark
        for start_tag in &["<Benchmark", "<xccdf:Benchmark", "<cdf:Benchmark"] {
            let end_tag = if *start_tag == "<Benchmark" {
                "</Benchmark>"
            } else if *start_tag == "<xccdf:Benchmark" {
                "</xccdf:Benchmark>"
            } else {
                "</cdf:Benchmark>"
            };

            let mut pos = 0;
            while let Some(start) = content[pos..].find(*start_tag) {
                let absolute_start = pos + start;
                if let Some(end) = content[absolute_start..].find(end_tag) {
                    let xccdf_xml = &content[absolute_start..absolute_start + end + end_tag.len()];
                    if let Ok(benchmark) = XccdfParser::parse(xccdf_xml) {
                        // Avoid duplicates by checking ID
                        if !benchmarks.iter().any(|b: &XccdfBenchmark| b.id == benchmark.id) {
                            log::debug!("Extracted XCCDF benchmark from DataStream: {}", benchmark.id);
                            benchmarks.push(benchmark);
                        }
                    }
                }
                pos = absolute_start + 1;
            }
        }

        // Extract OVAL components - handle both namespaced and non-namespaced
        // Patterns: <oval_definitions, <oval-def:oval_definitions
        for start_tag in &["<oval_definitions", "<oval-def:oval_definitions"] {
            let end_tag = if *start_tag == "<oval_definitions" {
                "</oval_definitions>"
            } else {
                "</oval-def:oval_definitions>"
            };

            let mut pos = 0;
            while let Some(start) = content[pos..].find(*start_tag) {
                let absolute_start = pos + start;
                if let Some(end) = content[absolute_start..].find(end_tag) {
                    let oval_xml = &content[absolute_start..absolute_start + end + end_tag.len()];
                    if let Ok(oval_defs) = OvalParser::parse(oval_xml) {
                        log::debug!("Extracted {} OVAL definitions from DataStream", oval_defs.definitions.len());
                        // Merge definitions
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
                }
                pos = absolute_start + 1;
            }
        }

        log::info!("Parsed DataStream: {} benchmarks, {} OVAL definitions",
            benchmarks.len(), all_oval_defs.definitions.len());

        Ok((benchmarks, all_oval_defs))
    }

    /// Parse content and return full details (for storing in repository)
    pub async fn parse_full(
        &self,
        data: &[u8],
    ) -> Result<ParsedScapContent> {
        let content_type = self.detect_content_type(data);

        match content_type {
            ContentType::Zip => {
                let (benchmarks, oval_defs) = self.parse_zip_content(data).await?;
                Ok(ParsedScapContent {
                    benchmarks,
                    oval_definitions: oval_defs,
                    content_type: "zip".to_string(),
                })
            }
            ContentType::XccdfXml => {
                let benchmark = self.parse_xccdf_content(data)?;
                Ok(ParsedScapContent {
                    benchmarks: vec![benchmark],
                    oval_definitions: OvalDefinitions::new(),
                    content_type: "xccdf".to_string(),
                })
            }
            ContentType::OvalXml => {
                let oval_defs = self.parse_oval_content(data)?;
                Ok(ParsedScapContent {
                    benchmarks: Vec::new(),
                    oval_definitions: oval_defs,
                    content_type: "oval".to_string(),
                })
            }
            ContentType::ScapDataStream => {
                let (benchmarks, oval_defs) = self.parse_datastream_content(data)?;
                Ok(ParsedScapContent {
                    benchmarks,
                    oval_definitions: oval_defs,
                    content_type: "datastream".to_string(),
                })
            }
            ContentType::Unknown => {
                bail!("Unknown content type");
            }
        }
    }
}

impl Default for ContentLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Detected content type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentType {
    Zip,
    XccdfXml,
    OvalXml,
    ScapDataStream,
    Unknown,
}

/// Result of parsing SCAP content
#[derive(Debug)]
pub struct ParsedScapContent {
    pub benchmarks: Vec<XccdfBenchmark>,
    pub oval_definitions: OvalDefinitions,
    pub content_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_zip() {
        let loader = ContentLoader::new();
        let zip_header = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert_eq!(loader.detect_content_type(&zip_header), ContentType::Zip);
    }

    #[test]
    fn test_detect_xccdf() {
        let loader = ContentLoader::new();
        let xccdf = b"<?xml version=\"1.0\"?>\n<Benchmark id=\"test\">";
        assert_eq!(loader.detect_content_type(xccdf), ContentType::XccdfXml);
    }

    #[test]
    fn test_detect_oval() {
        let loader = ContentLoader::new();
        let oval = b"<?xml version=\"1.0\"?>\n<oval_definitions>";
        assert_eq!(loader.detect_content_type(oval), ContentType::OvalXml);
    }

    #[test]
    fn test_detect_datastream() {
        let loader = ContentLoader::new();
        let ds = b"<?xml version=\"1.0\"?>\n<data-stream-collection>";
        assert_eq!(loader.detect_content_type(ds), ContentType::ScapDataStream);
    }
}
