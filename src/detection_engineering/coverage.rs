//! MITRE ATT&CK Coverage Mapping
//!
//! This module provides:
//! - Detection to MITRE ATT&CK technique mapping
//! - Coverage gap analysis
//! - Data source requirements mapping
//! - Coverage scoring per tactic/technique

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::detections::{Detection, DetectionStatus};

/// Type of coverage for a technique
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageType {
    /// Full detection coverage
    Full,
    /// Partial coverage (some sub-techniques or behaviors covered)
    Partial,
    /// Basic/minimal coverage
    Basic,
    /// No active coverage (deprecated or disabled detections only)
    None,
}

impl Default for CoverageType {
    fn default() -> Self {
        Self::None
    }
}

impl CoverageType {
    /// Get a numeric value for scoring (0-100)
    pub fn score(&self) -> u32 {
        match self {
            Self::Full => 100,
            Self::Partial => 60,
            Self::Basic => 30,
            Self::None => 0,
        }
    }
}

/// MITRE ATT&CK Tactic enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    /// Get the MITRE ATT&CK ID for this tactic
    pub fn id(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    /// Get all tactics
    pub fn all() -> Vec<Self> {
        vec![
            Self::Reconnaissance,
            Self::ResourceDevelopment,
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::DefenseEvasion,
            Self::CredentialAccess,
            Self::Discovery,
            Self::LateralMovement,
            Self::Collection,
            Self::CommandAndControl,
            Self::Exfiltration,
            Self::Impact,
        ]
    }

    /// Parse from tactic ID
    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_uppercase().as_str() {
            "TA0043" => Some(Self::Reconnaissance),
            "TA0042" => Some(Self::ResourceDevelopment),
            "TA0001" => Some(Self::InitialAccess),
            "TA0002" => Some(Self::Execution),
            "TA0003" => Some(Self::Persistence),
            "TA0004" => Some(Self::PrivilegeEscalation),
            "TA0005" => Some(Self::DefenseEvasion),
            "TA0006" => Some(Self::CredentialAccess),
            "TA0007" => Some(Self::Discovery),
            "TA0008" => Some(Self::LateralMovement),
            "TA0009" => Some(Self::Collection),
            "TA0011" => Some(Self::CommandAndControl),
            "TA0010" => Some(Self::Exfiltration),
            "TA0040" => Some(Self::Impact),
            _ => None,
        }
    }
}

/// Coverage mapping for a single detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMapping {
    /// Detection ID
    pub detection_id: String,
    /// MITRE ATT&CK technique ID (e.g., T1059.001)
    pub technique_id: String,
    /// Coverage type
    pub coverage_type: CoverageType,
    /// Additional notes about the coverage
    pub notes: Option<String>,
    /// When this mapping was created
    pub created_at: DateTime<Utc>,
    /// Who created this mapping
    pub created_by: String,
}

/// Coverage information for a single technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    /// Technique ID (e.g., T1059)
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Parent technique ID (for sub-techniques)
    pub parent_id: Option<String>,
    /// Associated tactics
    pub tactics: Vec<String>,
    /// Overall coverage type
    pub coverage_type: CoverageType,
    /// Number of detections covering this technique
    pub detection_count: u32,
    /// Number of production detections
    pub production_detection_count: u32,
    /// List of detection IDs covering this technique
    pub detection_ids: Vec<String>,
    /// Required data sources
    pub required_data_sources: Vec<String>,
    /// Available data sources (from current detections)
    pub available_data_sources: Vec<String>,
    /// Whether all required data sources are available
    pub data_sources_complete: bool,
}

/// Coverage information for a tactic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    /// Tactic ID
    pub tactic_id: String,
    /// Tactic name
    pub tactic_name: String,
    /// Total techniques in this tactic
    pub total_techniques: u32,
    /// Techniques with full coverage
    pub full_coverage: u32,
    /// Techniques with partial coverage
    pub partial_coverage: u32,
    /// Techniques with basic coverage
    pub basic_coverage: u32,
    /// Techniques with no coverage
    pub no_coverage: u32,
    /// Overall coverage percentage
    pub coverage_percentage: f64,
    /// Coverage score (weighted)
    pub coverage_score: f64,
    /// List of covered techniques
    pub covered_techniques: Vec<TechniqueCoverage>,
    /// List of uncovered techniques (gaps)
    pub gaps: Vec<CoverageGap>,
}

/// A gap in detection coverage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    /// Technique ID
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Associated tactics
    pub tactics: Vec<String>,
    /// Priority for coverage (based on prevalence, impact, etc.)
    pub priority: GapPriority,
    /// Required data sources to cover this technique
    pub required_data_sources: Vec<String>,
    /// Which required data sources are currently available
    pub available_data_sources: Vec<String>,
    /// Suggested detection approaches
    pub suggestions: Vec<String>,
    /// Reference URLs for creating detections
    pub references: Vec<String>,
    /// Estimated effort to implement (hours)
    pub estimated_effort: Option<f64>,
}

/// Priority level for coverage gaps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GapPriority {
    /// Critical - commonly used by adversaries, high impact
    Critical,
    /// High - frequently observed, significant impact
    High,
    /// Medium - moderate prevalence and impact
    Medium,
    /// Low - less common or lower impact
    Low,
}

impl GapPriority {
    pub fn score(&self) -> u32 {
        match self {
            Self::Critical => 100,
            Self::High => 75,
            Self::Medium => 50,
            Self::Low => 25,
        }
    }
}

/// Overall coverage score summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageScore {
    /// Overall coverage percentage (0-100)
    pub overall_percentage: f64,
    /// Weighted coverage score
    pub weighted_score: f64,
    /// Total techniques in scope
    pub total_techniques: u32,
    /// Techniques with any coverage
    pub covered_techniques: u32,
    /// Techniques with full coverage
    pub fully_covered: u32,
    /// Number of production detections
    pub production_detections: u32,
    /// Total detections (all statuses)
    pub total_detections: u32,
    /// Coverage by tactic
    pub tactic_scores: HashMap<String, TacticCoverage>,
    /// Top gaps to address
    pub top_gaps: Vec<CoverageGap>,
    /// Data source coverage
    pub data_source_coverage: DataSourceCoverage,
}

/// Data source coverage analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceCoverage {
    /// All unique data sources across detections
    pub available_sources: Vec<DataSourceInfo>,
    /// Required data sources that are missing
    pub missing_sources: Vec<DataSourceInfo>,
    /// Data source utilization percentage
    pub utilization_percentage: f64,
}

/// Information about a data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceInfo {
    /// Data source name
    pub name: String,
    /// Number of detections using this source
    pub detection_count: u32,
    /// Number of techniques this source can detect
    pub technique_count: u32,
    /// Whether this source is currently available
    pub available: bool,
    /// Estimated importance score
    pub importance_score: f64,
}

/// MITRE ATT&CK technique reference data
pub struct MitreReference {
    /// Technique to tactic mapping
    pub technique_tactics: HashMap<String, Vec<String>>,
    /// Technique names
    pub technique_names: HashMap<String, String>,
    /// Common data sources per technique
    pub technique_data_sources: HashMap<String, Vec<String>>,
    /// Technique prevalence scores
    pub technique_prevalence: HashMap<String, f64>,
}

impl MitreReference {
    /// Create a new MITRE reference with common techniques
    pub fn new() -> Self {
        let mut technique_tactics = HashMap::new();
        let mut technique_names = HashMap::new();
        let mut technique_data_sources = HashMap::new();
        let mut technique_prevalence = HashMap::new();

        // Execution techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1059", "Command and Scripting Interpreter", vec!["TA0002"],
            vec!["process_creation", "command_line", "script_execution"], 0.95);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1059.001", "PowerShell", vec!["TA0002"],
            vec!["process_creation", "powershell_logs", "script_block_logging"], 0.90);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1059.003", "Windows Command Shell", vec!["TA0002"],
            vec!["process_creation", "command_line"], 0.85);

        // Persistence techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1547", "Boot or Logon Autostart Execution", vec!["TA0003", "TA0004"],
            vec!["registry", "file_creation", "process_creation"], 0.80);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1547.001", "Registry Run Keys / Startup Folder", vec!["TA0003", "TA0004"],
            vec!["registry", "file_creation"], 0.85);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1053", "Scheduled Task/Job", vec!["TA0002", "TA0003", "TA0004"],
            vec!["process_creation", "scheduled_task", "windows_event_logs"], 0.75);

        // Defense Evasion techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1027", "Obfuscated Files or Information", vec!["TA0005"],
            vec!["file_creation", "process_creation", "script_execution"], 0.80);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1070", "Indicator Removal", vec!["TA0005"],
            vec!["windows_event_logs", "file_deletion", "registry"], 0.70);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1055", "Process Injection", vec!["TA0005", "TA0004"],
            vec!["process_creation", "api_monitoring", "memory_analysis"], 0.75);

        // Credential Access techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1003", "OS Credential Dumping", vec!["TA0006"],
            vec!["process_creation", "api_monitoring", "file_access"], 0.90);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1003.001", "LSASS Memory", vec!["TA0006"],
            vec!["process_access", "api_monitoring"], 0.95);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1110", "Brute Force", vec!["TA0006"],
            vec!["authentication_logs", "network_traffic"], 0.80);

        // Discovery techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1087", "Account Discovery", vec!["TA0007"],
            vec!["process_creation", "command_line", "api_monitoring"], 0.70);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1082", "System Information Discovery", vec!["TA0007"],
            vec!["process_creation", "command_line"], 0.65);

        // Lateral Movement techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1021", "Remote Services", vec!["TA0008"],
            vec!["authentication_logs", "network_traffic", "process_creation"], 0.85);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1021.001", "Remote Desktop Protocol", vec!["TA0008"],
            vec!["authentication_logs", "network_traffic"], 0.80);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1021.002", "SMB/Windows Admin Shares", vec!["TA0008"],
            vec!["authentication_logs", "network_traffic", "file_access"], 0.85);

        // Command and Control techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1071", "Application Layer Protocol", vec!["TA0011"],
            vec!["network_traffic", "proxy_logs", "dns_logs"], 0.90);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1071.001", "Web Protocols", vec!["TA0011"],
            vec!["network_traffic", "proxy_logs"], 0.85);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1105", "Ingress Tool Transfer", vec!["TA0011"],
            vec!["network_traffic", "file_creation", "proxy_logs"], 0.80);

        // Exfiltration techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1041", "Exfiltration Over C2 Channel", vec!["TA0010"],
            vec!["network_traffic", "process_creation"], 0.75);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1567", "Exfiltration Over Web Service", vec!["TA0010"],
            vec!["network_traffic", "proxy_logs", "cloud_logs"], 0.70);

        // Impact techniques
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1486", "Data Encrypted for Impact", vec!["TA0040"],
            vec!["file_modification", "process_creation", "api_monitoring"], 0.95);
        Self::add_technique(&mut technique_tactics, &mut technique_names, &mut technique_data_sources, &mut technique_prevalence,
            "T1489", "Service Stop", vec!["TA0040"],
            vec!["service_modification", "process_creation"], 0.70);

        Self {
            technique_tactics,
            technique_names,
            technique_data_sources,
            technique_prevalence,
        }
    }

    fn add_technique(
        technique_tactics: &mut HashMap<String, Vec<String>>,
        technique_names: &mut HashMap<String, String>,
        technique_data_sources: &mut HashMap<String, Vec<String>>,
        technique_prevalence: &mut HashMap<String, f64>,
        id: &str,
        name: &str,
        tactics: Vec<&str>,
        data_sources: Vec<&str>,
        prevalence: f64,
    ) {
        technique_tactics.insert(id.to_string(), tactics.iter().map(|s| s.to_string()).collect());
        technique_names.insert(id.to_string(), name.to_string());
        technique_data_sources.insert(id.to_string(), data_sources.iter().map(|s| s.to_string()).collect());
        technique_prevalence.insert(id.to_string(), prevalence);
    }

    /// Get technique name
    pub fn get_technique_name(&self, technique_id: &str) -> Option<&String> {
        self.technique_names.get(technique_id)
    }

    /// Get tactics for a technique
    pub fn get_technique_tactics(&self, technique_id: &str) -> Option<&Vec<String>> {
        self.technique_tactics.get(technique_id)
    }

    /// Get required data sources for a technique
    pub fn get_required_data_sources(&self, technique_id: &str) -> Option<&Vec<String>> {
        self.technique_data_sources.get(technique_id)
    }

    /// Get prevalence score for a technique
    pub fn get_prevalence(&self, technique_id: &str) -> f64 {
        self.technique_prevalence.get(technique_id).copied().unwrap_or(0.5)
    }

    /// Get all technique IDs
    pub fn all_techniques(&self) -> Vec<&String> {
        self.technique_names.keys().collect()
    }
}

impl Default for MitreReference {
    fn default() -> Self {
        Self::new()
    }
}

/// Coverage analyzer for detection engineering
pub struct CoverageAnalyzer {
    mitre_ref: MitreReference,
}

impl CoverageAnalyzer {
    pub fn new() -> Self {
        Self {
            mitre_ref: MitreReference::new(),
        }
    }

    /// Analyze coverage for a set of detections
    pub fn analyze(&self, detections: &[Detection]) -> CoverageScore {
        let mut technique_coverage: HashMap<String, TechniqueCoverage> = HashMap::new();
        let mut tactic_scores: HashMap<String, TacticCoverage> = HashMap::new();
        let mut all_data_sources: HashSet<String> = HashSet::new();
        let mut required_data_sources: HashSet<String> = HashSet::new();

        // Count production detections
        let production_detections = detections.iter()
            .filter(|d| d.status == DetectionStatus::Production && d.enabled)
            .count() as u32;

        // Collect coverage from all detections
        for detection in detections {
            // Skip disabled or deprecated detections for coverage calculation
            if !detection.enabled || detection.status == DetectionStatus::Deprecated {
                continue;
            }

            // Collect data sources
            for ds in &detection.data_sources {
                all_data_sources.insert(ds.name.clone());
            }

            // Map techniques
            for technique in &detection.mitre_techniques {
                let coverage_type = if detection.status == DetectionStatus::Production {
                    CoverageType::Full
                } else if detection.status == DetectionStatus::Testing {
                    CoverageType::Partial
                } else {
                    CoverageType::Basic
                };

                let entry = technique_coverage.entry(technique.clone()).or_insert_with(|| {
                    let tactics = self.mitre_ref.get_technique_tactics(technique)
                        .cloned()
                        .unwrap_or_default();
                    let name = self.mitre_ref.get_technique_name(technique)
                        .cloned()
                        .unwrap_or_else(|| technique.clone());
                    let req_sources = self.mitre_ref.get_required_data_sources(technique)
                        .cloned()
                        .unwrap_or_default();

                    // Track required data sources
                    for src in &req_sources {
                        required_data_sources.insert(src.clone());
                    }

                    TechniqueCoverage {
                        technique_id: technique.clone(),
                        technique_name: name,
                        parent_id: if technique.contains('.') {
                            Some(technique.split('.').next().unwrap().to_string())
                        } else {
                            None
                        },
                        tactics,
                        coverage_type: CoverageType::None,
                        detection_count: 0,
                        production_detection_count: 0,
                        detection_ids: Vec::new(),
                        required_data_sources: req_sources,
                        available_data_sources: Vec::new(),
                        data_sources_complete: false,
                    }
                });

                entry.detection_count += 1;
                if detection.status == DetectionStatus::Production {
                    entry.production_detection_count += 1;
                }
                entry.detection_ids.push(detection.id.clone());

                // Upgrade coverage type if better
                if coverage_type.score() > entry.coverage_type.score() {
                    entry.coverage_type = coverage_type;
                }

                // Update available data sources
                for ds in &detection.data_sources {
                    if !entry.available_data_sources.contains(&ds.name) {
                        entry.available_data_sources.push(ds.name.clone());
                    }
                }
            }
        }

        // Check data source completeness
        for coverage in technique_coverage.values_mut() {
            coverage.data_sources_complete = coverage.required_data_sources.iter()
                .all(|req| coverage.available_data_sources.contains(req));
        }

        // Build tactic coverage
        for tactic in MitreTactic::all() {
            let tactic_id = tactic.id().to_string();
            let tactic_name = tactic.name().to_string();

            let mut tactic_coverage = TacticCoverage {
                tactic_id: tactic_id.clone(),
                tactic_name,
                total_techniques: 0,
                full_coverage: 0,
                partial_coverage: 0,
                basic_coverage: 0,
                no_coverage: 0,
                coverage_percentage: 0.0,
                coverage_score: 0.0,
                covered_techniques: Vec::new(),
                gaps: Vec::new(),
            };

            // Find all techniques for this tactic
            for (tech_id, tactics) in &self.mitre_ref.technique_tactics {
                if tactics.contains(&tactic_id) {
                    tactic_coverage.total_techniques += 1;

                    if let Some(coverage) = technique_coverage.get(tech_id) {
                        match coverage.coverage_type {
                            CoverageType::Full => tactic_coverage.full_coverage += 1,
                            CoverageType::Partial => tactic_coverage.partial_coverage += 1,
                            CoverageType::Basic => tactic_coverage.basic_coverage += 1,
                            CoverageType::None => tactic_coverage.no_coverage += 1,
                        }
                        tactic_coverage.covered_techniques.push(coverage.clone());
                    } else {
                        tactic_coverage.no_coverage += 1;

                        // Create gap entry
                        let name = self.mitre_ref.get_technique_name(tech_id)
                            .cloned()
                            .unwrap_or_else(|| tech_id.clone());
                        let req_sources = self.mitre_ref.get_required_data_sources(tech_id)
                            .cloned()
                            .unwrap_or_default();
                        let prevalence = self.mitre_ref.get_prevalence(tech_id);

                        let priority = if prevalence >= 0.85 {
                            GapPriority::Critical
                        } else if prevalence >= 0.70 {
                            GapPriority::High
                        } else if prevalence >= 0.50 {
                            GapPriority::Medium
                        } else {
                            GapPriority::Low
                        };

                        let available_sources: Vec<_> = req_sources.iter()
                            .filter(|s| all_data_sources.contains(*s))
                            .cloned()
                            .collect();

                        tactic_coverage.gaps.push(CoverageGap {
                            technique_id: tech_id.clone(),
                            technique_name: name,
                            tactics: tactics.clone(),
                            priority,
                            required_data_sources: req_sources,
                            available_data_sources: available_sources,
                            suggestions: vec![format!("Create detection for {}", tech_id)],
                            references: vec![
                                format!("https://attack.mitre.org/techniques/{}/", tech_id.replace('.', "/"))
                            ],
                            estimated_effort: Some(4.0), // Default estimate
                        });
                    }
                }
            }

            // Calculate coverage percentage and score
            if tactic_coverage.total_techniques > 0 {
                let covered = tactic_coverage.full_coverage
                    + tactic_coverage.partial_coverage
                    + tactic_coverage.basic_coverage;
                tactic_coverage.coverage_percentage =
                    (covered as f64 / tactic_coverage.total_techniques as f64) * 100.0;

                let weighted_score =
                    (tactic_coverage.full_coverage as f64 * 100.0 +
                     tactic_coverage.partial_coverage as f64 * 60.0 +
                     tactic_coverage.basic_coverage as f64 * 30.0) /
                    tactic_coverage.total_techniques as f64;
                tactic_coverage.coverage_score = weighted_score;
            }

            // Sort gaps by priority
            tactic_coverage.gaps.sort_by(|a, b| b.priority.score().cmp(&a.priority.score()));

            tactic_scores.insert(tactic_id, tactic_coverage);
        }

        // Calculate overall metrics
        let total_techniques = self.mitre_ref.technique_names.len() as u32;
        let covered_techniques = technique_coverage.len() as u32;
        let fully_covered = technique_coverage.values()
            .filter(|t| t.coverage_type == CoverageType::Full)
            .count() as u32;

        let overall_percentage = (covered_techniques as f64 / total_techniques as f64) * 100.0;
        let weighted_score = technique_coverage.values()
            .map(|t| t.coverage_type.score() as f64)
            .sum::<f64>() / total_techniques as f64;

        // Collect top gaps across all tactics
        let mut all_gaps: Vec<CoverageGap> = tactic_scores.values()
            .flat_map(|t| t.gaps.clone())
            .collect();
        all_gaps.sort_by(|a, b| b.priority.score().cmp(&a.priority.score()));
        let top_gaps: Vec<_> = all_gaps.into_iter().take(10).collect();

        // Build data source coverage
        let missing_sources: Vec<_> = required_data_sources.iter()
            .filter(|s| !all_data_sources.contains(*s))
            .map(|s| DataSourceInfo {
                name: s.clone(),
                detection_count: 0,
                technique_count: self.mitre_ref.technique_data_sources.values()
                    .filter(|sources| sources.contains(s))
                    .count() as u32,
                available: false,
                importance_score: 0.5,
            })
            .collect();

        let available_sources: Vec<_> = all_data_sources.iter()
            .map(|s| DataSourceInfo {
                name: s.clone(),
                detection_count: detections.iter()
                    .filter(|d| d.data_sources.iter().any(|ds| &ds.name == s))
                    .count() as u32,
                technique_count: self.mitre_ref.technique_data_sources.values()
                    .filter(|sources| sources.contains(s))
                    .count() as u32,
                available: true,
                importance_score: 0.8,
            })
            .collect();

        let utilization = if required_data_sources.len() > 0 {
            (all_data_sources.intersection(&required_data_sources).count() as f64 /
             required_data_sources.len() as f64) * 100.0
        } else {
            0.0
        };

        CoverageScore {
            overall_percentage,
            weighted_score,
            total_techniques,
            covered_techniques,
            fully_covered,
            production_detections,
            total_detections: detections.len() as u32,
            tactic_scores,
            top_gaps,
            data_source_coverage: DataSourceCoverage {
                available_sources,
                missing_sources,
                utilization_percentage: utilization,
            },
        }
    }

    /// Get gaps for a specific tactic
    pub fn get_tactic_gaps(&self, tactic_id: &str, detections: &[Detection]) -> Vec<CoverageGap> {
        let score = self.analyze(detections);
        score.tactic_scores.get(tactic_id)
            .map(|t| t.gaps.clone())
            .unwrap_or_default()
    }

    /// Get coverage for a specific technique
    pub fn get_technique_coverage(&self, technique_id: &str, detections: &[Detection]) -> Option<TechniqueCoverage> {
        let score = self.analyze(detections);
        score.tactic_scores.values()
            .flat_map(|t| t.covered_techniques.clone())
            .find(|t| t.technique_id == technique_id)
    }

    /// Check if data sources are sufficient for a set of techniques
    pub fn check_data_source_sufficiency(
        &self,
        techniques: &[String],
        available_sources: &[String],
    ) -> Vec<(String, Vec<String>)> {
        let available: HashSet<_> = available_sources.iter().collect();
        let mut missing_by_technique = Vec::new();

        for technique in techniques {
            if let Some(required) = self.mitre_ref.get_required_data_sources(technique) {
                let missing: Vec<_> = required.iter()
                    .filter(|s| !available.contains(s))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    missing_by_technique.push((technique.clone(), missing));
                }
            }
        }

        missing_by_technique
    }
}

impl Default for CoverageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection_engineering::detections::DetectionMetadata;

    fn create_test_detection(id: &str, techniques: Vec<&str>, status: DetectionStatus) -> Detection {
        let now = Utc::now();
        Detection {
            id: id.to_string(),
            name: format!("Test Detection {}", id),
            description: "Test".to_string(),
            severity: super::super::detections::DetectionSeverity::Medium,
            status,
            logic: super::super::detections::DetectionLogic {
                language: "sigma".to_string(),
                query: "test".to_string(),
                field_mappings: HashMap::new(),
                aggregation: None,
                threshold: None,
                timeframe: None,
                condition: None,
            },
            data_sources: vec![super::super::detections::DataSource {
                name: "process_creation".to_string(),
                event_ids: vec!["1".to_string()],
                required: true,
                description: None,
            }],
            mitre_techniques: techniques.iter().map(|s| s.to_string()).collect(),
            mitre_tactics: Vec::new(),
            metadata: DetectionMetadata {
                author: "Test".to_string(),
                author_email: None,
                created_at: now,
                updated_at: now,
                references: Vec::new(),
                related_detections: Vec::new(),
                tags: Vec::new(),
                license: None,
                source: None,
            },
            version: 1,
            fp_rate: None,
            confidence: None,
            enabled: true,
        }
    }

    #[test]
    fn test_coverage_analyzer() {
        let analyzer = CoverageAnalyzer::new();

        let detections = vec![
            create_test_detection("DET-001", vec!["T1059.001"], DetectionStatus::Production),
            create_test_detection("DET-002", vec!["T1059.003"], DetectionStatus::Testing),
            create_test_detection("DET-003", vec!["T1003.001"], DetectionStatus::Draft),
        ];

        let score = analyzer.analyze(&detections);

        assert!(score.covered_techniques > 0);
        assert!(score.production_detections == 1);
        assert!(score.total_detections == 3);
    }

    #[test]
    fn test_gap_detection() {
        let analyzer = CoverageAnalyzer::new();

        // Empty detections should show all techniques as gaps
        let score = analyzer.analyze(&[]);
        assert!(!score.top_gaps.is_empty());

        // Gaps should be sorted by priority
        for i in 0..score.top_gaps.len().saturating_sub(1) {
            assert!(score.top_gaps[i].priority.score() >= score.top_gaps[i + 1].priority.score());
        }
    }

    #[test]
    fn test_tactic_coverage() {
        let analyzer = CoverageAnalyzer::new();

        let detections = vec![
            create_test_detection("DET-001", vec!["T1059.001", "T1059.003"], DetectionStatus::Production),
        ];

        let score = analyzer.analyze(&detections);

        // Should have coverage in Execution tactic
        let execution = score.tactic_scores.get("TA0002");
        assert!(execution.is_some());
        assert!(execution.unwrap().covered_techniques.len() > 0);
    }

    #[test]
    fn test_mitre_reference() {
        let mitre = MitreReference::new();

        assert!(mitre.get_technique_name("T1059.001").is_some());
        assert_eq!(mitre.get_technique_name("T1059.001").unwrap(), "PowerShell");

        let tactics = mitre.get_technique_tactics("T1059.001").unwrap();
        assert!(tactics.contains(&"TA0002".to_string()));

        let sources = mitre.get_required_data_sources("T1059.001").unwrap();
        assert!(!sources.is_empty());
    }
}
