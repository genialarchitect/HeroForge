// =============================================================================
// Yellow Team (DevSecOps / Security Architecture) Types
// =============================================================================

export type SastScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type SbomStatus = 'pending' | 'generating' | 'completed' | 'failed';
export type ArchReviewStatus = 'draft' | 'in_progress' | 'approved' | 'rejected';
export type StrideCategoryType = 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation_of_privilege';
export type ThreatStatus = 'identified' | 'mitigated' | 'accepted' | 'transferred';

// SAST (Static Application Security Testing)
export interface SastScan {
  id: string;
  user_id: string;
  project_name: string;
  language?: string;
  source_type: 'git' | 'upload' | 'path';
  source_path: string;
  status: SastScanStatus;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  lines_of_code?: number;
  scan_duration_ms?: number;
  created_at: string;
  completed_at?: string;
}

export interface SastFinding {
  id: string;
  scan_id: string;
  rule_id: string;
  category: string;
  severity: string;
  message: string;
  file_path: string;
  line_number: number;
  column_number?: number;
  code_snippet?: string;
  remediation?: string;
  cwe_id?: number;
  owasp_category?: string;
  created_at: string;
}

export interface SastRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  languages: string[];
  cwe_ids: number[];
  is_enabled: boolean;
}

export interface CreateSastScanRequest {
  project_name: string;
  language?: string;
  source_type: 'git' | 'upload' | 'path';
  source_path: string;
}

// Semgrep Rule Integration
export interface SemgrepRule {
  id: string;
  user_id: string;
  rule_id: string;
  name: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  languages: string[];
  patterns: SemgrepPattern[];
  metadata?: SemgrepMetadata;
  is_enabled: boolean;
  created_at: string;
}

export interface SemgrepPattern {
  pattern?: string;
  pattern_either?: string[];
  pattern_not?: string;
  patterns?: SemgrepPattern[];
  metavariable_regex?: Record<string, string>;
}

export interface SemgrepMetadata {
  cwe?: string[];
  owasp?: string[];
  references?: string[];
  source?: string;
  source_url?: string;
}

// Taint Analysis Types
export interface TaintFlow {
  id: string;
  scan_id: string;
  source: { id: string; name: string };
  sink: { id: string; name: string };
  file_path: string;
  source_line: number;
  sink_line: number;
  flow_path: TaintFlowStep[];
  sanitizers_passed?: string;
  is_sanitized: boolean;
  severity: string;
  category: string;
  cwe_id?: string;
  confidence: string;
  status: 'open' | 'confirmed' | 'false_positive' | 'fixed';
  created_at: string;
}

export interface TaintFlowStep {
  file_path: string;
  line: number;
  column?: number;
  code_snippet?: string;
  node_type: string;
}

export interface TaintFlowsResponse {
  flows: TaintFlow[];
  total: number;
}

export interface TaintAnalysisResult {
  flows: TaintFlow[];
  sources_found: number;
  sinks_found: number;
  sanitizers_found: number;
}

// Security Hotspots Types
export type HotspotPriority = 'high' | 'medium' | 'low';
export type HotspotResolution = 'to_review' | 'vulnerability' | 'safe' | 'acknowledged' | 'fixed';
export type HotspotCategory =
  | 'authentication'
  | 'authorization'
  | 'cryptography'
  | 'input_validation'
  | 'output_encoding'
  | 'configuration'
  | 'logging'
  | 'error_handling'
  | 'resource_management'
  | 'injection_prevention'
  | 'sensitive_data'
  | 'network_security'
  | 'file_operations'
  | 'session_management'
  | 'other';

export interface SecurityHotspot {
  id: string;
  scan_id: string;
  rule_id: string;
  category: HotspotCategory;
  priority: HotspotPriority;
  message: string;
  file_path: string;
  line_number: number;
  column_number?: number;
  code_snippet?: string;
  security_context: string;
  review_guidance: string;
  resolution: HotspotResolution;
  reviewer_id?: string;
  review_comment?: string;
  reviewed_at?: string;
  cwe_id?: number;
  created_at: string;
}

export interface HotspotsResponse {
  hotspots: SecurityHotspot[];
  total: number;
}

export interface DetectHotspotsResult {
  hotspots: SecurityHotspot[];
  stats: HotspotStats;
}

export interface HotspotStats {
  total: number;
  by_priority: { high: number; medium: number; low: number };
  by_category: Record<HotspotCategory, number>;
  by_resolution: Record<HotspotResolution, number>;
  reviewed: number;
  pending_review: number;
}

// SBOM (Software Bill of Materials)
export interface SbomProject {
  id: string;
  user_id: string;
  name: string;
  source_type: 'git' | 'container' | 'path';
  source_path: string;
  status: SbomStatus;
  component_count: number;
  vulnerable_count: number;
  license_issues: number;
  sbom_format: 'cyclonedx' | 'spdx';
  created_at: string;
  updated_at: string;
}

export interface SbomComponent {
  id: string;
  project_id: string;
  name: string;
  version: string;
  purl?: string;
  component_type: string;
  license?: string;
  license_risk?: 'low' | 'medium' | 'high';
  vulnerabilities?: SbomVulnerability[];
  is_direct: boolean;
}

export interface SbomVulnerability {
  cve_id: string;
  severity: string;
  cvss_score?: number;
  description: string;
  fixed_version?: string;
}

export interface CreateSbomRequest {
  name: string;
  source_type: 'git' | 'container' | 'path';
  source_path: string;
}

// Architecture Reviews & STRIDE Threat Modeling
export interface ArchitectureReview {
  id: string;
  user_id: string;
  project_name: string;
  description: string;
  diagram_data?: string;
  status: ArchReviewStatus;
  threat_count: number;
  critical_threats: number;
  high_threats: number;
  created_at: string;
  updated_at: string;
}

export interface StrideThreat {
  id: string;
  review_id: string;
  stride_category: StrideCategoryType;
  title: string;
  description: string;
  severity: string;
  affected_component: string;
  attack_vector: string;
  mitigation?: string;
  status: ThreatStatus;
  created_at: string;
  updated_at: string;
}

export interface CreateArchitectureReviewRequest {
  project_name: string;
  description: string;
  diagram_data?: string;
}

// Yellow Team Dashboard
export interface YellowTeamDashboard {
  mttr_days: number;
  mttr_trend: number;
  vuln_density: number;
  vuln_density_trend: number;
  sla_compliance: number;
  sla_trend: number;
  open_findings: number;
  critical_findings: number;
  total_findings: number;
  findings_by_category: CategoryCount[];
  sla_by_severity: SlaBySeverity[];
  recent_activity: YellowTeamActivity[];
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface SlaBySeverity {
  severity: string;
  compliance_rate: number;
  total: number;
  within_sla: number;
}

export interface YellowTeamActivity {
  type: 'sast' | 'sbom' | 'architecture';
  message: string;
  status: string;
  timestamp: string;
}

// Binary Analysis Types
export interface BinarySampleSummary {
  id: string;
  filename: string;
  file_size: number;
  file_type: string;
  architecture: string | null;
  sha256: string;
  entropy: number;
  is_packed: boolean;
  packer_name: string | null;
  analysis_status: string;
  strings_count: number;
  imports_count: number;
  created_at: string;
}

export interface BinarySectionInfo {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  is_executable: boolean;
  is_writable: boolean;
}

export interface BinaryPeInfo {
  machine_type: string | null;
  subsystem: string | null;
  is_dll: boolean;
  is_64bit: boolean;
  has_debug_info: boolean;
  has_tls: boolean;
  has_rich_header: boolean;
  checksum_valid: boolean;
  timestamp: string | null;
  entry_point: number | null;
  image_base: number | null;
}

export interface BinaryElfInfo {
  machine_type: string | null;
  elf_type: string | null;
  os_abi: string | null;
  is_pie: boolean;
  has_relro: boolean;
  has_nx: boolean;
  has_stack_canary: boolean;
  interpreter: string | null;
  entry_point: number | null;
}

export interface BinarySampleDetail {
  id: string;
  filename: string;
  file_size: number;
  file_type: string;
  architecture: string | null;
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep: string | null;
  imphash: string | null;
  entropy: number;
  is_packed: boolean;
  packer_name: string | null;
  packer_version: string | null;
  packer_confidence: number | null;
  analysis_status: string;
  strings_count: number;
  imports_count: number;
  exports_count: number;
  sections: BinarySectionInfo[];
  pe_info: BinaryPeInfo | null;
  elf_info: BinaryElfInfo | null;
  created_at: string;
  analyzed_at: string | null;
}

export interface BinaryExtractedString {
  value: string;
  encoding: string;
  offset: number;
  length: number;
  string_type: string | null;
  entropy: number | null;
}

export interface BinaryImport {
  dll_name: string;
  functions: string[];
}

export interface BinaryExport {
  name: string;
  ordinal: number;
  address: number;
}

export interface BinaryAnalysisStats {
  total_samples: number;
  packed_samples: number;
  pe_samples: number;
  elf_samples: number;
  samples_by_type: Record<string, number>;
  avg_entropy: number;
  recent_uploads: number;
}
