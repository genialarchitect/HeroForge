// ============================================================================
// Compliance Types - Framework analysis, controls, and manual assessments
// ============================================================================

export type ComplianceFrameworkId =
  | 'pci_dss'
  | 'nist_800_53'
  | 'nist_csf'
  | 'cis'
  | 'hipaa'
  | 'soc2'
  | 'ferpa'
  | 'owasp'
  | 'owasp_top10';

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  control_count: number;
  automated_percentage: number;
}

export interface ComplianceControl {
  id: string;
  control_id: string;
  title: string;
  description: string;
  category: string;
  priority: 'High' | 'Medium' | 'Low';
  automated: boolean;
  remediation_guidance: string | null;
}

export interface ComplianceControlList {
  framework_id: string;
  framework_name: string;
  controls: ComplianceControl[];
  categories: string[];
}

export type ControlStatus =
  | 'Compliant'
  | 'NonCompliant'
  | 'PartiallyCompliant'
  | 'NotApplicable'
  | 'NotAssessed'
  | 'ManualOverride';

export interface ComplianceFinding {
  id: string;
  scan_id: string;
  control_id: string;
  framework: string;
  status: ControlStatus;
  severity: string;
  evidence: string[];
  affected_hosts: string[];
  affected_ports: number[];
  remediation: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface FrameworkSummary {
  framework: string;
  total_controls: number;
  compliant: number;
  non_compliant: number;
  partially_compliant: number;
  not_applicable: number;
  not_assessed: number;
  manual_overrides: number;
  compliance_score: number;
  by_category: CategorySummary[];
}

export interface CategorySummary {
  category: string;
  total: number;
  compliant: number;
  non_compliant: number;
  percentage: number;
}

export interface ComplianceSummary {
  scan_id: string;
  frameworks: FrameworkSummary[];
  overall_score: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  generated_at: string;
}

export interface ComplianceAnalyzeRequest {
  frameworks: ComplianceFrameworkId[];
}

export interface ComplianceAnalyzeResponse {
  scan_id: string;
  summary: ComplianceSummary;
  message: string;
}

// ============================================================================
// Manual Compliance Assessment Types
// ============================================================================

// Rating scale types
export type RatingScaleType = 'five_point' | 'compliance_status' | 'maturity';
export type EvidenceType = 'file' | 'link' | 'screenshot' | 'note';
export type OverallRating = 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
export type ReviewStatus = 'draft' | 'pending_review' | 'approved' | 'rejected';
export type CampaignStatus = 'draft' | 'active' | 'completed' | 'archived';

export interface RatingLevel {
  value: number;
  label: string;
  description: string;
  maps_to_status: ControlStatus;
}

export interface RatingScale {
  scale_type: RatingScaleType;
  levels: RatingLevel[];
}

export interface AssessmentCriterion {
  id: string;
  question: string;
  description: string;
  guidance: string;
  weight: number;
  evidence_hint: string;
}

export interface CriterionResponse {
  criterion_id: string;
  rating: number;
  notes: string;
  evidence_ids: string[];
}

export interface EvidenceRequirement {
  evidence_type: EvidenceType;
  description: string;
  required: boolean;
}

export interface ComplianceRubric {
  id: string;
  user_id: string | null;
  framework_id: string;
  control_id: string;
  name: string;
  description: string | null;
  assessment_criteria: AssessmentCriterion[];
  rating_scale: RatingScale;
  evidence_requirements: EvidenceRequirement[];
  is_system_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface ManualAssessment {
  id: string;
  user_id: string;
  rubric_id: string;
  framework_id: string;
  control_id: string;
  assessment_period_start: string;
  assessment_period_end: string;
  overall_rating: OverallRating;
  rating_score: number | null;
  criteria_responses: CriterionResponse[];
  evidence_summary: string | null;
  findings: string | null;
  recommendations: string | null;
  review_status: ReviewStatus;
  reviewer_notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssessmentEvidence {
  id: string;
  assessment_id: string;
  evidence_type: EvidenceType;
  title: string;
  description: string | null;
  file_path: string | null;
  file_size: number | null;
  mime_type: string | null;
  external_url: string | null;
  content: string | null;
  created_at: string;
}

export interface AssessmentCampaign {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  frameworks: string[];
  due_date: string | null;
  status: CampaignStatus;
  created_at: string;
  updated_at: string;
}

export interface CampaignProgress {
  total_controls: number;
  assessed: number;
  pending_review: number;
  approved: number;
  percentage_complete: number;
}

export interface CampaignWithProgress extends AssessmentCampaign {
  progress: CampaignProgress;
}

// For creating/updating assessments
export interface CreateManualAssessmentRequest {
  rubric_id: string;
  framework_id: string;
  control_id: string;
  assessment_period_start: string;
  assessment_period_end: string;
  overall_rating: OverallRating;
  rating_score?: number;
  criteria_responses: CriterionResponse[];
  evidence_summary?: string;
  findings?: string;
  recommendations?: string;
}

export interface CreateCampaignRequest {
  name: string;
  description?: string;
  frameworks: string[];
  due_date?: string;
}

// Combined compliance results (automated + manual)
export interface CombinedComplianceResults {
  scan_id: string;
  automated_results: ComplianceSummary | null;
  manual_assessments: ManualAssessment[];
  combined_score: number;
  framework_scores: Record<string, number>;
  generated_at: string;
}

// SIEM Integration types
export type SiemType = "syslog" | "splunk" | "elasticsearch";

export interface SiemSettings {
  id: string;
  user_id: string;
  siem_type: SiemType;
  endpoint_url: string;
  api_key: string | null;
  protocol: string | null; // For syslog: "tcp" or "udp"
  enabled: boolean;
  export_on_scan_complete: boolean;
  export_on_critical_vuln: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateSiemSettingsRequest {
  siem_type: SiemType;
  endpoint_url: string;
  api_key?: string;
  protocol?: string;
  enabled: boolean;
  export_on_scan_complete: boolean;
  export_on_critical_vuln: boolean;
}

export interface UpdateSiemSettingsRequest {
  endpoint_url?: string;
  api_key?: string;
  protocol?: string;
  enabled?: boolean;
  export_on_scan_complete?: boolean;
  export_on_critical_vuln?: boolean;
}

export interface SiemTestResponse {
  success: boolean;
  message: string;
}

export interface SiemExportResponse {
  success: boolean;
  exported_to: number;
  events_count: number;
  errors: string[];
}
