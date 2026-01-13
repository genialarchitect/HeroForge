// ============================================================================
// Asset Types - Asset inventory, tags, and groups
// ============================================================================

export type AssetTagCategory =
  | 'environment'
  | 'criticality'
  | 'owner'
  | 'department'
  | 'location'
  | 'compliance'
  | 'custom';

export interface AssetTag {
  id: string;
  user_id: string;
  name: string;
  color: string;
  category: AssetTagCategory;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface AssetTagWithCount {
  tag: AssetTag;
  asset_count: number;
}

export interface CreateAssetTagRequest {
  name: string;
  color: string;
  category: AssetTagCategory;
  description?: string;
}

export interface UpdateAssetTagRequest {
  name?: string;
  color?: string;
  category?: AssetTagCategory;
  description?: string;
}

export interface AddAssetTagsRequest {
  tag_ids: string[];
}

export interface Asset {
  id: string;
  user_id: string;
  ip_address: string;
  hostname?: string;
  mac_address?: string;
  first_seen: string;
  last_seen: string;
  scan_count: number;
  os_family?: string;
  os_version?: string;
  status: 'active' | 'inactive';
  tags: string;
  notes?: string;
}

export interface AssetPort {
  id: string;
  asset_id: string;
  port: number;
  protocol: string;
  service_name?: string;
  service_version?: string;
  first_seen: string;
  last_seen: string;
  current_state: 'open' | 'closed' | 'filtered';
}

export interface AssetHistoryWithScan {
  id: string;
  scan_id: string;
  scan_name: string;
  changes: Record<string, unknown>;
  recorded_at: string;
}

export interface AssetDetailWithTags {
  asset: Asset;
  ports: AssetPort[];
  history: AssetHistoryWithScan[];
  asset_tags: AssetTag[];
}

// Asset Groups
export interface AssetGroup {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  color: string;
  created_at: string;
  updated_at: string;
}

export interface AssetGroupWithCount {
  group: AssetGroup;
  asset_count: number;
}

export interface AssetGroupWithMembers {
  group: AssetGroup;
  assets: Asset[];
}

export interface CreateAssetGroupRequest {
  name: string;
  description?: string;
  color: string;
}

export interface UpdateAssetGroupRequest {
  name?: string;
  description?: string;
  color?: string;
}

export interface AddAssetsToGroupRequest {
  asset_ids: string[];
}

export interface BulkAddToGroupResponse {
  message: string;
  added_count: number;
  requested_count: number;
}

export interface AssetWithTags {
  asset: Asset;
  asset_tags: AssetTag[];
}

export interface AssetDetailFull {
  asset: Asset;
  ports: AssetPort[];
  history: AssetHistoryWithScan[];
  asset_tags: AssetTag[];
  asset_groups: AssetGroup[];
}

// ============================================================================
// Finding Templates Types
// ============================================================================

export interface FindingTemplate {
  id: string;
  user_id: string | null;
  category: string;
  title: string;
  severity: string;
  description: string;
  impact: string | null;
  remediation: string | null;
  references: string | null;  // JSON array
  cwe_ids: string | null;     // JSON array
  cvss_vector: string | null;
  cvss_score: number | null;
  tags: string | null;        // JSON array
  is_system: boolean;
  created_at: string;
  updated_at: string;
  // Enhanced fields for template library
  evidence_placeholders: string | null;  // JSON array of EvidencePlaceholder
  testing_steps: string | null;
  owasp_category: string | null;
  mitre_attack_ids: string | null;  // JSON array
  compliance_mappings: string | null;  // JSON object
  use_count: number | null;
  last_used_at: string | null;
  affected_components: string | null;
}

export interface EvidencePlaceholder {
  id: string;
  label: string;
  placeholder_type: 'screenshot' | 'code_snippet' | 'request_response' | 'command_output' | 'file' | 'text';
  description?: string;
  required: boolean;
}

export interface ComplianceMapping {
  // Original frameworks
  cis?: string[];
  nist_800_53?: string[];
  nist_csf?: string[];
  pci_dss?: string[];
  hipaa?: string[];
  ferpa?: string[];
  soc2?: string[];
  owasp_top_10?: string[];
  hitrust_csf?: string[];
  iso_27001?: string[];
  gdpr?: string[];
  dod_stig?: string[];
  // US Federal
  fedramp?: string[];
  cmmc?: string[];
  fisma?: string[];
  nist_800_171?: string[];
  nist_800_82?: string[];
  nist_800_61?: string[];
  stateramp?: string[];
  itar?: string[];
  ear?: string[];
  dfars?: string[];
  icd_503?: string[];
  cnssi_1253?: string[];
  rmf?: string[];
  disa_cloud_srg?: string[];
  dod_zero_trust?: string[];
  nist_privacy?: string[];
  // Industry/Sector
  csa_ccm?: string[];
  nerc_cip?: string[];
  iec_62443?: string[];
  tsa_pipeline?: string[];
  cisa_cpgs?: string[];
  eo_14028?: string[];
  sox?: string[];
  glba?: string[];
  // International
  cyber_essentials?: string[];
  ism_australia?: string[];
  irap?: string[];
  nis2?: string[];
  ens_spain?: string[];
  bsi_grundschutz?: string[];
  c5?: string[];
  secnumcloud?: string[];
  nato_cyber?: string[];
}

export interface CreateFindingTemplateRequest {
  category: string;
  title: string;
  severity: string;
  description: string;
  impact?: string;
  remediation?: string;
  references?: string[];
  cwe_ids?: number[];
  cvss_vector?: string;
  cvss_score?: number;
  tags?: string[];
  // Enhanced fields
  evidence_placeholders?: EvidencePlaceholder[];
  testing_steps?: string;
  owasp_category?: string;
  mitre_attack_ids?: string[];
  compliance_mappings?: ComplianceMapping;
  affected_components?: string[];
}

export interface UpdateFindingTemplateRequest {
  category?: string;
  title?: string;
  severity?: string;
  description?: string;
  impact?: string;
  remediation?: string;
  references?: string[];
  cwe_ids?: number[];
  cvss_vector?: string;
  cvss_score?: number;
  tags?: string[];
  // Enhanced fields
  evidence_placeholders?: EvidencePlaceholder[];
  testing_steps?: string;
  owasp_category?: string;
  mitre_attack_ids?: string[];
  compliance_mappings?: ComplianceMapping;
  affected_components?: string[];
}

export interface CloneFindingTemplateRequest {
  new_title?: string;
}

export interface FindingTemplateCategory {
  category: string;
  count: number;
}

// Enhanced Finding Template Library Types
export interface FindingTemplateCategoryFull {
  id: string;
  name: string;
  parent_id: string | null;
  description: string | null;
  icon: string | null;
  color: string | null;
  sort_order: number;
  created_at: string;
}

export interface ApplyTemplateRequest {
  vulnerability_id: string;
  evidence?: AppliedEvidence[];
}

export interface AppliedEvidence {
  placeholder_id: string;
  content: string;
  content_type?: string;
}

export interface ImportTemplatesRequest {
  templates: FindingTemplate[];
  overwrite_existing?: boolean;
}

export interface ImportTemplatesResponse {
  imported: number;
  skipped: number;
  errors: string[];
}

export interface TemplateSearchQuery {
  query?: string;
  category?: string;
  severity?: string;
  owasp?: string;
  mitre?: string;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Methodology Checklists Types
// ============================================================================

export interface MethodologyTemplate {
  id: string;
  name: string;
  version: string | null;
  description: string | null;
  categories: string | null; // JSON array
  item_count: number;
  is_system: boolean;
  created_at: string;
  updated_at: string;
}

export interface MethodologyTemplateItem {
  id: string;
  template_id: string;
  category: string;
  item_id: string | null; // e.g., WSTG-INFO-01
  title: string;
  description: string | null;
  guidance: string | null;
  expected_evidence: string | null;
  tools: string | null; // JSON array
  references: string | null; // JSON array
  sort_order: number;
}

export interface MethodologyTemplateWithItems {
  template: MethodologyTemplate;
  items: MethodologyTemplateItem[];
}

export interface MethodologyChecklist {
  id: string;
  template_id: string;
  user_id: string;
  scan_id: string | null;
  engagement_id: string | null;
  name: string;
  description: string | null;
  progress_percent: number;
  status: 'in_progress' | 'completed' | 'archived';
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface ChecklistItem {
  id: string;
  checklist_id: string;
  template_item_id: string;
  status: ChecklistItemStatus;
  notes: string | null;
  evidence: string | null;
  findings: string | null; // JSON array
  tested_at: string | null;
  tester_id: string | null;
}

export type ChecklistItemStatus = 'not_started' | 'in_progress' | 'pass' | 'fail' | 'na';

export interface ChecklistItemWithTemplate {
  id: string;
  checklist_id: string;
  template_item_id: string;
  status: ChecklistItemStatus;
  notes: string | null;
  evidence: string | null;
  findings: string | null;
  tested_at: string | null;
  tester_id: string | null;
  // Template item fields
  category: string;
  template_item_code: string | null;
  title: string;
  description: string | null;
  guidance: string | null;
  expected_evidence: string | null;
  tools: string | null;
  references: string | null;
  sort_order: number;
}

export interface ChecklistSummary {
  id: string;
  template_id: string;
  template_name: string;
  user_id: string;
  scan_id: string | null;
  engagement_id: string | null;
  name: string;
  description: string | null;
  progress_percent: number;
  status: 'in_progress' | 'completed' | 'archived';
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  total_items: number;
}

export interface ChecklistWithItems {
  checklist: MethodologyChecklist;
  template_name: string;
  template_version: string | null;
  items: ChecklistItemWithTemplate[];
}

export interface ChecklistProgress {
  total_items: number;
  completed_items: number;
  passed: number;
  failed: number;
  not_applicable: number;
  in_progress: number;
  not_started: number;
  progress_percent: number;
  by_category: CategoryProgress[];
}

export interface CategoryProgress {
  category: string;
  total: number;
  completed: number;
}

export interface CreateChecklistRequest {
  template_id: string;
  name: string;
  description?: string;
  scan_id?: string;
  engagement_id?: string;
}

export interface UpdateChecklistRequest {
  name?: string;
  description?: string;
  status?: 'in_progress' | 'completed' | 'archived';
}

export interface UpdateChecklistItemRequest {
  status?: ChecklistItemStatus;
  notes?: string;
  evidence?: string;
  findings?: string[];
}

// ============================================================================
// Executive Analytics Types
// ============================================================================

export interface CustomerSecurityTrends {
  customer_id: string;
  customer_name: string;
  months: MonthlySecuritySnapshot[];
  improvement_percent: number;
  current_risk_score: number;
}

export interface MonthlySecuritySnapshot {
  month: string;
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved: number;
  risk_score: number;
}

export interface ExecutiveSummary {
  customer_id: string;
  customer_name: string;
  total_engagements: number;
  active_engagements: number;
  total_scans: number;
  total_vulnerabilities: number;
  open_vulnerabilities: number;
  critical_open: number;
  high_open: number;
  avg_remediation_days: number;
  compliance_score: number | null;
  last_scan_date: string | null;
  risk_rating: 'Critical' | 'High' | 'Medium' | 'Low';
  trend_direction: 'Improving' | 'Stable' | 'Declining';
}

export interface RemediationVelocity {
  avg_days_to_remediate: number;
  avg_days_critical: number;
  avg_days_high: number;
  avg_days_medium: number;
  avg_days_low: number;
  remediation_rate: number;
  velocity_trend: VelocityPoint[];
}

export interface VelocityPoint {
  week: string;
  resolved_count: number;
  avg_days: number;
}

export interface RiskTrendPoint {
  date: string;
  risk_score: number;
  vulnerability_count: number;
  weighted_severity: number;
}

export interface MethodologyExecutiveCoverage {
  total_checklists: number;
  completed_checklists: number;
  total_items_tested: number;
  passed_items: number;
  failed_items: number;
  coverage_by_framework: FrameworkCoverage[];
}

export interface FrameworkCoverage {
  framework_name: string;
  total_items: number;
  tested_items: number;
  coverage_percent: number;
}

export interface ExecutiveDashboard {
  summary: ExecutiveSummary | null;
  security_trends: CustomerSecurityTrends | null;
  remediation_velocity: RemediationVelocity | null;
  risk_trends: RiskTrendPoint[];
  methodology_coverage: MethodologyExecutiveCoverage | null;
}

// ============================================================================
// Webhook Types
// ============================================================================

export type WebhookEventType =
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  | 'vulnerability.found'
  | 'vulnerability.critical'
  | 'vulnerability.resolved'
  | 'asset.discovered'
  | 'compliance.violation';

export interface Webhook {
  id: string;
  user_id: string;
  name: string;
  url: string;
  has_secret: boolean;
  events: WebhookEventType[];
  headers: Record<string, string> | null;
  is_active: boolean;
  last_triggered_at: string | null;
  last_status_code: number | null;
  failure_count: number;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  payload: string;
  response_status: number | null;
  response_body: string | null;
  error: string | null;
  delivered_at: string;
}

export interface WebhookStats {
  total_deliveries: number;
  successful_deliveries: number;
  failed_deliveries: number;
  last_7_days_deliveries: number;
}

export interface WebhookEventTypeInfo {
  id: string;
  name: string;
  description: string;
}

export interface CreateWebhookRequest {
  name: string;
  url: string;
  secret?: string;
  events: WebhookEventType[];
  headers?: Record<string, string>;
  is_active?: boolean;
}

export interface UpdateWebhookRequest {
  name?: string;
  url?: string;
  secret?: string;
  events?: WebhookEventType[];
  headers?: Record<string, string>;
  is_active?: boolean;
}

export interface WebhookTestResponse {
  success: boolean;
  status_code: number | null;
  error: string | null;
  attempts: number;
}

export interface GenerateSecretResponse {
  secret: string;
}

// Secret Findings Types
export type SecretSeverity = 'critical' | 'high' | 'medium' | 'low';
export type SecretStatus = 'open' | 'resolved' | 'investigating' | 'false_positive';

export interface SecretFinding {
  id: string;
  scan_id: string;
  host_ip: string;
  port: number | null;
  secret_type: string;
  severity: SecretSeverity;
  redacted_value: string;
  source_type: string;
  source_location: string;
  line_number: number | null;
  context: string | null;
  confidence: number;
  status: SecretStatus;
  resolved_at: string | null;
  resolved_by: string | null;
  false_positive: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecretTypeCount {
  secret_type: string;
  count: number;
}

export interface SecretFindingStats {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  open_count: number;
  resolved_count: number;
  false_positive_count: number;
  by_type: SecretTypeCount[];
}

export interface SecretFindingsQuery {
  scan_id?: string;
  host_ip?: string;
  secret_type?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface UpdateSecretFindingRequest {
  status?: SecretStatus;
  false_positive?: boolean;
  notes?: string;
}

export interface BulkUpdateSecretsRequest {
  ids: string[];
  status: SecretStatus;
}

export interface BulkUpdateSecretsResponse {
  updated: number;
  message: string;
}
