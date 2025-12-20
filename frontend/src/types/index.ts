export type UserRole = 'admin' | 'user' | 'auditor' | 'viewer';

// Badge type definitions for type-safe severity/status rendering
export type BadgeSeverityType = 'critical' | 'high' | 'medium' | 'low';
export type BadgeStatusType = 'pending' | 'running' | 'completed' | 'failed';
export type BadgeType = BadgeSeverityType | BadgeStatusType;

/**
 * Convert a severity string to a type-safe badge type.
 * Handles both uppercase (from API) and lowercase formats.
 */
export function toSeverityBadgeType(severity: string): BadgeSeverityType {
  const normalized = severity.toLowerCase();
  switch (normalized) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
    case 'info':
    case 'informational':
      return 'low';
    default:
      return 'low';
  }
}

export interface User {
  id: string;
  username: string;
  email: string;
  roles?: UserRole[]; // Added for admin console
  is_active?: boolean; // Added for admin console
  created_at?: string;
  mfa_enabled?: boolean; // MFA/TOTP enabled status
  is_locked?: boolean; // Account lockout status
  locked_until?: string; // Lockout expiration time
  failed_attempts?: number; // Number of failed login attempts
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}

export interface ScanResult {
  id: string;
  user_id: string;
  name: string;
  targets: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  results: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  // Computed fields (may not be present in all API responses)
  total_hosts?: number;
  total_ports?: number;
}

// Scan Tags
export interface ScanTag {
  id: string;
  name: string;
  color: string;
  created_at: string;
}

export interface CreateScanTagRequest {
  name: string;
  color?: string;
}

export interface AddTagsToScanRequest {
  tag_ids: string[];
}

export interface ScanWithTags extends ScanResult {
  tags: ScanTag[];
}

export interface DuplicateScanRequest {
  name?: string;
}

export type EnumDepth = 'passive' | 'light' | 'aggressive';

export type ScanType = 'tcp_connect' | 'udp' | 'comprehensive' | 'syn';

export type EnumService =
  | 'http'
  | 'https'
  | 'dns'
  | 'smb'
  | 'ftp'
  | 'ssh'
  | 'smtp'
  | 'ldap'
  | 'mysql'
  | 'postgresql'
  | 'mongodb'
  | 'redis'
  | 'elasticsearch'
  | 'vnc'
  | 'telnet'
  | 'rdp'
  | 'snmp';

export interface CreateScanRequest {
  name: string;
  targets: string[];
  port_range: [number, number];
  threads: number;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  // Scan type options
  scan_type?: ScanType;
  udp_port_range?: [number, number];
  udp_retries?: number;
  // Enumeration options
  enable_enumeration?: boolean;
  enum_depth?: EnumDepth;
  enum_services?: EnumService[];
  // VPN options
  vpn_config_id?: string;
  // CRM integration
  customer_id?: string;
  engagement_id?: string;
  // Tags
  tag_ids?: string[];
  // Exclusions
  exclusion_ids?: string[];
  skip_global_exclusions?: boolean;
}

// Tag suggestion for predefined tags
export interface TagSuggestion {
  name: string;
  color: string;
  category: string;
}

export interface ScanPreset {
  id: string;
  name: string;
  description: string;
  icon: string;
  port_range: [number, number];
  threads: number;
  scan_type: ScanType;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  enable_enumeration: boolean;
  enum_depth?: EnumDepth;
  udp_port_range?: [number, number];
  udp_retries?: number;
  enum_services?: EnumService[];
}

export interface HostInfo {
  target: {
    ip: string;
    hostname: string | null;
  };
  is_alive: boolean;
  os_guess: {
    os_family: string;
    os_version: string | null;
    confidence: number;
  } | null;
  ports: PortInfo[];
  vulnerabilities: Vulnerability[];
  scan_duration: {
    secs: number;
    nanos: number;
  };
}

export interface PortInfo {
  port: number;
  protocol: string;
  state: string;
  service: {
    name: string;
    version: string | null;
    banner: string | null;
    ssl_info: SslInfo | null;
  } | null;
}

export interface SslInfo {
  cert_valid: boolean;
  cert_expired: boolean;
  days_until_expiry: number | null;
  self_signed: boolean;
  hostname_mismatch: boolean;
  issuer: string;
  subject: string;
  valid_from: string;
  valid_until: string;
  protocols: string[];
  cipher_suites: string[];
  weak_ciphers: string[];
  weak_protocols: string[];
  hsts_enabled: boolean;
  hsts_max_age: number | null;
  chain_issues: string[];
  ssl_grade?: SslGrade;
}

// SSL/TLS Grading Types
// T = Trust issues (self-signed, untrusted CA)
// M = Hostname mismatch
export type SslGradeLevel = 'A+' | 'A' | 'A-' | 'B+' | 'B' | 'B-' | 'C' | 'D' | 'F' | 'T' | 'M' | 'Unknown';

export type SslVulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface SslVulnerability {
  id: string;
  name: string;
  severity: SslVulnerabilitySeverity;
  description: string;
  cve: string | null;
}

export interface SslGrade {
  grade: SslGradeLevel;
  overall_score: number;
  protocol_score: number;
  cipher_score: number;
  certificate_score: number;
  key_exchange_score: number;
  vulnerabilities_found: SslVulnerability[];
  recommendations: string[];
  grade_capped: boolean;
  cap_reason: string | null;
}

// SSL Report Types
export interface SslReportEntry {
  host: string;
  port: number;
  service: string | null;
  grade: SslGradeLevel;
  overall_score: number;
  protocol_score: number;
  cipher_score: number;
  certificate_score: number;
  key_exchange_score: number;
  vulnerabilities_count: number;
  recommendations_count: number;
  ssl_info: SslInfo;
}

export interface SslReportSummary {
  scan_id: string;
  scan_name: string;
  total_ssl_services: number;
  grade_distribution: Record<string, number>;
  average_score: number;
  services_with_critical_issues: number;
  services_with_high_issues: number;
  entries: SslReportEntry[];
}

export interface Vulnerability {
  cve_id: string | null;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  affected_service: string | null;
}

// Admin Console Types

export interface Role {
  id: string;
  name: string;
  description?: string;
  can_manage_users: boolean;
  can_manage_scans: boolean;
  can_view_all_scans: boolean;
  can_delete_any_scan: boolean;
  can_view_audit_logs: boolean;
  can_manage_settings: boolean;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  username?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  details?: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface AuditLogResponse {
  logs: AuditLog[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditLogFilter {
  user_id?: string;
  action?: string;
  target_type?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

export interface AuditUser {
  id: string;
  username: string;
  email: string;
}

export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  updated_by?: string;
  updated_at: string;
}

// Report Types

export type ReportFormat = 'pdf' | 'html' | 'json';

export type ReportTemplateId = 'executive' | 'technical' | 'compliance';

export type ReportStatus = 'pending' | 'generating' | 'completed' | 'failed';

export type ReportSectionId =
  | 'tableOfContents'
  | 'executiveSummary'
  | 'riskOverview'
  | 'hostInventory'
  | 'portAnalysis'
  | 'vulnerabilityFindings'
  | 'serviceEnumeration'
  | 'remediationRecommendations'
  | 'appendix';

export interface ReportOptions {
  include_charts?: boolean;
  company_name?: string;
  assessor_name?: string;
  classification?: string;
}

export interface CreateReportRequest {
  scan_id: string;
  name: string;
  description?: string;
  format: ReportFormat;
  template_id: ReportTemplateId;
  sections: string[];
  options?: ReportOptions;
}

export interface Report {
  id: string;
  user_id: string;
  scan_id: string;
  name: string;
  description?: string;
  format: string;
  template_id: string;
  sections: string;
  file_path?: string;
  file_size?: number;
  status: ReportStatus;
  error_message?: string;
  metadata?: string;
  created_at: string;
  completed_at?: string;
  expires_at?: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  default_sections: string[];
  supports_formats: string[];
}

// Scan Comparison Types

export interface ScanDiff {
  new_hosts: string[];
  removed_hosts: string[];
  host_changes: HostDiff[];
  summary: DiffSummary;
}

export interface DiffSummary {
  total_new_hosts: number;
  total_removed_hosts: number;
  total_hosts_changed: number;
  total_new_ports: number;
  total_closed_ports: number;
  total_new_vulnerabilities: number;
  total_resolved_vulnerabilities: number;
  total_service_changes: number;
}

export interface HostDiff {
  ip: string;
  hostname: string | null;
  new_ports: PortInfo[];
  closed_ports: PortInfo[];
  new_vulnerabilities: Vulnerability[];
  resolved_vulnerabilities: Vulnerability[];
  service_changes: ServiceChange[];
  os_change: OsChange | null;
}

export interface ServiceChange {
  port: number;
  protocol: string;
  old_service: string | null;
  new_service: string | null;
  old_version: string | null;
  new_version: string | null;
  change_type: ServiceChangeType;
}

export type ServiceChangeType =
  | 'NewService'
  | 'ServiceChanged'
  | 'VersionChanged'
  | 'ServiceRemoved';

export interface OsChange {
  old_os: string;
  new_os: string;
  old_confidence: number;
  new_confidence: number;
}

export interface ScanComparisonResponse {
  scan1: {
    id: string;
    name: string;
    created_at: string;
  };
  scan2: {
    id: string;
    name: string;
    created_at: string;
  };
  diff: ScanDiff;
}

// Target Groups

export interface TargetGroup {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  targets: string; // JSON array string
  color: string;
  created_at: string;
  updated_at: string;
}

export interface CreateTargetGroupRequest {
  name: string;
  description?: string;
  targets: string[];
  color: string;
}

export interface UpdateTargetGroupRequest {
  name?: string;
  description?: string;
  targets?: string[];
  color?: string;
}

// Scheduled Scans

export interface ScheduledScan {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  config: string; // JSON string
  schedule_type: 'daily' | 'weekly' | 'monthly' | 'cron';
  schedule_value: string;
  next_run_at: string;
  last_run_at: string | null;
  last_scan_id: string | null;
  is_active: boolean;
  run_count: number;
  created_at: string;
  updated_at: string;
}

export interface ScheduledScanConfig {
  targets: string[];
  port_range: [number, number];
  threads: number;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  enable_enumeration: boolean;
  enum_depth?: string;
  enum_services?: string[];
  scan_type?: string;
  udp_port_range?: [number, number];
  udp_retries?: number;
}

export interface CreateScheduledScanRequest {
  name: string;
  description?: string;
  config: ScheduledScanConfig;
  schedule_type: string;
  schedule_value: string;
}

export interface UpdateScheduledScanRequest {
  name?: string;
  description?: string;
  config?: ScheduledScanConfig;
  schedule_type?: string;
  schedule_value?: string;
  is_active?: boolean;
}

// Notification Settings

export interface NotificationSettings {
  user_id: string;
  email_on_scan_complete: boolean;
  email_on_critical_vuln: boolean;
  email_address: string;
  slack_webhook_url?: string | null;
  teams_webhook_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface UpdateNotificationSettingsRequest {
  email_on_scan_complete?: boolean;
  email_on_critical_vuln?: boolean;
  email_address?: string;
  slack_webhook_url?: string | null;
  teams_webhook_url?: string | null;
}

// Scan Templates

export interface ScanTemplate {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  config: string; // JSON string of scan config
  created_at: string;
  updated_at: string;
}

export interface CreateTemplateRequest {
  name: string;
  description?: string;
  config: ScheduledScanConfig;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  config?: ScheduledScanConfig;
}

// Profile Types

export interface UpdateProfileRequest {
  email?: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

// MFA Types

export interface MfaSetupResponse {
  secret: string;
  qr_code_url: string;
  recovery_codes: string[];
}

export interface MfaVerifySetupRequest {
  totp_code: string;
}

export interface MfaDisableRequest {
  password: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface MfaRegenerateRecoveryCodesRequest {
  password: string;
  totp_code: string;
}

export interface MfaRegenerateRecoveryCodesResponse {
  recovery_codes: string[];
}

export interface MfaVerifyRequest {
  mfa_token: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface MfaLoginResponse extends LoginResponse {
  mfa_required?: boolean;
  mfa_token?: string;
}

// Analytics Types

export interface AnalyticsSummary {
  total_scans: number;
  total_hosts: number;
  total_ports: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  scans_this_week: number;
  scans_this_month: number;
}

export interface TimeSeriesDataPoint {
  date: string;
  value: number;
}

export interface VulnerabilityTimeSeriesDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ServiceCount {
  service: string;
  count: number;
}

// Real-time Scan Progress Types

export enum ScanPhase {
  HostDiscovery = 'Host Discovery',
  PortScanning = 'Port Scanning',
  ServiceDetection = 'Service Detection',
  Enumeration = 'Enumeration',
  OSFingerprinting = 'OS Fingerprinting',
  VulnerabilityScanning = 'Vulnerability Scanning',
}

export interface PhaseProgress {
  phase: ScanPhase;
  progress: number;
  isActive: boolean;
  isComplete: boolean;
}

export interface LiveMetrics {
  hostsFound: number;
  portsOpen: number;
  servicesDetected: number;
  vulnerabilitiesFound: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
}

export interface ScanEstimate {
  estimatedTimeRemaining: number | null;
  estimatedCompletion: Date | null;
  scanSpeed: number;
}

export interface ScanActivity {
  currentPhase: string;
  currentActivity: string;
  overallProgress: number;
  phaseProgress: number;
}

// ============================================================================
// Vulnerability Management Types
// ============================================================================

export type VulnerabilityStatus = 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk';

export interface VulnerabilityTracking {
  id: string;
  scan_id: string;
  host_ip: string;
  port: number | null;
  vulnerability_id: string;
  severity: string;
  status: string;
  assignee_id: string | null;
  notes: string | null;
  due_date: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  jira_ticket_id: string | null;
  jira_ticket_key: string | null;
  jira_ticket_url?: string;
  // Remediation workflow fields
  priority: string | null;
  remediation_steps: string | null;
  estimated_effort: number | null;
  actual_effort: number | null;
  verification_scan_id: string | null;
  verified_at: string | null;
  verified_by: string | null;
  // Retest workflow fields
  retest_requested_at: string | null;
  retest_completed_at: string | null;
  retest_result: 'still_vulnerable' | 'remediated' | 'partially_remediated' | null;
  retest_scan_id: string | null;
  retest_requested_by: string | null;
}

export interface VulnerabilityComment {
  id: string;
  vulnerability_tracking_id: string;
  user_id: string;
  comment: string;
  created_at: string;
}

export interface VulnerabilityCommentWithUser {
  id: string;
  vulnerability_tracking_id: string;
  user_id: string;
  username: string;
  comment: string;
  created_at: string;
  updated_at: string | null;
}

export interface RemediationTimelineEvent {
  id: string;
  vulnerability_tracking_id: string;
  user_id: string;
  username: string;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_at: string;
}

export interface VulnerabilityDetail {
  vulnerability: VulnerabilityTracking;
  comments: VulnerabilityCommentWithUser[];
  timeline: RemediationTimelineEvent[];
  assignee: User | null;
  resolved_by_user: User | null;
  verified_by_user: User | null;
}

export interface UpdateVulnerabilityRequest {
  status?: string;
  assignee_id?: string;
  notes?: string;
  due_date?: string;
  // Remediation workflow fields
  priority?: string;
  remediation_steps?: string;
  estimated_effort?: number;
  actual_effort?: number;
}

export interface AddVulnerabilityCommentRequest {
  comment: string;
}

export interface BulkUpdateVulnerabilitiesRequest {
  vulnerability_ids: string[];
  status?: string;
  assignee_id?: string;
  due_date?: string;
  priority?: string;
}

export interface BulkAssignVulnerabilitiesRequest {
  vulnerability_ids: string[];
  assignee_id: string;
  due_date?: string;
}

export interface BulkUpdateSeverityRequest {
  vulnerability_ids: string[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface BulkDeleteVulnerabilitiesRequest {
  vulnerability_ids: string[];
}

export interface BulkAddTagsRequest {
  vulnerability_ids: string[];
  tags: string[];
}

export interface BulkOperationResponse {
  updated?: number;
  deleted?: number;
  failed: number;
  message: string;
}

export interface VerifyVulnerabilityRequest {
  scan_id?: string;
}

// Vulnerability Assignment Types
export interface VulnerabilityAssignmentWithUser {
  id: string;
  scan_id: string;
  host_ip: string;
  port: number | null;
  vulnerability_id: string;
  severity: string;
  status: string;
  assignee_id: string | null;
  assignee_username: string | null;
  assignee_email: string | null;
  notes: string | null;
  due_date: string | null;
  priority: string | null;
  created_at: string;
  updated_at: string;
  scan_name: string | null;
  is_overdue: boolean;
  days_until_due: number | null;
}

export interface UserAssignmentStats {
  total: number;
  open: number;
  in_progress: number;
  overdue: number;
  due_today: number;
  due_this_week: number;
  critical: number;
  high: number;
}

export interface MyAssignmentsResponse {
  stats: UserAssignmentStats;
  assignments: VulnerabilityAssignmentWithUser[];
}

export interface AssignVulnerabilityRequest {
  assignee_id: string;
  due_date?: string;
  priority?: string;
}

export interface UpdateAssignmentRequest {
  due_date?: string;
  priority?: string;
  status?: string;
}

// Retest workflow types
export interface RequestRetestRequest {
  notes?: string;
}

export interface BulkRetestRequest {
  vulnerability_ids: string[];
  notes?: string;
}

export interface CompleteRetestRequest {
  result: 'still_vulnerable' | 'remediated' | 'partially_remediated';
  scan_id?: string;
  notes?: string;
}

export interface VulnerabilityStats {
  total: number;
  open: number;
  in_progress: number;
  resolved: number;
  false_positive: number;
  accepted_risk: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// ============================================================================
// Compliance Types
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

// API Keys types
export interface ApiKey {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  permissions: string[] | null;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: boolean;
}

export interface CreateApiKeyRequest {
  name: string;
  permissions?: string[];
  expires_at?: string;
}

export interface CreateApiKeyResponse {
  id: string;
  name: string;
  key: string; // Full key (only returned once)
  prefix: string;
  permissions: string[] | null;
  created_at: string;
  expires_at: string | null;
}

export interface UpdateApiKeyRequest {
  name?: string;
  permissions?: string[];
}

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

// ============================================================================
// VPN Types
// ============================================================================

export type VpnType = 'openvpn' | 'wireguard';
export type VpnConnectionMode = 'per_scan' | 'persistent';

export interface VpnConfig {
  id: string;
  name: string;
  vpn_type: VpnType;
  requires_credentials: boolean;
  has_credentials: boolean;
  is_default: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface VpnStatus {
  connected: boolean;
  config_id: string | null;
  config_name: string | null;
  connection_mode: VpnConnectionMode | null;
  assigned_ip: string | null;
  connected_since: string | null;
  interface_name: string | null;
}

export interface UploadVpnConfigRequest {
  name: string;
  vpn_type: VpnType;
  config_data: string; // base64 encoded
  filename: string;
  username?: string;
  password?: string;
  set_as_default: boolean;
}

export interface UpdateVpnConfigRequest {
  name?: string;
  username?: string;
  password?: string;
  is_default?: boolean;
}

export interface VpnConnectRequest {
  config_id: string;
  connection_mode: VpnConnectionMode;
}

export interface VpnTestResult {
  success: boolean;
  message: string;
  assigned_ip?: string;
  connection_time_ms?: number;
}

// ============================================================================
// CRM Types
// ============================================================================

export type CustomerStatus = 'active' | 'inactive' | 'prospect';
export type CompanySize = 'small' | 'medium' | 'enterprise';
export type EngagementType = 'pentest' | 'vuln_assessment' | 'red_team' | 'compliance_audit' | 'consulting';
export type EngagementStatus = 'planning' | 'in_progress' | 'on_hold' | 'completed' | 'cancelled';
export type MilestoneStatus = 'pending' | 'in_progress' | 'completed' | 'overdue';
export type ContractType = 'msa' | 'sow' | 'nda' | 'amendment';
export type ContractStatus = 'draft' | 'pending_signature' | 'active' | 'expired' | 'terminated';
export type CommunicationType = 'email' | 'call' | 'meeting' | 'note';

export interface Customer {
  id: string;
  user_id: string;
  name: string;
  industry: string | null;
  company_size: CompanySize | null;
  website: string | null;
  address: string | null;
  notes: string | null;
  status: CustomerStatus;
  created_at: string;
  updated_at: string;
}

export interface Contact {
  id: string;
  customer_id: string;
  first_name: string;
  last_name: string;
  email: string | null;
  phone: string | null;
  title: string | null;
  is_primary: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface Engagement {
  id: string;
  customer_id: string;
  name: string;
  engagement_type: EngagementType;
  status: EngagementStatus;
  scope: string | null;
  start_date: string | null;
  end_date: string | null;
  budget: number | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface EngagementMilestone {
  id: string;
  engagement_id: string;
  name: string;
  description: string | null;
  due_date: string | null;
  completed_at: string | null;
  status: MilestoneStatus;
  created_at: string;
}

export interface Contract {
  id: string;
  customer_id: string;
  engagement_id: string | null;
  contract_type: ContractType;
  name: string;
  value: number | null;
  start_date: string | null;
  end_date: string | null;
  status: ContractStatus;
  file_path: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface SlaDefinition {
  id: string;
  customer_id: string | null;
  name: string;
  description: string | null;
  response_time_critical: number | null;
  response_time_high: number | null;
  response_time_medium: number | null;
  response_time_low: number | null;
  resolution_time_critical: number | null;
  resolution_time_high: number | null;
  resolution_time_medium: number | null;
  resolution_time_low: number | null;
  is_template: boolean;
  created_at: string;
  updated_at: string;
}

export interface TimeEntry {
  id: string;
  engagement_id: string;
  user_id: string;
  description: string;
  hours: number;
  billable: boolean;
  date: string;
  created_at: string;
}

export interface Communication {
  id: string;
  customer_id: string;
  engagement_id: string | null;
  contact_id: string | null;
  user_id: string;
  comm_type: CommunicationType;
  subject: string | null;
  content: string | null;
  comm_date: string;
  created_at: string;
}

export interface CrmDashboardStats {
  total_customers: number;
  active_customers: number;
  total_engagements: number;
  active_engagements: number;
  total_contracts_value: number;
  upcoming_milestones: EngagementMilestone[];
  overdue_milestones: number;
  recent_communications: Communication[];
  total_hours_this_month: number;
  billable_hours_this_month: number;
}

export interface CustomerSummary {
  customer: Customer;
  contact_count: number;
  engagement_count: number;
  active_engagement_count: number;
  contract_count: number;
  total_contract_value: number;
  scan_count: number;
  vulnerability_count: number;
}

// CRM Request Types
export interface CreateCustomerRequest {
  name: string;
  industry?: string;
  company_size?: CompanySize;
  website?: string;
  address?: string;
  notes?: string;
  status?: CustomerStatus;
}

export interface UpdateCustomerRequest {
  name?: string;
  industry?: string;
  company_size?: CompanySize;
  website?: string;
  address?: string;
  notes?: string;
  status?: CustomerStatus;
}

export interface CreateContactRequest {
  first_name: string;
  last_name: string;
  email?: string;
  phone?: string;
  title?: string;
  is_primary?: boolean;
  notes?: string;
}

export interface UpdateContactRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
  phone?: string;
  title?: string;
  is_primary?: boolean;
  notes?: string;
}

export interface CreateEngagementRequest {
  name: string;
  engagement_type: EngagementType;
  status?: EngagementStatus;
  scope?: string;
  start_date?: string;
  end_date?: string;
  budget?: number;
  notes?: string;
}

export interface UpdateEngagementRequest {
  name?: string;
  engagement_type?: EngagementType;
  status?: EngagementStatus;
  scope?: string;
  start_date?: string;
  end_date?: string;
  budget?: number;
  notes?: string;
}

export interface CreateMilestoneRequest {
  name: string;
  description?: string;
  due_date?: string;
  status?: MilestoneStatus;
}

export interface UpdateMilestoneRequest {
  name?: string;
  description?: string;
  due_date?: string;
  status?: MilestoneStatus;
  completed_at?: string;
}

export interface CreateContractRequest {
  name: string;
  contract_type: ContractType;
  engagement_id?: string;
  value?: number;
  start_date?: string;
  end_date?: string;
  status?: ContractStatus;
  notes?: string;
}

export interface UpdateContractRequest {
  name?: string;
  contract_type?: ContractType;
  engagement_id?: string;
  value?: number;
  start_date?: string;
  end_date?: string;
  status?: ContractStatus;
  notes?: string;
}

export interface CreateSlaRequest {
  name: string;
  description?: string;
  response_time_critical?: number;
  response_time_high?: number;
  response_time_medium?: number;
  response_time_low?: number;
  resolution_time_critical?: number;
  resolution_time_high?: number;
  resolution_time_medium?: number;
  resolution_time_low?: number;
  is_template?: boolean;
}

export interface CreateTimeEntryRequest {
  description: string;
  hours: number;
  billable?: boolean;
  date: string;
}

export interface CreateCommunicationRequest {
  comm_type: CommunicationType;
  subject?: string;
  content?: string;
  comm_date: string;
  engagement_id?: string;
  contact_id?: string;
}

// CRM Portal User Management Types
export type PortalUserRole = 'admin' | 'member' | 'viewer';

export interface CrmPortalUser {
  id: string;
  customer_id: string;
  contact_id?: string;
  email: string;
  is_active: boolean;
  last_login?: string;
  role: PortalUserRole;
  created_at: string;
  updated_at: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
}

export interface CreatePortalUserRequest {
  email: string;
  password: string;
  contact_id?: string;
  role?: PortalUserRole;
}

export interface UpdatePortalUserRequest {
  contact_id?: string;
  is_active?: boolean;
  role?: PortalUserRole;
}

export interface ResetPortalUserPasswordRequest {
  new_password: string;
}

// ============================================================================
// Portal Types
// ============================================================================

export interface PortalLoginRequest {
  email: string;
  password: string;
}

export interface PortalLoginResponse {
  token: string;
  user: PortalUserInfo;
}

export interface PortalUserInfo {
  id: string;
  email: string;
  customer_id: string;
  customer_name?: string;
  role: PortalUserRole;
}

export interface PortalChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface PortalProfile {
  id: string;
  email: string;
  customer_id: string;
  customer_name?: string;
  role: PortalUserRole;
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
  last_login?: string;
  created_at: string;
}

export interface UpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
}

export interface PortalDashboardStats {
  customer_name: string;
  active_engagements: number;
  total_engagements: number;
  open_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  available_reports: number;
  recent_scans: PortalRecentScan[];
  upcoming_milestones: PortalUpcomingMilestone[];
}

export interface PortalRecentScan {
  id: string;
  name: string;
  status: string;
  created_at: string;
  total_hosts?: number;
}

export interface PortalUpcomingMilestone {
  id: string;
  name: string;
  engagement_name: string;
  due_date?: string;
  status: string;
}

export interface PortalEngagement {
  id: string;
  name: string;
  engagement_type: string;
  status: string;
  scope?: string;
  start_date?: string;
  end_date?: string;
  created_at: string;
}

export interface PortalEngagementDetail {
  engagement: PortalEngagement;
  milestones: PortalMilestone[];
  scan_count: number;
  vulnerability_count: number;
}

export interface PortalMilestone {
  id: string;
  name: string;
  description?: string;
  due_date?: string;
  completed_at?: string;
  status: string;
}

export interface PortalVulnerability {
  id: string;
  scan_id: string;
  host: string;
  port?: number;
  service?: string;
  title: string;
  severity: string;
  status: string;
  cve_ids?: string;
  cvss_score?: number;
  discovered_at: string;
}

export interface PortalVulnerabilityDetail {
  vulnerability: PortalVulnerability;
  description?: string;
  remediation?: string;
  references?: string;
  engagement_name?: string;
  scan_name: string;
}

export interface PortalVulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  in_progress: number;
  resolved: number;
}

export interface PortalVulnerabilityQuery {
  severity?: string;
  status?: string;
  engagement_id?: string;
  limit?: number;
  offset?: number;
}

export interface PortalVulnerabilitiesResponse {
  vulnerabilities: PortalVulnerability[];
  stats: PortalVulnerabilityStats;
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface PortalReport {
  id: string;
  name: string;
  report_type: string;
  format: string;
  status: string;
  created_at: string;
  engagement_id?: string;
  engagement_name?: string;
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
}

export interface CloneTemplateRequest {
  new_title?: string;
}

export interface TemplateCategory {
  category: string;
  count: number;
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
// Threat Intelligence Types
// ============================================================================

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertType =
  | 'exposed_service'
  | 'exploit_available'
  | 'known_exploited_vulnerability'
  | 'critical_cve'
  | 'new_cve'
  | 'ransomware_threat'
  | 'misconfiguration';
export type ThreatSource = 'Shodan' | 'ExploitDB' | 'NVD CVE' | 'CISA KEV' | 'Manual';

export interface ThreatAlertAsset {
  ip: string;
  port?: number;
  service?: string;
}

export interface ThreatAlert {
  id: string;
  scan_id: string;
  alert_type: AlertType;
  severity: ThreatSeverity;
  title: string;
  description: string;
  affected_host?: string;
  affected_assets: ThreatAlertAsset[];
  source: ThreatSource;
  source_reference?: string;
  cve_ids: string[];
  recommendations: string[];
  references: string[];
  in_cisa_kev: boolean;
  exploit_available: boolean;
  acknowledged: boolean;
  acknowledged_at?: string;
  acknowledged_by?: string;
  created_at: string;
}

export interface IpThreatIntel {
  ip: string;
  is_malicious: boolean;
  abuse_confidence_score?: number;
  country?: string;
  isp?: string;
  domain?: string;
  usage_type?: string;
  reports_count?: number;
  last_reported_at?: string;
  categories?: string[];
  tags?: string[];
  sources_checked: ThreatSource[];
}

export interface EnrichedCve {
  cve_id: string;
  description: string;
  cvss_score?: number;
  cvss_vector?: string;
  severity: string;
  published_date?: string;
  modified_date?: string;
  has_known_exploit: boolean;
  exploit_count: number;
  exploit_sources: string[];
  in_cisa_kev: boolean;
  kev_due_date?: string;
  affected_products: string[];
  references: string[];
}

export interface ThreatIntelApiStatus {
  enabled: boolean;
  apis_configured: string[];
  quota_remaining?: Record<string, number>;
  last_updated?: string;
  shodan_available?: boolean;
}

export interface EnrichScanRequest {
  check_ip_reputation?: boolean;
  enrich_cves?: boolean;
  check_exploits?: boolean;
}

export interface EnrichmentResult {
  scan_id: string;
  alerts_created: number;
  ips_checked: number;
  malicious_ips_found: number;
  cves_enriched: number;
  exploitable_cves: number;
  enriched_at: string;
}

// ============================================================================
// Attack Path Analysis Types
// ============================================================================

export type AttackPathRiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface AttackNode {
  id: string;
  node_type: 'host' | 'service' | 'vulnerability' | 'credential' | 'data' | 'entry' | 'pivot' | 'target';
  label: string;
  host_ip?: string;
  port?: number;
  service?: string;
  vulnerability_id?: string;
  vulnerability_ids: string[];
  severity?: string;
  x?: number;
  y?: number;
  position_x: number;
  position_y: number;
}

export interface AttackEdge {
  id: string;
  source: string;
  target: string;
  source_node_id: string;
  target_node_id: string;
  label: string;
  technique?: string;
  technique_id?: string;
  attack_technique?: string;
  probability?: number;
}

export interface AttackPath {
  id: string;
  scan_id: string;
  name: string;
  description: string;
  risk_level: AttackPathRiskLevel;
  risk_score: number;
  nodes: AttackNode[];
  edges: AttackEdge[];
  attack_chain: string[];
  mitigations: string[];
  mitigation_steps: string[];
  affected_assets: string[];
  exploited_vulns: string[];
  path_length: number;
  total_cvss: number;
  probability: number;
  created_at: string;
}

export interface AttackPathStats {
  total_paths: number;
  critical_paths: number;
  high_paths: number;
  medium_paths: number;
  low_paths: number;
  unique_hosts_at_risk: number;
  unique_vulns_exploited: number;
  total_nodes?: number;
  avg_path_length?: number;
}

export interface AnalyzeAttackPathsRequest {
  include_lateral_movement?: boolean;
  include_privilege_escalation?: boolean;
  max_path_depth?: number;
  target_hosts?: string[];
  force?: boolean;
}

export interface AnalyzeAttackPathsResponse {
  scan_id: string;
  paths_found: number;
  critical_paths: number;
  analysis_time_ms: number;
  message: string;
}

export interface GetAttackPathsResponse {
  scan_id: string;
  paths: AttackPath[];
  stats: AttackPathStats;
}

// ============================================================================
// Asset Tags Types
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
// Rate Limit Dashboard Types
// ============================================================================

export type RateLimitCategory = 'auth' | 'api' | 'scan';

export interface RateLimitConfig {
  category: RateLimitCategory;
  name: string;
  requests_per_period: number;
  period: string;
  burst_size: number;
  description: string;
}

export interface RateLimitEvent {
  id: string;
  ip: string;
  category: RateLimitCategory;
  endpoint: string;
  timestamp: string;
  user_agent: string | null;
}

export interface IpStats {
  ip: string;
  total_requests: number;
  blocked_requests: number;
  last_seen: string;
  requests_by_category: Record<string, number>;
}

export interface RateLimitSummary {
  total_requests_24h: number;
  blocked_requests_24h: number;
  block_rate_percent: number;
  unique_ips_24h: number;
  requests_by_category: Record<string, number>;
  blocked_by_category: Record<string, number>;
}

export interface RequestTimePoint {
  timestamp: string;
  total_requests: number;
  blocked_requests: number;
}

export interface RateLimitDashboardData {
  configs: RateLimitConfig[];
  summary: RateLimitSummary;
  recent_events: RateLimitEvent[];
  top_ips: IpStats[];
  requests_over_time: RequestTimePoint[];
}

// ============================================================================
// Scan Exclusions Types
// ============================================================================

export type ExclusionType = 'host' | 'cidr' | 'hostname' | 'port' | 'port_range';

export interface ScanExclusion {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  exclusion_type: ExclusionType;
  value: string;
  is_global: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateExclusionRequest {
  name: string;
  description?: string;
  exclusion_type: ExclusionType;
  value: string;
  is_global: boolean;
}

export interface UpdateExclusionRequest {
  name?: string;
  description?: string;
  exclusion_type?: ExclusionType;
  value?: string;
  is_global?: boolean;
}

