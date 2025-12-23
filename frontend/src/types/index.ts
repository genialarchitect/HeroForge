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
  // Agent-based scanning
  execution_mode?: 'local' | 'agent' | 'agent_group';
  agent_id?: string;
  agent_group_id?: string;
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

// Scan Templates (Profiles/Presets)

export type TemplateCategory = 'quick' | 'standard' | 'comprehensive' | 'web' | 'stealth' | 'custom';

export interface ScanTemplateConfig {
  port_range: [number, number];
  threads: number;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  enable_enumeration: boolean;
  enum_depth?: EnumDepth | null;
  enum_services?: EnumService[] | null;
  scan_type?: ScanType | null;
  udp_port_range?: [number, number] | null;
  udp_retries?: number;
  target_group_id?: string | null;
}

export interface ScanTemplate {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  config: ScanTemplateConfig;
  is_default: boolean;
  is_system: boolean;
  category: TemplateCategory;
  estimated_duration_mins: number | null;
  use_count: number;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TemplateCategorySummary {
  category: string;
  count: number;
}

export interface CreateTemplateRequest {
  name: string;
  description?: string;
  config: ScanTemplateConfig;
  is_default?: boolean;
  category?: TemplateCategory;
  estimated_duration_mins?: number;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  config?: ScanTemplateConfig;
  is_default?: boolean;
  category?: TemplateCategory;
  estimated_duration_mins?: number;
}

export interface CloneTemplateRequest {
  new_name?: string;
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
  owasp_top_10?: string[];
  pci_dss?: string[];
  nist_800_53?: string[];
  cis?: string[];
  hipaa?: string[];
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

export interface CloneTemplateRequest {
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
// Vulnerability Trends Types
// ============================================================================

export interface DailyVulnerabilityCount {
  date: string;
  total: number;
  new: number;
  resolved: number;
  open: number;
}

export interface RemediationRatePoint {
  date: string;
  total_found: number;
  total_resolved: number;
  remediation_rate: number;
  mttr_days: number;
}

export interface RecurringVulnerability {
  vulnerability_id: string;
  title: string;
  severity: string;
  count: number;
  affected_hosts: number;
  avg_resolution_days: number | null;
}

export interface VulnerabilityTrendsSummary {
  total_found: number;
  total_resolved: number;
  current_open: number;
  avg_mttr_days: number;
  remediation_rate: number;
  trend_direction: 'improving' | 'stable' | 'declining';
  critical_open: number;
  high_open: number;
}

export interface VulnerabilityTrendsData {
  daily_counts: DailyVulnerabilityCount[];
  severity_trends: VulnerabilityTimeSeriesDataPoint[];
  remediation_rates: RemediationRatePoint[];
  top_recurring: RecurringVulnerability[];
  summary: VulnerabilityTrendsSummary;
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

// ============================================================================
// AI Vulnerability Prioritization Types
// ============================================================================

export type RiskCategory = 'critical' | 'high' | 'medium' | 'low';
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low';
export type NetworkExposure = 'internet_facing' | 'dmz' | 'internal' | 'isolated';
export type ExploitMaturity = 'active_exploitation' | 'functional' | 'proof_of_concept' | 'unproven';
export type EffortLevel = 'low' | 'medium' | 'high' | 'very_high';
export type ImpactLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ScoringWeights {
  cvss_weight: number;
  exploit_weight: number;
  asset_criticality_weight: number;
  network_exposure_weight: number;
  attack_path_weight: number;
  compliance_weight: number;
  business_context_weight: number;
}

export interface AIModelConfig {
  id: string;
  name: string;
  description: string | null;
  weights: ScoringWeights;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface FactorScore {
  factor_name: string;
  raw_value: number;
  normalized_value: number;
  weight: number;
  contribution: number;
}

export interface RemediationEffort {
  estimated_hours: number;
  effort_level: EffortLevel;
  impact_level: ImpactLevel;
  requires_downtime: boolean;
  requires_testing: boolean;
}

export interface AIVulnerabilityScore {
  vulnerability_id: string;
  effective_risk_score: number;
  risk_category: RiskCategory;
  factor_scores: FactorScore[];
  remediation_priority: number;
  estimated_effort: RemediationEffort;
  confidence: number;
  calculated_at: string;
}

export interface PrioritizationSummary {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  average_risk_score: number;
  highest_risk_score: number;
}

export interface AIPrioritizationResult {
  scan_id: string;
  scores: AIVulnerabilityScore[];
  summary: PrioritizationSummary;
  calculated_at: string;
}

export interface PrioritizeRequest {
  force_recalculate?: boolean;
}

export interface UpdateAIConfigRequest {
  name?: string;
  description?: string;
  weights?: ScoringWeights;
}

export interface SubmitAIFeedbackRequest {
  vulnerability_id: string;
  priority_appropriate: boolean;
  priority_adjustment?: number;
  effort_accurate?: boolean;
  actual_effort_hours?: number;
  notes?: string;
}

// ============================================================================
// Agent-Based Scanning Types
// ============================================================================

export type AgentStatus = 'pending' | 'online' | 'busy' | 'offline' | 'disabled';

export type AgentTaskStatus = 'pending' | 'assigned' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timed_out';

export interface ScanAgent {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  token_prefix: string;
  status: AgentStatus;
  version: string | null;
  hostname: string | null;
  ip_address: string | null;
  os_info: string | null;
  capabilities: string | null; // JSON array
  network_zones: string | null; // JSON array
  max_concurrent_tasks: number;
  current_tasks: number;
  last_heartbeat_at: string | null;
  last_task_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentGroup {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  network_ranges: string | null; // JSON array
  color: string;
  created_at: string;
  updated_at: string;
}

export interface AgentWithGroups {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  token_prefix: string;
  status: AgentStatus;
  version: string | null;
  hostname: string | null;
  ip_address: string | null;
  os_info: string | null;
  capabilities: string | null;
  network_zones: string | null;
  max_concurrent_tasks: number;
  current_tasks: number;
  last_heartbeat_at: string | null;
  last_task_at: string | null;
  created_at: string;
  updated_at: string;
  groups: AgentGroup[];
}

export interface AgentGroupWithCount extends AgentGroup {
  agent_count: number;
}

export interface AgentGroupWithAgents extends AgentGroup {
  agents: ScanAgent[];
}

export interface AgentStats {
  total_agents: number;
  online_agents: number;
  busy_agents: number;
  offline_agents: number;
  total_tasks_completed: number;
  total_tasks_failed: number;
  average_task_duration_secs: number | null;
}

export interface AgentHeartbeat {
  id: string;
  agent_id: string;
  cpu_usage: number | null;
  memory_usage: number | null;
  disk_usage: number | null;
  active_tasks: number;
  queued_tasks: number;
  latency_ms: number | null;
  created_at: string;
}

export interface AgentTask {
  id: string;
  scan_id: string;
  agent_id: string | null;
  group_id: string | null;
  user_id: string;
  status: AgentTaskStatus;
  task_type: string;
  config: string; // JSON
  targets: string;
  priority: number;
  timeout_seconds: number;
  retry_count: number;
  max_retries: number;
  error_message: string | null;
  assigned_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RegisterAgentRequest {
  name: string;
  description?: string;
  network_zones?: string[];
  max_concurrent_tasks?: number;
}

export interface RegisterAgentResponse {
  id: string;
  name: string;
  token: string;
  token_prefix: string;
  created_at: string;
}

export interface UpdateAgentRequest {
  name?: string;
  description?: string;
  network_zones?: string[];
  max_concurrent_tasks?: number;
  status?: string;
}

export interface CreateAgentGroupRequest {
  name: string;
  description?: string;
  network_ranges?: string[];
  color?: string;
}

export interface UpdateAgentGroupRequest {
  name?: string;
  description?: string;
  network_ranges?: string[];
  color?: string;
}

export interface AssignAgentsToGroupRequest {
  agent_ids: string[];
}

// ============================================================================
// SSO (SAML/OIDC) Types
// ============================================================================

export type SsoProviderType = 'saml' | 'oidc' | 'okta' | 'azure_ad' | 'google' | 'onelogin' | 'ping' | 'auth0' | 'keycloak' | 'jumpcloud';
export type SsoProviderStatus = 'active' | 'disabled' | 'incomplete' | 'error';

export interface SsoProviderForLogin {
  id: string;
  name: string;
  display_name: string;
  provider_type: SsoProviderType;
  icon: string | null;
}

export interface SsoProvider {
  id: string;
  name: string;
  display_name: string;
  provider_type: SsoProviderType;
  status: SsoProviderStatus;
  icon: string | null;
  jit_provisioning: boolean;
  default_role: string;
  update_on_login: boolean;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  config?: SamlConfig | OidcConfig;
  attribute_mappings?: AttributeMapping[];
  group_mappings?: GroupMapping[];
}

export interface SamlConfig {
  type: 'saml';
  idp_entity_id: string;
  idp_sso_url: string;
  idp_slo_url?: string;
  idp_certificate: string;
  sp_entity_id?: string;
  sign_requests: boolean;
  require_signed_response: boolean;
  require_signed_assertion: boolean;
  encrypt_assertions: boolean;
  name_id_format?: string;
  acs_binding?: string;
  force_authn: boolean;
  authn_context?: string[];
  allowed_clock_skew: number;
}

export interface OidcConfig {
  type: 'oidc';
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
  claims?: string[];
  use_pkce: boolean;
  response_type: string;
  response_mode?: string;
  token_endpoint_auth_method?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
}

export interface AttributeMapping {
  source: string;
  target: string;
  required: boolean;
  default_value?: string;
}

export interface GroupMapping {
  group: string;
  role: string;
  priority: number;
}

export interface CreateSsoProviderRequest {
  name: string;
  display_name: string;
  provider_type: SsoProviderType;
  icon?: string;
  config: SamlConfig | OidcConfig;
  attribute_mappings?: AttributeMapping[];
  group_mappings?: GroupMapping[];
  jit_provisioning?: boolean;
  default_role?: string;
  update_on_login?: boolean;
}

export interface UpdateSsoProviderRequest {
  display_name?: string;
  icon?: string;
  status?: SsoProviderStatus;
  config?: SamlConfig | OidcConfig;
  attribute_mappings?: AttributeMapping[];
  group_mappings?: GroupMapping[];
  jit_provisioning?: boolean;
  default_role?: string;
  update_on_login?: boolean;
}

export interface SsoMetadata {
  entity_id: string;
  metadata_xml?: string;
  acs_url?: string;
  slo_url?: string;
  redirect_uri?: string;
}

export interface SsoLoginResponse {
  redirect_url: string;
  state?: string;
  request_id?: string;
}

export interface SsoTestResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface SsoProviderPreset {
  id: string;
  name: string;
  description: string;
  provider_type: SsoProviderType;
  icon: string;
  default_config: SamlConfig | OidcConfig;
  default_attribute_mappings: AttributeMapping[];
  setup_instructions: string;
}

export interface UpdateMappingsRequest {
  attribute_mappings?: AttributeMapping[];
  group_mappings?: GroupMapping[];
}

// ============================================================================
// CI/CD Integration Types
// ============================================================================

export type CiCdPlatform = 'github_actions' | 'jenkins' | 'gitlab_ci' | 'azure_devops' | 'bitbucket_pipelines' | 'circleci';

export type CiCdSeverity = 'low' | 'medium' | 'high' | 'critical';

export type CiCdPermission = 'trigger_scans' | 'view_results' | 'download_reports' | 'view_quality_gates';

export interface CiCdTokenPermissions {
  trigger_scans: boolean;
  view_results: boolean;
  download_reports: boolean;
  view_quality_gates: boolean;
}

export interface CiCdToken {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  permissions: CiCdTokenPermissions;
  platform: CiCdPlatform;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: boolean;
  created_at: string;
}

export interface CreateCiCdTokenRequest {
  name: string;
  platform: CiCdPlatform;
  permissions: CiCdTokenPermissions;
  expires_at?: string;
}

export interface CreateCiCdTokenResponse {
  id: string;
  name: string;
  token: string;
  prefix: string;
  platform: CiCdPlatform;
  permissions: CiCdTokenPermissions;
  created_at: string;
  expires_at: string | null;
}

export interface SeverityThreshold {
  severity: CiCdSeverity;
  max_count: number;
}

export interface QualityGate {
  id: string;
  user_id: string | null;
  name: string;
  description: string | null;
  is_default: boolean;
  fail_on_critical: boolean;
  fail_on_high: boolean;
  max_critical: number;
  max_high: number;
  max_medium: number;
  max_low: number;
  created_at: string;
  updated_at: string;
}

export interface CreateQualityGateRequest {
  name: string;
  description?: string;
  is_default?: boolean;
  fail_on_critical?: boolean;
  fail_on_high?: boolean;
  max_critical?: number;
  max_high?: number;
  max_medium?: number;
  max_low?: number;
}

export interface UpdateQualityGateRequest {
  name?: string;
  description?: string;
  is_default?: boolean;
  fail_on_critical?: boolean;
  fail_on_high?: boolean;
  max_critical?: number;
  max_high?: number;
  max_medium?: number;
  max_low?: number;
}

export type CiCdRunStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface CiCdRun {
  id: string;
  user_id: string;
  token_id: string;
  scan_id: string | null;
  status: CiCdRunStatus;
  platform: CiCdPlatform;
  pipeline_id: string | null;
  pipeline_url: string | null;
  commit_sha: string | null;
  branch: string | null;
  quality_gate_passed: boolean | null;
  quality_gate_id: string | null;
  exit_code: number | null;
  started_at: string;
  completed_at: string | null;
  created_at: string;
}

export interface CiCdScanRequest {
  targets: string[];
  name?: string;
  port_range?: [number, number];
  quality_gate_id?: string;
  template_id?: string;
  commit_sha?: string;
  branch?: string;
  pipeline_id?: string;
  pipeline_url?: string;
}

export interface QualityGateResult {
  passed: boolean;
  gate_name: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  critical_exceeded: boolean;
  high_exceeded: boolean;
  medium_exceeded: boolean;
  low_exceeded: boolean;
  exit_code: number;
}

export interface PipelineExample {
  platform: CiCdPlatform;
  name: string;
  content: string;
}

// ============================================================================
// Container/K8s Security Scanning Types
// ============================================================================

export type ContainerScanType = 'image' | 'dockerfile' | 'runtime' | 'k8s_manifest' | 'k8s_cluster' | 'comprehensive';
export type ContainerScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ContainerFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ContainerFindingType =
  | 'cve'
  | 'misconfiguration'
  | 'secret'
  | 'best_practice'
  | 'rbac'
  | 'network_policy'
  | 'pod_security'
  | 'resource_limits';
export type FindingStatus = 'open' | 'resolved' | 'accepted' | 'false_positive';
export type K8sResourceType =
  | 'Pod'
  | 'Deployment'
  | 'DaemonSet'
  | 'StatefulSet'
  | 'ReplicaSet'
  | 'Service'
  | 'Ingress'
  | 'ConfigMap'
  | 'Secret'
  | 'Role'
  | 'ClusterRole'
  | 'RoleBinding'
  | 'ClusterRoleBinding'
  | 'NetworkPolicy'
  | 'ServiceAccount'
  | 'Namespace';

export interface ContainerImage {
  id: string;
  scan_id: string;
  image_name: string;
  image_tag: string;
  image_digest: string | null;
  registry: string | null;
  os: string | null;
  architecture: string | null;
  size_bytes: number | null;
  layer_count: number | null;
  created_at: string;
}

export interface K8sResource {
  id: string;
  scan_id: string;
  resource_type: K8sResourceType;
  name: string;
  namespace: string | null;
  api_version: string | null;
  labels: string | null;
  annotations: string | null;
  spec_summary: string | null;
  created_at: string;
}

export interface ContainerFinding {
  id: string;
  scan_id: string;
  image_id: string | null;
  resource_id: string | null;
  finding_type: ContainerFindingType;
  severity: ContainerFindingSeverity;
  title: string;
  description: string;
  cve_id: string | null;
  cvss_score: number | null;
  package_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  file_path: string | null;
  line_number: number | null;
  remediation: string | null;
  references: string | null;
  status: FindingStatus;
  created_at: string;
  updated_at: string;
}

export interface ContainerScanSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  images_scanned: number;
  resources_scanned: number;
  cve_count: number;
  misconfig_count: number;
  secret_count: number;
}

export interface ContainerScan {
  id: string;
  user_id: string;
  name: string;
  scan_type: ContainerScanType;
  status: ContainerScanStatus;
  target: string;
  registry_url: string | null;
  k8s_context: string | null;
  k8s_namespace: string | null;
  images_scanned: number;
  resources_scanned: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface DockerfileIssue {
  severity: ContainerFindingSeverity;
  title: string;
  description: string;
  line_number: number | null;
  instruction: string | null;
  remediation: string;
  references: string[];
}

export interface DockerfileAnalysis {
  dockerfile_path: string | null;
  base_image: string | null;
  base_image_tag: string | null;
  issues: DockerfileIssue[];
  best_practices_score: number;
  security_score: number;
}

export interface K8sManifestIssue {
  severity: ContainerFindingSeverity;
  finding_type: ContainerFindingType;
  resource_type: string;
  resource_name: string;
  title: string;
  description: string;
  remediation: string;
  references: string[];
}

export interface K8sManifestAnalysis {
  resources_analyzed: number;
  issues: K8sManifestIssue[];
  security_score: number;
  by_resource_type: Record<string, number>;
}

// Container Scan API Requests

export interface CreateContainerScanRequest {
  name: string;
  scan_type: ContainerScanType;
  target: string;
  registry_url?: string;
  registry_username?: string;
  registry_password?: string;
  k8s_context?: string;
  k8s_namespace?: string;
  demo_mode?: boolean;
}

export interface AnalyzeDockerfileRequest {
  content: string;
  filename?: string;
}

export interface AnalyzeK8sManifestRequest {
  content: string;
  filename?: string;
}

export interface UpdateContainerFindingStatusRequest {
  status: FindingStatus;
}

// Container Scan API Responses

export interface ContainerScanListResponse {
  scans: ContainerScan[];
  total: number;
}

export interface ContainerScanDetailResponse {
  scan: ContainerScan;
  summary: ContainerScanSummary;
}

export interface ContainerScanTypeInfo {
  id: ContainerScanType;
  name: string;
  description: string;
  requires_registry: boolean;
  requires_k8s: boolean;
}

// ============================================================================
// IaC (Infrastructure-as-Code) Security Scanning Types
// ============================================================================

export type IacPlatform = 'Terraform' | 'CloudFormation' | 'AzureArm' | 'Kubernetes' | 'Ansible';
export type IacCloudProvider = 'Aws' | 'Azure' | 'Gcp' | 'Multi' | 'None';
export type IacScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type IacSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IacFindingStatus = 'open' | 'resolved' | 'false_positive' | 'accepted' | 'suppressed';
export type IacFindingCategory =
  | 'hardcoded_secret'
  | 'iam_misconfiguration'
  | 'public_storage'
  | 'missing_encryption'
  | 'missing_logging'
  | 'network_exposure'
  | 'missing_tags'
  | 'deprecated_resource'
  | 'weak_cryptography'
  | 'insecure_default'
  | 'compliance_violation'
  | 'best_practice';

export interface IacScan {
  id: string;
  user_id: string;
  name: string;
  source_type: string;
  source_url: string | null;
  platforms: IacPlatform[];
  providers: IacCloudProvider[];
  status: IacScanStatus;
  file_count: number;
  resource_count: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  customer_id: string | null;
  engagement_id: string | null;
}

export interface IacFile {
  id: string;
  scan_id: string;
  filename: string;
  path: string;
  content: string | null;
  platform: string;
  provider: string;
  size_bytes: number;
  line_count: number;
  resource_count: number;
  finding_count: number;
  created_at: string;
}

export interface IacFileInfo {
  id: string;
  filename: string;
  path: string;
  platform: string;
  provider: string;
  size_bytes: number;
  line_count: number;
  resource_count: number;
  finding_count: number;
}

export interface IacFinding {
  id: string;
  scan_id: string;
  file_id: string;
  rule_id: string;
  severity: IacSeverity;
  category: IacFindingCategory;
  title: string;
  description: string;
  resource_type: string | null;
  resource_name: string | null;
  line_start: number;
  line_end: number;
  code_snippet: string | null;
  remediation: string;
  documentation_url: string | null;
  compliance_mappings: IacComplianceMapping[];
  status: IacFindingStatus;
  suppressed: boolean;
  suppression_reason: string | null;
  created_at: string;
}

export interface IacComplianceMapping {
  framework: string;
  control_id: string;
  control_name: string;
}

export interface IacRule {
  id: string;
  name: string;
  description: string;
  severity: IacSeverity;
  category: IacFindingCategory;
  platforms: IacPlatform[];
  providers: IacCloudProvider[];
  resource_types: string[];
  pattern: string;
  pattern_type: string;
  remediation: string;
  documentation_url: string | null;
  compliance_mappings: IacComplianceMapping[];
  is_builtin: boolean;
  is_enabled: boolean;
  user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface IacPlatformInfo {
  id: string;
  name: string;
  description: string;
  file_extensions: string[];
  providers: string[];
}

export interface IacFindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  by_category: Record<string, number>;
}

export interface IacScanDetailResponse {
  scan: IacScan;
  files: IacFileInfo[];
  finding_summary: IacFindingSummary;
}

export interface IacAnalyzeFileRequest {
  filename: string;
  content: string;
  platform?: string;
}

export interface IacAnalyzeFileResponse {
  platform: string;
  provider: string;
  findings: IacFindingInfo[];
  resources: IacResourceInfo[];
}

export interface IacFindingInfo {
  id: string;
  rule_id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  resource_type: string | null;
  resource_name: string | null;
  line_start: number;
  line_end: number;
  code_snippet: string | null;
  remediation: string;
  documentation_url: string | null;
}

export interface IacResourceInfo {
  resource_type: string;
  resource_name: string;
  line_number: number | null;
}

export interface CreateIacRuleRequest {
  name: string;
  description: string;
  severity: string;
  category: string;
  platforms?: string[];
  providers?: string[];
  resource_types?: string[];
  pattern: string;
  pattern_type?: string;
  remediation: string;
  documentation_url?: string;
}

export interface UpdateIacRuleRequest {
  name?: string;
  description?: string;
  severity?: string;
  category?: string;
  pattern?: string;
  remediation?: string;
  is_enabled?: boolean;
}

export interface UpdateIacFindingStatusRequest {
  status: string;
  suppression_reason?: string;
}

// ============================================================================
// Remediation Workflow Types
// ============================================================================

export type WorkflowStatus = 'active' | 'completed' | 'cancelled' | 'on_hold' | 'rejected';
export type StageStatus = 'pending' | 'active' | 'completed' | 'skipped' | 'rejected';
export type StageType = 'assignment' | 'work' | 'review' | 'verification' | 'cab_approval' | 'deployment' | 'closure';
export type TransitionAction = 'started' | 'advanced' | 'approved' | 'rejected' | 'completed' | 'cancelled' | 'on_hold' | 'resumed' | 'sent_back';

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  is_active: boolean;
}

export interface WorkflowStage {
  id: string;
  template_id: string;
  name: string;
  description: string | null;
  stage_order: number;
  stage_type: string;
  required_approvals: number;
  approver_role: string | null;
  approver_user_ids: string | null;
  sla_hours: number | null;
  notify_on_enter: boolean;
  notify_on_sla_breach: boolean;
  auto_advance_conditions: string | null;
}

export interface WorkflowInstance {
  id: string;
  template_id: string;
  vulnerability_id: string;
  current_stage_id: string;
  status: string;
  started_by: string;
  started_at: string;
  completed_at: string | null;
  notes: string | null;
}

export interface WorkflowStageInstance {
  id: string;
  instance_id: string;
  stage_id: string;
  status: string;
  entered_at: string;
  completed_at: string | null;
  sla_deadline: string | null;
  sla_breached: boolean;
  approvals_received: number;
  notes: string | null;
}

export interface WorkflowApproval {
  id: string;
  stage_instance_id: string;
  user_id: string;
  approved: boolean;
  comment: string | null;
  created_at: string;
}

export interface WorkflowTransition {
  id: string;
  instance_id: string;
  from_stage_id: string | null;
  to_stage_id: string;
  action: string;
  performed_by: string;
  comment: string | null;
  created_at: string;
}

export interface WorkflowTemplateWithStages {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  is_active: boolean;
  stages: WorkflowStage[];
}

export interface ApprovalWithUser {
  id: string;
  stage_instance_id: string;
  user_id: string;
  approved: boolean;
  comment: string | null;
  created_at: string;
  username: string;
}

export interface StageInstanceWithDetails {
  id: string;
  instance_id: string;
  stage_id: string;
  status: string;
  entered_at: string;
  completed_at: string | null;
  sla_deadline: string | null;
  sla_breached: boolean;
  approvals_received: number;
  notes: string | null;
  stage: WorkflowStage;
  approvals: ApprovalWithUser[];
}

export interface WorkflowTransitionWithUser {
  id: string;
  instance_id: string;
  from_stage_id: string | null;
  to_stage_id: string;
  action: string;
  performed_by: string;
  username: string;
  comment: string | null;
  created_at: string;
}

export interface WorkflowInstanceDetail {
  id: string;
  template_id: string;
  vulnerability_id: string;
  current_stage_id: string;
  status: string;
  started_by: string;
  started_at: string;
  completed_at: string | null;
  notes: string | null;
  template: WorkflowTemplate;
  current_stage: WorkflowStage;
  stage_instances: StageInstanceWithDetails[];
  transitions: WorkflowTransitionWithUser[];
}

export interface PendingApproval {
  instance_id: string;
  stage_instance_id: string;
  vulnerability_id: string;
  vulnerability_title: string;
  severity: string;
  stage_name: string;
  stage_type: string;
  entered_at: string;
  sla_deadline: string | null;
  sla_breached: boolean;
  required_approvals: number;
  approvals_received: number;
}

export interface WorkflowStats {
  active_workflows: number;
  pending_approvals: number;
  completed_today: number;
  sla_breaches: number;
  avg_completion_hours: number | null;
}

// Workflow Request Types
export interface CreateWorkflowStageRequest {
  name: string;
  description?: string;
  stage_type: string;
  required_approvals: number;
  approver_role?: string;
  approver_user_ids?: string[];
  sla_hours?: number;
  notify_on_enter?: boolean;
  notify_on_sla_breach?: boolean;
  auto_advance_conditions?: Record<string, unknown>;
}

export interface CreateWorkflowTemplateRequest {
  name: string;
  description?: string;
  stages: CreateWorkflowStageRequest[];
}

export interface UpdateWorkflowTemplateRequest {
  name?: string;
  description?: string;
  is_active?: boolean;
  stages?: CreateWorkflowStageRequest[];
}

export interface StartWorkflowRequest {
  template_id: string;
  notes?: string;
}

export interface ApproveWorkflowRequest {
  comment?: string;
}

export interface RejectWorkflowRequest {
  comment: string;
  restart_from_stage?: string;
}

export interface UpdateWorkflowRequest {
  status?: string;
  notes?: string;
}

// ============================================================================
// Agent Mesh Network Types
// ============================================================================

export interface AgentMeshConfig {
  agent_id: string;
  enabled: boolean;
  mesh_port: number;
  external_address: string | null;
  cluster_id: string | null;
  cluster_role: string | null;
  config_json: string | null;
  created_at: string;
  updated_at: string;
}

export interface MeshPeerConnection {
  id: string;
  from_agent_id: string;
  to_agent_id: string;
  connection_status: 'connected' | 'disconnected' | 'connecting' | 'error';
  latency_ms: number | null;
  bandwidth_mbps: number | null;
  last_seen_at: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface MeshConnectionStats {
  total_connections: number;
  active_connections: number;
  failed_connections: number;
  avg_latency_ms: number | null;
  total_bandwidth_mbps: number | null;
}

export interface AgentMeshPeerData {
  agent_id: string;
  agent_name: string;
  mesh_config: AgentMeshConfig;
  peers: MeshPeerConnection[];
  stats: MeshConnectionStats | null;
}

export interface MeshCluster {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  leader_agent_id: string | null;
  config_json: string | null;
  health_json: string | null;
  created_at: string;
  updated_at: string;
}

export interface MeshClusterWithMembers extends MeshCluster {
  member_count: number;
  members: ScanAgent[];
}

export interface CreateMeshClusterRequest {
  name: string;
  description?: string;
  config_json?: string;
}

export interface UpdateMeshClusterRequest {
  name?: string;
  description?: string;
  config_json?: string;
  health_json?: string;
}

export interface UpdateMeshConfigRequest {
  enabled?: boolean;
  mesh_port?: number;
  external_address?: string;
  cluster_id?: string;
  cluster_role?: string;
  config_json?: string;
}

// ============================================================================
// Breach & Attack Simulation (BAS) Types
// ============================================================================

/** MITRE ATT&CK Tactic */
export interface MitreTactic {
  id: string;
  name: string;
  description: string;
  techniques: string[]; // List of technique IDs belonging to this tactic
}

/** MITRE ATT&CK Technique */
export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  tactic: string;
  tactic_name: string;
  mitre_url: string;
  platforms: string[];
  permissions_required: string[];
  data_sources: string[];
  detection: string;
  payloads: string[]; // Available payload types for this technique
}

/** Execution mode for BAS simulations */
export type BasExecutionMode = 'dry_run' | 'safe' | 'full';

/** Status of a BAS scenario */
export type BasScenarioStatus = 'draft' | 'ready' | 'builtin';

/** Status of a BAS simulation */
export type BasSimulationStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

/** BAS Scenario - a configured set of techniques to run */
export interface SimulationScenario {
  id: string;
  name: string;
  description?: string;
  status: BasScenarioStatus;
  execution_mode: BasExecutionMode;
  technique_count: number;
  target_count: number;
  tags: string[];
  created_at: string;
  updated_at: string;
}

/** Summary of a BAS simulation run */
export interface SimulationSummary {
  id: string;
  scenario_id: string;
  status: BasSimulationStatus;
  execution_mode: BasExecutionMode;
  total_techniques: number;
  detection_rate: number;
  security_score: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
}

/** Statistics from a simulation run */
export interface SimulationStats {
  total_techniques: number;
  succeeded: number;
  blocked: number;
  detected: number;
  failed: number;
  skipped: number;
  detection_rate: number;
  block_rate: number;
  security_score: number;
}

/** Result of executing a single technique */
export interface TechniqueExecution {
  id: string;
  technique_id: string;
  target?: string;
  status: string;
  detection_observed: boolean;
  detection_details?: string;
  duration_ms?: number;
  error?: string;
}

/** A detection gap - technique that wasn't detected */
export interface DetectionGap {
  id: string;
  technique_id: string;
  technique_name: string;
  tactics: string[];
  severity: number; // 1-5, where 5 is critical
  reason?: string;
  recommendations: string[];
  acknowledged: boolean;
}

/** Full details of a simulation run */
export interface SimulationDetails {
  id: string;
  scenario_id: string;
  status: BasSimulationStatus;
  execution_mode: BasExecutionMode;
  summary: SimulationStats;
  executions: TechniqueExecution[];
  detection_gaps: DetectionGap[];
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  error?: string;
}

/** Overall BAS statistics for the user */
export interface BasStats {
  total_scenarios: number;
  total_simulations: number;
  total_techniques_tested: number;
  avg_detection_rate: number;
  avg_security_score: number;
  total_detection_gaps: number;
  unacknowledged_gaps: number;
}

/** Request to create a new BAS scenario */
export interface CreateScenarioRequest {
  name: string;
  description: string;
  execution_mode: BasExecutionMode;
  technique_ids: string[];
  targets: string[];
  timeout_secs: number;
  parallel_execution: boolean;
  continue_on_failure: boolean;
  tags: string[];
}

/** Request to start a simulation */
export interface StartSimulationRequest {
  scenario_id: string;
  execution_mode?: BasExecutionMode;
  target_override?: string;
}

/** Request to acknowledge a detection gap */
export interface AcknowledgeGapRequest {
  notes?: string;
}

// =============================================================================
// SIEM (Security Information and Event Management) Types
// =============================================================================

/** Log format types */
export type SiemLogFormat =
  | 'syslog_rfc3164'
  | 'syslog_rfc5424'
  | 'cef'
  | 'leef'
  | 'json'
  | 'windows_event'
  | 'raw'
  | 'heroforge';

/** Transport protocol types */
export type SiemTransportProtocol = 'udp' | 'tcp' | 'tcp_tls' | 'http' | 'https';

/** Log source status */
export type SiemLogSourceStatus = 'pending' | 'active' | 'inactive' | 'error';

/** SIEM severity levels */
export type SiemSeverity =
  | 'debug'
  | 'info'
  | 'notice'
  | 'warning'
  | 'error'
  | 'critical'
  | 'alert'
  | 'emergency';

/** Detection rule types */
export type SiemRuleType =
  | 'pattern'
  | 'regex'
  | 'threshold'
  | 'correlation'
  | 'anomaly'
  | 'machine_learning'
  | 'sigma'
  | 'yara';

/** Rule status */
export type SiemRuleStatus = 'enabled' | 'disabled' | 'testing';

/** Alert status */
export type SiemAlertStatus =
  | 'new'
  | 'in_progress'
  | 'escalated'
  | 'resolved'
  | 'false_positive'
  | 'ignored';

/** Log source configuration */
export interface SiemLogSource {
  id: string;
  name: string;
  description?: string;
  source_type: string;
  host?: string;
  format: SiemLogFormat;
  protocol: SiemTransportProtocol;
  port?: number;
  status: SiemLogSourceStatus;
  last_seen?: string;
  log_count: number;
  logs_per_hour: number;
  custom_patterns?: Record<string, string>;
  field_mappings?: Record<string, string>;
  tags: string[];
  auto_enrich: boolean;
  retention_days?: number;
  created_at: string;
  updated_at: string;
  created_by?: string;
}

/** Create log source request */
export interface CreateSiemLogSourceRequest {
  name: string;
  description?: string;
  source_type: string;
  host?: string;
  format: string;
  protocol: string;
  port?: number;
  tags?: string[];
  auto_enrich?: boolean;
  retention_days?: number;
}

/** Update log source request */
export interface UpdateSiemLogSourceRequest {
  name?: string;
  description?: string;
  source_type?: string;
  host?: string;
  format?: string;
  protocol?: string;
  port?: number;
  status?: string;
  tags?: string[];
  auto_enrich?: boolean;
  retention_days?: number;
}

/** Log entry */
export interface SiemLogEntry {
  id: string;
  source_id: string;
  timestamp: string;
  received_at: string;
  severity: string;
  facility?: number;
  format: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  hostname?: string;
  application?: string;
  pid?: number;
  message_id?: string;
  structured_data: Record<string, unknown>;
  message: string;
  raw: string;
  category?: string;
  action?: string;
  outcome?: string;
  user?: string;
  tags: string[];
  alerted: boolean;
  alert_ids: string[];
  partition_date: string;
}

/** Log search query parameters */
export interface SiemLogSearchParams {
  query?: string;
  source_id?: string;
  min_severity?: string;
  source_ip?: string;
  destination_ip?: string;
  hostname?: string;
  application?: string;
  user?: string;
  start_time?: string;
  end_time?: string;
  alerted?: boolean;
  offset?: number;
  limit?: number;
}

/** Log search response */
export interface SiemLogSearchResponse {
  entries: SiemLogEntry[];
  total_count: number;
  query_time_ms: number;
  offset: number;
  limit: number;
}

/** Detection rule */
export interface SiemRule {
  id: string;
  name: string;
  description?: string;
  rule_type: SiemRuleType;
  severity: SiemSeverity;
  status: SiemRuleStatus;
  definition: Record<string, unknown>;
  source_ids: string[];
  categories: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  false_positive_rate?: number;
  trigger_count: number;
  last_triggered?: string;
  tags: string[];
  response_actions: string[];
  time_window_seconds?: number;
  threshold_count?: number;
  group_by_fields: string[];
  created_at: string;
  updated_at: string;
  created_by?: string;
}

/** Create rule request */
export interface CreateSiemRuleRequest {
  name: string;
  description?: string;
  rule_type: string;
  severity: string;
  status?: string;
  definition: Record<string, unknown>;
  source_ids?: string[];
  categories?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
  response_actions?: string[];
  time_window_seconds?: number;
  threshold_count?: number;
  group_by_fields?: string[];
}

/** Update rule request */
export interface UpdateSiemRuleRequest {
  name?: string;
  description?: string;
  rule_type?: string;
  severity?: string;
  status?: string;
  definition?: Record<string, unknown>;
  source_ids?: string[];
  categories?: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  tags?: string[];
  response_actions?: string[];
  time_window_seconds?: number;
  threshold_count?: number;
  group_by_fields?: string[];
}

/** SIEM Alert */
export interface SiemAlert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: SiemSeverity;
  status: SiemAlertStatus;
  title: string;
  description?: string;
  log_entry_ids: string[];
  event_count: number;
  source_ips: string[];
  destination_ips: string[];
  users: string[];
  hosts: string[];
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  resolved_by?: string;
  resolved_at?: string;
  resolution_notes?: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags: string[];
  context: Record<string, unknown>;
  related_alert_ids: string[];
  external_ticket_id?: string;
}

/** Update alert status request */
export interface UpdateSiemAlertStatusRequest {
  status: string;
  assigned_to?: string;
}

/** Resolve alert request */
export interface ResolveSiemAlertRequest {
  resolution_notes?: string;
  is_false_positive?: boolean;
}

/** Alert status count */
export interface SiemAlertStatusCount {
  status: string;
  count: number;
}

/** Alert severity count */
export interface SiemAlertSeverityCount {
  severity: string;
  count: number;
}

/** Top log source stats */
export interface SiemTopSourceStats {
  id: string;
  name: string;
  log_count: number;
  logs_per_hour: number;
}

/** SIEM statistics response */
export interface SiemStatsResponse {
  total_sources: number;
  active_sources: number;
  total_logs_today: number;
  total_logs_all: number;
  logs_per_hour: number;
  total_rules: number;
  enabled_rules: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  alerts_by_status: SiemAlertStatusCount[];
  alerts_by_severity: SiemAlertSeverityCount[];
  top_sources: SiemTopSourceStats[];
  ingestion_rate: number;
}

// =============================================================================
// Password Cracking Types
// =============================================================================

/** Hash type enum matching backend modes */
export type HashTypeMode =
  | 0      // MD5
  | 100    // SHA-1
  | 1000   // NTLM
  | 1400   // SHA-256
  | 1700   // SHA-512
  | 1800   // sha512crypt
  | 3000   // LM
  | 3200   // bcrypt
  | 5600   // NetNTLMv2
  | 13100  // Kerberos 5 TGS
  | 18200  // Kerberos 5 AS-REP
  | 22000; // WPA-PMKID-PBKDF2

/** Hash type information */
export interface HashTypeInfo {
  mode: number;
  name: string;
  example?: string;
}

/** Cracker type */
export type CrackerType = 'hashcat' | 'john';

/** Cracking job status */
export type CrackingJobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'stopped';

/** Hash entry in a cracking job */
export interface HashEntry {
  hash: string;
  username?: string;
  source?: string;
}

/** Cracking job progress */
export interface CrackingProgress {
  total_hashes: number;
  cracked: number;
  speed: string;
  estimated_time: string;
  progress_percent: number;
}

/** Cracking job */
export interface CrackingJob {
  id: string;
  user_id: string;
  name: string;
  status: CrackingJobStatus;
  hash_type: number;
  hash_type_name: string;
  cracker_type: CrackerType;
  hashes_count: number;
  wordlist_ids: string[];
  rule_ids: string[];
  config: CrackingConfig;
  progress: CrackingProgress;
  cracked_count: number;
  source_campaign_id?: string;
  customer_id?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
}

/** Cracking job configuration */
export interface CrackingConfig {
  attack_mode?: number;
  workload_profile?: number;
  optimized_kernel?: boolean;
  custom_args?: string[];
}

/** Cracked credential */
export interface CrackedCredential {
  id: string;
  job_id: string;
  hash: string;
  plaintext: string;
  hash_type: number;
  username?: string;
  asset_id?: string;
  cracked_at: string;
}

/** Wordlist entry */
export interface Wordlist {
  id: string;
  user_id?: string;
  name: string;
  description?: string;
  file_path: string;
  size_bytes?: number;
  line_count?: number;
  is_builtin: boolean;
  category?: string;
  created_at: string;
}

/** Rule file entry */
export interface RuleFile {
  id: string;
  user_id?: string;
  name: string;
  description?: string;
  file_path: string;
  rule_count?: number;
  cracker_type: CrackerType;
  is_builtin: boolean;
  created_at: string;
}

/** Create cracking job request */
export interface CreateCrackingJobRequest {
  name: string;
  hash_type: number;
  cracker_type: CrackerType;
  hashes: HashEntry[];
  wordlist_ids?: string[];
  rule_ids?: string[];
  config?: CrackingConfig;
  source_campaign_id?: string;
  customer_id?: string;
  auto_start?: boolean;
}

/** Detect hash type request */
export interface DetectHashRequest {
  hashes: string[];
}

/** Detect hash type response */
export interface DetectHashResponse {
  hash_type?: number;
  hash_type_name?: string;
  confidence: 'high' | 'medium' | 'low' | 'none';
  alternatives: HashTypeInfo[];
}

/** Cracking statistics */
export interface CrackingStats {
  total_jobs: number;
  running_jobs: number;
  completed_jobs: number;
  total_hashes: number;
  total_cracked: number;
  success_rate: number;
  total_wordlists: number;
  total_rules: number;
}

/** WebSocket progress message */
export interface CrackingProgressMessage {
  message_type: 'job_started' | 'progress_update' | 'hash_cracked' | 'job_completed' | 'job_failed';
  job_id: string;
  data: {
    total_hashes?: number;
    cracked?: number;
    speed?: string;
    eta?: string;
    hash?: string;
    plaintext?: string;
    total_cracked?: number;
    error?: string;
  };
}

// ============================================================================
// Attack Surface Management (ASM) Types
// ============================================================================

export type AsmAlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AsmChangeType =
  | 'new_subdomain'
  | 'new_port'
  | 'port_closed'
  | 'certificate_change'
  | 'certificate_expiring'
  | 'technology_change'
  | 'ip_address_change'
  | 'asset_removed'
  | 'service_change'
  | 'shadow_it_detected';

export type AsmTimelineEventType =
  | 'monitor_run'
  | 'baseline_created'
  | 'change_detected'
  | 'change_acknowledged'
  | 'monitor_enabled'
  | 'monitor_disabled';

export type AsmRiskFactorType =
  | 'exposed_ports'
  | 'technology_stack'
  | 'ssl_tls'
  | 'internet_exposure'
  | 'visibility'
  | 'authorization'
  | 'vulnerability_presence'
  | 'service_age';

/** Asset discovery configuration for ASM */
export interface AsmDiscoveryConfig {
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_service_detection: boolean;
  enable_ssl_analysis: boolean;
  enable_tech_detection: boolean;
  port_range?: string;
  threads?: number;
  dns_resolvers: string[];
}

/** Alert configuration for change detection */
export interface AsmAlertConfig {
  alert_on_new_subdomain: boolean;
  alert_on_new_port: boolean;
  alert_on_cert_change: boolean;
  alert_on_tech_change: boolean;
  alert_on_ip_change: boolean;
  alert_on_asset_removed: boolean;
  alert_on_shadow_it: boolean;
  min_severity: AsmAlertSeverity;
  notification_channels: string[];
}

/** ASM Monitor configuration */
export interface AsmMonitor {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  domains: string[];
  discovery_config: AsmDiscoveryConfig;
  schedule: string;
  alert_config: AsmAlertConfig;
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
  updated_at: string;
}

/** Port information in baseline */
export interface AsmBaselinePort {
  port: number;
  protocol: string;
  service?: string;
  version?: string;
}

/** SSL information in baseline */
export interface AsmBaselineSslInfo {
  issuer: string;
  subject: string;
  valid_from: string;
  valid_until: string;
  fingerprint: string;
}

/** Individual asset in a baseline */
export interface AsmBaselineAsset {
  hostname: string;
  ip_addresses: string[];
  ports: AsmBaselinePort[];
  technologies: string[];
  ssl_info?: AsmBaselineSslInfo;
  first_seen: string;
  last_seen: string;
}

/** Summary statistics for a baseline */
export interface AsmBaselineSummary {
  total_assets: number;
  total_ports: number;
  total_services: number;
  assets_with_ssl: number;
  unique_technologies: number;
}

/** Baseline snapshot of discovered assets */
export interface AsmBaseline {
  id: string;
  monitor_id: string;
  assets: AsmBaselineAsset[];
  summary: AsmBaselineSummary;
  is_active: boolean;
  created_at: string;
}

/** Detailed information about a change */
export interface AsmChangeDetails {
  description: string;
  old_value?: string;
  new_value?: string;
  affected_ports: number[];
  metadata: Record<string, string>;
}

/** A detected change in the attack surface */
export interface AsmChange {
  id: string;
  monitor_id: string;
  baseline_id: string;
  change_type: AsmChangeType;
  severity: AsmAlertSeverity;
  hostname: string;
  details: AsmChangeDetails;
  detected_at: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

/** Authorized asset pattern for shadow IT detection */
export interface AsmAuthorizedAsset {
  id: string;
  user_id: string;
  hostname_pattern: string;
  ip_ranges: string[];
  description?: string;
  created_at: string;
}

/** Individual risk factor contributing to overall score */
export interface AsmRiskFactor {
  factor_type: AsmRiskFactorType;
  weight: number;
  score: number;
  description: string;
  details?: string;
}

/** Risk score for an asset */
export interface AsmAssetRiskScore {
  id: string;
  asset_id?: string;
  hostname: string;
  overall_score: number;
  factors: AsmRiskFactor[];
  calculated_at: string;
}

/** ASM Dashboard statistics */
export interface AsmDashboard {
  total_monitors: number;
  active_monitors: number;
  total_assets: number;
  total_changes_24h: number;
  total_changes_7d: number;
  critical_changes: number;
  unacknowledged_changes: number;
  average_risk_score: number;
  high_risk_assets: number;
  shadow_it_count: number;
  next_scan_at?: string;
  last_scan_at?: string;
}

/** Timeline event for visualization */
export interface AsmTimelineEvent {
  timestamp: string;
  event_type: AsmTimelineEventType;
  monitor_id: string;
  monitor_name: string;
  description: string;
  severity?: AsmAlertSeverity;
  change_id?: string;
}

/** Monitor execution result */
export interface AsmMonitorRunResult {
  monitor_id: string;
  baseline_id: string;
  assets_discovered: number;
  changes_detected: number;
  duration_secs: number;
  started_at: string;
  completed_at: string;
  error?: string;
}

/** Create monitor request */
export interface CreateAsmMonitorRequest {
  name: string;
  description?: string;
  domains: string[];
  discovery_config?: Partial<AsmDiscoveryConfig>;
  schedule: string;
  alert_config?: Partial<AsmAlertConfig>;
}

/** Update monitor request */
export interface UpdateAsmMonitorRequest {
  name?: string;
  description?: string;
  domains?: string[];
  discovery_config?: Partial<AsmDiscoveryConfig>;
  schedule?: string;
  alert_config?: Partial<AsmAlertConfig>;
  enabled?: boolean;
}

/** Create authorized asset request */
export interface CreateAsmAuthorizedAssetRequest {
  hostname_pattern: string;
  ip_ranges?: string[];
  description?: string;
}

/** Acknowledge change request */
export interface AsmAcknowledgeChangeRequest {
  notes?: string;
}

/** Changes query parameters */
export interface AsmChangesQuery {
  change_type?: AsmChangeType;
  severity?: AsmAlertSeverity;
  acknowledged?: boolean;
  limit?: number;
  offset?: number;
}

// =============================================================================
// Purple Team Types
// =============================================================================

export type ExerciseStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type AttackStatus = 'executed' | 'blocked' | 'failed' | 'skipped';
export type PurpleDetectionStatus = 'detected' | 'partially_detected' | 'not_detected' | 'pending';
export type GapSeverity = 'critical' | 'high' | 'medium' | 'low';
export type GapStatus = 'open' | 'in_progress' | 'remediated' | 'accepted';
export type RecommendationType = 'new_rule' | 'rule_tuning' | 'data_source' | 'log_enhancement' | 'integration';

// Purple Team specific tactic type (string union for ease of use)
export type PurpleTactic =
  | 'Reconnaissance'
  | 'ResourceDevelopment'
  | 'InitialAccess'
  | 'Execution'
  | 'Persistence'
  | 'PrivilegeEscalation'
  | 'DefenseEvasion'
  | 'CredentialAccess'
  | 'Discovery'
  | 'LateralMovement'
  | 'Collection'
  | 'CommandAndControl'
  | 'Exfiltration'
  | 'Impact';

export interface PurpleMitreTechnique {
  id: string;
  name: string;
  tactic: PurpleTactic;
  description: string;
  data_sources: string[];
  is_subtechnique: boolean;
  parent_id?: string;
}

export interface PurpleAttackConfig {
  technique_id: string;
  technique_name: string;
  tactic: PurpleTactic;
  attack_type: string;
  target: string;
  parameters: Record<string, string>;
  enabled: boolean;
}

export interface PurpleTeamExercise {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  siem_integration_id?: string;
  attack_configs: PurpleAttackConfig[];
  detection_timeout_secs: number;
  status: ExerciseStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface MatchedAlert {
  alert_id: string;
  rule_name: string;
  severity: string;
  timestamp: string;
  description: string;
}

export interface DetectionDetails {
  alerts_matched: MatchedAlert[];
  log_sources: string[];
  detection_time?: string;
  confidence: number;
}

export interface PurpleAttackResult {
  id: string;
  exercise_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  attack_type: string;
  target: string;
  attack_status: AttackStatus;
  detection_status: PurpleDetectionStatus;
  detection_details?: DetectionDetails;
  time_to_detect_ms?: number;
  executed_at: string;
  error_message?: string;
}

export interface TacticCoverage {
  tactic_id: string;
  tactic_name: string;
  total_techniques: number;
  detected: number;
  partially_detected: number;
  not_detected: number;
  coverage_percent: number;
}

export interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tests_run: number;
  detected: number;
  partially_detected: number;
  not_detected: number;
  coverage_percent: number;
  avg_time_to_detect_ms?: number;
}

export interface DetectionCoverage {
  id: string;
  exercise_id: string;
  by_tactic: Record<string, TacticCoverage>;
  by_technique: Record<string, TechniqueCoverage>;
  overall_score: number;
  calculated_at: string;
}

export interface DetectionRecommendation {
  recommendation_type: RecommendationType;
  title: string;
  description: string;
  sigma_rule?: string;
  splunk_query?: string;
  elastic_query?: string;
  data_sources_required: string[];
  priority: number;
}

export interface PurpleDetectionGap {
  id: string;
  exercise_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  severity: GapSeverity;
  recommendations: DetectionRecommendation[];
  status: GapStatus;
  created_at: string;
  remediated_at?: string;
}

export interface MatrixCell {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tested: boolean;
  detection_status?: PurpleDetectionStatus;
  coverage_percent: number;
  gap_severity?: GapSeverity;
}

export interface AttackMatrix {
  tactics: string[];
  cells: Record<string, MatrixCell[]>;
  overall_coverage: number;
  tested_techniques: number;
  total_techniques: number;
}

export interface ExerciseSummary {
  id: string;
  name: string;
  status: ExerciseStatus;
  attacks_run: number;
  detection_rate: number;
  gaps_found: number;
  created_at: string;
  completed_at?: string;
}

export interface PurpleTeamDashboard {
  total_exercises: number;
  running_exercises: number;
  completed_exercises: number;
  total_attacks_run: number;
  detection_rate: number;
  overall_coverage: number;
  avg_time_to_detect_ms: number;
  open_gaps: number;
  critical_gaps: number;
  coverage_by_tactic: TacticCoverage[];
  recent_exercises: ExerciseSummary[];
}

export interface TacticInfo {
  id: string;
  name: string;
}

export interface AttackParameterInfo {
  name: string;
  param_type: string;
  required: boolean;
  description: string;
  default_value?: string;
}

export interface AvailableAttack {
  technique_id: string;
  technique_name: string;
  tactic: string;
  attack_type: string;
  description: string;
  parameters: AttackParameterInfo[];
}

export interface PurpleTeamReport {
  exercise: PurpleTeamExercise;
  results: PurpleAttackResult[];
  coverage?: DetectionCoverage;
  gaps: PurpleDetectionGap[];
  generated_at: string;
}

export interface AttackTypeMapping {
  attack_type: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface CreateExerciseRequest {
  name: string;
  description?: string;
  siem_integration_id?: string;
  attack_configs: PurpleAttackConfig[];
  detection_timeout_secs?: number;
}

export interface UpdateGapStatusRequest {
  status: GapStatus;
  notes?: string;
}

// =============================================================================
// Organization & Multi-tenancy Types
// =============================================================================

export type OrgRole = 'owner' | 'admin' | 'member';
export type TeamRole = 'lead' | 'member';
export type ScopeType = 'organization' | 'department' | 'team' | 'global';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  role: OrgRole;
  member_count: number;
  team_count: number;
}

export interface CreateOrganizationRequest {
  name: string;
  slug: string;
  description?: string;
}

export interface UpdateOrganizationRequest {
  name?: string;
  description?: string;
  is_active?: boolean;
}

export interface Department {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description?: string;
  parent_department_id?: string;
  manager_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateDepartmentRequest {
  name: string;
  slug: string;
  description?: string;
  parent_department_id?: string;
  manager_user_id?: string;
}

export interface UpdateDepartmentRequest {
  name?: string;
  description?: string;
  parent_department_id?: string;
  manager_user_id?: string;
}

export interface Team {
  id: string;
  department_id: string;
  name: string;
  slug: string;
  description?: string;
  team_lead_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateTeamRequest {
  name: string;
  slug: string;
  description?: string;
  team_lead_user_id?: string;
}

export interface UpdateTeamRequest {
  name?: string;
  description?: string;
  team_lead_user_id?: string;
}

export interface TeamMember {
  user_id: string;
  username: string;
  email: string;
  role: TeamRole;
  joined_at: string;
}

export interface OrgMember {
  user_id: string;
  username: string;
  email: string;
  role: OrgRole;
  joined_at: string;
}

export interface AddOrgMemberRequest {
  user_id?: string;
  email?: string;
  role: OrgRole;
}

export interface AddTeamMemberRequest {
  user_id: string;
  role: TeamRole;
}

export interface RoleTemplate {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  icon?: string;
  color?: string;
  is_system: boolean;
  permissions: string[];
  created_at: string;
}

export interface CustomRole {
  id: string;
  organization_id: string;
  name: string;
  display_name: string;
  description?: string;
  is_active: boolean;
  based_on_template_id?: string;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateCustomRoleRequest {
  name: string;
  display_name: string;
  description?: string;
  based_on_template_id?: string;
  permissions: string[];
}

export interface UpdateCustomRoleRequest {
  display_name?: string;
  description?: string;
  is_active?: boolean;
  permissions?: string[];
}

export interface UserRoleAssignment {
  id: string;
  user_id: string;
  role_type: 'template' | 'custom';
  role_id: string;
  role_name: string;
  scope_type?: ScopeType;
  scope_id?: string;
  scope_name?: string;
  assigned_at: string;
  assigned_by?: string;
  expires_at?: string;
  is_active: boolean;
}

export interface AssignRoleRequest {
  user_id: string;
  role_type: 'template' | 'custom';
  role_id: string;
  scope_type?: ScopeType;
  scope_id?: string;
  expires_at?: string;
}

export interface Permission {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  category: string;
  resource_type?: string;
}

export interface EffectivePermissions {
  user_id: string;
  permissions: string[];
  roles: UserRoleAssignment[];
  is_org_owner: boolean;
  is_org_admin: boolean;
}

export interface PermissionCheck {
  permission: string;
  granted: boolean;
  source?: string;
}

// Organization Quotas
export interface OrganizationQuotas {
  id: string;
  organization_id: string;
  max_users: number;
  max_scans_per_day: number;
  max_concurrent_scans: number;
  max_assets: number;
  max_reports_per_month: number;
  max_storage_mb: number;
  max_api_requests_per_hour: number;
  max_scheduled_scans: number;
  max_teams: number;
  created_at: string;
  updated_at: string;
}

export interface UpdateQuotasRequest {
  max_users?: number;
  max_scans_per_day?: number;
  max_concurrent_scans?: number;
  max_assets?: number;
  max_reports_per_month?: number;
  max_storage_mb?: number;
  max_api_requests_per_hour?: number;
  max_scheduled_scans?: number;
  max_teams?: number;
}

export interface QuotaUsage {
  quota_type: string;
  current_value: number;
  max_value: number;
  percentage: number;
  period_start?: string;
  period_end?: string;
}

export interface OrganizationQuotaUsage {
  organization_id: string;
  usages: QuotaUsage[];
  updated_at: string;
}
