export type UserRole = 'admin' | 'user' | 'auditor' | 'viewer';

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
  action: string;
  target_type?: string;
  target_id?: string;
  details?: string;
  ip_address?: string;
  created_at: string;
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
}

export interface BulkAssignVulnerabilitiesRequest {
  vulnerability_ids: string[];
  assignee_id: string;
}

export interface VerifyVulnerabilityRequest {
  scan_id?: string;
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
export interface SiemSettings {
  id: string;
  user_id: string;
  siem_type: "syslog" | "splunk" | "elasticsearch";
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
  siem_type: "syslog" | "splunk" | "elasticsearch";
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

