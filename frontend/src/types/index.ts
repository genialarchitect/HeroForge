export type UserRole = 'admin' | 'user' | 'auditor' | 'viewer';

export interface User {
  id: string;
  username: string;
  email: string;
  roles?: UserRole[]; // Added for admin console
  is_active?: boolean; // Added for admin console
  created_at?: string;
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
  } | null;
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
  created_at: string;
  updated_at: string;
}

export interface UpdateNotificationSettingsRequest {
  email_on_scan_complete?: boolean;
  email_on_critical_vuln?: boolean;
  email_address?: string;
}
