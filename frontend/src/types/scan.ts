// ============================================================================
// Scan Types - Scan results, configuration, scheduling, and comparison
// ============================================================================

import type { SslInfo } from './ssl';
import type { Vulnerability } from './vulnerability';

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

export interface CloneScanTemplateRequest {
  new_name?: string;
}

// Alias for backward compatibility
export type CloneTemplateRequest = CloneScanTemplateRequest;

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

// Scan Exclusions Types

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

// VPN Types

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
