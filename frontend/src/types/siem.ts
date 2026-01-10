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
