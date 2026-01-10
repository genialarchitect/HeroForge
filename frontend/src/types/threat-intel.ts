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
