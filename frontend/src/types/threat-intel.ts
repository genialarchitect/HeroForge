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
// Attack Path AI Interpretation Types
// ============================================================================

export interface InterpretAttackPathRequest {
  force?: boolean;
}

export interface InterpNarrativeStep {
  step: number;
  action: string;
  rationale: string;
  technical_detail: string;
  vulnerabilities: string[];
}

export interface InterpAttackNarrative {
  summary: string;
  attack_steps: InterpNarrativeStep[];
  attacker_perspective: string;
  consequence_description: string;
  complexity: string;
}

export interface InterpMitreTactic {
  id: string;
  name: string;
  description: string;
  url: string;
}

export interface InterpMitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  relevance: string;
  url: string;
}

export interface InterpKillChainStage {
  stage: number;
  name: string;
  description: string;
  techniques: string[];
}

export interface InterpMitreMapping {
  tactics: InterpMitreTactic[];
  techniques: InterpMitreTechnique[];
  kill_chain_stages: InterpKillChainStage[];
}

export interface InterpDataRiskItem {
  data_type: string;
  classification: string;
  risk: string;
}

export interface InterpFinancialImpact {
  min_estimate_usd: number;
  max_estimate_usd: number;
  cost_factors: string[];
  confidence: string;
}

export interface InterpReputationalRisk {
  level: string;
  description: string;
  potential_headlines: string[];
}

export interface InterpBusinessImpact {
  level: string;
  description: string;
  affected_functions: string[];
  data_at_risk: InterpDataRiskItem[];
  financial_impact?: InterpFinancialImpact;
  regulatory_implications: string[];
  reputational_risk: InterpReputationalRisk;
}

export interface InterpBlockingPoint {
  step: number;
  action: string;
  effectiveness: string;
  implementation_effort: string;
  priority: number;
  controls: string[];
}

export interface InterpRiskFactor {
  name: string;
  weight: number;
  score: number;
  description: string;
}

export interface InterpRiskAssessment {
  risk_score: number;
  exploitation_probability: number;
  impact_score: number;
  estimated_time_to_exploit: string;
  risk_factors: InterpRiskFactor[];
  recommendation: string;
}

export interface AttackPathInterpretation {
  path_id: string;
  generated_at: string;
  narrative: InterpAttackNarrative;
  mitre_mapping: InterpMitreMapping;
  business_impact: InterpBusinessImpact;
  blocking_points: InterpBlockingPoint[];
  risk_assessment: InterpRiskAssessment;
}
