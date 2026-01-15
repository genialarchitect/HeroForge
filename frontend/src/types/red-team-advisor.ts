// =============================================================================
// AI Red Team Advisor Types
// =============================================================================

/** AI-generated red team recommendation */
export interface AiRedTeamRecommendation {
  id: string;
  topology_id?: string;
  scan_id?: string;
  engagement_id?: string;
  user_id: string;
  target_node_id: string;
  target_ip?: string;
  target_hostname?: string;
  target_type: string;
  action_type: RecommendationActionType;
  action_category: RecommendationActionCategory;
  title: string;
  description: string;
  rationale?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  mitre_tactic?: string;
  risk_level: RecommendationRiskLevel;
  priority: number;
  estimated_time_minutes?: number;
  prerequisites?: string;
  command_template?: string;
  tool_name?: string;
  status: RecommendationStatus;
  accepted_at?: string;
  rejected_at?: string;
  executed_at?: string;
  completed_at?: string;
  execution_result?: string;
  execution_output?: string;
  created_at: string;
  updated_at?: string;
}

/** Recommendation status */
export type RecommendationStatus =
  | 'pending'
  | 'accepted'
  | 'rejected'
  | 'running'
  | 'completed'
  | 'failed';

/** Risk level for recommendations */
export type RecommendationRiskLevel =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info';

/** Action types */
export type RecommendationActionType =
  | 'scan'
  | 'exploit'
  | 'enumerate'
  | 'credential_test'
  | 'lateral_movement'
  | 'persistence'
  | 'exfiltration';

/** Action categories (MITRE ATT&CK tactics) */
export type RecommendationActionCategory =
  | 'reconnaissance'
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'exfiltration'
  | 'impact';

/** AI analysis session */
export interface AiRedTeamSession {
  id: string;
  topology_id?: string;
  scan_id?: string;
  engagement_id?: string;
  user_id: string;
  analysis_type: string;
  prompt_used?: string;
  ai_model: string;
  recommendations_count: number;
  high_priority_count: number;
  tokens_used?: number;
  analysis_duration_ms?: number;
  status: string;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

/** Recommendation execution record */
export interface AiRedTeamExecution {
  id: string;
  recommendation_id: string;
  user_id: string;
  execution_type: string;
  tool_used?: string;
  command_executed?: string;
  target_ip?: string;
  target_port?: number;
  status: string;
  exit_code?: number;
  stdout?: string;
  stderr?: string;
  findings_count?: number;
  vulnerabilities_found?: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
}

/** Request to analyze topology */
export interface AnalyzeTopologyRequest {
  topology: TopologyForAnalysis;
  topology_id?: string;
  scan_id?: string;
  engagement_id?: string;
  analysis_type?: string;
  focus_areas?: string[];
  exclude_node_ids?: string[];
  max_recommendations?: number;
}

/** Topology data for AI analysis */
export interface TopologyForAnalysis {
  nodes: TopologyNodeForAnalysis[];
  edges: TopologyEdgeForAnalysis[];
  metadata?: TopologyMetadata;
}

/** Topology node for analysis */
export interface TopologyNodeForAnalysis {
  id: string;
  label: string;
  device_type: string;
  security_zone: string;
  ip_address?: string;
  hostname?: string;
  os?: string;
  compliance_status: string;
  vulnerabilities?: number;
  open_ports?: number[];
  services?: string[];
}

/** Topology edge for analysis */
export interface TopologyEdgeForAnalysis {
  source: string;
  target: string;
  protocol?: string;
  port?: number;
  encrypted?: boolean;
  data_classification?: string;
}

/** Topology metadata */
export interface TopologyMetadata {
  name?: string;
  organization?: string;
  industry?: string;
  compliance_frameworks?: string[];
}

/** Red Team AI Analysis result */
export interface RedTeamAnalysisResult {
  session_id: string;
  recommendations: AiRedTeamRecommendation[];
  summary: AnalysisSummary;
}

/** Analysis summary */
export interface AnalysisSummary {
  total_recommendations: number;
  high_priority_count: number;
  critical_targets: string[];
  suggested_attack_path?: string[];
  key_findings: string[];
}

/** Update recommendation status request */
export interface UpdateRecommendationStatusRequest {
  status: RecommendationStatus;
}

/** Execute recommendation request */
export interface ExecuteRecommendationRequest {
  custom_target_ip?: string;
  custom_target_port?: number;
  custom_options?: string;
}

/** Recommendations summary */
export interface RecommendationsSummary {
  total: number;
  pending: number;
  accepted: number;
  rejected: number;
  running: number;
  completed: number;
  failed: number;
  by_risk_level: RecommendationRiskLevelCount[];
  by_category: RecommendationCategoryCount[];
  by_target: RecommendationTargetCount[];
}

/** Count by risk level for recommendations */
export interface RecommendationRiskLevelCount {
  risk_level: string;
  count: number;
}

/** Count by category for recommendations */
export interface RecommendationCategoryCount {
  category: string;
  count: number;
}

/** Count by target for recommendations */
export interface RecommendationTargetCount {
  target_node_id: string;
  target_ip?: string;
  target_hostname?: string;
  count: number;
}

/** Query params for getting recommendations */
export interface GetRecommendationsQuery {
  topology_id?: string;
  scan_id?: string;
  status?: RecommendationStatus;
}

/** Bulk action result */
export interface BulkActionResult {
  accepted_count?: number;
  rejected_count?: number;
  message: string;
}
