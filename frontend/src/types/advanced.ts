// =============================================================================
// Advanced Types - Fuzzing, UEBA, AI, SSO, CI/CD, Container, IaC, Workflows, Purple Team, Organizations
// =============================================================================

import type { UserRole } from './common';

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
// AI Configuration Types (LLM Provider Settings)
// ============================================================================

export type LLMProviderType = 'anthropic' | 'ollama' | 'openai';

export interface AiConfigurationResponse {
  provider: string;
  model: string;
  ollama_base_url: string | null;
  has_anthropic_key: boolean;
  has_openai_key: boolean;
  fallback_provider: string | null;
  auto_reports: boolean;
  auto_remediation: boolean;
  updated_at: string | null;
}

export interface UpdateAiConfigurationRequest {
  provider: string;
  model?: string;
  anthropic_api_key?: string;
  openai_api_key?: string;
  ollama_base_url?: string;
  ollama_model?: string;
  fallback_provider?: string;
  auto_reports?: boolean;
  auto_remediation?: boolean;
}

export interface ProviderStatusResponse {
  provider: string;
  name: string;
  model: string;
  available: boolean;
  streaming: boolean;
  max_context_tokens: number;
}

export interface TestConnectionResponse {
  success: boolean;
  message: string;
  provider: string;
  model: string;
  response_time_ms: number | null;
}

export interface ModelInfo {
  id: string;
  name: string;
  description: string | null;
}

export interface AvailableModelsResponse {
  anthropic: ModelInfo[];
  ollama: ModelInfo[];
  openai: ModelInfo[];
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
export type OrgTeamRole = 'lead' | 'member';
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
  role: OrgTeamRole;
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
  role: OrgTeamRole;
}

export interface RoleTemplate {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  icon?: string;
  color?: string;
  is_system: boolean;
  permissions?: string[];
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

// ============================================================================
// Green Team - SOAR Types
// ============================================================================

// Case Management Types
export type CaseSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed';
export type CasePriority = 'low' | 'medium' | 'high' | 'urgent';
export type CaseType = 'incident' | 'investigation' | 'threat_hunt' | 'vulnerability' | 'compliance' | 'other';
export type CaseTlp = 'white' | 'green' | 'amber' | 'red';
export type TaskStatus = 'pending' | 'in_progress' | 'completed' | 'blocked' | 'cancelled';
export type TimelineEventType = 'created' | 'status_change' | 'assignment' | 'comment' | 'evidence' | 'task' | 'playbook' | 'resolution' | 'reopened';

export interface SoarCase {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  severity: CaseSeverity;
  status: CaseStatus;
  priority: CasePriority;
  case_type: CaseType;
  assignee_id: string | null;
  source: string | null;
  source_ref: string | null;
  tlp: CaseTlp;
  tags: string[];
  resolution: string | null;
  resolution_time_hours: number | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
}

export interface CreateCaseRequest {
  title: string;
  description?: string;
  severity: CaseSeverity;
  case_type: CaseType;
  priority: CasePriority;
  tlp: CaseTlp;
}

export interface UpdateCaseRequest {
  status?: CaseStatus;
  assignee_id?: string;
  resolution?: string;
  severity?: CaseSeverity;
  priority?: CasePriority;
}

export interface CaseTask {
  id: string;
  case_id: string;
  title: string;
  description: string | null;
  status: TaskStatus;
  priority: CasePriority;
  assignee_id: string | null;
  due_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface CreateCaseTaskRequest {
  title: string;
  description?: string;
  priority?: CasePriority;
}

export interface CaseComment {
  id: string;
  case_id: string;
  user_id: string;
  content: string;
  is_internal: boolean;
  created_at: string;
}

export interface CreateCaseCommentRequest {
  content: string;
  is_internal?: boolean;
}

export interface CaseTimelineEvent {
  id: string;
  case_id: string;
  event_type: TimelineEventType;
  event_data: Record<string, unknown>;
  user_id: string | null;
  created_at: string;
}

// Playbook Types
export type PlaybookCategory = 'incident_response' | 'threat_hunting' | 'compliance' | 'enrichment' | 'remediation' | 'notification' | 'custom';
export type PlaybookTriggerType = 'manual' | 'alert' | 'schedule' | 'webhook' | 'ioc' | 'event';
export type PlaybookRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'waiting_approval';

export interface PlaybookStep {
  id: string;
  name: string;
  action: Record<string, unknown>;
  condition?: Record<string, unknown>;
  on_success?: string;
  on_failure?: string;
  timeout_seconds: number;
  retry_count?: number;
}

export interface Playbook {
  id: string;
  name: string;
  description: string | null;
  category: PlaybookCategory;
  trigger: Record<string, unknown>;
  steps: PlaybookStep[];
  is_active: boolean;
  is_template: boolean;
  marketplace_id: string | null;
  version: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CreatePlaybookRequest {
  name: string;
  description?: string;
  category: string;
  trigger_type: string;
  steps: Array<{
    id: string;
    name: string;
    action: Record<string, unknown>;
    timeout_seconds: number;
  }>;
}

export interface PlaybookRun {
  id: string;
  playbook_id: string;
  trigger_type: string;
  trigger_source: string | null;
  status: PlaybookRunStatus;
  current_step: number;
  total_steps: number;
  input_data: Record<string, unknown> | null;
  output_data: Record<string, unknown> | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
}

// IOC Feed Types
export type IocFeedType = 'stix' | 'csv' | 'json' | 'taxii' | 'misp' | 'openioc' | 'custom';

export interface IocFeed {
  id: string;
  name: string;
  description: string | null;
  feed_type: IocFeedType;
  url: string;
  api_key: string | null;
  poll_interval_minutes: number;
  is_active: boolean;
  last_poll_at: string | null;
  last_poll_status: string | null;
  ioc_count: number;
  created_at: string;
}

export interface CreateIocFeedRequest {
  name: string;
  feed_type: string;
  url: string;
  poll_interval_minutes: number;
}

// Metrics Types
export interface MetricsOverview {
  total_cases: number;
  open_cases: number;
  resolved_today: number;
  avg_mttd_minutes: number;
  avg_mttr_minutes: number;
  sla_compliance_rate: number;
  playbooks_executed: number;
  automation_rate: number;
}

// ==================== Fuzzing Types ====================

export type FuzzTargetType = 'protocol' | 'http' | 'file' | 'api' | 'binary';
export type FuzzerType = 'mutation' | 'generation' | 'grammar' | 'template';
export type FuzzingCampaignStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed';
export type CrashType = 'segfault' | 'heap_overflow' | 'stack_overflow' | 'use_after_free' | 'double_free' | 'null_deref' | 'assertion' | 'timeout' | 'unknown';
export type Exploitability = 'high' | 'medium' | 'low' | 'unknown';
export type MutationStrategy = 'bit_flip' | 'byte_flip' | 'arithmetic' | 'interesting_values' | 'havoc' | 'splice' | 'dictionary';

export interface FuzzingCampaign {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  target_type: FuzzTargetType;
  fuzzer_type: FuzzerType;
  target_config: FuzzTargetConfig;
  fuzzer_config: FuzzerConfig;
  status: FuzzingCampaignStatus;
  iterations: number;
  crashes_found: number;
  unique_crashes: number;
  coverage_percent: number | null;
  last_crash_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface FuzzTargetConfig {
  // Protocol target
  host?: string;
  port?: number;
  protocol?: 'tcp' | 'udp';
  // HTTP target
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  // File target
  file_path?: string;
  command?: string;
  args?: string[];
}

export interface FuzzerConfig {
  max_iterations?: number;
  timeout_ms?: number;
  mutation_strategies?: MutationStrategy[];
  dictionary?: string[];
  seed_inputs?: string[];
  template_id?: string;
  grammar_rules?: string;
}

export interface FuzzingCrash {
  id: string;
  campaign_id: string;
  crash_type: CrashType;
  crash_hash: string;
  input_data: string; // base64 encoded
  output: string | null;
  stack_trace: string | null;
  registers: Record<string, string> | null;
  exploitability: Exploitability;
  iteration: number;
  is_unique: boolean;
  is_minimized: boolean;
  minimized_input: string | null;
  notes: string | null;
  created_at: string;
}

export interface FuzzingCoverage {
  campaign_id: string;
  edge_coverage: number;
  block_coverage: number;
  total_edges: number;
  total_blocks: number;
  coverage_percent: number;
  new_edges_found: number;
  updated_at: string;
}

export interface FuzzingTemplate {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  target_type: FuzzTargetType;
  template_data: string; // JSON
  is_public: boolean;
  created_at: string;
  updated_at: string;
}

export interface FuzzingSeed {
  id: string;
  campaign_id: string;
  data: string; // base64 encoded
  source: 'initial' | 'corpus' | 'crash';
  coverage_contribution: number | null;
  created_at: string;
}

export interface FuzzingStats {
  total_campaigns: number;
  active_campaigns: number;
  total_crashes: number;
  unique_crashes: number;
  total_iterations: number;
  avg_coverage: number;
  crashes_by_type: Record<string, number>;
  crashes_by_exploitability: Record<string, number>;
}

export interface FuzzingDictionary {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  entries: string[];
  created_at: string;
}

export interface CreateFuzzingCampaignRequest {
  name: string;
  description?: string;
  target_type: FuzzTargetType;
  fuzzer_type: FuzzerType;
  target_config: FuzzTargetConfig;
  fuzzer_config: FuzzerConfig;
}

export interface UpdateFuzzingCampaignRequest {
  name?: string;
  description?: string;
  fuzzer_config?: FuzzerConfig;
}

export interface CreateFuzzingTemplateRequest {
  name: string;
  description?: string;
  target_type: FuzzTargetType;
  template_data: string;
  is_public?: boolean;
}

export interface CreateFuzzingDictionaryRequest {
  name: string;
  description?: string;
  entries: string[];
}

// =============================================================================
// UEBA (User Entity Behavior Analytics) Types
// =============================================================================

export type UebaEntityType = 'user' | 'host' | 'service_account' | 'application' | 'device' | 'ip_address';

export type UebaRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type UebaActivityType =
  | 'login'
  | 'logout'
  | 'failed_login'
  | 'file_access'
  | 'file_modify'
  | 'file_delete'
  | 'privilege_use'
  | 'privilege_escalation'
  | 'network_connection'
  | 'email_send'
  | 'email_receive'
  | 'data_download'
  | 'data_upload'
  | 'process_execution'
  | 'service_access'
  | 'admin_action'
  | 'config_change'
  | 'policy_violation'
  | 'other';

export type UebaAnomalyType =
  | 'impossible_travel'
  | 'unusual_login_time'
  | 'unusual_login_location'
  | 'excessive_failed_logins'
  | 'unusual_data_access'
  | 'large_data_transfer'
  | 'unusual_privilege_use'
  | 'service_account_abuse'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'off_hours_activity'
  | 'unusual_network_activity'
  | 'new_device_login'
  | 'suspicious_process_execution'
  | 'policy_violation'
  | 'baseline_deviation'
  | 'rapid_activity_burst'
  | 'dormant_account_activity'
  | 'credential_sharing'
  | 'other';

export type UebaAnomalyStatus =
  | 'new'
  | 'acknowledged'
  | 'investigating'
  | 'confirmed'
  | 'false_positive'
  | 'resolved'
  | 'suppressed';

export interface UebaEntity {
  id: string;
  user_id: string;
  entity_type: string;
  entity_id: string;
  display_name?: string;
  department?: string;
  role?: string;
  manager?: string;
  location?: string;
  peer_group_id?: string;
  risk_score: number;
  risk_level: string;
  baseline_data?: string;
  tags?: string;
  last_activity_at?: string;
  first_seen_at?: string;
  is_active: boolean;
  is_privileged: boolean;
  is_service_account: boolean;
  metadata?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateUebaEntityRequest {
  entity_type: string;
  entity_id: string;
  display_name?: string;
  department?: string;
  role?: string;
  manager?: string;
  location?: string;
  is_privileged?: boolean;
  is_service_account?: boolean;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface UpdateUebaEntityRequest {
  display_name?: string;
  department?: string;
  role?: string;
  manager?: string;
  location?: string;
  peer_group_id?: string;
  is_privileged?: boolean;
  is_service_account?: boolean;
  is_active?: boolean;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface UebaPeerGroup {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  criteria: string;
  member_count: number;
  baseline_metrics?: string;
  is_auto_generated: boolean;
  last_updated_at?: string;
  created_at: string;
  updated_at: string;
}

export interface UebaPeerGroupCriteria {
  department?: string;
  role?: string;
  location?: string;
  is_privileged?: boolean;
  entity_type?: string;
  tags?: string[];
}

export interface CreateUebaPeerGroupRequest {
  name: string;
  description?: string;
  criteria: UebaPeerGroupCriteria;
}

export interface UpdateUebaPeerGroupRequest {
  name?: string;
  description?: string;
  criteria?: UebaPeerGroupCriteria;
}

export interface UebaActivity {
  id: string;
  entity_id: string;
  activity_type: string;
  source_ip?: string;
  source_location?: string;
  source_country?: string;
  source_city?: string;
  source_lat?: number;
  source_lon?: number;
  destination?: string;
  destination_type?: string;
  action?: string;
  resource?: string;
  resource_type?: string;
  status?: string;
  risk_contribution: number;
  is_anomalous: boolean;
  anomaly_reasons?: string;
  raw_event?: string;
  event_source?: string;
  timestamp: string;
  created_at: string;
}

export interface RecordUebaActivityRequest {
  entity_id: string;
  activity_type: string;
  source_ip?: string;
  source_country?: string;
  source_city?: string;
  source_lat?: number;
  source_lon?: number;
  destination?: string;
  destination_type?: string;
  action?: string;
  resource?: string;
  resource_type?: string;
  status?: string;
  raw_event?: Record<string, unknown>;
  event_source?: string;
  timestamp?: string;
}

export interface UebaAnomaly {
  id: string;
  entity_id: string;
  anomaly_type: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  baseline_deviation?: number;
  confidence?: number;
  status: string;
  priority: string;
  assigned_to?: string;
  related_activities?: string;
  related_anomalies?: string;
  mitre_techniques?: string;
  risk_score_impact: number;
  detected_at: string;
  acknowledged_at?: string;
  acknowledged_by?: string;
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
  false_positive: boolean;
  suppressed: boolean;
  suppression_reason?: string;
  created_at: string;
  updated_at: string;
}

export interface UpdateUebaAnomalyRequest {
  status?: string;
  priority?: string;
  assigned_to?: string;
  resolution_notes?: string;
  false_positive?: boolean;
  suppressed?: boolean;
  suppression_reason?: string;
}

export interface UebaSession {
  id: string;
  entity_id: string;
  session_id?: string;
  session_type: string;
  source_ip: string;
  source_country?: string;
  source_city?: string;
  source_lat?: number;
  source_lon?: number;
  source_asn?: string;
  source_isp?: string;
  user_agent?: string;
  device_type?: string;
  device_fingerprint?: string;
  auth_method?: string;
  auth_status: string;
  mfa_used: boolean;
  is_vpn: boolean;
  is_tor: boolean;
  is_proxy: boolean;
  risk_score: number;
  anomaly_flags?: string;
  started_at: string;
  ended_at?: string;
  duration_seconds?: number;
  created_at: string;
}

export interface RecordUebaSessionRequest {
  entity_id: string;
  session_id?: string;
  session_type: string;
  source_ip: string;
  source_country?: string;
  source_city?: string;
  source_lat?: number;
  source_lon?: number;
  user_agent?: string;
  device_fingerprint?: string;
  auth_method?: string;
  auth_status: string;
  mfa_used?: boolean;
}

export interface UebaBaseline {
  id: string;
  entity_id?: string;
  peer_group_id?: string;
  metric_name: string;
  metric_category: string;
  period: string;
  mean_value?: number;
  std_deviation?: number;
  min_value?: number;
  max_value?: number;
  median_value?: number;
  percentile_25?: number;
  percentile_75?: number;
  percentile_95?: number;
  percentile_99?: number;
  sample_count?: number;
  last_value?: number;
  trend?: string;
  is_stable: boolean;
  last_calculated_at?: string;
  created_at: string;
  updated_at: string;
}

export interface UebaRiskFactor {
  id: string;
  entity_id: string;
  factor_type: string;
  factor_value?: string;
  description?: string;
  weight: number;
  contribution?: number;
  source?: string;
  source_id?: string;
  valid_from: string;
  valid_until?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface UebaDashboardStats {
  total_entities: number;
  high_risk_entities: number;
  critical_risk_entities: number;
  total_anomalies: number;
  new_anomalies: number;
  open_anomalies: number;
  anomalies_by_type: { anomaly_type: string; count: number }[];
  risk_distribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  recent_anomalies: UebaAnomaly[];
  top_risk_entities: {
    entity_id: string;
    display_name?: string;
    entity_type: string;
    risk_score: number;
    risk_level: string;
  }[];
  activity_trend: { date: string; count: number }[];
}

export interface UebaEntityListResponse {
  entities: UebaEntity[];
  total: number;
  offset: number;
  limit: number;
}

export interface UebaActivityListResponse {
  activities: UebaActivity[];
  total: number;
  offset: number;
  limit: number;
}

export interface UebaAnomalyListResponse {
  anomalies: UebaAnomaly[];
  total: number;
  offset: number;
  limit: number;
}

export interface UebaSessionListResponse {
  sessions: UebaSession[];
  total: number;
  offset: number;
  limit: number;
}

export interface UebaBaselineListResponse {
  baselines: UebaBaseline[];
  total: number;
}

export interface UebaRiskFactorListResponse {
  risk_factors: UebaRiskFactor[];
  total: number;
}

export interface ProcessUebaActivityResponse {
  activity_id: string;
  is_anomalous: boolean;
  anomaly_reasons: string[];
  detected_anomalies: string[];
  risk_contribution: number;
}

export interface AddToWatchlistRequest {
  entity_id: string;
  reason: string;
  expires_at?: string;
}

// =============================================================================
// UEBA Advanced Behavioral Detection Types
// =============================================================================

export type UebaAdvancedDetectionType =
  | 'impossible_travel'
  | 'unusual_data_access'
  | 'off_hours_activity'
  | 'service_account_abuse'
  | 'lateral_movement'
  | 'data_exfiltration';

export type UebaDataSensitivity = 'public' | 'internal' | 'confidential' | 'restricted' | 'top_secret';

export interface UebaAdvancedStats {
  total_detections: number;
  detections_by_type: { detection_type: string; count: number }[];
  detections_by_severity: { severity: string; count: number }[];
  new_detections_24h: number;
  confirmed_detections: number;
  false_positives: number;
  detection_trend: { date: string; count: number }[];
  top_affected_entities: { entity_id: string; display_name?: string; count: number }[];
}

export interface UebaAdvancedDetection {
  id: string;
  user_id: string;
  entity_id: string;
  detection_type: string;
  severity: string;
  title: string;
  description: string;
  confidence: number;
  risk_score: number;
  evidence: string;
  source_data?: string;
  related_activities?: string;
  mitre_techniques?: string;
  geolocation_data?: string;
  status: string;
  assigned_to?: string;
  acknowledged_at?: string;
  acknowledged_by?: string;
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
  false_positive: boolean;
  suppressed: boolean;
  detection_rule_id?: string;
  detected_at: string;
  created_at: string;
  updated_at: string;
}

export interface UebaAdvancedDetectionListResponse {
  detections: UebaAdvancedDetection[];
  total: number;
  offset: number;
  limit: number;
}

export interface UebaBusinessHours {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  timezone: string;
  monday_start?: string;
  monday_end?: string;
  tuesday_start?: string;
  tuesday_end?: string;
  wednesday_start?: string;
  wednesday_end?: string;
  thursday_start?: string;
  thursday_end?: string;
  friday_start?: string;
  friday_end?: string;
  saturday_start?: string;
  saturday_end?: string;
  sunday_start?: string;
  sunday_end?: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateBusinessHoursRequest {
  name: string;
  description?: string;
  timezone: string;
  monday_start?: string;
  monday_end?: string;
  tuesday_start?: string;
  tuesday_end?: string;
  wednesday_start?: string;
  wednesday_end?: string;
  thursday_start?: string;
  thursday_end?: string;
  friday_start?: string;
  friday_end?: string;
  saturday_start?: string;
  saturday_end?: string;
  sunday_start?: string;
  sunday_end?: string;
  is_default?: boolean;
}

export interface UebaSensitiveResource {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  resource_type: string;
  resource_pattern: string;
  sensitivity_level: string;
  access_restrictions?: string;
  alert_on_access: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateSensitiveResourceRequest {
  name: string;
  description?: string;
  resource_type: string;
  resource_pattern: string;
  sensitivity_level: string;
  access_restrictions?: string[];
  alert_on_access?: boolean;
}

export interface UebaKnownVpn {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  ip_ranges: string;
  provider?: string;
  is_corporate: boolean;
  is_trusted: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateKnownVpnRequest {
  name: string;
  description?: string;
  ip_ranges: string[];
  provider?: string;
  is_corporate?: boolean;
  is_trusted?: boolean;
}

export interface UebaDetectionRule {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  detection_type: string;
  enabled: boolean;
  severity: string;
  conditions: string;
  thresholds: string;
  actions: string;
  cooldown_minutes: number;
  last_triggered_at?: string;
  trigger_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateDetectionRuleRequest {
  name: string;
  description?: string;
  detection_type: string;
  enabled?: boolean;
  severity: string;
  conditions: Record<string, unknown>;
  thresholds: Record<string, unknown>;
  actions: string[];
  cooldown_minutes?: number;
}

export interface UebaDataAccess {
  id: string;
  entity_id: string;
  resource_id?: string;
  resource_name: string;
  resource_type: string;
  sensitivity_level: string;
  access_type: string;
  source_ip?: string;
  source_location?: string;
  bytes_accessed?: number;
  is_anomalous: boolean;
  anomaly_score?: number;
  accessed_at: string;
  created_at: string;
}

export interface UebaDataAccessListResponse {
  accesses: UebaDataAccess[];
  total: number;
  offset: number;
  limit: number;
}

export interface RecordDataAccessRequest {
  entity_id: string;
  resource_id?: string;
  resource_name: string;
  resource_type: string;
  sensitivity_level: string;
  access_type: string;
  source_ip?: string;
  source_location?: string;
  bytes_accessed?: number;
  accessed_at?: string;
}

export interface UebaHostAccess {
  id: string;
  entity_id: string;
  source_host: string;
  destination_host: string;
  destination_ip?: string;
  port?: number;
  protocol?: string;
  service?: string;
  auth_method?: string;
  auth_status: string;
  bytes_transferred?: number;
  is_lateral_movement: boolean;
  hop_count?: number;
  accessed_at: string;
  created_at: string;
}

export interface UebaHostAccessListResponse {
  accesses: UebaHostAccess[];
  total: number;
  offset: number;
  limit: number;
}

export interface RecordHostAccessRequest {
  entity_id: string;
  source_host: string;
  destination_host: string;
  destination_ip?: string;
  port?: number;
  protocol?: string;
  service?: string;
  auth_method?: string;
  auth_status: string;
  bytes_transferred?: number;
  accessed_at?: string;
}

export interface UebaDataTransfer {
  id: string;
  entity_id: string;
  source: string;
  destination: string;
  destination_type: string;
  transfer_method: string;
  bytes_transferred: number;
  file_count?: number;
  file_types?: string;
  is_external: boolean;
  is_encrypted: boolean;
  is_anomalous: boolean;
  anomaly_reasons?: string;
  transferred_at: string;
  created_at: string;
}

export interface UebaDataTransferListResponse {
  transfers: UebaDataTransfer[];
  total: number;
  offset: number;
  limit: number;
}

export interface RecordDataTransferRequest {
  entity_id: string;
  source: string;
  destination: string;
  destination_type: string;
  transfer_method: string;
  bytes_transferred: number;
  file_count?: number;
  file_types?: string[];
  is_external?: boolean;
  is_encrypted?: boolean;
  transferred_at?: string;
}

export interface RunAdvancedDetectionRequest {
  detection_type: UebaAdvancedDetectionType;
  entity_id?: string;
  time_window_hours?: number;
}

export interface AdvancedDetectionResult {
  detections_created: number;
  entities_analyzed: number;
  detection_type: string;
}
