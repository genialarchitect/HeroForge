import axios from 'axios';
import type {
  LoginRequest,
  RegisterRequest,
  LoginResponse,
  User,
  CreateScanRequest,
  ScanResult,
  HostInfo,
  AuditLogResponse,
  AuditLogFilter,
  AuditUser,
  SystemSetting,
  Report,
  ReportTemplate,
  CreateReportRequest,
  TargetGroup,
  CreateTargetGroupRequest,
  UpdateTargetGroupRequest,
  ScheduledScan,
  CreateScheduledScanRequest,
  UpdateScheduledScanRequest,
  NotificationSettings,
  UpdateNotificationSettingsRequest,
  ScanComparisonResponse,
  ScanTemplate,
  TemplateCategorySummary,
  CreateTemplateRequest,
  UpdateTemplateRequest,
  UpdateProfileRequest,
  ChangePasswordRequest,
  Role,
  MfaSetupResponse,
  MfaVerifySetupRequest,
  MfaDisableRequest,
  MfaRegenerateRecoveryCodesRequest,
  MfaRegenerateRecoveryCodesResponse,
  MfaVerifyRequest,
  MfaLoginResponse,
  AnalyticsSummary,
  TimeSeriesDataPoint,
  VulnerabilityTimeSeriesDataPoint,
  ServiceCount,
  VulnerabilityTracking,
  VulnerabilityDetail,
  VulnerabilityComment,
  VulnerabilityCommentWithUser,
  UpdateVulnerabilityRequest,
  BulkUpdateVulnerabilitiesRequest,
  BulkAssignVulnerabilitiesRequest,
  VerifyVulnerabilityRequest,
  RemediationTimelineEvent,
  VulnerabilityStats,
  RequestRetestRequest,
  BulkRetestRequest,
  CompleteRetestRequest,
  VulnerabilityAssignmentWithUser,
  UserAssignmentStats,
  MyAssignmentsResponse,
  AssignVulnerabilityRequest,
  UpdateAssignmentRequest,
  // False Positive Prediction types
  FPPrediction,
  FPFeedbackRequest,
  BatchFPPredictionRequest,
  // Finding Deduplication types
  DeduplicatedFinding,
  DeduplicationStats,
  RegisterFindingRequest,
  RegisterFindingResult,
  ListFindingsQuery,
  ListFindingsResponse,
  MergeFindingsRequest,
  UpdateFindingStatusRequest,
  ComplianceFramework,
  ComplianceControlList,
  ComplianceAnalyzeRequest,
  ComplianceAnalyzeResponse,
  ScanPreset,
  ApiKey,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  UpdateApiKeyRequest,
  SiemSettings,
  CreateSiemSettingsRequest,
  UpdateSiemSettingsRequest,
  SiemTestResponse,
  SiemExportResponse,
  ComplianceRubric,
  ManualAssessment,
  AssessmentEvidence,
  AssessmentCampaign,
  CampaignWithProgress,
  CampaignProgress,
  CreateManualAssessmentRequest,
  CreateCampaignRequest,
  CombinedComplianceResults,
  VpnConfig,
  VpnStatus,
  UploadVpnConfigRequest,
  UpdateVpnConfigRequest,
  VpnConnectRequest,
  VpnTestResult,
  Customer,
  Contact,
  Engagement,
  EngagementMilestone,
  Contract,
  SlaDefinition,
  TimeEntry,
  Communication,
  CrmDashboardStats,
  CustomerSummary,
  CreateCustomerRequest,
  UpdateCustomerRequest,
  CreateContactRequest,
  UpdateContactRequest,
  CreateEngagementRequest,
  UpdateEngagementRequest,
  CreateMilestoneRequest,
  UpdateMilestoneRequest,
  CreateContractRequest,
  UpdateContractRequest,
  CreateSlaRequest,
  CreateTimeEntryRequest,
  CreateCommunicationRequest,
  CrmPortalUser,
  CreatePortalUserRequest,
  UpdatePortalUserRequest,
  ResetPortalUserPasswordRequest,
  CrmDiscoveredAsset,
  DiscoveredAssetsSummary,
  CreateDiscoveredAssetRequest,
  UpdateDiscoveredAssetRequest,
  BulkScopeRequest,
  FindingTemplate,
  CreateFindingTemplateRequest,
  UpdateFindingTemplateRequest,
  CloneTemplateRequest,
  CloneFindingTemplateRequest,
  FindingTemplateCategory,
  FindingTemplateCategoryFull,
  ApplyTemplateRequest,
  ImportTemplatesRequest,
  ImportTemplatesResponse,
  TemplateSearchQuery,
  MethodologyTemplate,
  MethodologyTemplateWithItems,
  MethodologyChecklist,
  ChecklistSummary,
  ChecklistWithItems,
  ChecklistProgress,
  ChecklistItem,
  CreateChecklistRequest,
  UpdateChecklistRequest,
  UpdateChecklistItemRequest,
  ScannerMapping,
  ExploitItemRequest,
  ExploitItemResponse,
  // Executive Analytics types
  CustomerSecurityTrends,
  ExecutiveSummary,
  RemediationVelocity,
  RiskTrendPoint,
  MethodologyExecutiveCoverage,
  ExecutiveDashboard,
  // Scan Tags types
  ScanTag,
  CreateScanTagRequest,
  AddTagsToScanRequest,
  ScanWithTags,
  DuplicateScanRequest,
  TagSuggestion,
  // Asset Tags types
  AssetTag,
  AssetTagWithCount,
  CreateAssetTagRequest,
  UpdateAssetTagRequest,
  AddAssetTagsRequest,
  Asset,
  AssetDetailWithTags,
  // Asset Groups types
  AssetGroup,
  AssetGroupWithCount,
  AssetGroupWithMembers,
  CreateAssetGroupRequest,
  UpdateAssetGroupRequest,
  AddAssetsToGroupRequest,
  AssetDetailFull,
  AssetWithTags,
  BulkAddToGroupResponse,
  // SSL Report types
  SslReportSummary,
  // Scan Exclusions types
  ScanExclusion,
  CreateExclusionRequest,
  UpdateExclusionRequest,
  // Vulnerability Trends types
  DailyVulnerabilityCount,
  RemediationRatePoint,
  RecurringVulnerability,
  VulnerabilityTrendsData,
  // Webhook types
  Webhook,
  WebhookDelivery,
  WebhookStats,
  WebhookEventTypeInfo,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookTestResponse,
  GenerateSecretResponse,
  // Secret Findings types
  SecretFinding,
  SecretFindingStats,
  UpdateSecretFindingRequest,
  BulkUpdateSecretsResponse,
  // Container/K8s Scanning types
  ContainerScan,
  ContainerScanSummary,
  ContainerImage,
  K8sResource,
  ContainerFinding,
  CreateContainerScanRequest,
  AnalyzeDockerfileRequest,
  AnalyzeK8sManifestRequest,
  DockerfileAnalysis,
  K8sManifestAnalysis,
  ContainerScanListResponse,
  ContainerScanDetailResponse,
  ContainerScanTypeInfo,
  UpdateContainerFindingStatusRequest,
  FindingStatus,
  // IaC Security Scanning types
  IacScan,
  IacScanDetailResponse,
  IacFile,
  IacFinding,
  IacRule,
  IacPlatformInfo,
  IacAnalyzeFileRequest,
  IacAnalyzeFileResponse,
  CreateIacRuleRequest,
  UpdateIacRuleRequest,
  UpdateIacFindingStatusRequest,
  // Workflow types
  WorkflowTemplate,
  WorkflowTemplateWithStages,
  WorkflowInstance,
  WorkflowInstanceDetail,
  PendingApproval,
  WorkflowStats,
  CreateWorkflowTemplateRequest,
  UpdateWorkflowTemplateRequest,
  StartWorkflowRequest,
  ApproveWorkflowRequest,
  RejectWorkflowRequest,
  UpdateWorkflowRequest,
  // BAS types
  MitreTactic,
  AttackTechnique,
  SimulationScenario,
  SimulationSummary,
  SimulationDetails,
  DetectionGap,
  BasStats,
  CreateScenarioRequest,
  StartSimulationRequest,
  AcknowledgeGapRequest,
  // SIEM types
  SiemLogSource,
  CreateSiemLogSourceRequest,
  UpdateSiemLogSourceRequest,
  SiemLogEntry,
  SiemLogSearchParams,
  SiemLogSearchResponse,
  SiemRule,
  CreateSiemRuleRequest,
  UpdateSiemRuleRequest,
  SiemAlert,
  UpdateSiemAlertStatusRequest,
  ResolveSiemAlertRequest,
  SiemStatsResponse,
  // Organization & Multi-tenancy types
  Organization,
  OrganizationSummary,
  CreateOrganizationRequest,
  UpdateOrganizationRequest,
  Department,
  CreateDepartmentRequest,
  UpdateDepartmentRequest,
  Team,
  CreateTeamRequest,
  UpdateTeamRequest,
  TeamMember,
  OrgMember,
  AddOrgMemberRequest,
  AddTeamMemberRequest,
  RoleTemplate,
  CustomRole,
  CreateCustomRoleRequest,
  UpdateCustomRoleRequest,
  UserRoleAssignment,
  AssignRoleRequest,
  Permission,
  EffectivePermissions,
  OrganizationQuotas,
  UpdateQuotasRequest,
  OrganizationQuotaUsage,
  // Green Team - SOAR types
  SoarCase,
  CreateCaseRequest,
  UpdateCaseRequest,
  CaseTask,
  CreateCaseTaskRequest,
  CaseComment,
  CreateCaseCommentRequest,
  CaseTimelineEvent,
  Playbook,
  CreatePlaybookRequest,
  PlaybookRun,
  IocFeed,
  CreateIocFeedRequest,
  MetricsOverview,
  // Yellow Team types
  YellowTeamDashboard,
  SastScan,
  SastFinding,
  SastRule,
  CreateSastScanRequest,
  SemgrepRule,
  TaintFlowsResponse,
  TaintAnalysisResult,
  HotspotsResponse,
  SecurityHotspot,
  DetectHotspotsResult,
  HotspotStats,
  SbomProject,
  SbomComponent,
  CreateSbomRequest,
  ArchitectureReview,
  StrideThreat,
  CreateArchitectureReviewRequest,
  // UEBA Types
  UebaEntity,
  UebaEntityListResponse,
  CreateUebaEntityRequest,
  UpdateUebaEntityRequest,
  UebaPeerGroup,
  CreateUebaPeerGroupRequest,
  UpdateUebaPeerGroupRequest,
  UebaActivity,
  UebaActivityListResponse,
  RecordUebaActivityRequest,
  ProcessUebaActivityResponse,
  UebaAnomaly,
  UebaAnomalyListResponse,
  UpdateUebaAnomalyRequest,
  UebaSession,
  UebaSessionListResponse,
  RecordUebaSessionRequest,
  UebaBaseline,
  UebaBaselineListResponse,
  UebaRiskFactor,
  UebaRiskFactorListResponse,
  UebaDashboardStats,
  AddToWatchlistRequest,
  // Sprint 4: Advanced Detection Types
  UebaAdvancedStats,
  UebaAdvancedDetection,
  UebaAdvancedDetectionListResponse,
  UebaBusinessHours,
  CreateBusinessHoursRequest,
  UebaSensitiveResource,
  CreateSensitiveResourceRequest,
  UebaKnownVpn,
  CreateKnownVpnRequest,
  UebaDetectionRule,
  CreateDetectionRuleRequest,
  UebaDataAccess,
  UebaDataAccessListResponse,
  RecordDataAccessRequest,
  UebaHostAccess,
  UebaHostAccessListResponse,
  RecordHostAccessRequest,
  UebaDataTransfer,
  UebaDataTransferListResponse,
  RecordDataTransferRequest,
  RunAdvancedDetectionRequest,
  AdvancedDetectionResult,
  ReportNotesResponse,
  UpdateReportNotesRequest,
  UpdateFindingNoteRequest,
  ReportFindingNote,
} from '../types';

const api = axios.create({
  baseURL: '/api',
});

// Add auth token and organization header to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  // Add organization context header for multi-tenant data isolation
  // Read from persisted org store in localStorage
  try {
    const orgStorage = localStorage.getItem('org-storage');
    if (orgStorage) {
      const orgState = JSON.parse(orgStorage);
      if (orgState?.state?.currentOrgId) {
        config.headers['X-Organization-Id'] = orgState.state.currentOrgId;
      }
    }
  } catch {
    // Ignore parsing errors - org header is optional
  }

  return config;
});

export const authAPI = {
  // Public auth routes (at /api/auth)
  register: (data: RegisterRequest) =>
    api.post<LoginResponse>('/auth/register', data),
  login: (data: LoginRequest) => api.post<MfaLoginResponse>('/auth/login', data),
  // Protected user routes (at /api/user)
  me: () => api.get<User>('/user/me'),
  updateProfile: (data: UpdateProfileRequest) =>
    api.put<User>('/user/profile', data),
  changePassword: (data: ChangePasswordRequest) =>
    api.put<{ message: string }>('/user/password', data),
};

// Registration API for tiered signup flow
export interface SubscriptionTier {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  monthly_price?: number;
  yearly_price?: number;
  max_users: number;
  max_scans_per_day: number;
  max_assets: number;
  features: Record<string, boolean>;
}

export interface InitRegistrationRequest {
  email: string;
  tier: string;
  billing_cycle?: 'monthly' | 'yearly';
}

export interface InitRegistrationResponse {
  verification_id: string;
  checkout_url?: string;
  message: string;
}

export interface VerifyEmailRequest {
  token: string;
}

export interface VerifyEmailResponse {
  verified: boolean;
  email: string;
  tier: string;
  payment_required: boolean;
  payment_verified: boolean;
}

export interface CompleteRegistrationRequest {
  token: string;
  username: string;
  password: string;
  accept_terms: boolean;
}

export interface CompleteRegistrationResponse {
  success: boolean;
  user_id: string;
  token: string;
  message: string;
}

export interface EnterpriseInquiryRequest {
  email: string;
  company_name: string;
  contact_name: string;
  phone?: string;
  job_title?: string;
  company_size?: string;
  message?: string;
}

export interface EnterpriseInquiryResponse {
  success: boolean;
  inquiry_id: string;
  message: string;
}

export const registrationAPI = {
  // Get available subscription tiers
  getTiers: () => api.get<SubscriptionTier[]>('/subscriptions/tiers'),

  // Check if email is available
  checkEmail: (email: string) =>
    api.post<{ available: boolean; message: string }>('/auth/register/check-email', { email }),

  // Initialize registration (creates verification, may return Stripe checkout URL)
  initRegistration: (data: InitRegistrationRequest) =>
    api.post<InitRegistrationResponse>('/auth/register/init', data),

  // Verify email token
  verifyEmail: (token: string) =>
    api.post<VerifyEmailResponse>('/auth/register/verify', { token }),

  // Complete registration after verification and payment
  completeRegistration: (data: CompleteRegistrationRequest) =>
    api.post<CompleteRegistrationResponse>('/auth/register/complete', data),

  // Submit enterprise inquiry
  submitEnterpriseInquiry: (data: EnterpriseInquiryRequest) =>
    api.post<EnterpriseInquiryResponse>('/enterprise/inquiry', data),
};

export const mfaAPI = {
  // Protected MFA management routes (at /api/user)
  // Setup MFA - returns secret, QR code URL, and recovery codes
  setup: () => api.post<MfaSetupResponse>('/user/mfa/setup'),

  // Verify setup with TOTP code
  verifySetup: (data: MfaVerifySetupRequest) =>
    api.post<{ message: string }>('/user/mfa/verify-setup', data),

  // Disable MFA (requires password + TOTP or recovery code)
  disable: (data: MfaDisableRequest) =>
    api.delete<{ message: string }>('/user/mfa', { data }),

  // Regenerate recovery codes (requires password + TOTP)
  regenerateRecoveryCodes: (data: MfaRegenerateRecoveryCodesRequest) =>
    api.post<MfaRegenerateRecoveryCodesResponse>('/user/mfa/recovery-codes', data),

  // Public MFA verification during login (at /api/auth)
  verify: (data: MfaVerifyRequest) =>
    api.post<LoginResponse>('/auth/mfa/verify', data),
};

export const scanAPI = {
  create: (data: CreateScanRequest) => api.post<ScanResult>('/scans', data),
  getAll: () => api.get<ScanResult[]>('/scans'),
  getById: (id: string) => api.get<ScanResult>(`/scans/${id}`),
  getResults: (id: string) => api.get<HostInfo[]>(`/scans/${id}/results`),
  delete: (id: string) => api.delete<{ message: string }>(`/scans/${id}`),
  getPresets: () => api.get<ScanPreset[]>('/scan-presets'),
  bulkDelete: (scan_ids: string[]) =>
    api.post<{ deleted: number; failed?: number; failed_ids?: string[]; message: string }>(
      '/scans/bulk-delete',
      { scan_ids }
    ),
  bulkExport: (scan_ids: string[], format: string, options?: { include_vulnerabilities?: boolean; include_services?: boolean }) =>
    api.post(
      '/scans/bulk-export',
      {
        scan_ids,
        format,
        ...options,
      },
      { responseType: 'blob' }
    ),
  // Duplicate scan
  duplicate: (id: string, data?: DuplicateScanRequest) =>
    api.post<ScanResult>(`/scans/${id}/duplicate`, data || {}),
  // Get scans with tags
  getAllWithTags: () => api.get<ScanWithTags[]>('/scans/with-tags'),
  // Get SSL/TLS report for a scan
  getSslReport: (id: string) => api.get<SslReportSummary>(`/scans/${id}/ssl-report`),
};

export const scanTagAPI = {
  // Tag management
  getAll: () => api.get<ScanTag[]>('/scans/tags'),
  create: (data: CreateScanTagRequest) => api.post<ScanTag>('/scans/tags', data),
  delete: (id: string) => api.delete<{ message: string }>(`/scans/tags/${id}`),
  getSuggestions: () => api.get<TagSuggestion[]>('/scans/tags/suggestions'),

  // Tag-scan associations
  getTagsForScan: (scanId: string) => api.get<ScanTag[]>(`/scans/${scanId}/tags`),
  addTagsToScan: (scanId: string, data: AddTagsToScanRequest) =>
    api.post<ScanTag[]>(`/scans/${scanId}/tags`, data),
  removeTagFromScan: (scanId: string, tagId: string) =>
    api.delete<{ message: string }>(`/scans/${scanId}/tags/${tagId}`),
};

import type { RateLimitDashboardData, AdminUser, RoleAssignmentInfo } from '../types';

// Request type for assigning role with scope
interface AssignRoleWithScopeRequest {
  role_type: 'template' | 'custom';
  role_id: string;
  organization_id: string;
  scope_type?: 'department' | 'team' | 'organization';
  scope_id?: string;
  expires_at?: string;
}

export const adminAPI = {
  // User management
  getUsers: () => api.get<AdminUser[]>('/admin/users'),
  getUser: (id: string) => api.get<User>(`/admin/users/${id}`),
  updateUser: (id: string, data: Partial<User>) =>
    api.patch(`/admin/users/${id}`, data),
  deleteUser: (id: string) => api.delete(`/admin/users/${id}`),

  // Legacy role endpoints (for backward compatibility)
  assignRole: (userId: string, roleId: string) =>
    api.post(`/admin/users/${userId}/roles`, { role_id: roleId }),
  removeRole: (userId: string, roleId: string) =>
    api.delete(`/admin/users/${userId}/roles/${roleId}`),
  unlockUser: (userId: string) =>
    api.post<{ message: string }>(`/admin/users/${userId}/unlock`),

  // ABAC Role Assignment endpoints
  getUserRoleAssignments: (userId: string) =>
    api.get<RoleAssignmentInfo[]>(`/admin/users/${userId}/role-assignments`),
  assignRoleWithScope: (userId: string, data: AssignRoleWithScopeRequest) =>
    api.post<{ message: string; assignment_id: string }>(`/admin/users/${userId}/role-assignments`, data),
  removeRoleAssignment: (userId: string, assignmentId: string) =>
    api.delete(`/admin/users/${userId}/role-assignments/${assignmentId}`),

  // Roles
  getRoles: () => api.get<Role[]>('/admin/roles'),

  // Scan management
  getAllScans: () => api.get<ScanResult[]>('/admin/scans'),
  deleteScan: (id: string) => api.delete(`/admin/scans/${id}`),

  // Audit logs
  getAuditLogs: (filter: AuditLogFilter = {}) => {
    const params = new URLSearchParams();
    if (filter.user_id) params.append('user_id', filter.user_id);
    if (filter.action) params.append('action', filter.action);
    if (filter.target_type) params.append('target_type', filter.target_type);
    if (filter.start_date) params.append('start_date', filter.start_date);
    if (filter.end_date) params.append('end_date', filter.end_date);
    if (filter.limit !== undefined) params.append('limit', filter.limit.toString());
    if (filter.offset !== undefined) params.append('offset', filter.offset.toString());
    return api.get<AuditLogResponse>(`/admin/audit-logs?${params.toString()}`);
  },
  getAuditActionTypes: () => api.get<{ actions: string[] }>('/admin/audit-logs/action-types'),
  getAuditUsers: () => api.get<{ users: AuditUser[] }>('/admin/audit-logs/users'),
  exportAuditLogs: async (filter: AuditLogFilter = {}) => {
    const params = new URLSearchParams();
    if (filter.user_id) params.append('user_id', filter.user_id);
    if (filter.action) params.append('action', filter.action);
    if (filter.target_type) params.append('target_type', filter.target_type);
    if (filter.start_date) params.append('start_date', filter.start_date);
    if (filter.end_date) params.append('end_date', filter.end_date);
    const response = await api.get(`/admin/audit-logs/export?${params.toString()}`, {
      responseType: 'blob',
    });
    return response;
  },

  // System settings
  getSettings: () => api.get<SystemSetting[]>('/admin/settings'),
  updateSetting: (key: string, value: string) =>
    api.patch(`/admin/settings/${key}`, { value }),

  // Rate limit dashboard
  getRateLimitDashboard: () => api.get<RateLimitDashboardData>('/admin/rate-limits'),
};

export const reportAPI = {
  // Create a new report
  create: (data: CreateReportRequest) => api.post<Report>('/reports', data),

  // Get all reports for current user
  getAll: (scanId?: string) => {
    const params = scanId ? `?scan_id=${scanId}` : '';
    return api.get<Report[]>(`/reports${params}`);
  },

  // Get a specific report
  getById: (id: string) => api.get<Report>(`/reports/${id}`),

  // Download a report file
  download: async (id: string) => {
    const response = await api.get(`/reports/${id}/download`, {
      responseType: 'blob',
    });
    return response;
  },

  // Delete a report
  delete: (id: string) => api.delete(`/reports/${id}`),

  // Get available templates
  getTemplates: () => api.get<ReportTemplate[]>('/reports/templates'),

  // Operator notes endpoints
  getNotes: (id: string) => api.get<ReportNotesResponse>(`/reports/${id}/notes`),

  updateNotes: (id: string, data: UpdateReportNotesRequest) =>
    api.put(`/reports/${id}/notes`, data),

  updateFindingNote: (reportId: string, findingId: string, data: UpdateFindingNoteRequest) =>
    api.put<ReportFindingNote>(`/reports/${reportId}/findings/${findingId}/notes`, data),

  deleteFindingNote: (reportId: string, findingId: string) =>
    api.delete(`/reports/${reportId}/findings/${findingId}/notes`),
};

export const targetGroupAPI = {
  getAll: () => api.get<TargetGroup[]>('/target-groups'),
  getById: (id: string) => api.get<TargetGroup>(`/target-groups/${id}`),
  create: (data: CreateTargetGroupRequest) =>
    api.post<TargetGroup>('/target-groups', data),
  update: (id: string, data: UpdateTargetGroupRequest) =>
    api.put<TargetGroup>(`/target-groups/${id}`, data),
  delete: (id: string) => api.delete(`/target-groups/${id}`),
};

export const scheduledScanAPI = {
  getAll: () => api.get<ScheduledScan[]>('/scheduled-scans'),
  getById: (id: string) => api.get<ScheduledScan>(`/scheduled-scans/${id}`),
  create: (data: CreateScheduledScanRequest) =>
    api.post<ScheduledScan>('/scheduled-scans', data),
  update: (id: string, data: UpdateScheduledScanRequest) =>
    api.put<ScheduledScan>(`/scheduled-scans/${id}`, data),
  delete: (id: string) => api.delete(`/scheduled-scans/${id}`),
};

// Scheduled Reports API
export interface ScheduledReport {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  report_type: string;
  format: string;
  schedule: string;
  recipients: string;
  filters: string | null;
  include_charts: boolean;
  last_run_at: string | null;
  next_run_at: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface SchedulePreset {
  id: string;
  label: string;
  cron: string;
  description: string;
}

export interface ReportFilters {
  min_severity?: string;
  frameworks?: string[];
  days_back?: number;
  scan_ids?: string[];
  customer_id?: string;
  engagement_id?: string;
}

export interface CreateScheduledReportRequest {
  name: string;
  description?: string;
  report_type: string;
  format: string;
  schedule: string;
  recipients: string[];
  filters?: ReportFilters;
  include_charts?: boolean;
}

export interface UpdateScheduledReportRequest {
  name?: string;
  description?: string;
  report_type?: string;
  format?: string;
  schedule?: string;
  recipients?: string[];
  filters?: ReportFilters;
  include_charts?: boolean;
  is_active?: boolean;
}

export const scheduledReportAPI = {
  getAll: () => api.get<ScheduledReport[]>('/scheduled-reports'),
  getById: (id: string) => api.get<ScheduledReport>(`/scheduled-reports/${id}`),
  getPresets: () => api.get<SchedulePreset[]>('/scheduled-reports/presets'),
  create: (data: CreateScheduledReportRequest) =>
    api.post<ScheduledReport>('/scheduled-reports', data),
  update: (id: string, data: UpdateScheduledReportRequest) =>
    api.put<ScheduledReport>(`/scheduled-reports/${id}`, data),
  delete: (id: string) => api.delete(`/scheduled-reports/${id}`),
  runNow: (id: string) =>
    api.post<{ message: string; report_id: string }>(`/scheduled-reports/${id}/run-now`),
};

export const notificationAPI = {
  getSettings: () => api.get<NotificationSettings>('/notifications/settings'),
  updateSettings: (data: UpdateNotificationSettingsRequest) =>
    api.put<NotificationSettings>('/notifications/settings', data),
  testSlack: () => api.post<{ success: boolean; message: string }>('/notifications/test-slack'),
  testTeams: () => api.post<{ success: boolean; message: string }>('/notifications/test-teams'),
  testEmail: () => api.post<{ success: boolean; message: string }>('/notifications/test-email'),
  checkSmtpStatus: () => api.get<{ configured: boolean; message: string }>('/notifications/smtp-status'),
};

export const apiKeyAPI = {
  getAll: () => api.get<ApiKey[]>('/api-keys'),
  create: (data: CreateApiKeyRequest) => api.post<CreateApiKeyResponse>('/api-keys', data),
  update: (id: string, data: UpdateApiKeyRequest) => api.patch<ApiKey>(`/api-keys/${id}`, data),
  delete: (id: string) => api.delete<{ message: string }>(`/api-keys/${id}`),
};

export const compareAPI = {
  compare: (scanId1: string, scanId2: string) =>
    api.post<ScanComparisonResponse>('/scans/compare', {
      scan_id_1: scanId1,
      scan_id_2: scanId2,
    }),
};

export const templateAPI = {
  // Get all templates (user's own + system templates)
  getAll: () => api.get<ScanTemplate[]>('/templates'),
  // Get system templates only
  getSystem: () => api.get<ScanTemplate[]>('/templates/system'),
  // Get template categories with counts
  getCategories: () => api.get<TemplateCategorySummary[]>('/templates/categories'),
  // Get user's default template
  getDefault: () => api.get<ScanTemplate | null>('/templates/default'),
  // Clear default template
  clearDefault: () => api.delete('/templates/default'),
  // Get template by ID
  getById: (id: string) => api.get<ScanTemplate>(`/templates/${id}`),
  // Create a new template
  create: (data: CreateTemplateRequest) => api.post<ScanTemplate>('/templates', data),
  // Update a template
  update: (id: string, data: UpdateTemplateRequest) => api.put<ScanTemplate>(`/templates/${id}`, data),
  // Delete a template
  delete: (id: string) => api.delete(`/templates/${id}`),
  // Clone a template (copies system or user template)
  clone: (id: string, newName?: string) => api.post<ScanTemplate>(`/templates/${id}/clone`, { new_name: newName }),
  // Set a template as default
  setDefault: (id: string) => api.post<ScanTemplate>(`/templates/${id}/set-default`),
  // Create scan from template
  createScan: (id: string, name: string, targets: string[]) =>
    api.post<ScanResult>(`/templates/${id}/scan`, { name, targets }),
  // Export template as JSON
  export: (id: string) => api.get<Blob>(`/templates/${id}/export`, { responseType: 'blob' }),
  // Import template from JSON
  import: (template: { name: string; description?: string; category?: string; estimated_duration_mins?: number; config: unknown; is_default?: boolean }) =>
    api.post<ScanTemplate>('/templates/import', { template }),
};

// User API (for assignment picker - available to all authenticated users)
export const usersAPI = {
  list: () => api.get<User[]>('/users'),
};

export const analyticsAPI = {
  getSummary: (days: number = 30) =>
    api.get<AnalyticsSummary>(`/analytics/summary?days=${days}`),

  getHosts: (days: number = 30) =>
    api.get<TimeSeriesDataPoint[]>(`/analytics/hosts?days=${days}`),

  getVulnerabilities: (days: number = 30) =>
    api.get<VulnerabilityTimeSeriesDataPoint[]>(`/analytics/vulnerabilities?days=${days}`),

  getServices: (limit: number = 10) =>
    api.get<ServiceCount[]>(`/analytics/services?limit=${limit}`),

  getFrequency: (days: number = 30) =>
    api.get<TimeSeriesDataPoint[]>(`/analytics/frequency?days=${days}`),

  // Vulnerability Trends Analytics
  getVulnerabilityTrends: (days: number = 30) =>
    api.get<DailyVulnerabilityCount[]>(`/analytics/vulnerability-trends?days=${days}`),

  getSeverityTrends: (days: number = 30) =>
    api.get<VulnerabilityTimeSeriesDataPoint[]>(`/analytics/severity-trends?days=${days}`),

  getRemediationRate: (days: number = 30) =>
    api.get<RemediationRatePoint[]>(`/analytics/remediation-rate?days=${days}`),

  getTopVulnerabilities: (limit: number = 10) =>
    api.get<RecurringVulnerability[]>(`/analytics/top-vulnerabilities?limit=${limit}`),

  getVulnerabilityTrendsDashboard: (days: number = 30) =>
    api.get<VulnerabilityTrendsData>(`/analytics/vulnerability-trends-dashboard?days=${days}`),
};

export const vulnerabilityAPI = {
  list: (params: { scan_id?: string; status?: string; severity?: string }) => {
    const queryParams = new URLSearchParams();
    if (params.scan_id) queryParams.append('scan_id', params.scan_id);
    if (params.status) queryParams.append('status', params.status);
    if (params.severity) queryParams.append('severity', params.severity);
    return api.get<VulnerabilityTracking[]>(`/vulnerabilities?${queryParams.toString()}`);
  },

  get: (id: string) => api.get<VulnerabilityDetail>(`/vulnerabilities/${id}`),

  update: (id: string, data: UpdateVulnerabilityRequest) =>
    api.put<VulnerabilityTracking>(`/vulnerabilities/${id}`, data),

  addComment: (id: string, comment: string) =>
    api.post<VulnerabilityComment>(`/vulnerabilities/${id}/comments`, { comment }),

  getComments: (id: string) =>
    api.get<VulnerabilityCommentWithUser[]>(`/vulnerabilities/${id}/comments`),

  updateComment: (vulnId: string, commentId: string, comment: string) =>
    api.put<VulnerabilityComment>(`/vulnerabilities/${vulnId}/comments/${commentId}`, { comment }),

  deleteComment: (vulnId: string, commentId: string) =>
    api.delete<{ message: string }>(`/vulnerabilities/${vulnId}/comments/${commentId}`),

  bulkUpdate: (data: BulkUpdateVulnerabilitiesRequest) =>
    api.post<{ updated: number }>('/vulnerabilities/bulk-update', data),

  bulkExport: (vulnerability_ids: string[], format: string) =>
    api.post(
      '/vulnerabilities/bulk-export',
      { vulnerability_ids, format },
      { responseType: 'blob' }
    ),

  getStats: (scan_id?: string) => {
    const queryParams = scan_id ? `?scan_id=${scan_id}` : '';
    return api.get<VulnerabilityStats>(`/vulnerabilities/stats${queryParams}`);
  },

  getTimeline: (id: string) =>
    api.get<RemediationTimelineEvent[]>(`/vulnerabilities/${id}/timeline`),

  markForVerification: (id: string, data: VerifyVulnerabilityRequest) =>
    api.post<VulnerabilityTracking>(`/vulnerabilities/${id}/verify`, data),

  bulkAssign: (data: BulkAssignVulnerabilitiesRequest) =>
    api.post<{ updated: number }>('/vulnerabilities/bulk-assign', data),

  // Assignment endpoints
  getMyAssignments: (params?: { status?: string; overdue?: boolean; user_id?: string }) => {
    const queryParams = new URLSearchParams();
    if (params?.status) queryParams.append('status', params.status);
    if (params?.overdue !== undefined) queryParams.append('overdue', params.overdue.toString());
    if (params?.user_id) queryParams.append('user_id', params.user_id);
    return api.get<MyAssignmentsResponse>(`/vulnerabilities/assigned?${queryParams.toString()}`);
  },

  getAssignmentStats: () =>
    api.get<UserAssignmentStats>('/vulnerabilities/assignment-stats'),

  listWithAssignments: (params?: {
    scan_id?: string;
    status?: string;
    severity?: string;
    assigned_to?: string;
    overdue?: boolean;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.scan_id) queryParams.append('scan_id', params.scan_id);
    if (params?.status) queryParams.append('status', params.status);
    if (params?.severity) queryParams.append('severity', params.severity);
    if (params?.assigned_to) queryParams.append('assigned_to', params.assigned_to);
    if (params?.overdue !== undefined) queryParams.append('overdue', params.overdue.toString());
    return api.get<VulnerabilityAssignmentWithUser[]>(`/vulnerabilities/with-assignments?${queryParams.toString()}`);
  },

  assign: (id: string, data: AssignVulnerabilityRequest) =>
    api.post<VulnerabilityTracking>(`/vulnerabilities/${id}/assign`, data),

  unassign: (id: string) =>
    api.delete<VulnerabilityTracking>(`/vulnerabilities/${id}/assign`),

  updateAssignment: (id: string, data: UpdateAssignmentRequest) =>
    api.put<VulnerabilityTracking>(`/vulnerabilities/${id}/assignment`, data),

  // New bulk operation endpoints
  bulkUpdateStatus: (vulnerability_ids: string[], status: string) =>
    api.post<{ updated: number; failed: number; message: string }>(
      '/vulnerabilities/bulk/status',
      { vulnerability_ids, status }
    ),

  bulkUpdateSeverity: (vulnerability_ids: string[], severity: string) =>
    api.post<{ updated: number; failed: number; message: string }>(
      '/vulnerabilities/bulk/severity',
      { vulnerability_ids, severity }
    ),

  bulkDelete: (vulnerability_ids: string[]) =>
    api.post<{ deleted: number; failed: number; message: string }>(
      '/vulnerabilities/bulk/delete',
      { vulnerability_ids }
    ),

  bulkAddTags: (vulnerability_ids: string[], tags: string[]) =>
    api.post<{ updated: number; failed: number; message: string }>(
      '/vulnerabilities/bulk/tags',
      { vulnerability_ids, tags }
    ),

  // Retest workflow methods
  requestRetest: (id: string, data: RequestRetestRequest = {}) =>
    api.post<VulnerabilityTracking>(`/vulnerabilities/${id}/request-retest`, data),

  bulkRequestRetest: (data: BulkRetestRequest) =>
    api.post<{ requested: number }>('/vulnerabilities/bulk-retest', data),

  completeRetest: (id: string, data: CompleteRetestRequest) =>
    api.post<VulnerabilityTracking>(`/vulnerabilities/${id}/complete-retest`, data),

  getPendingRetests: (scan_id?: string) => {
    const queryParams = scan_id ? `?scan_id=${scan_id}` : '';
    return api.get<VulnerabilityTracking[]>(`/vulnerabilities/pending-retest${queryParams}`);
  },

  getRetestHistory: (id: string) =>
    api.get<RemediationTimelineEvent[]>(`/vulnerabilities/${id}/retest-history`),

  // False positive prediction methods
  getFPPrediction: (id: string) =>
    api.get<FPPrediction>(`/vulnerabilities/${id}/fp-prediction`),

  getBatchFPPredictions: (vulnerability_ids: string[]) =>
    api.post<FPPrediction[]>('/vulnerabilities/fp-predictions', { vulnerability_ids }),

  submitFPFeedback: (id: string, data: FPFeedbackRequest) =>
    api.post<{ message: string; vulnerability_id: string; is_false_positive: boolean }>(
      `/vulnerabilities/${id}/fp-feedback`,
      data
    ),
};

// ============================================================================
// Findings Deduplication API
// ============================================================================
export const findingsAPI = {
  // List deduplicated findings with optional filters
  list: (query?: ListFindingsQuery) =>
    api.get<ListFindingsResponse>('/findings', { params: query }),

  // Get a specific finding by ID
  get: (id: string) =>
    api.get<{ finding: DeduplicatedFinding }>(`/findings/${id}`),

  // Get findings for a specific scan
  getByScan: (scanId: string) =>
    api.get<{ findings: DeduplicatedFinding[]; scan_id: string; count: number }>(
      `/findings/by-scan/${scanId}`
    ),

  // Find finding by fingerprint hash
  getByFingerprint: (hash: string) =>
    api.get<{ finding: DeduplicatedFinding }>(`/findings/by-fingerprint/${hash}`),

  // Register a new finding occurrence
  register: (data: RegisterFindingRequest) =>
    api.post<RegisterFindingResult>('/findings', data),

  // Update finding status
  updateStatus: (id: string, data: UpdateFindingStatusRequest) =>
    api.put<{ message: string; finding_id: string; status: string }>(
      `/findings/${id}/status`,
      data
    ),

  // Merge two findings
  merge: (data: MergeFindingsRequest) =>
    api.post<{ message: string; source_id: string; target_id: string; merged_occurrence_count: number }>(
      '/findings/merge',
      data
    ),

  // Get deduplication statistics
  getStats: () =>
    api.get<{ stats: DeduplicationStats }>('/findings/stats'),
};

export const complianceAPI = {
  // Get all available compliance frameworks
  getFrameworks: () =>
    api.get<{ frameworks: ComplianceFramework[] }>('/compliance/frameworks'),

  // Get a specific framework's details
  getFramework: (id: string) =>
    api.get<ComplianceFramework>(`/compliance/frameworks/${id}`),

  // Get all controls for a framework
  getFrameworkControls: (id: string) =>
    api.get<ComplianceControlList>(`/compliance/frameworks/${id}/controls`),

  // Run compliance analysis on a scan
  analyzeScan: (scanId: string, data: ComplianceAnalyzeRequest) =>
    api.post<ComplianceAnalyzeResponse>(`/scans/${scanId}/compliance`, data),

  // Get compliance results for a scan
  getScanCompliance: (scanId: string) =>
    api.get<ComplianceAnalyzeResponse>(`/scans/${scanId}/compliance`),

  // Generate a compliance report
  generateReport: (
    scanId: string,
    data: { frameworks: string[]; format: 'pdf' | 'html' | 'json'; include_evidence?: boolean }
  ) =>
    api.post<{
      report_id: string;
      file_path: string;
      file_size: number;
      format: string;
      download_url: string;
      message: string;
    }>(`/scans/${scanId}/compliance/report`, data),

  // Download a compliance report
  downloadReport: (reportId: string) =>
    api.get(`/compliance/reports/${reportId}/download`, { responseType: 'blob' }),
};

export const jiraAPI = {
  // Get JIRA settings for current user
  getSettings: () => api.get('/integrations/jira/settings'),

  // Update JIRA settings
  updateSettings: (data: {
    jira_url: string;
    username: string;
    api_token: string;
    project_key: string;
    issue_type: string;
    default_assignee?: string;
    enabled: boolean;
  }) => api.post('/integrations/jira/settings', data),

  // Test JIRA connection
  testConnection: () => api.post('/integrations/jira/test'),

  // List available JIRA projects
  listProjects: () => api.get<Array<{ id: string; key: string; name: string }>>('/integrations/jira/projects'),

  // List available issue types for the configured project
  listIssueTypes: () => api.get<Array<{ id: string; name: string; description?: string }>>('/integrations/jira/issue-types'),

  // Create JIRA ticket from vulnerability
  createTicket: (vulnerabilityId: string, data?: { assignee?: string; labels?: string[] }) =>
    api.post<{
      jira_ticket_id: string;
      jira_ticket_key: string;
      jira_ticket_url: string;
    }>(`/vulnerabilities/${vulnerabilityId}/create-ticket`, data || {}),
};

export const dnsAPI = {
  // Perform DNS reconnaissance
  performRecon: (data: {
    domain: string;
    includeSubdomains?: boolean;
    customWordlist?: string[];
    timeoutSecs?: number;
  }) =>
    api.post('/dns/recon', {
      domain: data.domain,
      include_subdomains: data.includeSubdomains,
      custom_wordlist: data.customWordlist,
      timeout_secs: data.timeoutSecs,
    }),

  // List all DNS recon results
  listResults: () => api.get('/dns/recon'),

  // Get specific DNS recon result
  getResult: (id: string) => api.get(`/dns/recon/${id}`),

  // Delete DNS recon result
  deleteResult: (id: string) => api.delete(`/dns/recon/${id}`),

  // Get built-in subdomain wordlist
  getWordlist: () => api.get<{ wordlist: string[]; count: number }>('/dns/wordlist'),
};

export const siemAPI = {
  // Get all SIEM settings
  getSettings: () => api.get<SiemSettings[]>('/integrations/siem/settings'),

  // Create new SIEM settings
  createSettings: (data: CreateSiemSettingsRequest) =>
    api.post<SiemSettings>('/integrations/siem/settings', data),

  // Update SIEM settings
  updateSettings: (id: string, data: UpdateSiemSettingsRequest) =>
    api.put<SiemSettings>(`/integrations/siem/settings/${id}`, data),

  // Delete SIEM settings
  deleteSettings: (id: string) =>
    api.delete(`/integrations/siem/settings/${id}`),

  // Test SIEM connection
  testConnection: (id: string) =>
    api.post<SiemTestResponse>(`/integrations/siem/settings/${id}/test`),

  // Manually export a scan to SIEM
  exportScan: (scanId: string) =>
    api.post<SiemExportResponse>(`/integrations/siem/export/${scanId}`),
};

// ============================================================================
// ServiceNow Integration API
// ============================================================================

export interface ServiceNowSettings {
  user_id: string;
  instance_url: string;
  username: string;
  default_assignment_group?: string;
  default_category?: string;
  default_impact: number;
  default_urgency: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ServiceNowTicket {
  id: string;
  vulnerability_id: string;
  ticket_number: string;
  ticket_type: string;
  ticket_sys_id: string;
  ticket_url: string;
  status?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ServiceNowAssignmentGroup {
  sys_id: string;
  name: string;
}

export interface ServiceNowCategory {
  label: string;
  value: string;
}

export interface ServiceNowTicketStatus {
  sys_id: string;
  number: string;
  state: string;
  short_description: string;
}

export const serviceNowAPI = {
  // Get ServiceNow settings for current user
  getSettings: () => api.get<ServiceNowSettings>('/integrations/servicenow/settings'),

  // Update ServiceNow settings
  updateSettings: (data: {
    instance_url: string;
    username: string;
    password: string;
    default_assignment_group?: string;
    default_category?: string;
    default_impact?: number;
    default_urgency?: number;
    enabled: boolean;
  }) => api.post('/integrations/servicenow/settings', data),

  // Test ServiceNow connection
  testConnection: () => api.post('/integrations/servicenow/test'),

  // Get available assignment groups
  getAssignmentGroups: () => api.get<ServiceNowAssignmentGroup[]>('/integrations/servicenow/assignment-groups'),

  // Get available categories
  getCategories: () => api.get<ServiceNowCategory[]>('/integrations/servicenow/categories'),

  // Get ticket status from ServiceNow
  getTicketStatus: (ticketNumber: string) =>
    api.get<ServiceNowTicketStatus>(`/integrations/servicenow/tickets/${ticketNumber}/status`),

  // Get ServiceNow tickets for a vulnerability
  getTicketsForVulnerability: (vulnerabilityId: string) =>
    api.get<ServiceNowTicket[]>(`/vulnerabilities/${vulnerabilityId}/servicenow/tickets`),

  // Create incident from vulnerability
  createIncident: (vulnerabilityId: string, data?: {
    ticket_type?: string;
    category?: string;
    assignment_group?: string;
  }) => api.post<{
    id: string;
    ticket_number: string;
    ticket_type: string;
    ticket_url: string;
  }>(`/vulnerabilities/${vulnerabilityId}/servicenow/incident`, data || { ticket_type: 'incident' }),

  // Create change request from vulnerability
  createChange: (vulnerabilityId: string, data?: {
    ticket_type?: string;
    category?: string;
    assignment_group?: string;
  }) => api.post<{
    id: string;
    ticket_number: string;
    ticket_type: string;
    ticket_url: string;
  }>(`/vulnerabilities/${vulnerabilityId}/servicenow/change`, data || { ticket_type: 'change' }),
};

export const webappAPI = {
  // Start a new web application scan
  startScan: (data: {
    target_url: string;
    max_depth?: number;
    max_pages?: number;
    respect_robots_txt?: boolean;
    checks_enabled?: string[];
  }) =>
    api.post('/webapp/scan', data),

  // Get scan status and results
  getScan: (scanId: string) =>
    api.get(`/webapp/scan/${scanId}`),
};

// ============================================================================
// GraphQL Security Scanning API
// ============================================================================

export interface GraphQLEndpoint {
  url: string;
  introspection_enabled: boolean;
  supports_batching: boolean | null;
  has_mutations: boolean | null;
  has_subscriptions: boolean | null;
  framework: string | null;
}

export interface GraphQLFinding {
  finding_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  field: string | null;
  cwe_id: number | null;
}

export interface GraphQLScanResult {
  endpoint: GraphQLEndpoint;
  findings: GraphQLFinding[];
  schema_discovered: boolean;
  scan_duration_ms: number;
}

export interface GraphQLScanConfig {
  target_url: string;
  check_introspection?: boolean;
  check_injection?: boolean;
  check_dos?: boolean;
  check_authorization?: boolean;
  max_query_depth?: number;
  max_batch_size?: number;
  auth_token?: string;
}

export const graphqlAPI = {
  // Detect GraphQL endpoints at a URL
  detectEndpoints: (targetUrl: string) =>
    api.post<{ endpoints: GraphQLEndpoint[] }>('/webapp/graphql/detect', { target_url: targetUrl }),

  // Start a GraphQL security scan
  startScan: (config: GraphQLScanConfig) =>
    api.post<{ scan_id: string; status: string; endpoints_found: string[] }>('/webapp/graphql/scan', config),

  // Get GraphQL scan status and results
  getScan: (scanId: string) =>
    api.get<{ scan_id: string; status: string; result: GraphQLScanResult | null }>(`/webapp/graphql/scan/${scanId}`),
};

// ============================================================================
// Continuous Monitoring API
// ============================================================================

export interface MonitoringStatus {
  is_running: boolean;
  targets_count: number;
  last_light_scan: string | null;
  last_full_scan: string | null;
  changes_detected_today: number;
  alerts_sent_today: number;
  uptime_seconds: number;
}

export interface AlertTriggers {
  new_port: boolean;
  closed_port: boolean;
  service_change: boolean;
  new_vulnerability: boolean;
  host_up: boolean;
  host_down: boolean;
  version_change: boolean;
}

export interface AlertDestination {
  type: 'Email' | 'Webhook' | 'Slack' | 'Teams' | 'Syslog';
  address?: string;
  url?: string;
  webhook_url?: string;
  secret?: string;
  channel?: string;
  host?: string;
  port?: number;
}

export interface PortState {
  port: number;
  protocol: string;
  service: string | null;
  version: string | null;
  banner: string | null;
  first_seen: string;
  last_seen: string;
}

export interface TargetState {
  target: string;
  ip: string | null;
  is_up: boolean;
  last_seen: string | null;
  open_ports: Record<number, PortState>;
  last_full_scan: string | null;
  last_light_scan: string | null;
}

export interface DetectedChange {
  id: string;
  change_type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  target: string;
  port: number | null;
  description: string;
  previous_value: string | null;
  current_value: string | null;
  detected_at: string;
  acknowledged: boolean;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
}

export interface MonitoringBaseline {
  id: string;
  name: string;
  created_at: string;
  targets: TargetState[];
  description: string | null;
}

export interface MonitoringConfig {
  targets: string[];
  light_scan_interval_secs: number;
  full_scan_interval_secs: number;
  light_scan_port_count: number;
  alerting_enabled: boolean;
  alert_destinations: AlertDestination[];
  alert_on: AlertTriggers;
}

export const monitoringAPI = {
  // Get monitoring status
  getStatus: () =>
    api.get<{ success: boolean; data: MonitoringStatus }>('/monitoring/status'),

  // Start monitoring
  start: (config: {
    targets: string[];
    light_scan_interval_secs?: number;
    full_scan_interval_secs?: number;
    alert_destinations?: AlertDestination[];
    alert_triggers?: AlertTriggers;
  }) =>
    api.post<{ success: boolean; data: { message: string; targets_count: number } }>('/monitoring/start', config),

  // Stop monitoring
  stop: () =>
    api.post<{ success: boolean; data: { message: string } }>('/monitoring/stop'),

  // Get configuration
  getConfig: () =>
    api.get<{ success: boolean; data: MonitoringConfig }>('/monitoring/config'),

  // Update configuration
  updateConfig: (config: MonitoringConfig) =>
    api.put<{ success: boolean; data: { message: string } }>('/monitoring/config', config),

  // Get all targets
  getTargets: () =>
    api.get<{ success: boolean; data: TargetState[] }>('/monitoring/targets'),

  // Add target
  addTarget: (target: string) =>
    api.post<{ success: boolean; data: { message: string } }>('/monitoring/targets', { target }),

  // Remove target
  removeTarget: (target: string) =>
    api.delete<{ success: boolean; data: { message: string } }>(`/monitoring/targets/${encodeURIComponent(target)}`),

  // Get recent changes
  getChanges: (limit?: number) =>
    api.get<{ success: boolean; data: DetectedChange[] }>(`/monitoring/changes${limit ? `?limit=${limit}` : ''}`),

  // Acknowledge a change
  acknowledgeChange: (changeId: string) =>
    api.post<{ success: boolean; data: { message: string } }>(`/monitoring/changes/${changeId}/acknowledge`),

  // Create baseline
  createBaseline: (name: string, description?: string) =>
    api.post<{ success: boolean; data: MonitoringBaseline }>('/monitoring/baseline', { name, description }),

  // Set baseline
  setBaseline: (baseline: MonitoringBaseline) =>
    api.post<{ success: boolean; data: { message: string } }>('/monitoring/baseline/set', baseline),
};

// ============================================================================
// Manual Compliance Assessment API
// ============================================================================

export const rubricAPI = {
  // Get all rubrics, optionally filtered by framework
  getAll: (frameworkId?: string) => {
    const params = frameworkId ? `?framework_id=${frameworkId}` : '';
    return api.get<ComplianceRubric[]>(`/compliance/rubrics${params}`);
  },

  // Get a specific rubric by ID
  getById: (id: string) => api.get<ComplianceRubric>(`/compliance/rubrics/${id}`),

  // Create a new rubric
  create: (rubric: Partial<ComplianceRubric>) =>
    api.post<ComplianceRubric>('/compliance/rubrics', rubric),

  // Update an existing rubric
  update: (id: string, rubric: Partial<ComplianceRubric>) =>
    api.put<ComplianceRubric>(`/compliance/rubrics/${id}`, rubric),

  // Delete a rubric
  delete: (id: string) => api.delete(`/compliance/rubrics/${id}`),

  // Get all rubrics for a specific framework
  getByFramework: (frameworkId: string) =>
    api.get<ComplianceRubric[]>(`/compliance/frameworks/${frameworkId}/rubrics`),
};

export const manualAssessmentAPI = {
  // Get all manual assessments, optionally filtered
  getAll: (frameworkId?: string, status?: string) => {
    const params = new URLSearchParams();
    if (frameworkId) params.append('framework_id', frameworkId);
    if (status) params.append('status', status);
    const queryString = params.toString();
    return api.get<ManualAssessment[]>(`/compliance/assessments${queryString ? `?${queryString}` : ''}`);
  },

  // Get a specific assessment by ID
  getById: (id: string) => api.get<ManualAssessment>(`/compliance/assessments/${id}`),

  // Create a new assessment
  create: (assessment: CreateManualAssessmentRequest) =>
    api.post<ManualAssessment>('/compliance/assessments', assessment),

  // Update an existing assessment
  update: (id: string, assessment: Partial<CreateManualAssessmentRequest>) =>
    api.put<ManualAssessment>(`/compliance/assessments/${id}`, assessment),

  // Delete an assessment
  delete: (id: string) => api.delete(`/compliance/assessments/${id}`),

  // Submit assessment for review
  submit: (id: string) =>
    api.post<ManualAssessment>(`/compliance/assessments/${id}/submit`),

  // Approve an assessment (reviewer action)
  approve: (id: string) =>
    api.post<ManualAssessment>(`/compliance/assessments/${id}/approve`),

  // Reject an assessment with notes (reviewer action)
  reject: (id: string, notes: string) =>
    api.post<ManualAssessment>(`/compliance/assessments/${id}/reject`, { notes }),
};

export const assessmentEvidenceAPI = {
  // Get all evidence for an assessment
  getAll: (assessmentId: string) =>
    api.get<AssessmentEvidence[]>(`/compliance/assessments/${assessmentId}/evidence`),

  // Upload evidence file
  upload: (assessmentId: string, formData: FormData) =>
    api.post<AssessmentEvidence>(`/compliance/assessments/${assessmentId}/evidence`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    }),

  // Add a link as evidence
  addLink: (assessmentId: string, title: string, url: string, description?: string) =>
    api.post<AssessmentEvidence>(`/compliance/assessments/${assessmentId}/evidence/link`, {
      title,
      url,
      description,
    }),

  // Delete evidence
  delete: (id: string) => api.delete(`/compliance/evidence/${id}`),

  // Download evidence file
  download: async (id: string) => {
    const response = await api.get(`/compliance/evidence/${id}/download`, {
      responseType: 'blob',
    });
    return response.data as Blob;
  },
};

export const campaignAPI = {
  // Get all campaigns with progress
  getAll: () => api.get<CampaignWithProgress[]>('/compliance/campaigns'),

  // Get a specific campaign with progress
  getById: (id: string) => api.get<CampaignWithProgress>(`/compliance/campaigns/${id}`),

  // Create a new campaign
  create: (campaign: CreateCampaignRequest) =>
    api.post<AssessmentCampaign>('/compliance/campaigns', campaign),

  // Update an existing campaign
  update: (id: string, campaign: Partial<CreateCampaignRequest>) =>
    api.put<AssessmentCampaign>(`/compliance/campaigns/${id}`, campaign),

  // Delete a campaign
  delete: (id: string) => api.delete(`/compliance/campaigns/${id}`),

  // Get campaign progress
  getProgress: (id: string) =>
    api.get<CampaignProgress>(`/compliance/campaigns/${id}/progress`),
};

export const combinedComplianceAPI = {
  // Get combined compliance results (automated + manual) for a scan
  getResults: (scanId: string) =>
    api.get<CombinedComplianceResults>(`/scans/${scanId}/compliance/combined`),
};

export const vpnAPI = {
  // Get all VPN configs for the current user
  getConfigs: () => api.get<VpnConfig[]>('/vpn/configs'),

  // Upload a new VPN config
  uploadConfig: (data: UploadVpnConfigRequest) =>
    api.post<VpnConfig>('/vpn/configs', data),

  // Update a VPN config
  updateConfig: (id: string, data: UpdateVpnConfigRequest) =>
    api.put<VpnConfig>(`/vpn/configs/${id}`, data),

  // Delete a VPN config
  deleteConfig: (id: string) => api.delete(`/vpn/configs/${id}`),

  // Test a VPN connection
  testConfig: (id: string) =>
    api.post<VpnTestResult>(`/vpn/configs/${id}/test`),

  // Get current VPN status
  getStatus: () => api.get<VpnStatus>('/vpn/status'),

  // Connect to a VPN
  connect: (data: VpnConnectRequest) =>
    api.post<VpnStatus>('/vpn/connect', data),

  // Disconnect from VPN
  disconnect: () => api.post<{ message: string }>('/vpn/disconnect'),
};

// ============================================================================
// CRM API
// ============================================================================

export const crmAPI = {
  // Dashboard
  getDashboard: () => api.get<CrmDashboardStats>('/crm/dashboard'),

  // Customers
  customers: {
    getAll: (status?: string) => {
      const params = status ? `?status=${status}` : '';
      return api.get<Customer[]>(`/crm/customers${params}`);
    },
    getById: (id: string) => api.get<Customer>(`/crm/customers/${id}`),
    getSummary: (id: string) => api.get<CustomerSummary>(`/crm/customers/${id}/summary`),
    create: (data: CreateCustomerRequest) => api.post<Customer>('/crm/customers', data),
    update: (id: string, data: UpdateCustomerRequest) => api.put<Customer>(`/crm/customers/${id}`, data),
    delete: (id: string) => api.delete(`/crm/customers/${id}`),
  },

  // Contacts
  contacts: {
    getByCustomer: (customerId: string) => api.get<Contact[]>(`/crm/customers/${customerId}/contacts`),
    getById: (id: string) => api.get<Contact>(`/crm/contacts/${id}`),
    create: (customerId: string, data: CreateContactRequest) =>
      api.post<Contact>(`/crm/customers/${customerId}/contacts`, data),
    update: (id: string, data: UpdateContactRequest) => api.put<Contact>(`/crm/contacts/${id}`, data),
    delete: (id: string) => api.delete(`/crm/contacts/${id}`),
  },

  // Engagements
  engagements: {
    getAll: (status?: string) => {
      const params = status ? `?status=${status}` : '';
      return api.get<Engagement[]>(`/crm/engagements${params}`);
    },
    getByCustomer: (customerId: string, status?: string) => {
      const params = status ? `?status=${status}` : '';
      return api.get<Engagement[]>(`/crm/customers/${customerId}/engagements${params}`);
    },
    getById: (id: string) => api.get<Engagement>(`/crm/engagements/${id}`),
    create: (customerId: string, data: CreateEngagementRequest) =>
      api.post<Engagement>(`/crm/customers/${customerId}/engagements`, data),
    update: (id: string, data: UpdateEngagementRequest) =>
      api.put<Engagement>(`/crm/engagements/${id}`, data),
    delete: (id: string) => api.delete(`/crm/engagements/${id}`),
  },

  // Milestones
  milestones: {
    getByEngagement: (engagementId: string) =>
      api.get<EngagementMilestone[]>(`/crm/engagements/${engagementId}/milestones`),
    create: (engagementId: string, data: CreateMilestoneRequest) =>
      api.post<EngagementMilestone>(`/crm/engagements/${engagementId}/milestones`, data),
    update: (id: string, data: UpdateMilestoneRequest) =>
      api.put<EngagementMilestone>(`/crm/milestones/${id}`, data),
    delete: (id: string) => api.delete(`/crm/milestones/${id}`),
  },

  // Contracts
  contracts: {
    getAll: (status?: string) => {
      const params = status ? `?status=${status}` : '';
      return api.get<Contract[]>(`/crm/contracts${params}`);
    },
    getByCustomer: (customerId: string) =>
      api.get<Contract[]>(`/crm/customers/${customerId}/contracts`),
    getById: (id: string) => api.get<Contract>(`/crm/contracts/${id}`),
    create: (customerId: string, data: CreateContractRequest) =>
      api.post<Contract>(`/crm/customers/${customerId}/contracts`, data),
    update: (id: string, data: UpdateContractRequest) => api.put<Contract>(`/crm/contracts/${id}`, data),
    delete: (id: string) => api.delete(`/crm/contracts/${id}`),
  },

  // SLA
  sla: {
    getTemplates: () => api.get<SlaDefinition[]>('/crm/sla-templates'),
    createTemplate: (data: CreateSlaRequest) => api.post<SlaDefinition>('/crm/sla-templates', data),
    getByCustomer: (customerId: string) =>
      api.get<SlaDefinition | null>(`/crm/customers/${customerId}/sla`),
    setForCustomer: (customerId: string, data: CreateSlaRequest) =>
      api.post<SlaDefinition>(`/crm/customers/${customerId}/sla`, data),
    delete: (id: string) => api.delete(`/crm/sla/${id}`),
  },

  // Time Tracking
  timeEntries: {
    getAll: (startDate?: string, endDate?: string) => {
      const params = new URLSearchParams();
      if (startDate) params.append('start_date', startDate);
      if (endDate) params.append('end_date', endDate);
      const queryString = params.toString();
      return api.get<TimeEntry[]>(`/crm/time${queryString ? `?${queryString}` : ''}`);
    },
    getByEngagement: (engagementId: string) =>
      api.get<TimeEntry[]>(`/crm/engagements/${engagementId}/time`),
    create: (engagementId: string, data: CreateTimeEntryRequest) =>
      api.post<TimeEntry>(`/crm/engagements/${engagementId}/time`, data),
    delete: (id: string) => api.delete(`/crm/time/${id}`),
  },

  // Communications
  communications: {
    getByCustomer: (customerId: string, limit?: number) => {
      const params = limit ? `?limit=${limit}` : '';
      return api.get<Communication[]>(`/crm/customers/${customerId}/communications${params}`);
    },
    create: (customerId: string, data: CreateCommunicationRequest) =>
      api.post<Communication>(`/crm/customers/${customerId}/communications`, data),
    delete: (id: string) => api.delete(`/crm/communications/${id}`),
  },

  // Portal Users (CRM admin management)
  portalUsers: {
    getByCustomer: (customerId: string) =>
      api.get<CrmPortalUser[]>(`/crm/customers/${customerId}/portal-users`),
    getById: (customerId: string, userId: string) =>
      api.get<CrmPortalUser>(`/crm/customers/${customerId}/portal-users/${userId}`),
    create: (customerId: string, data: CreatePortalUserRequest) =>
      api.post<CrmPortalUser>(`/crm/customers/${customerId}/portal-users`, data),
    update: (customerId: string, userId: string, data: UpdatePortalUserRequest) =>
      api.put<CrmPortalUser>(`/crm/customers/${customerId}/portal-users/${userId}`, data),
    delete: (customerId: string, userId: string) =>
      api.delete(`/crm/customers/${customerId}/portal-users/${userId}`),
    activate: (customerId: string, userId: string) =>
      api.post<{ message: string }>(`/crm/customers/${customerId}/portal-users/${userId}/activate`),
    deactivate: (customerId: string, userId: string) =>
      api.post<{ message: string }>(`/crm/customers/${customerId}/portal-users/${userId}/deactivate`),
    resetPassword: (customerId: string, userId: string, data: ResetPortalUserPasswordRequest) =>
      api.post<{ message: string }>(`/crm/customers/${customerId}/portal-users/${userId}/reset-password`, data),
  },

  // Discovered Assets (auto-populated from recon scans)
  discoveredAssets: {
    getByCustomer: (customerId: string, params?: { asset_type?: string; is_in_scope?: boolean; limit?: number; offset?: number }) => {
      const queryParams = new URLSearchParams();
      if (params?.asset_type) queryParams.append('asset_type', params.asset_type);
      if (params?.is_in_scope !== undefined) queryParams.append('is_in_scope', String(params.is_in_scope));
      if (params?.limit) queryParams.append('limit', String(params.limit));
      if (params?.offset) queryParams.append('offset', String(params.offset));
      const qs = queryParams.toString();
      return api.get<CrmDiscoveredAsset[]>(`/crm/customers/${customerId}/discovered-assets${qs ? `?${qs}` : ''}`);
    },
    getSummary: (customerId: string) =>
      api.get<DiscoveredAssetsSummary>(`/crm/customers/${customerId}/discovered-assets/summary`),
    getById: (id: string) =>
      api.get<CrmDiscoveredAsset>(`/crm/discovered-assets/${id}`),
    create: (customerId: string, data: CreateDiscoveredAssetRequest) =>
      api.post<CrmDiscoveredAsset>(`/crm/customers/${customerId}/discovered-assets`, data),
    update: (id: string, data: UpdateDiscoveredAssetRequest) =>
      api.put<CrmDiscoveredAsset>(`/crm/discovered-assets/${id}`, data),
    delete: (id: string) =>
      api.delete(`/crm/discovered-assets/${id}`),
    bulkSetScope: (customerId: string, data: BulkScopeRequest) =>
      api.post<{ updated: number }>(`/crm/customers/${customerId}/discovered-assets/bulk-scope`, data),
  },
};

// ============================================================================
// Finding Templates API
// ============================================================================

export interface ListFindingTemplatesParams {
  category?: string;
  severity?: string;
  search?: string;
  include_system?: boolean;
}

export const findingTemplatesAPI = {
  // List all finding templates with optional filters
  list: (params?: ListFindingTemplatesParams) => {
    const queryParams = new URLSearchParams();
    if (params?.category) queryParams.append('category', params.category);
    if (params?.severity) queryParams.append('severity', params.severity);
    if (params?.search) queryParams.append('search', params.search);
    if (params?.include_system !== undefined) {
      queryParams.append('include_system', params.include_system.toString());
    }
    const query = queryParams.toString();
    return api.get<FindingTemplate[]>(`/finding-templates${query ? `?${query}` : ''}`);
  },

  // Get a single template by ID
  getById: (id: string) => api.get<FindingTemplate>(`/finding-templates/${id}`),

  // Create a new template
  create: (data: CreateFindingTemplateRequest) =>
    api.post<FindingTemplate>('/finding-templates', data),

  // Update an existing template
  update: (id: string, data: UpdateFindingTemplateRequest) =>
    api.put<FindingTemplate>(`/finding-templates/${id}`, data),

  // Delete a template
  delete: (id: string) => api.delete(`/finding-templates/${id}`),

  // Clone a template
  clone: (id: string, data?: CloneFindingTemplateRequest) =>
    api.post<FindingTemplate>(`/finding-templates/${id}/clone`, data || {}),

  // Get categories with counts
  getCategories: () => api.get<FindingTemplateCategory[]>('/finding-templates/categories'),

  // Enhanced Template Library Methods

  // Get all categories (hierarchical)
  getAllCategories: () => api.get<FindingTemplateCategoryFull[]>('/finding-templates/categories/all'),

  // Get popular templates
  getPopular: (limit = 10) => api.get<FindingTemplate[]>('/finding-templates/popular', { params: { limit } }),

  // Search templates with advanced filters
  search: (params: TemplateSearchQuery) => {
    const queryParams = new URLSearchParams();
    if (params.query) queryParams.append('q', params.query);
    if (params.category) queryParams.append('category', params.category);
    if (params.severity) queryParams.append('severity', params.severity);
    if (params.owasp) queryParams.append('owasp', params.owasp);
    if (params.mitre) queryParams.append('mitre', params.mitre);
    if (params.limit) queryParams.append('limit', params.limit.toString());
    if (params.offset) queryParams.append('offset', params.offset.toString());
    const query = queryParams.toString();
    return api.get<FindingTemplate[]>(`/finding-templates/search${query ? `?${query}` : ''}`);
  },

  // Get templates by OWASP category
  getByOwasp: (category: string) => api.get<FindingTemplate[]>(`/finding-templates/owasp/${encodeURIComponent(category)}`),

  // Get templates by MITRE ATT&CK technique
  getByMitre: (techniqueId: string) => api.get<FindingTemplate[]>(`/finding-templates/mitre/${encodeURIComponent(techniqueId)}`),

  // Import templates from JSON
  importTemplates: (data: ImportTemplatesRequest) =>
    api.post<ImportTemplatesResponse>('/finding-templates/import', data),

  // Export templates to JSON
  exportTemplates: (ids?: string[]) => {
    const params = ids?.length ? { ids: ids.join(',') } : {};
    return api.get<FindingTemplate[]>('/finding-templates/export', { params });
  },

  // Apply template to a vulnerability
  applyToVulnerability: (templateId: string, data: ApplyTemplateRequest) =>
    api.post<{ success: boolean; message: string }>(`/finding-templates/${templateId}/apply`, data),
};

// Methodology Checklists API
export const methodologyAPI = {
  // List all methodology templates (PTES, OWASP WSTG, etc.)
  listTemplates: () => api.get<MethodologyTemplate[]>('/methodology/templates'),

  // Get a single template with all its items
  getTemplate: (id: string) =>
    api.get<MethodologyTemplateWithItems>(`/methodology/templates/${id}`),

  // List all user's checklists
  listChecklists: () => api.get<ChecklistSummary[]>('/methodology/checklists'),

  // Create a new checklist from a template
  createChecklist: (data: CreateChecklistRequest) =>
    api.post<MethodologyChecklist>('/methodology/checklists', data),

  // Get a checklist with all items
  getChecklist: (id: string) =>
    api.get<ChecklistWithItems>(`/methodology/checklists/${id}`),

  // Update checklist metadata
  updateChecklist: (id: string, data: UpdateChecklistRequest) =>
    api.put<MethodologyChecklist>(`/methodology/checklists/${id}`, data),

  // Delete a checklist
  deleteChecklist: (id: string) => api.delete(`/methodology/checklists/${id}`),

  // Get checklist progress
  getProgress: (checklistId: string) =>
    api.get<ChecklistProgress>(`/methodology/checklists/${checklistId}/progress`),

  // Get a single checklist item
  getItem: (checklistId: string, itemId: string) =>
    api.get<ChecklistItem>(
      `/methodology/checklists/${checklistId}/items/${itemId}`
    ),

  // Update a checklist item
  updateItem: (
    checklistId: string,
    itemId: string,
    data: UpdateChecklistItemRequest
  ) =>
    api.put<ChecklistItem>(
      `/methodology/checklists/${checklistId}/items/${itemId}`,
      data
    ),

  // Get scanner info for a methodology item
  getScannerInfo: (itemCode: string) =>
    api.get<ScannerMapping>(`/methodology/items/${itemCode}/scanner-info`),

  // Exploit a checklist item (run automated test)
  exploitItem: (
    checklistId: string,
    itemId: string,
    data: ExploitItemRequest
  ) =>
    api.post<ExploitItemResponse>(
      `/methodology/checklists/${checklistId}/items/${itemId}/exploit`,
      data
    ),

  // List all scanner mappings
  listScannerMappings: () =>
    api.get<ScannerMapping[]>('/methodology/scanner-mappings'),
};

// ============================================================================
// Executive Analytics API
// ============================================================================

export const executiveAnalyticsAPI = {
  // Get security trends for a specific customer
  getCustomerTrends: (customerId: string, months = 6) =>
    api.get<CustomerSecurityTrends>(
      `/analytics/customer/${customerId}/trends`,
      { params: { months } }
    ),

  // Get executive summary for a specific customer
  getCustomerSummary: (customerId: string) =>
    api.get<ExecutiveSummary>(`/analytics/customer/${customerId}/summary`),

  // Get remediation velocity metrics
  getRemediationVelocity: (days = 90) =>
    api.get<RemediationVelocity>('/analytics/remediation-velocity', {
      params: { days },
    }),

  // Get risk trends
  getRiskTrends: (months = 6) =>
    api.get<RiskTrendPoint[]>('/analytics/risk-trends', {
      params: { months },
    }),

  // Get methodology coverage statistics
  getMethodologyCoverage: () =>
    api.get<MethodologyExecutiveCoverage>('/analytics/methodology-coverage'),

  // Get combined executive dashboard data
  getExecutiveDashboard: (customerId?: string, months = 6) =>
    api.get<ExecutiveDashboard>('/analytics/executive-dashboard', {
      params: { customer_id: customerId, months },
    }),
};

// ============================================================================
// Threat Intelligence API
// ============================================================================

import type {
  ThreatAlert,
  IpThreatIntel,
  EnrichedCve,
  ThreatIntelApiStatus,
  EnrichmentResult,
  EnrichScanRequest,
} from '../types';

export const threatIntelAPI = {
  // Get API status and quota info
  getStatus: () => api.get<ThreatIntelApiStatus>('/threat-intel/status'),

  // Look up threat intel for an IP address
  lookupIp: (ip: string) => api.get<IpThreatIntel>(`/threat-intel/lookup/${ip}`),

  // Get enriched CVE data with exploit info
  lookupCve: (cveId: string) => api.get<EnrichedCve>(`/threat-intel/cve/${cveId}`),

  // Get recent threat alerts
  getAlerts: (params?: { limit?: number; scan_id?: string; severity?: string }) =>
    api.get<{ alerts: ThreatAlert[]; total: number }>('/threat-intel/alerts', { params }),

  // Acknowledge an alert
  acknowledgeAlert: (alertId: string) =>
    api.post(`/threat-intel/alerts/${alertId}/acknowledge`),

  // Enrich a scan with threat intelligence
  enrichScan: (scanId: string, options?: EnrichScanRequest) =>
    api.post<EnrichmentResult>(`/threat-intel/enrich/${scanId}`, options || {}),

  // Get enrichment results for a scan
  getEnrichment: (scanId: string) =>
    api.get<EnrichmentResult>(`/threat-intel/scan/${scanId}/enrichment`),
};

// ============================================================================
// Attack Path Analysis API
// ============================================================================

import type {
  AnalyzeAttackPathsRequest,
  AnalyzeAttackPathsResponse,
  GetAttackPathsResponse,
  AttackPath,
  InterpretAttackPathRequest,
  AttackPathInterpretation,
} from '../types';

export const attackPathsAPI = {
  // Analyze a scan for attack paths
  analyze: (scanId: string, options?: AnalyzeAttackPathsRequest) =>
    api.post<AnalyzeAttackPathsResponse>(
      `/attack-paths/analyze/${scanId}`,
      options || {}
    ),

  // Get all attack paths for a scan
  getByScan: (scanId: string) =>
    api.get<GetAttackPathsResponse>(`/attack-paths/${scanId}`),

  // Get critical attack paths only
  getCritical: (scanId: string) =>
    api.get<GetAttackPathsResponse>(`/attack-paths/${scanId}/critical`),

  // Get a single attack path with full details
  getPath: (pathId: string) =>
    api.get<AttackPath>(`/attack-paths/path/${pathId}`),

  // Generate AI interpretation for an attack path
  interpretPath: (pathId: string, options?: InterpretAttackPathRequest) =>
    api.post<AttackPathInterpretation>(
      `/attack-paths/path/${pathId}/interpret`,
      options || {}
    ),

  // Get existing AI interpretation for an attack path
  getInterpretation: (pathId: string) =>
    api.get<AttackPathInterpretation>(`/attack-paths/path/${pathId}/interpretation`),
};

// ============================================================================
// API Security Scanning API
// ============================================================================

export interface StartApiScanRequest {
  name: string;
  target_url: string;
  spec_type?: string;
  spec_content?: string;
  auth_config?: {
    auth_type: string;
    credentials: Record<string, string>;
  };
  scan_options?: {
    test_auth_bypass?: boolean;
    test_injection?: boolean;
    test_rate_limit?: boolean;
    test_cors?: boolean;
    test_bola?: boolean;
    test_bfla?: boolean;
    discover_endpoints?: boolean;
  };
  customer_id?: string;
  engagement_id?: string;
}

export interface DiscoverEndpointsRequest {
  target_url: string;
  spec_type?: string;
  spec_content?: string;
}

export const apiSecurityAPI = {
  // Start a new API security scan
  startScan: (data: StartApiScanRequest) =>
    api.post('/api-security/scans', data),

  // List all API scans for the current user
  listScans: () => api.get('/api-security/scans'),

  // Get scan details by ID
  getScan: (scanId: string) => api.get(`/api-security/scans/${scanId}`),

  // Delete a scan
  deleteScan: (scanId: string) => api.delete(`/api-security/scans/${scanId}`),

  // Get findings for a scan
  getFindings: (scanId: string) =>
    api.get(`/api-security/scans/${scanId}/findings`),

  // Get discovered endpoints for a scan
  getEndpoints: (scanId: string) =>
    api.get(`/api-security/scans/${scanId}/endpoints`),

  // Discover API endpoints from a URL or spec
  discoverEndpoints: (data: DiscoverEndpointsRequest) =>
    api.post('/api-security/discover', data),

  // Get API security statistics
  getStats: () => api.get('/api-security/stats'),
};

// ============================================================================
// Asset Tags API
// ============================================================================

export const assetTagsAPI = {
  // Get all asset tags with usage counts
  getTags: () =>
    api.get<AssetTagWithCount[]>('/assets/tags'),

  // Create a new asset tag
  createTag: (data: CreateAssetTagRequest) =>
    api.post<AssetTag>('/assets/tags', data),

  // Get a specific tag by ID
  getTag: (tagId: string) =>
    api.get<AssetTag>(`/assets/tags/${tagId}`),

  // Update an existing tag
  updateTag: (tagId: string, data: UpdateAssetTagRequest) =>
    api.put<AssetTag>(`/assets/tags/${tagId}`, data),

  // Delete a tag
  deleteTag: (tagId: string) =>
    api.delete(`/assets/tags/${tagId}`),

  // Get all assets (with optional filters)
  getAssets: (params?: { status?: string; tag_ids?: string }) =>
    api.get<Asset[]>('/assets', { params }),

  // Get all assets with their tags (for displaying tag badges)
  getAssetsWithTags: (params?: { status?: string; tag_ids?: string; group_id?: string }) =>
    api.get<AssetWithTags[]>('/assets/with-tags', { params }),

  // Get assets filtered by tags
  getAssetsByTags: (params?: { status?: string; tag_ids?: string }) =>
    api.get<Asset[]>('/assets/by-tags', { params }),

  // Get a specific asset with tags
  getAsset: (assetId: string) =>
    api.get<AssetDetailWithTags>(`/assets/${assetId}`),

  // Add tags to an asset
  addTagsToAsset: (assetId: string, data: AddAssetTagsRequest) =>
    api.post<AssetDetailWithTags>(`/assets/${assetId}/tags`, data),

  // Remove a tag from an asset
  removeTagFromAsset: (assetId: string, tagId: string) =>
    api.delete<AssetDetailWithTags>(`/assets/${assetId}/tags/${tagId}`),

  // Update asset
  updateAsset: (assetId: string, data: { status?: string; tags?: string[]; notes?: string }) =>
    api.patch<Asset>(`/assets/${assetId}`, data),

  // Delete asset
  deleteAsset: (assetId: string) =>
    api.delete(`/assets/${assetId}`),

  // Get asset history
  getAssetHistory: (assetId: string) =>
    api.get(`/assets/${assetId}/history`),

  // Get asset with full details (tags and groups)
  getAssetFull: (assetId: string) =>
    api.get<AssetDetailFull>(`/assets/${assetId}/full`),
};

// Asset Groups API
export const assetGroupsAPI = {
  // Get all asset groups with member counts
  getGroups: () =>
    api.get<AssetGroupWithCount[]>('/asset-groups'),

  // Create a new asset group
  createGroup: (data: CreateAssetGroupRequest) =>
    api.post<AssetGroup>('/asset-groups', data),

  // Get a specific group by ID with its members
  getGroup: (groupId: string) =>
    api.get<AssetGroupWithMembers>(`/asset-groups/${groupId}`),

  // Update an existing group
  updateGroup: (groupId: string, data: UpdateAssetGroupRequest) =>
    api.put<AssetGroup>(`/asset-groups/${groupId}`, data),

  // Delete a group
  deleteGroup: (groupId: string) =>
    api.delete<{ message: string }>(`/asset-groups/${groupId}`),

  // Add assets to a group
  addAssetsToGroup: (groupId: string, data: AddAssetsToGroupRequest) =>
    api.post<AssetGroupWithMembers>(`/asset-groups/${groupId}/members`, data),

  // Remove an asset from a group
  removeAssetFromGroup: (groupId: string, assetId: string) =>
    api.delete<AssetGroupWithMembers>(`/asset-groups/${groupId}/members/${assetId}`),

  // Get assets filtered by group
  getAssetsByGroup: (params: { group_id: string; status?: string }) =>
    api.get<Asset[]>('/asset-groups/assets', { params }),

  // Bulk add assets to a group
  bulkAddAssetsToGroup: (groupId: string, data: AddAssetsToGroupRequest) =>
    api.post<BulkAddToGroupResponse>(`/asset-groups/${groupId}/bulk-add`, data),
};

// Exclusion validation types
interface ValidateExclusionRequest {
  exclusion_type: string;
  value: string;
}

interface ValidateExclusionResponse {
  valid: boolean;
  error: string | null;
  normalized_value: string | null;
}

// Bulk import types
interface BulkImportExclusionsRequest {
  exclusion_type: string;
  values: string;
  is_global: boolean;
  name_prefix?: string;
}

interface BulkImportExclusionsResponse {
  imported: number;
  failed: number;
  errors: string[];
  created: ScanExclusion[];
}

// Scan Exclusions API
export const exclusionsAPI = {
  // Get all exclusions for current user
  getAll: () => api.get<ScanExclusion[]>('/exclusions'),

  // Get global exclusions only
  getGlobal: () => api.get<ScanExclusion[]>('/exclusions/global'),

  // Get a specific exclusion
  get: (id: string) => api.get<ScanExclusion>(`/exclusions/${id}`),

  // Create a new exclusion
  create: (data: CreateExclusionRequest) =>
    api.post<ScanExclusion>('/exclusions', data),

  // Update an exclusion
  update: (id: string, data: UpdateExclusionRequest) =>
    api.put<ScanExclusion>(`/exclusions/${id}`, data),

  // Delete an exclusion
  delete: (id: string) =>
    api.delete<{ message: string }>(`/exclusions/${id}`),

  // Validate an exclusion value without creating it
  validate: (data: ValidateExclusionRequest) =>
    api.post<ValidateExclusionResponse>('/exclusions/validate', data),

  // Bulk import exclusions from a list
  bulkImport: (data: BulkImportExclusionsRequest) =>
    api.post<BulkImportExclusionsResponse>('/exclusions/bulk-import', data),
};

// Webhooks API
// Secret Findings API
export const secretFindingsAPI = {
  // List all secret findings with optional filters
  list: (params?: {
    scan_id?: string;
    host_ip?: string;
    secret_type?: string;
    severity?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }) => api.get<SecretFinding[]>('/secrets', { params }),

  // Get secret findings for a specific scan
  getByScan: (scanId: string) =>
    api.get<SecretFinding[]>(`/scans/${scanId}/secrets`),

  // Get statistics for secret findings
  getStats: (scanId?: string) =>
    api.get<SecretFindingStats>('/secrets/stats', {
      params: scanId ? { scan_id: scanId } : undefined,
    }),

  // Get a single secret finding
  get: (id: string) => api.get<SecretFinding>(`/secrets/${id}`),

  // Update a secret finding
  update: (id: string, data: UpdateSecretFindingRequest) =>
    api.patch<SecretFinding>(`/secrets/${id}`, data),

  // Bulk update status
  bulkUpdateStatus: (ids: string[], status: string) =>
    api.post<BulkUpdateSecretsResponse>('/secrets/bulk-status', { ids, status }),
};

export const webhooksAPI = {
  // Get all webhooks for current user
  list: () => api.get<Webhook[]>('/webhooks'),

  // Get a specific webhook
  get: (id: string) => api.get<Webhook>(`/webhooks/${id}`),

  // Create a new webhook
  create: (data: CreateWebhookRequest) =>
    api.post<Webhook>('/webhooks', data),

  // Update a webhook
  update: (id: string, data: UpdateWebhookRequest) =>
    api.put<Webhook>(`/webhooks/${id}`, data),

  // Delete a webhook
  delete: (id: string) =>
    api.delete(`/webhooks/${id}`),

  // Get available event types
  getEventTypes: () =>
    api.get<{ event_types: WebhookEventTypeInfo[] }>('/webhooks/event-types'),

  // Generate a random secret
  generateSecret: () =>
    api.post<GenerateSecretResponse>('/webhooks/generate-secret'),

  // Test a webhook
  test: (id: string) =>
    api.post<WebhookTestResponse>(`/webhooks/${id}/test`),

  // Get delivery history for a webhook
  getDeliveries: (id: string, limit?: number) =>
    api.get<WebhookDelivery[]>(`/webhooks/${id}/deliveries`, {
      params: { limit },
    }),

  // Get statistics for a webhook
  getStats: (id: string) =>
    api.get<WebhookStats>(`/webhooks/${id}/stats`),
};

// ============================================================================
// AI Vulnerability Prioritization API
// ============================================================================

import type {
  AIPrioritizationResult,
  AIVulnerabilityScore,
  AIModelConfig,
  PrioritizeRequest,
  UpdateAIConfigRequest,
  SubmitAIFeedbackRequest,
} from '../types';

export const aiAPI = {
  // Calculate AI prioritization scores for a scan
  prioritize: (scanId: string, data?: PrioritizeRequest) =>
    api.post<AIPrioritizationResult>(`/ai/prioritize/${scanId}`, data || {}),

  // Get existing prioritization scores for a scan
  getScores: (scanId: string) =>
    api.get<AIPrioritizationResult>(`/ai/scores/${scanId}`),

  // Get score breakdown for a specific vulnerability
  getVulnerabilityScore: (vulnId: string) =>
    api.get<AIVulnerabilityScore>(`/ai/scores/vulnerability/${vulnId}`),

  // Get current AI model configuration
  getConfig: () =>
    api.get<AIModelConfig>('/ai/config'),

  // Update AI model configuration (admin only)
  updateConfig: (data: UpdateAIConfigRequest) =>
    api.put<AIModelConfig>('/ai/config', data),

  // Submit feedback for AI learning
  submitFeedback: (data: SubmitAIFeedbackRequest) =>
    api.post<{ message: string }>('/ai/feedback', data),
};

// ============================================================================
// AI Settings API (LLM Provider Configuration)
// ============================================================================

import type {
  AiConfigurationResponse,
  UpdateAiConfigurationRequest,
  ProviderStatusResponse,
  TestConnectionResponse,
  AvailableModelsResponse,
} from '../types';

export const aiSettingsAPI = {
  // Get current AI configuration
  getConfiguration: () =>
    api.get<AiConfigurationResponse>('/ai-settings'),

  // Update AI configuration
  updateConfiguration: (data: UpdateAiConfigurationRequest) =>
    api.put<AiConfigurationResponse>('/ai-settings', data),

  // Test AI connection
  testConnection: () =>
    api.post<TestConnectionResponse>('/ai-settings/test'),

  // Get status of all configured providers
  getProviders: () =>
    api.get<ProviderStatusResponse[]>('/ai-settings/providers'),

  // Get available models for each provider
  getModels: () =>
    api.get<AvailableModelsResponse>('/ai-settings/models'),
};

// ============================================================================
// AI Red Team Advisor API
// ============================================================================

import type {
  AiRedTeamRecommendation,
  AnalyzeTopologyRequest,
  RedTeamAnalysisResult,
  UpdateRecommendationStatusRequest,
  RecommendationsSummary,
  BulkActionResult,
  GetRecommendationsQuery,
} from '../types';

export const redTeamAdvisorAPI = {
  // Analyze topology and generate AI recommendations
  analyzeTopology: (data: AnalyzeTopologyRequest) =>
    api.post<RedTeamAnalysisResult>('/red-team-advisor/analyze', data),

  // Get recommendations (with optional filters)
  getRecommendations: (params?: GetRecommendationsQuery) =>
    api.get<AiRedTeamRecommendation[]>('/red-team-advisor/recommendations', { params }),

  // Get recommendations summary
  getSummary: (params?: { topology_id?: string; scan_id?: string }) =>
    api.get<RecommendationsSummary>('/red-team-advisor/summary', { params }),

  // Update recommendation status (accept/reject)
  updateStatus: (id: string, data: UpdateRecommendationStatusRequest) =>
    api.put<AiRedTeamRecommendation>(`/red-team-advisor/recommendations/${id}/status`, data),

  // Accept a single recommendation
  accept: (id: string) =>
    api.put<AiRedTeamRecommendation>(`/red-team-advisor/recommendations/${id}/status`, { status: 'accepted' }),

  // Reject a single recommendation
  reject: (id: string) =>
    api.put<AiRedTeamRecommendation>(`/red-team-advisor/recommendations/${id}/status`, { status: 'rejected' }),

  // Accept all pending recommendations
  acceptAll: (topologyId?: string) =>
    api.post<BulkActionResult>('/red-team-advisor/recommendations/accept-all', null, {
      params: topologyId ? { topology_id: topologyId } : undefined,
    }),

  // Reject all pending recommendations
  rejectAll: (topologyId?: string) =>
    api.post<BulkActionResult>('/red-team-advisor/recommendations/reject-all', null, {
      params: topologyId ? { topology_id: topologyId } : undefined,
    }),
};

// ============================================================================
// Agent-Based Scanning API
// ============================================================================

import type {
  AgentWithGroups,
  AgentGroup,
  AgentGroupWithCount,
  AgentGroupWithAgents,
  AgentStats,
  AgentHeartbeat,
  AgentTask,
  AgentMeshConfig,
  AgentMeshPeerData,
  MeshClusterWithMembers,
  RegisterAgentRequest,
  RegisterAgentResponse,
  UpdateAgentRequest,
  CreateAgentGroupRequest,
  UpdateAgentGroupRequest,
  AssignAgentsToGroupRequest,
  CreateMeshClusterRequest,
  UpdateMeshClusterRequest,
  UpdateMeshConfigRequest,
} from '../types';

export const agentAPI = {
  // Register a new agent
  register: (data: RegisterAgentRequest) =>
    api.post<RegisterAgentResponse>('/agents/register', data),

  // List all agents
  list: () =>
    api.get<AgentWithGroups[]>('/agents'),

  // Get agent by ID
  get: (id: string) =>
    api.get<AgentWithGroups>(`/agents/${id}`),

  // Update an agent
  update: (id: string, data: UpdateAgentRequest) =>
    api.put<AgentWithGroups>(`/agents/${id}`, data),

  // Delete an agent
  delete: (id: string) =>
    api.delete(`/agents/${id}`),

  // Get agent statistics
  getStats: () =>
    api.get<AgentStats>('/agents/stats'),

  // Regenerate agent token
  regenerateToken: (id: string) =>
    api.post<{ token: string; token_prefix: string }>(`/agents/${id}/regenerate-token`),

  // Get agent heartbeat history
  getHeartbeats: (id: string, limit?: number) =>
    api.get<AgentHeartbeat[]>(`/agents/${id}/heartbeats`, {
      params: { limit },
    }),

  // Agent groups
  groups: {
    // List all groups
    list: () =>
      api.get<AgentGroupWithCount[]>('/agents/groups'),

    // Get group by ID
    get: (id: string) =>
      api.get<AgentGroupWithAgents>(`/agents/groups/${id}`),

    // Create a new group
    create: (data: CreateAgentGroupRequest) =>
      api.post<AgentGroup>('/agents/groups', data),

    // Update a group
    update: (id: string, data: UpdateAgentGroupRequest) =>
      api.put<AgentGroup>(`/agents/groups/${id}`, data),

    // Delete a group
    delete: (id: string) =>
      api.delete(`/agents/groups/${id}`),

    // Assign agents to group
    assignAgents: (groupId: string, data: AssignAgentsToGroupRequest) =>
      api.put(`/agents/groups/${groupId}/agents`, data),

    // Remove agent from group
    removeAgent: (groupId: string, agentId: string) =>
      api.delete(`/agents/groups/${groupId}/agents/${agentId}`),
  },

  // Task management
  tasks: {
    // List all tasks
    list: (params?: { limit?: number; status?: string }) =>
      api.get<AgentTask[]>('/agents/tasks', { params }),

    // Get tasks for a specific agent
    getForAgent: (agentId: string) =>
      api.get<AgentTask[]>(`/agents/${agentId}/tasks`),
  },

  // Mesh networking
  mesh: {
    // Get mesh peers for all user agents
    getPeers: () =>
      api.get<AgentMeshPeerData[]>('/agents/mesh/peers'),

    // Get all clusters
    getClusters: () =>
      api.get<MeshClusterWithMembers[]>('/agents/mesh/clusters'),

    // Create a new cluster
    createCluster: (data: CreateMeshClusterRequest) =>
      api.post<MeshClusterWithMembers>('/agents/mesh/clusters', data),

    // Get a cluster by ID
    getCluster: (id: string) =>
      api.get<MeshClusterWithMembers>(`/agents/mesh/clusters/${id}`),

    // Update a cluster
    updateCluster: (id: string, data: UpdateMeshClusterRequest) =>
      api.put<MeshClusterWithMembers>(`/agents/mesh/clusters/${id}`, data),

    // Delete a cluster
    deleteCluster: (id: string) =>
      api.delete(`/agents/mesh/clusters/${id}`),

    // Add agent to cluster
    addAgentToCluster: (clusterId: string, agentId: string) =>
      api.post(`/agents/mesh/clusters/${clusterId}/agents/${agentId}`),

    // Remove agent from cluster
    removeAgentFromCluster: (clusterId: string, agentId: string) =>
      api.delete(`/agents/mesh/clusters/${clusterId}/agents/${agentId}`),

    // Get mesh config for an agent
    getAgentConfig: (agentId: string) =>
      api.get<AgentMeshConfig | null>(`/agents/${agentId}/mesh`),

    // Update mesh config for an agent
    updateAgentConfig: (agentId: string, data: UpdateMeshConfigRequest) =>
      api.put<AgentMeshConfig>(`/agents/${agentId}/mesh`, data),
  },
};

// ============================================================================
// SSO (SAML/OIDC) API
// ============================================================================

import type {
  SsoProviderForLogin,
  SsoProvider,
  SsoProviderPreset,
  SsoMetadata,
  SsoLoginResponse,
  SsoTestResult,
  CreateSsoProviderRequest,
  UpdateSsoProviderRequest,
  UpdateMappingsRequest,
  SamlConfig,
} from '../types';

export const ssoAPI = {
  // Public endpoints (for login page)
  getProvidersForLogin: () =>
    api.get<SsoProviderForLogin[]>('/sso/providers'),

  initiateLogin: (providerId: string) =>
    api.get<SsoLoginResponse>(`/sso/login/${providerId}`),

  // Admin endpoints
  admin: {
    // List all providers
    listProviders: () =>
      api.get<SsoProvider[]>('/sso/admin/providers'),

    // Get provider by ID
    getProvider: (id: string) =>
      api.get<SsoProvider>(`/sso/admin/providers/${id}`),

    // Create provider
    createProvider: (data: CreateSsoProviderRequest) =>
      api.post<SsoProvider>('/sso/admin/providers', data),

    // Update provider
    updateProvider: (id: string, data: UpdateSsoProviderRequest) =>
      api.put<SsoProvider>(`/sso/admin/providers/${id}`, data),

    // Delete provider
    deleteProvider: (id: string) =>
      api.delete(`/sso/admin/providers/${id}`),

    // Get provider presets (templates for common IdPs)
    getPresets: () =>
      api.get<SsoProviderPreset[]>('/sso/admin/presets'),

    // Get SP metadata for a provider
    getMetadata: (id: string) =>
      api.get<SsoMetadata>(`/sso/admin/providers/${id}/metadata`),

    // Download SP metadata XML (SAML only)
    downloadMetadataXml: (id: string) =>
      api.get(`/sso/admin/providers/${id}/metadata.xml`, {
        responseType: 'blob',
      }),

    // Update attribute/group mappings
    updateMappings: (id: string, data: UpdateMappingsRequest) =>
      api.put<SsoProvider>(`/sso/admin/providers/${id}/mappings`, data),

    // Test provider connection
    testProvider: (id: string) =>
      api.post<SsoTestResult>(`/sso/admin/providers/${id}/test`),

    // Parse IdP metadata (SAML)
    parseMetadata: (metadata_xml: string) =>
      api.post<SamlConfig>('/sso/admin/parse-metadata', { metadata_xml }),
  },

  // Logout (authenticated)
  logout: (logoutFromIdp?: boolean) =>
    api.post<{ success: boolean; idp_logout_url?: string }>('/sso/logout', {
      logout_from_idp: logoutFromIdp,
    }),
};

// ============================================================================
// CI/CD Integration API
// ============================================================================

import type {
  CiCdToken,
  CreateCiCdTokenRequest,
  CreateCiCdTokenResponse,
  QualityGate,
  CreateQualityGateRequest,
  UpdateQualityGateRequest,
  CiCdRun,
  CiCdScanRequest,
  QualityGateResult,
  PipelineExample,
} from '../types';

export const cicdQualityGateAPI = {
  // Token Management
  tokens: {
    // Get all CI/CD tokens for the current user
    list: () => api.get<CiCdToken[]>('/cicd/tokens'),

    // Create a new CI/CD token
    create: (data: CreateCiCdTokenRequest) =>
      api.post<CreateCiCdTokenResponse>('/cicd/tokens', data),

    // Delete a CI/CD token
    delete: (id: string) =>
      api.delete<{ message: string }>(`/cicd/tokens/${id}`),
  },

  // Quality Gates
  qualityGates: {
    // Get all quality gates
    list: () => api.get<QualityGate[]>('/cicd/quality-gates'),

    // Get the default quality gate
    getDefault: () => api.get<QualityGate>('/cicd/quality-gates/default'),

    // Get a specific quality gate
    get: (id: string) => api.get<QualityGate>(`/cicd/quality-gates/${id}`),

    // Create a new quality gate
    create: (data: CreateQualityGateRequest) =>
      api.post<QualityGate>('/cicd/quality-gates', data),

    // Update a quality gate
    update: (id: string, data: UpdateQualityGateRequest) =>
      api.put<QualityGate>(`/cicd/quality-gates/${id}`, data),

    // Delete a quality gate
    delete: (id: string) =>
      api.delete<{ message: string }>(`/cicd/quality-gates/${id}`),
  },

  // CI/CD Runs
  runs: {
    // Get recent CI/CD runs
    list: (limit?: number) =>
      api.get<CiCdRun[]>('/cicd/runs', { params: { limit } }),

    // Get a specific run
    get: (id: string) => api.get<CiCdRun>(`/cicd/runs/${id}`),

    // Trigger a new scan from CI/CD
    trigger: (data: CiCdScanRequest) =>
      api.post<CiCdRun>('/cicd/scan', data),

    // Get the status of a run
    getStatus: (id: string) =>
      api.get<CiCdRun>(`/cicd/runs/${id}/status`),

    // Get quality gate result for a run
    getQualityGateResult: (runId: string) =>
      api.get<QualityGateResult>(`/cicd/runs/${runId}/quality-gate`),
  },

  // Reports
  reports: {
    // Get SARIF report for a scan (GitHub Security tab format)
    getSarif: (scanId: string) =>
      api.get(`/cicd/scans/${scanId}/sarif`, { responseType: 'blob' }),

    // Get JUnit XML report for a scan (Jenkins format)
    getJunit: (scanId: string) =>
      api.get(`/cicd/scans/${scanId}/junit`, { responseType: 'blob' }),

    // Get GitLab Security Report
    getGitLabSecurity: (scanId: string) =>
      api.get(`/cicd/scans/${scanId}/gitlab-security`, { responseType: 'blob' }),

    // Get GitLab Code Quality Report
    getGitLabQuality: (scanId: string) =>
      api.get(`/cicd/scans/${scanId}/gitlab-quality`, { responseType: 'blob' }),
  },

  // Pipeline Examples
  examples: {
    // Get pipeline example for a platform
    get: (platform: string) =>
      api.get<PipelineExample>(`/cicd/examples/${platform}`),

    // Get all pipeline examples
    list: () => api.get<PipelineExample[]>('/cicd/examples'),
  },
};

// ============================================================================
// Container/K8s Security Scanning API
// ============================================================================

export const containerAPI = {
  // List all container scans
  listScans: (params?: { scan_type?: string; status?: string; limit?: number; offset?: number }) =>
    api.get<ContainerScanListResponse>('/container/scans', { params }),

  // Get a specific scan with summary
  getScan: (id: string) =>
    api.get<ContainerScanDetailResponse>(`/container/scans/${id}`),

  // Create a new container scan
  createScan: (data: CreateContainerScanRequest) =>
    api.post<ContainerScan>('/container/scans', data),

  // Delete a container scan
  deleteScan: (id: string) =>
    api.delete<{ message: string }>(`/container/scans/${id}`),

  // Get findings for a scan
  getFindings: (scanId: string, params?: { severity?: string; finding_type?: string; status?: string }) =>
    api.get<ContainerFinding[]>(`/container/scans/${scanId}/findings`, { params }),

  // Get images for a scan
  getImages: (scanId: string) =>
    api.get<ContainerImage[]>(`/container/scans/${scanId}/images`),

  // Get K8s resources for a scan
  getResources: (scanId: string) =>
    api.get<K8sResource[]>(`/container/scans/${scanId}/resources`),

  // Update finding status
  updateFindingStatus: (findingId: string, data: UpdateContainerFindingStatusRequest) =>
    api.patch<ContainerFinding>(`/container/findings/${findingId}/status`, data),

  // Analyze a Dockerfile (without creating a full scan)
  analyzeDockerfile: (data: AnalyzeDockerfileRequest) =>
    api.post<DockerfileAnalysis>('/container/analyze-dockerfile', data),

  // Analyze K8s manifests (without creating a full scan)
  analyzeManifest: (data: AnalyzeK8sManifestRequest) =>
    api.post<K8sManifestAnalysis>('/container/analyze-manifest', data),

  // Get available scan types with descriptions
  getScanTypes: () =>
    api.get<ContainerScanTypeInfo[]>('/container/scan-types'),
};

// ============================================================================
// Remediation Workflow API
// ============================================================================

export const workflowAPI = {
  // Template management
  templates: {
    // Get all workflow templates
    list: () => api.get<WorkflowTemplate[]>('/workflows/templates'),

    // Get a specific template with stages
    get: (id: string) => api.get<WorkflowTemplateWithStages>(`/workflows/templates/${id}`),

    // Create a new template
    create: (data: CreateWorkflowTemplateRequest) =>
      api.post<WorkflowTemplateWithStages>('/workflows/templates', data),

    // Update a template
    update: (id: string, data: UpdateWorkflowTemplateRequest) =>
      api.put<WorkflowTemplateWithStages>(`/workflows/templates/${id}`, data),

    // Delete a template
    delete: (id: string) =>
      api.delete<{ message: string }>(`/workflows/templates/${id}`),
  },

  // Workflow instance management
  instances: {
    // List all workflow instances
    list: (params?: { status?: string; vulnerability_id?: string }) => {
      const queryParams = new URLSearchParams();
      if (params?.status) queryParams.append('status', params.status);
      if (params?.vulnerability_id) queryParams.append('vulnerability_id', params.vulnerability_id);
      const query = queryParams.toString();
      return api.get<WorkflowInstance[]>(`/workflows/instances${query ? `?${query}` : ''}`);
    },

    // Get a specific instance with full details
    get: (id: string) => api.get<WorkflowInstanceDetail>(`/workflows/instances/${id}`),

    // Start a workflow for a vulnerability
    start: (vulnerabilityId: string, data: StartWorkflowRequest) =>
      api.post<WorkflowInstance>(`/vulnerabilities/${vulnerabilityId}/workflow`, data),

    // Update a workflow instance (e.g., put on hold)
    update: (id: string, data: UpdateWorkflowRequest) =>
      api.put<WorkflowInstance>(`/workflows/instances/${id}`, data),

    // Cancel a workflow
    cancel: (id: string, comment?: string) =>
      api.post<WorkflowInstance>(`/workflows/instances/${id}/cancel`, { comment }),

    // Put a workflow on hold
    hold: (id: string, notes?: string) =>
      api.post<WorkflowInstance>(`/workflows/instances/${id}/hold`, { notes }),

    // Resume a workflow from hold
    resume: (id: string) =>
      api.post<WorkflowInstance>(`/workflows/instances/${id}/resume`),
  },

  // Stage actions
  stages: {
    // Approve the current stage
    approve: (instanceId: string, data?: ApproveWorkflowRequest) =>
      api.post<WorkflowInstance>(`/workflows/instances/${instanceId}/approve`, data || {}),

    // Advance to the next stage (for non-approval stages)
    advance: (instanceId: string, comment?: string) =>
      api.post<WorkflowInstance>(`/workflows/instances/${instanceId}/advance`, { comment }),

    // Reject the current stage
    reject: (instanceId: string, data: RejectWorkflowRequest) =>
      api.post<WorkflowInstance>(`/workflows/instances/${instanceId}/reject`, data),
  },

  // Dashboard and approvals
  // Get pending approvals for the current user
  getPendingApprovals: () => api.get<PendingApproval[]>('/workflows/pending-approvals'),

  // Get workflow statistics
  getStats: () => api.get<WorkflowStats>('/workflows/stats'),

  // Get workflow for a specific vulnerability
  getForVulnerability: (vulnerabilityId: string) =>
    api.get<WorkflowInstanceDetail | null>(`/vulnerabilities/${vulnerabilityId}/workflow`),
};

// ============================================================================
// IaC (Infrastructure-as-Code) Security Scanning API
// ============================================================================

export const iacAPI = {
  // Create a new IaC scan from uploaded files
  createScan: (formData: FormData) =>
    api.post<{ id: string; message: string }>('/iac/scan', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),

  // List all IaC scans
  listScans: (params?: { limit?: number; offset?: number; status?: string }) =>
    api.get<IacScan[]>('/iac/scans', { params }),

  // Get a specific scan with details
  getScan: (id: string) =>
    api.get<IacScanDetailResponse>(`/iac/scans/${id}`),

  // Delete an IaC scan
  deleteScan: (id: string) =>
    api.delete<{ message: string }>(`/iac/scans/${id}`),

  // Get findings for a scan
  getFindings: (scanId: string) =>
    api.get<IacFinding[]>(`/iac/scans/${scanId}/findings`),

  // Get files for a scan
  getFiles: (scanId: string) =>
    api.get<IacFile[]>(`/iac/scans/${scanId}/files`),

  // Get a specific file with content
  getFile: (fileId: string) =>
    api.get<IacFile>(`/iac/files/${fileId}`),

  // Get findings for a specific file
  getFileFindings: (fileId: string) =>
    api.get<IacFinding[]>(`/iac/files/${fileId}/findings`),

  // Update finding status
  updateFindingStatus: (findingId: string, data: UpdateIacFindingStatusRequest) =>
    api.patch<{ message: string; status: string }>(`/iac/findings/${findingId}/status`, data),

  // Analyze a file immediately (without creating a scan)
  analyzeFile: (data: IacAnalyzeFileRequest) =>
    api.post<IacAnalyzeFileResponse>('/iac/analyze', data),

  // List security rules (builtin + user's custom)
  listRules: () =>
    api.get<IacRule[]>('/iac/rules'),

  // Create a custom rule
  createRule: (data: CreateIacRuleRequest) =>
    api.post<IacRule>('/iac/rules', data),

  // Update a custom rule
  updateRule: (id: string, data: UpdateIacRuleRequest) =>
    api.put<IacRule>(`/iac/rules/${id}`, data),

  // Delete a custom rule
  deleteRule: (id: string) =>
    api.delete<{ message: string }>(`/iac/rules/${id}`),

  // Get supported platforms
  getPlatforms: () =>
    api.get<IacPlatformInfo[]>('/iac/platforms'),
};

// ============================================================================
// Breach & Attack Simulation (BAS) API
// ============================================================================

export const basAPI = {
  // Techniques
  listTechniques: () =>
    api.get<{ techniques: AttackTechnique[]; total: number }>('/bas/techniques'),

  listTactics: () =>
    api.get<{ tactics: MitreTactic[]; total: number }>('/bas/tactics'),

  // Scenarios
  listScenarios: () =>
    api.get<{ scenarios: SimulationScenario[]; total: number }>('/bas/scenarios'),

  createScenario: (data: CreateScenarioRequest) =>
    api.post<SimulationScenario>('/bas/scenarios', data),

  getScenario: (id: string) =>
    api.get<SimulationScenario>(`/bas/scenarios/${id}`),

  deleteScenario: (id: string) =>
    api.delete<{ message: string }>(`/bas/scenarios/${id}`),

  // Simulations
  listSimulations: () =>
    api.get<{ simulations: SimulationSummary[]; total: number }>('/bas/simulations'),

  startSimulation: (data: StartSimulationRequest) =>
    api.post<SimulationSummary>('/bas/simulations', data),

  getSimulation: (id: string) =>
    api.get<SimulationDetails>(`/bas/simulations/${id}`),

  // Detection Gaps
  getUnacknowledgedGaps: () =>
    api.get<DetectionGap[]>('/bas/gaps/unacknowledged'),

  acknowledgeGap: (id: string, data: AcknowledgeGapRequest) =>
    api.post<{ message: string }>(`/bas/gaps/${id}/acknowledge`, data),

  // Statistics
  getStats: () =>
    api.get<BasStats>('/bas/stats'),
};

// ============================================================================
// SIEM (Full SIEM Capabilities) API
// ============================================================================

export const siemFullAPI = {
  // Log Sources
  listLogSources: (params?: { status?: string; source_type?: string }) =>
    api.get<SiemLogSource[]>('/siem/sources', { params }),

  createLogSource: (data: CreateSiemLogSourceRequest) =>
    api.post<SiemLogSource>('/siem/sources', data),

  getLogSource: (id: string) =>
    api.get<SiemLogSource>(`/siem/sources/${id}`),

  updateLogSource: (id: string, data: UpdateSiemLogSourceRequest) =>
    api.put<SiemLogSource>(`/siem/sources/${id}`, data),

  deleteLogSource: (id: string) =>
    api.delete<{ message: string }>(`/siem/sources/${id}`),

  // Log Entries
  queryLogs: (params: SiemLogSearchParams) =>
    api.get<SiemLogSearchResponse>('/siem/logs', { params }),

  getLogEntry: (id: string) =>
    api.get<SiemLogEntry>(`/siem/logs/${id}`),

  // Detection Rules
  listRules: (params?: { status?: string; rule_type?: string; severity?: string }) =>
    api.get<SiemRule[]>('/siem/rules', { params }),

  createRule: (data: CreateSiemRuleRequest) =>
    api.post<SiemRule>('/siem/rules', data),

  updateRule: (id: string, data: UpdateSiemRuleRequest) =>
    api.put<SiemRule>(`/siem/rules/${id}`, data),

  deleteRule: (id: string) =>
    api.delete<{ message: string }>(`/siem/rules/${id}`),

  // Alerts
  listAlerts: (params?: { status?: string; severity?: string; rule_id?: string; assigned_to?: string; limit?: number }) =>
    api.get<SiemAlert[]>('/siem/alerts', { params }),

  updateAlertStatus: (id: string, data: UpdateSiemAlertStatusRequest) =>
    api.put<SiemAlert>(`/siem/alerts/${id}/status`, data),

  resolveAlert: (id: string, data: ResolveSiemAlertRequest) =>
    api.post<SiemAlert>(`/siem/alerts/${id}/resolve`, data),

  // Statistics
  getStats: () =>
    api.get<SiemStatsResponse>('/siem/stats'),

  // =========================================================================
  // Sigma Rules (Sprint 2 Enhancements)
  // =========================================================================

  // Sigma Rule CRUD
  listSigmaRules: (params?: { enabled?: boolean; severity?: string; category?: string }) =>
    api.get<SigmaRuleResponse[]>('/siem/sigma/rules', { params }),

  createSigmaRule: (data: CreateSigmaRuleRequest) =>
    api.post<SigmaRuleResponse>('/siem/sigma/rules', data),

  getSigmaRule: (id: string) =>
    api.get<SigmaRuleResponse>(`/siem/sigma/rules/${id}`),

  updateSigmaRule: (id: string, data: UpdateSigmaRuleRequest) =>
    api.put<SigmaRuleResponse>(`/siem/sigma/rules/${id}`, data),

  deleteSigmaRule: (id: string) =>
    api.delete<{ message: string }>(`/siem/sigma/rules/${id}`),

  // Backend Conversion (Sprint 2)
  convertSigmaRule: (data: ConvertSigmaRuleRequest) =>
    api.post<SigmaConversionResponse>('/siem/sigma/convert', data),

  convertSigmaRuleAll: (data: ConvertSigmaRuleAllRequest) =>
    api.post<SigmaConversionAllResponse>('/siem/sigma/convert-all', data),

  // Rule Testing (Sprint 2)
  testSigmaRuleWithStorage: (id: string, data: TestSigmaRuleRequest) =>
    api.post<SigmaRuleTestResult>(`/siem/sigma/rules/${id}/test`, data),

  getSigmaRuleTestResults: (id: string) =>
    api.get<SigmaRuleTestResult[]>(`/siem/sigma/rules/${id}/test-results`),

  updateTestResult: (id: string, data: UpdateTestResultRequest) =>
    api.put<SigmaRuleTestResult>(`/siem/sigma/test-results/${id}`, data),

  // ATT&CK Coverage (Sprint 2)
  getAttackCoverage: () =>
    api.get<AttackCoverageResponse>('/siem/sigma/coverage'),

  // Tuning Recommendations (Sprint 2)
  getTuningRecommendations: () =>
    api.get<RuleTuningRecommendation[]>('/siem/sigma/tuning/recommendations'),

  // Rule Chains (Sprint 2)
  listRuleChains: () =>
    api.get<SigmaRuleChain[]>('/siem/sigma/chains'),

  createRuleChain: (data: CreateRuleChainRequest) =>
    api.post<SigmaRuleChain>('/siem/sigma/chains', data),

  deleteRuleChain: (id: string) =>
    api.delete<{ message: string }>(`/siem/sigma/chains/${id}`),
};

// ============================================================================
// UEBA (User Entity Behavior Analytics) API
// ============================================================================

export const uebaAPI = {
  // Dashboard & Stats
  getDashboard: () =>
    api.get<UebaDashboardStats>('/ueba/dashboard'),

  getStats: () =>
    api.get<{
      entity_stats: { entity_type: string; risk_level: string; count: number }[];
      anomaly_stats: { anomaly_type: string; status: string; count: number }[];
      activity_stats: { activity_type: string; count: number }[];
    }>('/ueba/stats'),

  // Entities
  listEntities: (params?: {
    entity_type?: string;
    risk_level?: string;
    department?: string;
    is_privileged?: boolean;
    is_active?: boolean;
    search?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaEntityListResponse>('/ueba/entities', { params }),

  getEntity: (id: string) =>
    api.get<UebaEntity>(`/ueba/entities/${id}`),

  createEntity: (data: CreateUebaEntityRequest) =>
    api.post<UebaEntity>('/ueba/entities', data),

  updateEntity: (id: string, data: UpdateUebaEntityRequest) =>
    api.put<UebaEntity>(`/ueba/entities/${id}`, data),

  deleteEntity: (id: string) =>
    api.delete<{ message: string }>(`/ueba/entities/${id}`),

  getEntityBaselines: (id: string) =>
    api.get<UebaBaseline[]>(`/ueba/entities/${id}/baselines`),

  getEntityRiskFactors: (id: string) =>
    api.get<UebaRiskFactorListResponse>(`/ueba/entities/${id}/risk-factors`),

  // Peer Groups
  listPeerGroups: () =>
    api.get<{ peer_groups: UebaPeerGroup[]; total: number }>('/ueba/peer-groups'),

  getPeerGroup: (id: string) =>
    api.get<UebaPeerGroup>(`/ueba/peer-groups/${id}`),

  createPeerGroup: (data: CreateUebaPeerGroupRequest) =>
    api.post<UebaPeerGroup>('/ueba/peer-groups', data),

  updatePeerGroup: (id: string, data: UpdateUebaPeerGroupRequest) =>
    api.put<UebaPeerGroup>(`/ueba/peer-groups/${id}`, data),

  deletePeerGroup: (id: string) =>
    api.delete<{ message: string }>(`/ueba/peer-groups/${id}`),

  getPeerGroupMembers: (id: string) =>
    api.get<UebaEntity[]>(`/ueba/peer-groups/${id}/members`),

  // Activities
  listActivities: (params?: {
    entity_id?: string;
    activity_type?: string;
    is_anomalous?: boolean;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaActivityListResponse>('/ueba/activities', { params }),

  recordActivity: (data: RecordUebaActivityRequest) =>
    api.post<ProcessUebaActivityResponse>('/ueba/activities', data),

  recordActivitiesBulk: (activities: RecordUebaActivityRequest[]) =>
    api.post<{
      processed: number;
      total_anomalies: number;
      results: {
        entity_id: string;
        is_anomalous?: boolean;
        detected_anomalies?: string[];
        risk_contribution?: number;
        error?: string;
      }[];
    }>('/ueba/activities/bulk', { activities }),

  // Anomalies
  listAnomalies: (params?: {
    entity_id?: string;
    anomaly_type?: string;
    status?: string;
    severity?: string;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaAnomalyListResponse>('/ueba/anomalies', { params }),

  getAnomaly: (id: string) =>
    api.get<UebaAnomaly>(`/ueba/anomalies/${id}`),

  updateAnomaly: (id: string, data: UpdateUebaAnomalyRequest) =>
    api.put<UebaAnomaly>(`/ueba/anomalies/${id}`, data),

  acknowledgeAnomaly: (id: string) =>
    api.post<{ message: string }>(`/ueba/anomalies/${id}/acknowledge`),

  resolveAnomaly: (id: string, data: { resolution_notes?: string; false_positive?: boolean }) =>
    api.post<{ message: string }>(`/ueba/anomalies/${id}/resolve`, data),

  // Sessions
  listSessions: (params?: {
    entity_id?: string;
    session_type?: string;
    auth_status?: string;
    is_anomalous?: boolean;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaSessionListResponse>('/ueba/sessions', { params }),

  recordSession: (data: RecordUebaSessionRequest) =>
    api.post<UebaSession>('/ueba/sessions', data),

  // Baselines
  listBaselines: (params?: {
    entity_id?: string;
    peer_group_id?: string;
    metric_category?: string;
  }) => api.get<UebaBaselineListResponse>('/ueba/baselines', { params }),

  // Watchlist
  addToWatchlist: (data: AddToWatchlistRequest) =>
    api.post<{ id: string; entity_id: string; reason: string; message: string }>('/ueba/watchlist', data),

  removeFromWatchlist: (entityId: string) =>
    api.delete<{ message: string }>(`/ueba/watchlist/${entityId}`),

  // Sprint 4: Advanced Detection
  getAdvancedStats: () =>
    api.get<UebaAdvancedStats>('/ueba/advanced/stats'),

  listAdvancedDetections: (params?: {
    entity_id?: string;
    detection_type?: string;
    severity?: string;
    status?: string;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaAdvancedDetectionListResponse>('/ueba/advanced/detections', { params }),

  getAdvancedDetection: (id: string) =>
    api.get<UebaAdvancedDetection>(`/ueba/advanced/detections/${id}`),

  updateAdvancedDetectionStatus: (id: string, data: { status: string; resolution?: string }) =>
    api.put<UebaAdvancedDetection>(`/ueba/advanced/detections/${id}/status`, data),

  // Business Hours
  listBusinessHours: () =>
    api.get<UebaBusinessHours[]>('/ueba/advanced/business-hours'),

  createBusinessHours: (data: CreateBusinessHoursRequest) =>
    api.post<UebaBusinessHours>('/ueba/advanced/business-hours', data),

  deleteBusinessHours: (id: string) =>
    api.delete<{ message: string }>(`/ueba/advanced/business-hours/${id}`),

  // Sensitive Resources
  listSensitiveResources: () =>
    api.get<UebaSensitiveResource[]>('/ueba/advanced/sensitive-resources'),

  createSensitiveResource: (data: CreateSensitiveResourceRequest) =>
    api.post<UebaSensitiveResource>('/ueba/advanced/sensitive-resources', data),

  deleteSensitiveResource: (id: string) =>
    api.delete<{ message: string }>(`/ueba/advanced/sensitive-resources/${id}`),

  // Known VPNs
  listKnownVpns: () =>
    api.get<UebaKnownVpn[]>('/ueba/advanced/known-vpns'),

  createKnownVpn: (data: CreateKnownVpnRequest) =>
    api.post<UebaKnownVpn>('/ueba/advanced/known-vpns', data),

  deleteKnownVpn: (id: string) =>
    api.delete<{ message: string }>(`/ueba/advanced/known-vpns/${id}`),

  // Detection Rules
  listDetectionRules: () =>
    api.get<UebaDetectionRule[]>('/ueba/advanced/detection-rules'),

  createDetectionRule: (data: CreateDetectionRuleRequest) =>
    api.post<UebaDetectionRule>('/ueba/advanced/detection-rules', data),

  toggleDetectionRule: (id: string) =>
    api.put<UebaDetectionRule>(`/ueba/advanced/detection-rules/${id}/toggle`),

  deleteDetectionRule: (id: string) =>
    api.delete<{ message: string }>(`/ueba/advanced/detection-rules/${id}`),

  // Data Access Recording
  listDataAccesses: (params?: {
    entity_id?: string;
    is_anomalous?: boolean;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaDataAccessListResponse>('/ueba/advanced/data-accesses', { params }),

  recordDataAccess: (data: RecordDataAccessRequest) =>
    api.post<UebaDataAccess>('/ueba/advanced/data-accesses', data),

  // Host Access Recording
  listHostAccesses: (params?: {
    entity_id?: string;
    is_anomalous?: boolean;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaHostAccessListResponse>('/ueba/advanced/host-accesses', { params }),

  recordHostAccess: (data: RecordHostAccessRequest) =>
    api.post<UebaHostAccess>('/ueba/advanced/host-accesses', data),

  // Data Transfer Recording
  listDataTransfers: (params?: {
    entity_id?: string;
    is_anomalous?: boolean;
    start_time?: string;
    end_time?: string;
    offset?: number;
    limit?: number;
  }) => api.get<UebaDataTransferListResponse>('/ueba/advanced/data-transfers', { params }),

  recordDataTransfer: (data: RecordDataTransferRequest) =>
    api.post<UebaDataTransfer>('/ueba/advanced/data-transfers', data),

  // Run Detection
  runAdvancedDetection: (data: RunAdvancedDetectionRequest) =>
    api.post<AdvancedDetectionResult>('/ueba/advanced/run-detection', data),
};

// ============================================================================
// Sigma Types (Sprint 2)
// ============================================================================

export interface SigmaRuleResponse {
  id: string;
  name: string;
  description: string;
  content: string;
  severity: string;
  status: string;
  enabled: boolean;
  logsource_category: string;
  logsource_product: string;
  tags: string[];
  mitre_attack_ids: string[];
  false_positive_count: number;
  true_positive_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateSigmaRuleRequest {
  name: string;
  description?: string;
  content: string;
  severity?: string;
  enabled?: boolean;
  tags?: string[];
}

export interface UpdateSigmaRuleRequest {
  name?: string;
  description?: string;
  content?: string;
  severity?: string;
  enabled?: boolean;
  tags?: string[];
}

export interface ConvertSigmaRuleRequest {
  rule_id?: string;
  rule_content?: string;
  backend: 'splunk' | 'elastic_lucene' | 'elastic_eql' | 'microsoft_sentinel' | 'qradar_aql' | 'logpoint' | 'crowdstrike';
  field_mappings?: Record<string, string>;
}

export interface ConvertSigmaRuleAllRequest {
  rule_id?: string;
  rule_content?: string;
}

export interface SigmaConversionResponse {
  backend: string;
  query: string;
  warnings: string[];
  errors: string[];
  field_mappings_used: string[];
}

export interface SigmaConversionAllResponse {
  conversions: SigmaConversionResponse[];
}

export interface TestSigmaRuleRequest {
  test_name: string;
  sample_logs: string[];
  expected_matches?: number;
}

export interface SigmaTestMatch {
  log_index: number;
  message: string;
}

export interface SigmaRuleTestResult {
  id: string;
  sigma_rule_id: string;
  test_name: string;
  sample_logs: string[];
  expected_matches: number | null;
  actual_matches: number;
  match_details: SigmaTestMatch[];
  passed: boolean;
  execution_time_ms: number;
  tested_at: string;
  tested_by: string | null;
}

export interface UpdateTestResultRequest {
  notes?: string;
  verified?: boolean;
}

export interface TechniqueCoverageEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  rule_count: number;
  rules: string[];
}

export interface AttackCoverageResponse {
  total_techniques_covered: number;
  total_rules: number;
  coverage_by_tactic: Record<string, number>;
  techniques: TechniqueCoverageEntry[];
}

export interface RuleTuningRecommendation {
  rule_id: string;
  rule_name: string;
  recommendation_type: string;
  description: string;
  current_value: string | null;
  suggested_value: string | null;
  false_positive_count: number;
  true_positive_count: number;
  fp_rate: number;
}

export interface SigmaRuleChain {
  id: string;
  name: string;
  description: string | null;
  rule_ids: string[];
  chain_logic: string;
  time_window_secs: number;
  enabled: boolean;
  created_at: string;
  created_by: string;
}

export interface CreateRuleChainRequest {
  name: string;
  description?: string;
  rule_ids: string[];
  chain_logic: string;
  time_window_secs: number;
  enabled?: boolean;
}

// ============================================================================
// Exploitation Framework API
// ============================================================================

export interface ExploitationStatus {
  msfvenom_available: boolean;
  active_campaigns: number;
  total_campaigns: number;
  credentials_stored: number;
  payloads_generated: number;
}

export interface ExploitationCampaign {
  id: string;
  name: string;
  attack_type: string;
  status: string;
  targets: string[];
  results_count: number;
  successful_count: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  // Safeguard fields - customer/asset binding
  customer_id?: string;
  customer_name?: string;
  asset_ids: string[];
  engagement_id?: string;
}

export interface ShellTemplate {
  format: string;
  platform: string;
  name: string;
  description: string;
  requires_msfvenom: boolean;
}

export interface PostExploitModule {
  module: string;
  name: string;
  description: string;
  category: string;
  platforms: string[];
}

export interface GeneratedPayload {
  id: string;
  payload_type: string;
  platform: string;
  format: string;
  payload_hash: string;
  created_at: string;
}

export interface GenerateShellResponse {
  id: string;
  payload: string;
  payload_hash: string;
  format: string;
  platform: string;
  listener_command: string;
  one_liner?: string;
  created_at: string;
}

export interface CreateCampaignExploitRequest {
  name: string;
  attack_type: string;
  config: Record<string, unknown>;
  targets: string[];
  // Required safeguard fields
  customer_id: string;
  asset_ids: string[];
  engagement_id?: string;
}

// Relevance filtering types
export interface RelevantModule {
  module: string;
  name: string;
  description: string;
  category: string;
  platforms: string[];
  relevance_reason: string;
}

export interface RelevantAttack {
  attack_type: string;
  name: string;
  description: string;
  applicable: boolean;
  relevance_reason: string;
}

export interface GenerateShellRequest {
  shell_type: string;
  platform: string;
  format: string;
  lhost: string;
  lport: number;
  encoding?: string;
  obfuscation_level?: number;
  staged?: boolean;
  xor_key?: string;
}

export const exploitationAPI = {
  // Get exploitation status
  getStatus: () =>
    api.get<ExploitationStatus>('/exploitation/status'),

  // Campaigns
  listCampaigns: () =>
    api.get<ExploitationCampaign[]>('/exploitation/campaigns'),

  createCampaign: (data: CreateCampaignExploitRequest) =>
    api.post<{ id: string; status: string; message: string }>('/exploitation/campaigns', data),

  getCampaign: (id: string) =>
    api.get<ExploitationCampaign & { config?: Record<string, unknown>; error_message?: string }>(`/exploitation/campaigns/${id}`),

  startCampaign: (id: string, authorized: boolean) =>
    api.post<{ id: string; status: string; message: string }>(`/exploitation/campaigns/${id}/start`, { authorized }),

  stopCampaign: (id: string) =>
    api.post<{ id: string; status: string; message: string }>(`/exploitation/campaigns/${id}/stop`),

  deleteCampaign: (id: string) =>
    api.delete<{ message: string }>(`/exploitation/campaigns/${id}`),

  getCampaignResults: (id: string) =>
    api.get<Array<{
      id: string;
      target: string;
      result_type: string;
      data: Record<string, unknown>;
      severity?: string;
      created_at: string;
      success?: boolean;
    }>>(`/exploitation/campaigns/${id}/results`),

  exportResults: (id: string, format: 'json' | 'csv') =>
    api.post<string>(`/exploitation/campaigns/${id}/export`, { format }),

  // Shell Generation
  generateShell: (data: GenerateShellRequest) =>
    api.post<GenerateShellResponse>('/exploitation/shells/generate', data),

  listShellTemplates: () =>
    api.get<ShellTemplate[]>('/exploitation/shells/templates'),

  listPayloads: () =>
    api.get<GeneratedPayload[]>('/exploitation/shells'),

  // Post-Exploitation Modules
  listModules: () =>
    api.get<PostExploitModule[]>('/exploitation/modules'),

  // Relevance filtering (SAFEGUARD)
  getRelevantModules: (assetIds: string[]) =>
    api.post<RelevantModule[]>('/exploitation/modules/relevant', { asset_ids: assetIds }),

  getRelevantAttacks: (assetIds: string[]) =>
    api.post<RelevantAttack[]>('/exploitation/attacks/relevant', { asset_ids: assetIds }),
};

// Privilege Escalation types
export interface PrivescScanSummary {
  id: string;
  target: string;
  os_type: string;
  status: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  created_at: string;
  completed_at?: string;
}

export interface PrivescFinding {
  id: string;
  severity: string;
  title: string;
  description: string;
  os_type: string;
  linux_vector?: Record<string, unknown>;
  windows_vector?: Record<string, unknown>;
  exploitation_steps: string[];
  references: string[];
  mitre_techniques: string[];
  raw_output?: string;
  discovered_at: string;
}

export interface PrivescResult {
  id: string;
  target: string;
  os_type: string;
  status: string;
  config: Record<string, unknown>;
  findings: PrivescFinding[];
  statistics: {
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    info_findings: number;
    exploitable_count: number;
    suid_binaries: number;
    sudo_rules: number;
    cron_jobs: number;
    kernel_exploits: number;
    service_issues: number;
    credential_findings: number;
  };
  system_info: {
    hostname?: string;
    os_name?: string;
    os_version?: string;
    kernel_version?: string;
    architecture?: string;
    current_user?: string;
    current_groups: string[];
  };
  peas_output?: string;
  errors: string[];
  started_at: string;
  completed_at?: string;
}

export interface StartPrivescRequest {
  target: string;
  os_type: string;
  ssh_username?: string;
  ssh_password?: string;
  ssh_key_path?: string;
  ssh_port?: number;
  winrm_username?: string;
  winrm_password?: string;
  winrm_port?: number;
  winrm_https?: boolean;
  run_peas?: boolean;
  timeout_secs?: number;
}

export interface GtfobinsEntry {
  binary: string;
  functions: Array<{
    name: string;
    description: string;
    code: string;
  }>;
}

export interface LolbasEntry {
  name: string;
  description: string;
  author?: string;
  commands: Array<{
    command: string;
    description: string;
    usecase: string;
    category: string;
    privileges: string;
    mitre_id?: string;
  }>;
}

export const privescAPI = {
  // Start a new privesc scan
  startScan: (data: StartPrivescRequest) =>
    api.post<{ id: string; target: string; os_type: string; status: string; message: string }>('/privesc', data),

  // List all privesc scans
  listScans: (limit?: number, offset?: number) =>
    api.get<{ scans: PrivescScanSummary[]; total: number }>('/privesc/scans', { params: { limit, offset } }),

  // Get a specific scan with findings
  getScan: (id: string) =>
    api.get<PrivescResult>(`/privesc/scans/${id}`),

  // Get findings for a scan
  getFindings: (id: string) =>
    api.get<PrivescFinding[]>(`/privesc/scans/${id}/findings`),

  // Cancel a running scan
  cancelScan: (id: string) =>
    api.post<{ message: string; id: string }>(`/privesc/scans/${id}/cancel`),

  // Delete a scan
  deleteScan: (id: string) =>
    api.delete<{ message: string; id: string }>(`/privesc/scans/${id}`),

  // Get GTFOBins information for a binary
  getGtfobins: (binary: string) =>
    api.get<GtfobinsEntry>(`/privesc/gtfobins/${encodeURIComponent(binary)}`),

  // Get LOLBAS information for a binary
  getLolbas: (binary: string) =>
    api.get<LolbasEntry>(`/privesc/lolbas/${encodeURIComponent(binary)}`),
};

// ==================== BloodHound API ====================

export interface BloodHoundImportStatistics {
  total_computers: number;
  total_users: number;
  total_groups: number;
  total_domains: number;
  total_gpos: number;
  total_ous: number;
  total_containers: number;
  total_sessions: number;
  total_relationships: number;
  domain_admins: number;
  enterprise_admins: number;
  attack_paths_found: number;
}

export interface BloodHoundImportSummary {
  id: string;
  domain: string;
  status: string;
  statistics: BloodHoundImportStatistics;
  created_at: string;
  completed_at?: string;
}

export interface PathNode {
  object_id: string;
  name: string;
  object_type: string;
  domain: string;
  is_high_value: boolean;
}

export interface PathStep {
  from_node: PathNode;
  to_node: PathNode;
  relationship: string;
  abuse_info: string;
  opsec_considerations?: string;
}

export interface BloodHoundAttackPath {
  id: string;
  start_node: PathNode;
  end_node: PathNode;
  path: PathStep[];
  length: number;
  risk_score: number;
  techniques: string[];
  description: string;
}

export interface HighValueTarget {
  object_id: string;
  name: string;
  object_type: string;
  domain: string;
  reason: string;
  paths_to_target: number;
}

export interface KerberoastableUser {
  object_id: string;
  name: string;
  domain: string;
  service_principal_names: string[];
  is_admin: boolean;
  password_last_set?: string;
  description?: string;
}

export interface AsrepRoastableUser {
  object_id: string;
  name: string;
  domain: string;
  is_enabled: boolean;
  is_admin: boolean;
  description?: string;
}

export interface UnconstrainedDelegation {
  object_id: string;
  name: string;
  object_type: string;
  domain: string;
  is_dc: boolean;
  description?: string;
}

export interface BloodHoundImportDetail {
  id: string;
  domain: string;
  status: string;
  statistics: BloodHoundImportStatistics;
  attack_paths: BloodHoundAttackPath[];
  high_value_targets: HighValueTarget[];
  kerberoastable_users: KerberoastableUser[];
  asrep_roastable_users: AsrepRoastableUser[];
  unconstrained_delegation: UnconstrainedDelegation[];
  created_at: string;
  completed_at?: string;
}

export const bloodhoundAPI = {
  // Upload SharpHound data (ZIP or JSON)
  uploadData: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post<{ id: string; status: string; message: string }>('/bloodhound/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  // List all imports
  listImports: (limit?: number, offset?: number) =>
    api.get<{ imports: BloodHoundImportSummary[]; total: number }>('/bloodhound/imports', { params: { limit, offset } }),

  // Get a specific import with full details
  getImport: (id: string) =>
    api.get<BloodHoundImportDetail>(`/bloodhound/imports/${id}`),

  // Delete an import
  deleteImport: (id: string) =>
    api.delete<{ message: string; id: string }>(`/bloodhound/imports/${id}`),

  // Get attack paths for an import
  getAttackPaths: (id: string) =>
    api.get<AttackPath[]>(`/bloodhound/imports/${id}/paths`),

  // Get Kerberoastable users for an import
  getKerberoastable: (id: string) =>
    api.get<KerberoastableUser[]>(`/bloodhound/imports/${id}/kerberoastable`),

  // Get AS-REP roastable users for an import
  getAsrepRoastable: (id: string) =>
    api.get<AsrepRoastableUser[]>(`/bloodhound/imports/${id}/asrep-roastable`),
};

// =============================================================================
// Password Cracking API
// =============================================================================

import type {
  CrackingJob,
  CrackedCredential,
  Wordlist,
  RuleFile,
  HashTypeInfo,
  CreateCrackingJobRequest,
  DetectHashRequest,
  DetectHashResponse,
  CrackingStats,
} from '../types';

export const crackingAPI = {
  // Jobs
  createJob: (data: CreateCrackingJobRequest) =>
    api.post<CrackingJob>('/cracking/jobs', data),

  listJobs: (limit?: number, offset?: number) =>
    api.get<CrackingJob[]>('/cracking/jobs', { params: { limit, offset } }),

  getJob: (id: string) =>
    api.get<CrackingJob>(`/cracking/jobs/${id}`),

  deleteJob: (id: string) =>
    api.delete<void>(`/cracking/jobs/${id}`),

  startJob: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/cracking/jobs/${id}/start`),

  stopJob: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/cracking/jobs/${id}/stop`),

  getJobResults: (id: string) =>
    api.get<CrackedCredential[]>(`/cracking/jobs/${id}/results`),

  // Wordlists
  listWordlists: () =>
    api.get<Wordlist[]>('/cracking/wordlists'),

  deleteWordlist: (id: string) =>
    api.delete<void>(`/cracking/wordlists/${id}`),

  // Rules
  listRules: (crackerType?: 'hashcat' | 'john') =>
    api.get<RuleFile[]>('/cracking/rules', { params: { cracker_type: crackerType } }),

  deleteRule: (id: string) =>
    api.delete<void>(`/cracking/rules/${id}`),

  // Utilities
  detectHashType: (data: DetectHashRequest) =>
    api.post<DetectHashResponse>('/cracking/detect-hash', data),

  listHashTypes: () =>
    api.get<HashTypeInfo[]>('/cracking/hash-types'),

  getStats: () =>
    api.get<CrackingStats>('/cracking/stats'),
};

// =============================================================================
// Attack Surface Management (ASM) API
// =============================================================================

import type {
  AsmMonitor,
  AsmBaseline,
  AsmChange,
  AsmAuthorizedAsset,
  AsmAssetRiskScore,
  AsmDashboard,
  AsmTimelineEvent,
  AsmMonitorRunResult,
  CreateAsmMonitorRequest,
  UpdateAsmMonitorRequest,
  CreateAsmAuthorizedAssetRequest,
  AsmAcknowledgeChangeRequest,
  AsmChangesQuery,
  // Purple Team types
  PurpleTeamExercise,
  PurpleTeamDashboard,
  PurpleAttackResult,
  DetectionCoverage,
  PurpleDetectionGap,
  AttackMatrix,
  PurpleMitreTechnique,
  CreateExerciseRequest,
  UpdateGapStatusRequest,
  AttackTypeMapping,
  PurpleTeamReport,
} from '../types';

export const asmAPI = {
  // Dashboard
  getDashboard: () =>
    api.get<AsmDashboard>('/asm/dashboard'),

  // Monitors
  createMonitor: (data: CreateAsmMonitorRequest) =>
    api.post<AsmMonitor>('/asm/monitors', data),

  listMonitors: () =>
    api.get<AsmMonitor[]>('/asm/monitors'),

  getMonitor: (id: string) =>
    api.get<AsmMonitor>(`/asm/monitors/${id}`),

  updateMonitor: (id: string, data: UpdateAsmMonitorRequest) =>
    api.put<AsmMonitor>(`/asm/monitors/${id}`, data),

  deleteMonitor: (id: string) =>
    api.delete<void>(`/asm/monitors/${id}`),

  runMonitor: (id: string) =>
    api.post<AsmMonitorRunResult>(`/asm/monitors/${id}/run`),

  enableMonitor: (id: string) =>
    api.post<AsmMonitor>(`/asm/monitors/${id}/enable`),

  disableMonitor: (id: string) =>
    api.post<AsmMonitor>(`/asm/monitors/${id}/disable`),

  // Baselines
  getMonitorBaselines: (monitorId: string) =>
    api.get<AsmBaseline[]>(`/asm/monitors/${monitorId}/baselines`),

  createBaseline: (monitorId: string) =>
    api.post<AsmBaseline>(`/asm/monitors/${monitorId}/baselines`),

  activateBaseline: (monitorId: string, baselineId: string) =>
    api.post<AsmBaseline>(`/asm/monitors/${monitorId}/baselines/${baselineId}/activate`),

  // Changes
  listChanges: (params?: AsmChangesQuery) =>
    api.get<AsmChange[]>('/asm/changes', { params }),

  getMonitorChanges: (monitorId: string, params?: AsmChangesQuery) =>
    api.get<AsmChange[]>(`/asm/monitors/${monitorId}/changes`, { params }),

  acknowledgeChange: (changeId: string, data?: AsmAcknowledgeChangeRequest) =>
    api.post<AsmChange>(`/asm/changes/${changeId}/acknowledge`, data),

  // Risk Scores
  listRiskScores: (limit?: number) =>
    api.get<AsmAssetRiskScore[]>('/asm/risk-scores', { params: { limit } }),

  getAssetRiskScore: (hostname: string) =>
    api.get<AsmAssetRiskScore>(`/asm/risk-scores/${encodeURIComponent(hostname)}`),

  // Authorized Assets (for Shadow IT detection)
  listAuthorizedAssets: () =>
    api.get<AsmAuthorizedAsset[]>('/asm/authorized-assets'),

  createAuthorizedAsset: (data: CreateAsmAuthorizedAssetRequest) =>
    api.post<AsmAuthorizedAsset>('/asm/authorized-assets', data),

  deleteAuthorizedAsset: (id: string) =>
    api.delete<void>(`/asm/authorized-assets/${id}`),

  // Timeline
  getTimeline: (monitorId?: string, days?: number) =>
    api.get<AsmTimelineEvent[]>('/asm/timeline', { params: { monitor_id: monitorId, days } }),
};

// Purple Team API
export const purpleTeamAPI = {
  // Dashboard
  getDashboard: () =>
    api.get<PurpleTeamDashboard>('/purple-team/dashboard'),

  // Exercises
  createExercise: (data: CreateExerciseRequest) =>
    api.post<PurpleTeamExercise>('/purple-team/exercises', data),

  listExercises: () =>
    api.get<PurpleTeamExercise[]>('/purple-team/exercises'),

  getExercise: (id: string) =>
    api.get<PurpleTeamExercise>(`/purple-team/exercises/${id}`),

  updateExercise: (id: string, data: Partial<CreateExerciseRequest>) =>
    api.put<PurpleTeamExercise>(`/purple-team/exercises/${id}`, data),

  deleteExercise: (id: string) =>
    api.delete<void>(`/purple-team/exercises/${id}`),

  startExercise: (id: string) =>
    api.post<PurpleTeamExercise>(`/purple-team/exercises/${id}/start`),

  stopExercise: (id: string) =>
    api.post<PurpleTeamExercise>(`/purple-team/exercises/${id}/stop`),

  // Results
  getExerciseResults: (id: string) =>
    api.get<PurpleAttackResult[]>(`/purple-team/exercises/${id}/results`),

  recheckDetection: (resultId: string) =>
    api.post<PurpleAttackResult>(`/purple-team/results/${resultId}/recheck`),

  // Coverage
  getExerciseCoverage: (id: string) =>
    api.get<DetectionCoverage>(`/purple-team/exercises/${id}/coverage`),

  getCoverageMatrix: () =>
    api.get<AttackMatrix>('/purple-team/coverage/matrix'),

  // Gaps
  listGaps: (status?: string) =>
    api.get<PurpleDetectionGap[]>('/purple-team/gaps', { params: { status } }),

  getExerciseGaps: (id: string) =>
    api.get<PurpleDetectionGap[]>(`/purple-team/exercises/${id}/gaps`),

  updateGapStatus: (id: string, data: UpdateGapStatusRequest) =>
    api.put<PurpleDetectionGap>(`/purple-team/gaps/${id}/status`, data),

  getGapRecommendations: (id: string) =>
    api.get<PurpleDetectionGap>(`/purple-team/gaps/${id}/recommendations`),

  // MITRE ATT&CK
  getMitreTechniques: () =>
    api.get<PurpleMitreTechnique[]>('/purple-team/mitre/techniques'),

  getMitreTactics: () =>
    api.get<string[]>('/purple-team/mitre/tactics'),

  getAttackTypeMappings: () =>
    api.get<AttackTypeMapping[]>('/purple-team/mitre/attacks'),

  // Reports
  generateExerciseReport: (id: string) =>
    api.get<PurpleTeamReport>(`/purple-team/exercises/${id}/report`),
};

// =============================================================================
// Organization & Multi-tenancy API
// =============================================================================

export const organizationAPI = {
  // Organizations
  list: () =>
    api.get<OrganizationSummary[]>('/organizations'),

  get: (id: string) =>
    api.get<Organization>(`/organizations/${id}`),

  create: (data: CreateOrganizationRequest) =>
    api.post<Organization>('/organizations', data),

  update: (id: string, data: UpdateOrganizationRequest) =>
    api.put<Organization>(`/organizations/${id}`, data),

  delete: (id: string) =>
    api.delete<void>(`/organizations/${id}`),

  // Members
  listMembers: (orgId: string) =>
    api.get<OrgMember[]>(`/organizations/${orgId}/members`),

  addMember: (orgId: string, data: AddOrgMemberRequest) =>
    api.post<{ message: string }>(`/organizations/${orgId}/members`, data),

  removeMember: (orgId: string, userId: string) =>
    api.delete<void>(`/organizations/${orgId}/members/${userId}`),

  // Departments
  listDepartments: (orgId: string) =>
    api.get<Department[]>(`/organizations/${orgId}/departments`),

  getDepartment: (id: string) =>
    api.get<Department>(`/departments/${id}`),

  createDepartment: (orgId: string, data: CreateDepartmentRequest) =>
    api.post<Department>(`/organizations/${orgId}/departments`, data),

  updateDepartment: (id: string, data: UpdateDepartmentRequest) =>
    api.put<Department>(`/departments/${id}`, data),

  deleteDepartment: (id: string) =>
    api.delete<void>(`/departments/${id}`),

  // Teams
  listTeams: (orgId: string) =>
    api.get<Team[]>(`/organizations/${orgId}/teams`),

  listTeamsInDepartment: (deptId: string) =>
    api.get<Team[]>(`/departments/${deptId}/teams`),

  getTeam: (id: string) =>
    api.get<Team>(`/teams/${id}`),

  createTeam: (deptId: string, data: CreateTeamRequest) =>
    api.post<Team>(`/departments/${deptId}/teams`, data),

  updateTeam: (id: string, data: UpdateTeamRequest) =>
    api.put<Team>(`/teams/${id}`, data),

  deleteTeam: (id: string) =>
    api.delete<void>(`/teams/${id}`),

  // Team Members
  listTeamMembers: (teamId: string) =>
    api.get<TeamMember[]>(`/teams/${teamId}/members`),

  addTeamMember: (teamId: string, data: AddTeamMemberRequest) =>
    api.post<{ message: string }>(`/teams/${teamId}/members`, data),

  removeTeamMember: (teamId: string, userId: string) =>
    api.delete<void>(`/teams/${teamId}/members/${userId}`),
};

export const rolesAPI = {
  // Role Templates (system-wide)
  listRoleTemplates: () =>
    api.get<RoleTemplate[]>('/role-templates'),

  getRoleTemplate: (id: string) =>
    api.get<RoleTemplate>(`/role-templates/${id}`),

  getRoleTemplatePermissions: (id: string) =>
    api.get<string[]>(`/role-templates/${id}/permissions`),

  // Custom Roles (org-specific)
  listCustomRoles: (orgId: string) =>
    api.get<CustomRole[]>(`/organizations/${orgId}/roles`),

  getCustomRole: (orgId: string, roleId: string) =>
    api.get<CustomRole>(`/organizations/${orgId}/roles/${roleId}`),

  createCustomRole: (orgId: string, data: CreateCustomRoleRequest) =>
    api.post<CustomRole>(`/organizations/${orgId}/roles`, data),

  updateCustomRole: (orgId: string, roleId: string, data: UpdateCustomRoleRequest) =>
    api.put<CustomRole>(`/organizations/${orgId}/roles/${roleId}`, data),

  deleteCustomRole: (orgId: string, roleId: string) =>
    api.delete<void>(`/organizations/${orgId}/roles/${roleId}`),

  cloneCustomRole: (orgId: string, roleId: string, name: string) =>
    api.post<CustomRole>(`/organizations/${orgId}/roles/${roleId}/clone`, { name }),

  // User Role Assignments
  listUserRoles: (userId: string) =>
    api.get<UserRoleAssignment[]>(`/users/${userId}/roles`),

  assignRole: (userId: string, data: AssignRoleRequest) =>
    api.post<UserRoleAssignment>(`/users/${userId}/roles`, data),

  removeRoleAssignment: (userId: string, assignmentId: string) =>
    api.delete<void>(`/users/${userId}/roles/${assignmentId}`),
};

export const permissionsAPI = {
  // Available Permissions
  listPermissions: () =>
    api.get<Permission[]>('/permissions'),

  listResourceTypes: () =>
    api.get<string[]>('/permissions/resource-types'),

  listActions: () =>
    api.get<string[]>('/permissions/actions'),

  // User Permissions
  getEffectivePermissions: (userId: string) =>
    api.get<EffectivePermissions>(`/users/${userId}/permissions`),

  checkPermission: (userId: string, permission: string, resourceType?: string, resourceId?: string) =>
    api.get<{ granted: boolean }>(`/users/${userId}/permissions/check`, {
      params: { permission, resource_type: resourceType, resource_id: resourceId }
    }),

  // Permission Overrides
  listPermissionOverrides: (userId: string) =>
    api.get<{ id: string; permission: string; granted: boolean }[]>(`/users/${userId}/permissions/overrides`),

  addPermissionOverride: (userId: string, permission: string, granted: boolean) =>
    api.post<{ id: string }>(`/users/${userId}/permissions`, { permission, granted }),

  removePermissionOverride: (userId: string, overrideId: string) =>
    api.delete<void>(`/users/${userId}/permissions/${overrideId}`),

  // Resource Sharing
  shareResource: (resourceType: string, resourceId: string, userId: string, permissions: string[]) =>
    api.post<{ id: string }>(`/resources/${resourceType}/${resourceId}/shares`, {
      user_id: userId,
      permissions,
    }),

  listResourceShares: (resourceType: string, resourceId: string) =>
    api.get<{ user_id: string; permissions: string[] }[]>(`/resources/${resourceType}/${resourceId}/shares`),

  removeResourceShare: (resourceType: string, resourceId: string, userId: string) =>
    api.delete<void>(`/resources/${resourceType}/${resourceId}/shares`, {
      data: { user_id: userId },
    }),

  // Policies
  listPolicies: () =>
    api.get<{ id: string; name: string; description: string }[]>('/policies'),
};

export const quotasAPI = {
  getQuotas: (orgId: string) =>
    api.get<OrganizationQuotas>(`/organizations/${orgId}/quotas`),

  updateQuotas: (orgId: string, data: UpdateQuotasRequest) =>
    api.put<OrganizationQuotas>(`/organizations/${orgId}/quotas`, data),

  getUsage: (orgId: string) =>
    api.get<OrganizationQuotaUsage>(`/organizations/${orgId}/quotas/usage`),
};

// =============================================================================
// Green Team - SOAR API
// =============================================================================

export const greenTeamAPI = {
  // Cases
  listCases: (params?: Record<string, string>) =>
    api.get<SoarCase[]>('/green-team/cases', { params }),

  getCase: (id: string) =>
    api.get<SoarCase>(`/green-team/cases/${id}`),

  createCase: (data: CreateCaseRequest) =>
    api.post<SoarCase>('/green-team/cases', data),

  updateCase: (id: string, data: UpdateCaseRequest) =>
    api.put<SoarCase>(`/green-team/cases/${id}`, data),

  deleteCase: (id: string) =>
    api.delete<void>(`/green-team/cases/${id}`),

  // Case Tasks
  getCaseTasks: (caseId: string) =>
    api.get<CaseTask[]>(`/green-team/cases/${caseId}/tasks`),

  addCaseTask: (caseId: string, data: CreateCaseTaskRequest) =>
    api.post<CaseTask>(`/green-team/cases/${caseId}/tasks`, data),

  updateCaseTask: (caseId: string, taskId: string, data: Partial<CaseTask>) =>
    api.put<CaseTask>(`/green-team/cases/${caseId}/tasks/${taskId}`, data),

  // Case Comments
  getCaseComments: (caseId: string) =>
    api.get<CaseComment[]>(`/green-team/cases/${caseId}/comments`),

  addCaseComment: (caseId: string, data: CreateCaseCommentRequest) =>
    api.post<CaseComment>(`/green-team/cases/${caseId}/comments`, data),

  // Case Timeline
  getCaseTimeline: (caseId: string) =>
    api.get<CaseTimelineEvent[]>(`/green-team/cases/${caseId}/timeline`),

  // Playbooks
  listPlaybooks: () =>
    api.get<Playbook[]>('/green-team/playbooks'),

  getPlaybook: (id: string) =>
    api.get<Playbook>(`/green-team/playbooks/${id}`),

  createPlaybook: (data: CreatePlaybookRequest) =>
    api.post<Playbook>('/green-team/playbooks', data),

  updatePlaybook: (id: string, data: Partial<CreatePlaybookRequest>) =>
    api.put<Playbook>(`/green-team/playbooks/${id}`, data),

  deletePlaybook: (id: string) =>
    api.delete<void>(`/green-team/playbooks/${id}`),

  runPlaybook: (id: string, inputData?: Record<string, unknown>) =>
    api.post<PlaybookRun>(`/green-team/playbooks/${id}/run`, { input_data: inputData }),

  getPlaybookRuns: (id: string) =>
    api.get<PlaybookRun[]>(`/green-team/playbooks/${id}/runs`),

  // IOC Feeds
  listFeeds: () =>
    api.get<IocFeed[]>('/green-team/feeds'),

  getFeed: (id: string) =>
    api.get<IocFeed>(`/green-team/feeds/${id}`),

  createFeed: (data: CreateIocFeedRequest) =>
    api.post<IocFeed>('/green-team/feeds', data),

  updateFeed: (id: string, data: Partial<CreateIocFeedRequest>) =>
    api.put<IocFeed>(`/green-team/feeds/${id}`, data),

  deleteFeed: (id: string) =>
    api.delete<void>(`/green-team/feeds/${id}`),

  pollFeed: (id: string) =>
    api.post<{ iocs_fetched: number }>(`/green-team/feeds/${id}/poll`),

  // Metrics
  getMetricsOverview: () =>
    api.get<MetricsOverview>('/green-team/metrics/overview'),
};

// =============================================================================
// Yellow Team - DevSecOps & Security Architecture API
// =============================================================================

export const yellowTeamAPI = {
  // Dashboard
  getDashboardOverview: () =>
    api.get<YellowTeamDashboard>('/yellow-team/dashboard/overview'),

  // SAST Scans
  listSastScans: () =>
    api.get<SastScan[]>('/yellow-team/sast/scans'),

  getSastScan: (id: string) =>
    api.get<SastScan>(`/yellow-team/sast/scans/${id}`),

  startSastScan: (data: CreateSastScanRequest) =>
    api.post<SastScan>('/yellow-team/sast/scan', data),

  deleteSastScan: (id: string) =>
    api.delete<void>(`/yellow-team/sast/scans/${id}`),

  getSastFindings: (scanId: string) =>
    api.get<SastFinding[]>(`/yellow-team/sast/scans/${scanId}/findings`),

  getSastRules: () =>
    api.get<SastRule[]>('/yellow-team/sast/rules'),

  updateSastRule: (id: string, data: Partial<SastRule>) =>
    api.put<SastRule>(`/yellow-team/sast/rules/${id}`, data),

  // SBOM Projects
  listSbomProjects: () =>
    api.get<SbomProject[]>('/yellow-team/sbom'),

  getSbomProject: (id: string) =>
    api.get<SbomProject>(`/yellow-team/sbom/${id}`),

  generateSbom: (data: CreateSbomRequest) =>
    api.post<SbomProject>('/yellow-team/sbom/generate', data),

  deleteSbomProject: (id: string) =>
    api.delete<void>(`/yellow-team/sbom/${id}`),

  getSbomComponents: (projectId: string) =>
    api.get<SbomComponent[]>(`/yellow-team/sbom/${projectId}/components`),

  exportSbom: (projectId: string, format: 'cyclonedx' | 'spdx') =>
    api.get(`/yellow-team/sbom/${projectId}/export/${format}`, {
      responseType: 'blob',
    }),

  // Architecture Reviews
  listArchitectureReviews: () =>
    api.get<ArchitectureReview[]>('/yellow-team/architecture/reviews'),

  getArchitectureReview: (id: string) =>
    api.get<ArchitectureReview>(`/yellow-team/architecture/reviews/${id}`),

  createArchitectureReview: (data: CreateArchitectureReviewRequest) =>
    api.post<ArchitectureReview>('/yellow-team/architecture/reviews', data),

  updateArchitectureReview: (id: string, data: Partial<CreateArchitectureReviewRequest>) =>
    api.put<ArchitectureReview>(`/yellow-team/architecture/reviews/${id}`, data),

  deleteArchitectureReview: (id: string) =>
    api.delete<void>(`/yellow-team/architecture/reviews/${id}`),

  getArchitectureThreats: (reviewId: string) =>
    api.get<StrideThreat[]>(`/yellow-team/architecture/reviews/${reviewId}/threats`),

  updateThreatStatus: (threatId: string, status: string, mitigation?: string) =>
    api.put<StrideThreat>(`/yellow-team/architecture/threats/${threatId}`, { status, mitigation }),

  // Semgrep Integration
  listSemgrepRules: () =>
    api.get<SemgrepRule[]>('/yellow-team/sast/semgrep/rules'),

  importSemgrepRules: (yaml: string) =>
    api.post<{ imported: number; message: string }>('/yellow-team/sast/semgrep/import', { yaml }),

  deleteSemgrepRule: (id: string) =>
    api.delete<void>(`/yellow-team/sast/semgrep/rules/${id}`),

  // Taint Analysis
  getTaintFlows: (scanId: string) =>
    api.get<TaintFlowsResponse>(`/yellow-team/sast/scans/${scanId}/taint-flows`),

  analyzeTaint: (code: string, language: string, sourcePath?: string) =>
    api.post<TaintAnalysisResult>('/yellow-team/sast/analyze-taint', { code, language, source_path: sourcePath }),

  // Security Hotspots
  getHotspots: (scanId: string) =>
    api.get<HotspotsResponse>(`/yellow-team/sast/scans/${scanId}/hotspots`),

  updateHotspot: (id: string, data: { resolution?: string; comment?: string }) =>
    api.put<SecurityHotspot>(`/yellow-team/sast/hotspots/${id}`, data),

  detectHotspots: (code: string, language: string, filePath?: string) =>
    api.post<DetectHotspotsResult>('/yellow-team/sast/detect-hotspots', { code, language, file_path: filePath }),

  getHotspotStats: () =>
    api.get<HotspotStats>('/yellow-team/sast/hotspots/stats'),
};

// =============================================================================
// Exploit Research API
// =============================================================================

export interface ExploitSearchParams {
  query?: string;
  source?: string;
  platform?: string;
  exploit_type?: string;
  limit?: number;
}

export interface PocEntry {
  id: string;
  cve_id?: string;
  exploit_id?: string;
  title: string;
  description?: string;
  language: string;
  code_path: string;
  author?: string;
  status: string;
  tags: string[];
  target_info?: string;
  requirements?: string[];
  versions: PocVersion[];
  test_results: PocTestResult[];
  created_at: string;
  updated_at: string;
}

export interface PocVersion {
  version: string;
  code: string;
  changelog?: string;
  created_at: string;
}

export interface PocTestResult {
  tested_at: string;
  success: boolean;
  target_info: string;
  output?: string;
  error?: string;
  execution_time_ms: number;
  notes?: string;
}

export interface CreatePocRequest {
  title: string;
  description?: string;
  code: string;
  language: string;
  cve_id?: string;
  tags?: string[];
  target_info?: string;
  requirements?: string[];
}

export interface ResearchWorkspace {
  id: string;
  cve_id: string;
  title: string;
  description?: string;
  status: string;
  notes: ResearchNote[];
  linked_exploits: string[];
  linked_pocs: string[];
  timeline_events: TimelineEvent[];
  created_at: string;
  updated_at: string;
}

export interface ResearchNote {
  id: string;
  title: string;
  content: string;
  note_type: string;
  references: string[];
  created_at: string;
  updated_at: string;
}

export interface TimelineEvent {
  id: string;
  event_type: string;
  title: string;
  description?: string;
  user_id: string;
  created_at: string;
}

export interface SandboxExecutionRequest {
  sandbox_type?: string;
  target_os?: string;
  target_host?: string;
  target_port?: number;
  isolated_network?: boolean;
  timeout_seconds?: number;
  additional_args?: string[];
}

export interface SandboxExecutionResponse {
  success: boolean;
  execution_id: string;
  status: string;
  result?: SandboxExecutionResult;
  error?: string;
}

export interface SandboxExecutionResult {
  exit_code?: number;
  stdout: string;
  stderr: string;
  execution_time_ms: number;
  success_detected: boolean;
  artifacts_collected: string[];
  network_connections: string[];
}

export interface SandboxEnvironment {
  id: string;
  name: string;
  sandbox_type: string;
  os: string;
  status: string;
  is_ready: boolean;
}

export interface EffectivenessScore {
  total_score: number;
  rating: string;
  reliability_score: number;
  impact_score: number;
  maturity_score: number;
  community_score: number;
  recommendations: string[];
}

export interface CalculateEffectivenessRequest {
  complexity?: string;
  impact_severity?: string;
  has_documentation?: boolean;
  version_count?: number;
  peer_reviewed?: boolean;
  target_coverage?: number;
  external_ratings?: { source: string; rating: string; score?: number }[];
}

export const exploitResearchAPI = {
  // Exploit Search
  searchExploits: (params: ExploitSearchParams) =>
    api.get('/exploit-research/exploits', { params }),

  getExploitsForCve: (cveId: string) =>
    api.get(`/exploit-research/exploits/cve/${cveId}`),

  getCveMapping: (cveId: string) =>
    api.get(`/exploit-research/cve-mapping/${cveId}`),

  batchCveMapping: (cveIds: string[]) =>
    api.post('/exploit-research/cve-mapping/batch', { cve_ids: cveIds }),

  getSyncStatus: () =>
    api.get('/exploit-research/sync-status'),

  getStats: () =>
    api.get('/exploit-research/stats'),

  // PoCs
  listPocs: () =>
    api.get<{ pocs: PocEntry[]; total: number }>('/exploit-research/pocs'),

  getPoc: (id: string) =>
    api.get<PocEntry>(`/exploit-research/pocs/${id}`),

  createPoc: (data: CreatePocRequest) =>
    api.post<{ id: string; poc: PocEntry }>('/exploit-research/pocs', data),

  updatePoc: (id: string, data: Partial<CreatePocRequest>) =>
    api.put<PocEntry>(`/exploit-research/pocs/${id}`, data),

  deletePoc: (id: string) =>
    api.delete<void>(`/exploit-research/pocs/${id}`),

  getPocCode: (id: string) =>
    api.get<{ code: string }>(`/exploit-research/pocs/${id}/code`),

  addPocTestResult: (id: string, result: Partial<PocTestResult>) =>
    api.post<void>(`/exploit-research/pocs/${id}/test`, result),

  // Sandbox Testing
  executePocInSandbox: (pocId: string, request: SandboxExecutionRequest) =>
    api.post<SandboxExecutionResponse>(`/exploit-research/pocs/${pocId}/sandbox`, request),

  getSandboxHistory: (pocId: string) =>
    api.get(`/exploit-research/pocs/${pocId}/sandbox-history`),

  listSandboxEnvironments: () =>
    api.get<{ environments: SandboxEnvironment[] }>('/exploit-research/sandbox/environments'),

  // Effectiveness Scoring
  getPocEffectiveness: (pocId: string) =>
    api.get<{ score: EffectivenessScore }>(`/exploit-research/pocs/${pocId}/effectiveness`),

  calculatePocEffectiveness: (pocId: string, data: CalculateEffectivenessRequest) =>
    api.post<{ score: EffectivenessScore }>(`/exploit-research/pocs/${pocId}/effectiveness/calculate`, data),

  // Timeline
  getPocTimeline: (pocId: string) =>
    api.get<{ events: TimelineEvent[] }>(`/exploit-research/pocs/${pocId}/timeline`),

  addPocTimelineEvent: (pocId: string, event: { event_type: string; title: string; description?: string }) =>
    api.post<void>(`/exploit-research/pocs/${pocId}/timeline`, event),

  // Research Notes
  listNotes: () =>
    api.get('/exploit-research/notes'),

  getNote: (id: string) =>
    api.get(`/exploit-research/notes/${id}`),

  createNote: (data: { title: string; content: string; note_type?: string; cve_ids?: string[]; references?: string[] }) =>
    api.post('/exploit-research/notes', data),

  updateNote: (id: string, data: Partial<{ title: string; content: string; note_type?: string }>) =>
    api.put(`/exploit-research/notes/${id}`, data),

  deleteNote: (id: string) =>
    api.delete<void>(`/exploit-research/notes/${id}`),

  // Research Workspaces
  listWorkspaces: () =>
    api.get<{ workspaces: ResearchWorkspace[] }>('/exploit-research/workspaces'),

  getWorkspace: (id: string) =>
    api.get<ResearchWorkspace>(`/exploit-research/workspaces/${id}`),

  createWorkspace: (data: { cve_id: string; title?: string; description?: string }) =>
    api.post<{ id: string }>('/exploit-research/workspaces', data),

  updateWorkspace: (id: string, data: Partial<{ title: string; description: string; status: string }>) =>
    api.put<ResearchWorkspace>(`/exploit-research/workspaces/${id}`, data),

  deleteWorkspace: (id: string) =>
    api.delete<void>(`/exploit-research/workspaces/${id}`),

  getWorkspaceTimeline: (id: string) =>
    api.get<{ events: TimelineEvent[] }>(`/exploit-research/workspaces/${id}/timeline`),

  exportWorkspace: (id: string) =>
    api.get(`/exploit-research/workspaces/${id}/export`, { responseType: 'blob' }),

  addItemToWorkspace: (workspaceId: string, data: { item_type: 'exploit' | 'poc' | 'note' | 'reference'; item_id?: string; reference?: string }) =>
    api.post<void>(`/exploit-research/workspaces/${workspaceId}/items`, data),
};

// Binary Analysis API
export const binaryAnalysisAPI = {
  // Upload and analyze a binary sample
  uploadSample: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post<{ id: string; message: string }>('/binary-analysis/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  // List samples with pagination
  listSamples: (params?: { limit?: number; offset?: number; file_type?: string; is_packed?: boolean }) =>
    api.get<BinarySampleSummary[]>('/binary-analysis/samples', { params }),

  // Get sample details
  getSample: (id: string) =>
    api.get<BinarySampleDetail>(`/binary-analysis/samples/${id}`),

  // Delete a sample
  deleteSample: (id: string) =>
    api.delete<void>(`/binary-analysis/samples/${id}`),

  // Get extracted strings
  getStrings: (id: string, params?: { limit?: number; min_length?: number; encoding?: string }) =>
    api.get<{ strings: BinaryExtractedString[] }>(`/binary-analysis/samples/${id}/strings`, { params }),

  // Get imports (PE files)
  getImports: (id: string) =>
    api.get<{ imports: BinaryImport[] }>(`/binary-analysis/samples/${id}/imports`),

  // Get exports (PE/ELF files)
  getExports: (id: string) =>
    api.get<{ exports: BinaryExport[] }>(`/binary-analysis/samples/${id}/exports`),

  // Get hex dump of a specific region
  getHexDump: (id: string, offset: number, length: number) =>
    api.get<{ hex: string; ascii: string; offset: number; length: number }>(
      `/binary-analysis/samples/${id}/hexdump`,
      { params: { offset, length } }
    ),

  // Search for patterns in binary
  searchPattern: (id: string, pattern: string, patternType: 'hex' | 'string' | 'regex') =>
    api.post<{ matches: { offset: number; length: number; match: string }[] }>(
      `/binary-analysis/samples/${id}/search`,
      { pattern, pattern_type: patternType }
    ),

  // Get analysis statistics
  getStats: () =>
    api.get<BinaryAnalysisStats>('/binary-analysis/stats'),

  // Get YARA matches
  getYaraMatches: (id: string) =>
    api.get<{ matches: { rule: string; strings: string[]; meta: Record<string, string> }[] }>(
      `/binary-analysis/samples/${id}/yara`
    ),

  // Compare two samples
  compareSamples: (id1: string, id2: string) =>
    api.get<{
      similarity: number;
      common_strings: number;
      common_imports: number;
      entropy_diff: number;
    }>(`/binary-analysis/compare/${id1}/${id2}`),
};

// Import types for the API
import type {
  BinarySampleSummary,
  BinarySampleDetail,
  BinaryExtractedString,
  BinaryImport,
  BinaryExport,
  BinaryAnalysisStats,
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingCoverage,
  FuzzingTemplate,
  FuzzingSeed,
  FuzzingStats,
  FuzzingDictionary,
  CreateFuzzingCampaignRequest,
  UpdateFuzzingCampaignRequest,
  CreateFuzzingTemplateRequest,
  CreateFuzzingDictionaryRequest,
} from '../types';

// Fuzzing API
export const fuzzingAPI = {
  // Campaign CRUD
  listCampaigns: (params?: { limit?: number; offset?: number; status?: string }) =>
    api.get<FuzzingCampaign[]>('/fuzzing/campaigns', { params }),

  createCampaign: (data: CreateFuzzingCampaignRequest) =>
    api.post<FuzzingCampaign>('/fuzzing/campaigns', data),

  getCampaign: (id: string) =>
    api.get<FuzzingCampaign>(`/fuzzing/campaigns/${id}`),

  updateCampaign: (id: string, data: UpdateFuzzingCampaignRequest) =>
    api.put<FuzzingCampaign>(`/fuzzing/campaigns/${id}`, data),

  deleteCampaign: (id: string) =>
    api.delete<void>(`/fuzzing/campaigns/${id}`),

  // Campaign control
  startCampaign: (id: string) =>
    api.post<{ message: string }>(`/fuzzing/campaigns/${id}/start`),

  stopCampaign: (id: string) =>
    api.post<{ message: string }>(`/fuzzing/campaigns/${id}/stop`),

  getCampaignStatus: (id: string) =>
    api.get<{ status: string; iterations: number; crashes_found: number; coverage_percent: number | null }>(
      `/fuzzing/campaigns/${id}/status`
    ),

  // Crashes
  listCrashes: (campaignId: string, params?: { limit?: number; offset?: number; crash_type?: string; is_unique?: boolean }) =>
    api.get<FuzzingCrash[]>(`/fuzzing/campaigns/${campaignId}/crashes`, { params }),

  getCrash: (campaignId: string, crashId: string) =>
    api.get<FuzzingCrash>(`/fuzzing/campaigns/${campaignId}/crashes/${crashId}`),

  updateCrash: (campaignId: string, crashId: string, data: { notes?: string }) =>
    api.put<FuzzingCrash>(`/fuzzing/campaigns/${campaignId}/crashes/${crashId}`, data),

  reproduceCrash: (campaignId: string, crashId: string) =>
    api.post<{ success: boolean; output: string; reproduced: boolean }>(
      `/fuzzing/campaigns/${campaignId}/crashes/${crashId}/reproduce`
    ),

  minimizeCrash: (campaignId: string, crashId: string) =>
    api.post<{ minimized_input: string; reduction_percent: number }>(
      `/fuzzing/campaigns/${campaignId}/crashes/${crashId}/minimize`
    ),

  // Coverage
  getCoverage: (campaignId: string) =>
    api.get<FuzzingCoverage>(`/fuzzing/campaigns/${campaignId}/coverage`),

  // Seeds
  listSeeds: (campaignId: string) =>
    api.get<FuzzingSeed[]>(`/fuzzing/campaigns/${campaignId}/seeds`),

  addSeed: (campaignId: string, data: { data: string; source?: string }) =>
    api.post<FuzzingSeed>(`/fuzzing/campaigns/${campaignId}/seeds`, data),

  // Statistics
  getStats: () =>
    api.get<FuzzingStats>('/fuzzing/stats'),

  getOverview: () =>
    api.get<{ stats: FuzzingStats; recent_campaigns: FuzzingCampaign[]; recent_crashes: FuzzingCrash[] }>(
      '/fuzzing/overview'
    ),

  // Templates
  listTemplates: (params?: { target_type?: string }) =>
    api.get<FuzzingTemplate[]>('/fuzzing/templates', { params }),

  createTemplate: (data: CreateFuzzingTemplateRequest) =>
    api.post<FuzzingTemplate>('/fuzzing/templates', data),

  getTemplate: (id: string) =>
    api.get<FuzzingTemplate>(`/fuzzing/templates/${id}`),

  deleteTemplate: (id: string) =>
    api.delete<void>(`/fuzzing/templates/${id}`),

  // Dictionaries
  listDictionaries: () =>
    api.get<FuzzingDictionary[]>('/fuzzing/dictionaries'),

  createDictionary: (data: CreateFuzzingDictionaryRequest) =>
    api.post<FuzzingDictionary>('/fuzzing/dictionaries', data),

  getDictionary: (id: string) =>
    api.get<FuzzingDictionary>(`/fuzzing/dictionaries/${id}`),

  deleteDictionary: (id: string) =>
    api.delete<void>(`/fuzzing/dictionaries/${id}`),
};

// === Malware Analysis API ===
export interface MalwareSample {
  id: string;
  original_filename: string;
  file_type: string;
  file_size: number;
  md5: string;
  sha1?: string;
  sha256: string;
  ssdeep?: string;
  mime_type?: string;
  entropy: number;
  source: string;
  source_url?: string;
  tags: string[];
  notes?: string;
  is_malicious?: boolean;
  threat_score?: number;
  classification?: string;
  family?: string;
  first_seen: string;
  last_analyzed?: string;
  analysis_count: number;
  created_at: string;
}

export interface MalwareStats {
  total_samples: number;
  samples_analyzed: number;
  samples_malicious: number;
  samples_clean: number;
  samples_pending: number;
  total_iocs: number;
  total_yara_rules: number;
  yara_matches_total: number;
  classifications: { classification: string; count: number }[];
  file_types: { file_type: string; count: number }[];
  recent_samples: MalwareSample[];
}

export interface YaraRule {
  id: string;
  name: string;
  description?: string;
  category: string;
  rule_content?: string;
  tags: string[];
  severity: string;
  is_enabled: boolean;
  is_builtin: boolean;
  match_count: number;
  created_at: string;
  updated_at?: string;
}

export interface MalwareIoc {
  id: string;
  sample_id: string;
  sample_filename?: string;
  sample_sha256?: string;
  ioc_type: string;
  value: string;
  context?: string;
  confidence: number;
  threat_intel_hit?: boolean;
  created_at: string;
}

export interface MalwareQueueItem {
  id: string;
  sample_id: string;
  sample_filename: string;
  sample_sha256: string;
  analysis_types: string;
  priority: number;
  status: string;
  attempts: number;
  error_message?: string;
  created_at: string;
}

export interface AnalysisResult {
  analysis_id: string;
  threat_score: number;
  classification: string;
  family?: string;
  yara_matches: number;
  iocs_extracted: number;
  suspicious_patterns: number;
  packer_detected: boolean;
  message: string;
}

// Sandbox Types
export type SandboxType = 'cuckoo' | 'anyrun' | 'hybrid_analysis';
export type SandboxStatus = 'pending' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled';
export type SandboxVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface SandboxConfig {
  id: string;
  name: string;
  sandbox_type: string;
  api_url: string;
  is_default: boolean;
  is_active: boolean;
  timeout_seconds: number;
  created_at: string;
}

export interface SandboxSubmission {
  id: string;
  sample_id: string;
  sandbox_type: string;
  sandbox_task_id: string;
  status: string;
  submitted_at: string;
  // Extended fields from results (may be null if not completed)
  sample_filename?: string;
  sample_sha256?: string;
  verdict?: string;
  threat_score?: number;
  report_url?: string;
  completed_at?: string;
}

// Aggregated sandbox stats
export interface SandboxStatsAggregate {
  total_submissions: number;
  pending_submissions: number;
  running_submissions: number;
  completed_submissions: number;
  failed_submissions: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  by_type: SandboxStats[];
}

export interface SandboxSubmissionOptions {
  timeout?: number;
  enable_network?: boolean;
  environment?: string;
  arguments?: string;
  password?: string;
  internet_access?: boolean;
  tags?: string[];
  priority?: number;
}

export interface SandboxResult {
  id: string;
  sample_id: string;
  sandbox_type: string;
  status: string;
  verdict: string;
  score: number;
  processes_count: number;
  network_iocs_count: number;
  file_iocs_count: number;
  dropped_files_count: number;
  signatures_count: number;
  mitre_techniques: string[];
  submitted_at: string;
  completed_at?: string;
  analysis_duration_seconds: number;
}

export interface SandboxProcess {
  pid: number;
  ppid: number;
  name: string;
  path?: string;
  command_line?: string;
  username?: string;
  is_injected: boolean;
  is_suspicious: boolean;
}

export interface SandboxDroppedFile {
  filename: string;
  path: string;
  file_type?: string;
  size: number;
  md5: string;
  sha256: string;
  is_executable: boolean;
  is_suspicious: boolean;
  detection?: string;
}

export interface SandboxSignature {
  name: string;
  description: string;
  severity: string;
  category: string;
  families: string[];
  mitre_techniques: string[];
}

export interface SandboxScreenshot {
  id: string;
  timestamp?: string;
  url?: string;
  thumbnail_url?: string;
}

export interface SandboxEnvironment {
  id: string;
  name: string;
  os: string;
  os_version?: string;
  architecture: string;
  available: boolean;
  description?: string;
}

export interface SandboxStats {
  sandbox_type: string;
  total_submissions: number;
  pending: number;
  running: number;
  completed: number;
  failed: number;
  malicious: number;
  suspicious: number;
  clean: number;
  average_analysis_time_seconds: number;
}

export interface SandboxComparison {
  consensus_verdict: string;
  average_score: number;
  sandbox_count: number;
  verdicts: { sandbox_type: string; verdict: string }[];
  scores: { sandbox_type: string; score: number }[];
  common_signatures: string[];
  common_mitre_techniques: string[];
  total_network_iocs: number;
  total_file_iocs: number;
}

export const malwareAnalysisAPI = {
  // Stats & Dashboard
  getStats: () =>
    api.get<MalwareStats>('/malware-analysis/stats'),

  getDashboard: () =>
    api.get<MalwareStats>('/malware-analysis/dashboard'),

  // Samples
  listSamples: (params?: { file_type?: string; classification?: string; is_malicious?: boolean; search?: string; limit?: number; offset?: number }) =>
    api.get<MalwareSample[]>('/malware-analysis/samples', { params }),

  uploadSample: (formData: FormData) =>
    api.post<{ id: string; sha256: string; md5: string; file_type: string; message: string }>('/malware-analysis/samples', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),

  getSample: (id: string) =>
    api.get<MalwareSample & { static_analysis?: unknown; yara_matches: unknown[]; iocs: unknown[] }>(`/malware-analysis/samples/${id}`),

  deleteSample: (id: string) =>
    api.delete<void>(`/malware-analysis/samples/${id}`),

  analyzeSample: (id: string) =>
    api.post<AnalysisResult>(`/malware-analysis/samples/${id}/analyze`),

  reanalyzeSample: (id: string) =>
    api.post<AnalysisResult>(`/malware-analysis/samples/${id}/reanalyze`),

  downloadSample: (id: string) =>
    api.get<Blob>(`/malware-analysis/samples/${id}/download`, { responseType: 'blob' }),

  getSampleStrings: (id: string) =>
    api.get<unknown[]>(`/malware-analysis/samples/${id}/strings`),

  getSampleImports: (id: string) =>
    api.get<unknown[]>(`/malware-analysis/samples/${id}/imports`),

  getSampleIocs: (id: string) =>
    api.get<MalwareIoc[]>(`/malware-analysis/samples/${id}/iocs`),

  getYaraMatches: (id: string) =>
    api.get<unknown[]>(`/malware-analysis/samples/${id}/yara-matches`),

  getClassification: (id: string) =>
    api.get<{ classification: string; family?: string; confidence: number; threat_score: number; reasoning?: string[] }>(`/malware-analysis/samples/${id}/classification`),

  updateTags: (id: string, tags: string[]) =>
    api.put<void>(`/malware-analysis/samples/${id}/tags`, { tags }),

  searchSamples: (params: { query?: string; hash?: string; file_type?: string; classification?: string; min_threat_score?: number; max_threat_score?: number; limit?: number }) =>
    api.post<MalwareSample[]>('/malware-analysis/samples/search', params),

  lookupSample: (hash: string) =>
    api.post<{ found: boolean; sample?: MalwareSample }>('/malware-analysis/samples/lookup', { hash }),

  // YARA Rules
  listYaraRules: (params?: { category?: string; include_builtin?: boolean }) =>
    api.get<YaraRule[]>('/malware-analysis/yara/rules', { params }),

  createYaraRule: (data: { name: string; description?: string; category: string; rule_content: string; tags: string[]; severity?: string }) =>
    api.post<{ id: string; message: string }>('/malware-analysis/yara/rules', data),

  getYaraRule: (id: string) =>
    api.get<YaraRule>(`/malware-analysis/yara/rules/${id}`),

  updateYaraRule: (id: string, data: { name: string; description?: string; category: string; rule_content: string; tags: string[]; severity?: string }) =>
    api.put<void>(`/malware-analysis/yara/rules/${id}`, data),

  deleteYaraRule: (id: string) =>
    api.delete<void>(`/malware-analysis/yara/rules/${id}`),

  toggleYaraRule: (id: string) =>
    api.post<void>(`/malware-analysis/yara/rules/${id}/toggle`),

  scanWithYara: (sampleId: string) =>
    api.post<AnalysisResult>('/malware-analysis/yara/scan', { sample_id: sampleId }),

  // IOCs
  listIocs: (params?: { ioc_type?: string; limit?: number; offset?: number }) =>
    api.get<MalwareIoc[]>('/malware-analysis/iocs', { params }),

  searchIocs: (value: string, iocType?: string) =>
    api.post<MalwareIoc[]>('/malware-analysis/iocs/search', { value, ioc_type: iocType }),

  exportIocs: (params?: { format?: string; ioc_type?: string }) =>
    api.get('/malware-analysis/iocs/export', { params, responseType: params?.format === 'csv' ? 'blob' : 'json' }),

  // Analysis Queue
  listQueue: () =>
    api.get<MalwareQueueItem[]>('/malware-analysis/queue'),

  cancelQueueItem: (id: string) =>
    api.post<void>(`/malware-analysis/queue/${id}/cancel`),
};

// Sandbox API
export const sandboxAPI = {
  // Configuration
  listConfigs: () =>
    api.get<SandboxConfig[]>('/sandbox/configs'),

  createConfig: (data: { name: string; sandbox_type: SandboxType; api_url: string; api_key?: string; is_default?: boolean; timeout_seconds?: number }) =>
    api.post<{ id: string; message: string }>('/sandbox/configs', data),

  getConfig: (id: string) =>
    api.get<SandboxConfig>(`/sandbox/configs/${id}`),

  updateConfig: (id: string, data: { name: string; sandbox_type: SandboxType; api_url: string; api_key?: string; is_default?: boolean; timeout_seconds?: number }) =>
    api.put<{ message: string }>(`/sandbox/configs/${id}`, data),

  deleteConfig: (id: string) =>
    api.delete<{ message: string }>(`/sandbox/configs/${id}`),

  testConnection: (id: string) =>
    api.post<{ success: boolean; message: string; environments_count?: number }>(`/sandbox/configs/${id}/test`),

  // Submissions
  submitSample: (data: { sample_id: string; sandbox_config_id: string; options?: SandboxSubmissionOptions }) =>
    api.post<SandboxSubmission>('/sandbox/submit', data),

  listSubmissions: (params?: { limit?: number; offset?: number; sandbox_type?: string; status?: string }) =>
    api.get<SandboxSubmission[]>('/sandbox/submissions', { params }),

  getSubmission: (id: string) =>
    api.get<SandboxSubmission>(`/sandbox/submissions/${id}`),

  getStatus: (id: string) =>
    api.get<{ submission_id: string; status: string; progress?: number; message?: string }>(`/sandbox/submissions/${id}/status`),

  getResults: (id: string) =>
    api.get<SandboxResult>(`/sandbox/submissions/${id}/results`),

  getProcesses: (id: string) =>
    api.get<SandboxProcess[]>(`/sandbox/submissions/${id}/processes`),

  getScreenshots: (id: string) =>
    api.get<SandboxScreenshot[]>(`/sandbox/submissions/${id}/screenshots`),

  getDroppedFiles: (id: string) =>
    api.get<SandboxDroppedFile[]>(`/sandbox/submissions/${id}/dropped`),

  getSignatures: (id: string) =>
    api.get<SandboxSignature[]>(`/sandbox/submissions/${id}/signatures`),

  getIocs: (id: string) =>
    api.get<{ network_iocs: unknown[]; file_iocs: unknown[] }>(`/sandbox/submissions/${id}/iocs`),

  // Comparison
  compareSubmissions: (submission_ids: string[]) =>
    api.post<SandboxComparison>('/sandbox/compare', { submission_ids }),

  // Environments
  listEnvironments: () =>
    api.get<SandboxEnvironment[]>('/sandbox/environments'),

  getEnvironmentsForConfig: (configId: string) =>
    api.get<SandboxEnvironment[]>(`/sandbox/environments/${configId}`),

  // Statistics
  getStats: () =>
    api.get<SandboxStats[]>('/sandbox/stats'),

  getStatsByType: (sandboxType: string) =>
    api.get<SandboxStats>(`/sandbox/stats/${sandboxType}`),
};

// ============================================================================
// Extended Threat Intelligence API - MISP, STIX, TAXII, Threat Actors
// ============================================================================

export interface MispServer {
  id: string;
  name: string;
  url: string;
  api_key?: string;
  enabled: boolean;
  last_sync_at?: string;
  last_sync_status?: string;
  events_synced: number;
  created_at: string;
}

export interface MispEvent {
  id: string;
  server_id: string;
  misp_event_id: string;
  misp_uuid: string;
  org_name: string;
  info: string;
  threat_level: string;
  analysis_status: string;
  date: string;
  published: boolean;
  attribute_count: number;
  tags: string[];
  synced_at: string;
}

export interface MispAttribute {
  id: string;
  event_id: string;
  category: string;
  attr_type: string;
  value: string;
  to_ids: boolean;
  comment?: string;
}

export interface TaxiiServer {
  id: string;
  name: string;
  url: string;
  username?: string;
  version: string;
  enabled: boolean;
  last_poll_at?: string;
  last_poll_status?: string;
  objects_synced: number;
  created_at: string;
}

export interface TaxiiCollection {
  id: string;
  server_id: string;
  collection_id: string;
  title: string;
  description?: string;
  can_read: boolean;
  can_write: boolean;
  objects_count: number;
  last_polled_at?: string;
}

export interface StixBundle {
  id: string;
  name: string;
  source: string;
  source_id?: string;
  spec_version: string;
  objects_count: number;
  created_at: string;
}

export interface StixObject {
  id: string;
  bundle_id: string;
  stix_id: string;
  stix_type: string;
  name?: string;
  description?: string;
  created: string;
  modified: string;
  raw_json: string;
}

export interface ThreatActorSummary {
  id: string;
  name: string;
  aliases: string[];
  actor_type: string;
  country?: string;
  motivation: string;
  active: boolean;
  sophistication: number;
  first_seen?: string;
  last_seen?: string;
  target_sectors: string[];
  campaign_count: number;
}

export interface ThreatActorDetail extends ThreatActorSummary {
  description?: string;
  resource_level: number;
  target_countries: string[];
  ttps: string[];
  tools: string[];
  malware: string[];
  infrastructure?: unknown;
  external_references: ExternalReference[];
  campaigns: CampaignSummary[];
  mitre_groups: string[];
}

export interface ExternalReference {
  source: string;
  url?: string;
  external_id?: string;
  description?: string;
}

export interface CampaignSummary {
  id: string;
  name: string;
  description?: string;
  first_seen?: string;
  last_seen?: string;
  status: string;
  target_count: number;
}

export interface IocCorrelation {
  ioc_type: string;
  ioc_value: string;
  source_type: string;
  source_id: string;
  source_name: string;
  confidence: number;
  threat_level?: string;
}

export interface CorrelationResult {
  iocs_checked: number;
  correlations_found: number;
  correlations: IocCorrelation[];
}

export interface ThreatIntelStats {
  misp_servers: number;
  misp_events: number;
  misp_attributes: number;
  taxii_servers: number;
  taxii_collections: number;
  stix_bundles: number;
  stix_objects: number;
  threat_actors: number;
  campaigns: number;
}

export const extendedThreatIntelAPI = {
  // Dashboard
  getStats: () =>
    api.get<ThreatIntelStats>('/threat-intel/dashboard/stats'),

  // MISP Servers
  listMispServers: () =>
    api.get<MispServer[]>('/threat-intel/misp/servers'),

  addMispServer: (data: { name: string; url: string; api_key: string }) =>
    api.post<MispServer>('/threat-intel/misp/servers', data),

  updateMispServer: (id: string, data: { name?: string; url?: string; api_key?: string; enabled?: boolean }) =>
    api.put<MispServer>(`/threat-intel/misp/servers/${id}`, data),

  deleteMispServer: (id: string) =>
    api.delete(`/threat-intel/misp/servers/${id}`),

  testMispServer: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/threat-intel/misp/servers/${id}/test`),

  syncMispServer: (id: string) =>
    api.post<{ success: boolean; message: string; events_synced?: number }>(`/threat-intel/misp/servers/${id}/sync`),

  listMispEvents: (params?: { server_id?: string; limit?: number }) =>
    api.get<MispEvent[]>('/threat-intel/misp/events', { params }),

  getMispEvent: (id: string) =>
    api.get<MispEvent>(`/threat-intel/misp/events/${id}`),

  getMispEventAttributes: (id: string) =>
    api.get<MispAttribute[]>(`/threat-intel/misp/events/${id}/attributes`),

  searchMispAttributes: (query: string) =>
    api.get<MispAttribute[]>('/threat-intel/misp/attributes/search', { params: { query } }),

  // TAXII Servers
  listTaxiiServers: () =>
    api.get<TaxiiServer[]>('/threat-intel/taxii/servers'),

  addTaxiiServer: (data: { name: string; url: string; username?: string; password?: string; version?: string }) =>
    api.post<TaxiiServer>('/threat-intel/taxii/servers', data),

  updateTaxiiServer: (id: string, data: { name?: string; url?: string; username?: string; password?: string; enabled?: boolean }) =>
    api.put<TaxiiServer>(`/threat-intel/taxii/servers/${id}`, data),

  deleteTaxiiServer: (id: string) =>
    api.delete(`/threat-intel/taxii/servers/${id}`),

  testTaxiiServer: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/threat-intel/taxii/servers/${id}/test`),

  discoverTaxiiCollections: (id: string) =>
    api.post<{ success: boolean; collections_found?: number }>(`/threat-intel/taxii/servers/${id}/discover`),

  listTaxiiCollections: (serverId: string) =>
    api.get<TaxiiCollection[]>(`/threat-intel/taxii/servers/${serverId}/collections`),

  pollTaxiiCollection: (serverId: string, collectionId: string) =>
    api.post<{ success: boolean; objects_retrieved?: number }>(`/threat-intel/taxii/servers/${serverId}/collections/${collectionId}/poll`),

  // STIX Objects
  listStixBundles: (params?: { source?: string; limit?: number }) =>
    api.get<StixBundle[]>('/threat-intel/stix/bundles', { params }),

  getStixBundle: (id: string) =>
    api.get<StixBundle>(`/threat-intel/stix/bundles/${id}`),

  getStixBundleObjects: (id: string, params?: { type?: string; limit?: number }) =>
    api.get<StixObject[]>(`/threat-intel/stix/bundles/${id}/objects`, { params }),

  importStixBundle: (data: { name: string; content: string }) =>
    api.post<{ success: boolean; bundle_id?: string; objects_imported?: number }>('/threat-intel/stix/bundles/import', data),

  exportStixBundle: (bundleId: string) =>
    api.get<{ bundle: string }>(`/threat-intel/stix/bundles/${bundleId}/export`),

  listStixObjects: (params?: { type?: string; name?: string; limit?: number }) =>
    api.get<{ objects: StixObject[]; total: number }>('/threat-intel/stix/objects', { params }).then(r => r.data.objects),

  getStixObject: (id: string) =>
    api.get<StixObject>(`/threat-intel/stix/objects/${id}`),

  // Threat Actors
  listThreatActors: (params?: { actor_type?: string; country?: string; motivation?: string; name?: string; active_only?: boolean; limit?: number }) =>
    api.get<ThreatActorSummary[]>('/threat-intel/threat-actors', { params }),

  getThreatActor: (id: string) =>
    api.get<ThreatActorDetail>(`/threat-intel/threat-actors/${id}`),

  searchThreatActors: (query: string) =>
    api.get<ThreatActorSummary[]>('/threat-intel/threat-actors/search', { params: { query } }),

  // IOC Correlation
  correlateIocs: (data: { iocs?: { ioc_type: string; value: string }[]; scan_id?: string }) =>
    api.post<CorrelationResult>('/threat-intel/correlate', data),

  // Sprint 12: Campaigns
  listCampaigns: () =>
    api.get<{ campaigns: ThreatCampaign[]; total: number }>('/threat-intel/campaigns').then(r => r.data.campaigns),

  getCampaign: (id: string) =>
    api.get<ThreatCampaignDetail>(`/threat-intel/campaigns/${id}`),

  createCampaign: (data: CreateThreatCampaignRequest) =>
    api.post<ThreatCampaign>('/threat-intel/campaigns', data),

  updateCampaign: (id: string, data: CreateThreatCampaignRequest) =>
    api.put<ThreatCampaign>(`/threat-intel/campaigns/${id}`, data),

  deleteCampaign: (id: string) =>
    api.delete(`/threat-intel/campaigns/${id}`),

  // Sprint 12: Diamond Model
  listDiamondEvents: (params?: { campaign_id?: string; limit?: number }) =>
    api.get<{ events: DiamondEvent[]; total: number }>('/threat-intel/diamond/events', { params }).then(r => r.data.events),

  getDiamondEvent: (id: string) =>
    api.get<DiamondEvent>(`/threat-intel/diamond/events/${id}`),

  createDiamondEvent: (data: CreateDiamondEventRequest) =>
    api.post<DiamondEvent>('/threat-intel/diamond/events', data),

  // Sprint 12: Kill Chain
  getKillChainAnalysis: (campaignId: string) =>
    api.get<KillChainAnalysis>(`/threat-intel/kill-chain/${campaignId}`),

  getKillChainPhases: () =>
    api.get<{ phases: KillChainPhaseInfo[]; total: number }>('/threat-intel/kill-chain/phases').then(r => r.data.phases),

  // Sprint 12: Intelligence Requirements
  listIntelRequirements: (params?: { status?: string; priority?: string }) =>
    api.get<{ requirements: IntelligenceRequirement[]; total: number }>('/threat-intel/requirements', { params }).then(r => r.data.requirements),

  createIntelRequirement: (data: CreateIntelRequirementRequest) =>
    api.post<IntelligenceRequirement>('/threat-intel/requirements', data),

  updateIntelRequirement: (id: string, data: UpdateIntelRequirementRequest) =>
    api.put<IntelligenceRequirement>(`/threat-intel/requirements/${id}`, data),

  deleteIntelRequirement: (id: string) =>
    api.delete(`/threat-intel/requirements/${id}`),

  // Sprint 12: Threat Briefings
  generateThreatBriefing: (data: GenerateBriefingRequest) =>
    api.post<ThreatBriefing>('/threat-intel/briefings/generate', data),

  getLatestBriefing: () =>
    api.get<ThreatBriefing>('/threat-intel/briefings/latest'),
};

// Sprint 12: Threat Campaign Types
export interface ThreatCampaign {
  id: string;
  name: string;
  threat_actor_id?: string;
  description?: string;
  objective?: string;
  first_seen?: string;
  last_seen?: string;
  status: string;
  created_at: string;
}

export interface ThreatCampaignDetail extends ThreatCampaign {
  threat_actor_name?: string;
  confidence: number;
  targets: CampaignTarget[];
  ttps: string[];
  iocs: CampaignIoc[];
  timeline_events: CampaignTimelineEvent[];
  attribution_confidence: number;
}

export interface CampaignTarget {
  target_type: string;
  value: string;
  sector?: string;
  country?: string;
}

export interface CampaignIoc {
  ioc_type: string;
  value: string;
  first_seen?: string;
  last_seen?: string;
  confidence: number;
}

export interface CampaignTimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  references: string[];
}

export interface CreateThreatCampaignRequest {
  name: string;
  threat_actor_id?: string;
  description?: string;
  objective?: string;
  first_seen?: string;
  status?: string;
  targets?: CampaignTarget[];
  ttps?: string[];
}

// Sprint 12: Diamond Model Types
export interface DiamondEvent {
  id: string;
  campaign_id?: string;
  adversary: DiamondVertex;
  capability: DiamondVertex;
  infrastructure: DiamondVertex;
  victim: DiamondVertex;
  timestamp?: string;
  phase?: string;
  confidence: number;
  notes?: string;
  created_at: string;
}

export interface DiamondVertex {
  name?: string;
  vertex_type?: string;
  attributes: Record<string, string>;
  confidence: number;
}

export interface CreateDiamondEventRequest {
  campaign_id?: string;
  adversary: DiamondVertex;
  capability: DiamondVertex;
  infrastructure: DiamondVertex;
  victim: DiamondVertex;
  timestamp?: string;
  phase?: string;
  notes?: string;
}

// Sprint 12: Kill Chain Types
export interface KillChainAnalysis {
  campaign_id: string;
  campaign_name: string;
  phases: KillChainPhase[];
  coverage: number;
  detected_techniques: number;
  total_techniques: number;
}

export interface KillChainPhase {
  phase: string;
  phase_name: string;
  order: number;
  techniques: KillChainTechnique[];
  coverage: number;
}

export interface KillChainTechnique {
  technique_id: string;
  technique_name: string;
  detected: boolean;
  detection_source?: string;
  timestamp?: string;
  evidence?: string;
}

export interface KillChainPhaseInfo {
  phase: string;
  phase_name: string;
  order: number;
  description: string;
}

// Sprint 12: Intelligence Requirements Types
export interface IntelligenceRequirement {
  id: string;
  title: string;
  description?: string;
  priority: string;
  category: string;
  status: string;
  source?: string;
  stakeholders?: string[];
  keywords?: string[];
  deadline?: string;
  related_actors?: string[];
  related_campaigns?: string[];
  answer?: string;
  answered_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateIntelRequirementRequest {
  title: string;
  description?: string;
  priority?: string;
  category?: string;
  source?: string;
  stakeholders?: string[];
  keywords?: string[];
  deadline?: string;
}

export interface UpdateIntelRequirementRequest {
  title?: string;
  description?: string;
  priority?: string;
  status?: string;
  answer?: string;
}

// Sprint 12: Threat Briefing Types
export interface ThreatBriefing {
  id: string;
  title: string;
  executive_summary: string;
  threat_landscape: ThreatLandscape;
  top_actors: ThreatActorBrief[];
  active_campaigns: CampaignBrief[];
  key_iocs: KeyIoc[];
  risk_assessment: RiskAssessment;
  recommendations: string[];
  generated_at: string;
  period_start: string;
  period_end: string;
}

export interface ThreatLandscape {
  overall_threat_level: string;
  trending_ttps: string[];
  targeted_sectors: SectorThreat[];
  geographic_focus: string[];
}

export interface SectorThreat {
  sector: string;
  threat_level: string;
  campaigns_targeting: number;
}

export interface ThreatActorBrief {
  id: string;
  name: string;
  aliases: string[];
  motivation: string;
  recent_activity: string;
  threat_level: string;
  key_ttps: string[];
}

export interface CampaignBrief {
  id: string;
  name: string;
  actor_name?: string;
  targets: string[];
  status: string;
  last_activity?: string;
}

export interface KeyIoc {
  ioc_type: string;
  value: string;
  associated_actors: string[];
  first_seen: string;
}

export interface RiskAssessment {
  overall_risk: string;
  risk_factors: string[];
  priority_actions: string[];
}

export interface GenerateBriefingRequest {
  title?: string;
  period_days?: number;
  focus_sectors?: string[];
  focus_actors?: string[];
}

// ============================================================================
// SCA (Software Composition Analysis) API
// ============================================================================

export interface ScaProject {
  id: string;
  name: string;
  repository_url?: string;
  ecosystem: string;
  manifest_files?: string[];
  last_scan_at?: string;
  total_dependencies: number;
  vulnerable_dependencies: number;
  license_issues: number;
  customer_id?: string;
  engagement_id?: string;
  created_at: string;
  updated_at: string;
}

export interface ScaDependency {
  id: string;
  project_id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl?: string;
  is_direct: boolean;
  depth: number;
  license?: string;
  license_risk?: string;
  latest_version?: string;
  update_available: boolean;
}

export interface ScaVulnerability {
  id: string;
  dependency_id: string;
  vuln_id: string;
  source: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  title?: string;
  description?: string;
  affected_versions?: string;
  fixed_version?: string;
  references?: string[];
  exploited_in_wild: boolean;
  status: string;
}

export interface ScaStats {
  total_projects: number;
  total_dependencies: number;
  vulnerable_dependencies: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  license_issues: number;
  updates_available: number;
}

export const scaAPI = {
  getStats: () => api.get<ScaStats>('/sca/stats'),
  getProjects: () => api.get<ScaProject[]>('/sca/projects'),
  getProject: (id: string) => api.get<ScaProject>(`/sca/projects/${id}`),
  createProject: (data: { name: string; repository_url?: string; ecosystem?: string; customer_id?: string; engagement_id?: string }) =>
    api.post<ScaProject>('/sca/projects', data),
  updateProject: (id: string, data: Partial<ScaProject>) =>
    api.put<ScaProject>(`/sca/projects/${id}`, data),
  deleteProject: (id: string) => api.delete(`/sca/projects/${id}`),
  analyzeProject: (id: string, data: { manifest_content?: string; manifest_filename?: string; check_updates?: boolean }) =>
    api.post(`/sca/projects/${id}/analyze`, data),
  getDependencies: (id: string, params?: { is_direct?: boolean; has_vulnerabilities?: boolean; license_risk?: string; update_available?: boolean; limit?: number; offset?: number }) =>
    api.get<ScaDependency[]>(`/sca/projects/${id}/dependencies`, { params }),
  getVulnerabilities: (id: string, params?: { severity?: string; status?: string; exploited_in_wild?: boolean; has_fix?: boolean; limit?: number; offset?: number }) =>
    api.get<ScaVulnerability[]>(`/sca/projects/${id}/vulnerabilities`, { params }),
  updateVulnStatus: (projectId: string, vulnId: string, status: string) =>
    api.put(`/sca/projects/${projectId}/vulnerabilities/${vulnId}/status`, { status }),
  getUpdates: (id: string) => api.get(`/sca/projects/${id}/updates`),
  exportSbom: (id: string, format: 'cyclonedx' | 'spdx') =>
    api.get(`/sca/projects/${id}/sbom`, {
      params: { format },
      responseType: 'blob'
    }),
};

// ============================================================================
// IoT Security API
// ============================================================================

export interface IotDevice {
  id: string;
  name?: string;
  device_type?: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  ip_address?: string;
  mac_address?: string;
  hostname?: string;
  protocols?: string[];
  open_ports?: number[];
  default_creds_status?: string;
  last_seen?: string;
  first_seen?: string;
  risk_score: number;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface IotScan {
  id: string;
  name: string;
  scan_type: string;
  target_range?: string;
  status: string;
  devices_found: number;
  vulnerabilities_found: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface IotCredential {
  id: string;
  device_type: string;
  vendor?: string;
  model?: string;
  protocol: string;
  username?: string;
  password?: string;
  source: string;
  created_at: string;
}

export const iotAPI = {
  getDashboard: () => api.get('/iot/dashboard'),
  getDevices: (params?: { device_type?: string; vendor?: string; risk_score_min?: number; limit?: number; offset?: number }) =>
    api.get<IotDevice[]>('/iot/devices', { params }),
  getDevice: (id: string) => api.get<IotDevice>(`/iot/devices/${id}`),
  createDevice: (data: Partial<IotDevice>) => api.post<IotDevice>('/iot/devices', data),
  updateDevice: (id: string, data: Partial<IotDevice>) => api.put<IotDevice>(`/iot/devices/${id}`, data),
  deleteDevice: (id: string) => api.delete(`/iot/devices/${id}`),
  startScan: (data: { name: string; scan_type: string; target_range?: string }) =>
    api.post<IotScan>('/iot/scan', data),
  getScans: (params?: { scan_type?: string; status?: string; limit?: number; offset?: number }) =>
    api.get<IotScan[]>('/iot/scans', { params }),
  getScan: (id: string) => api.get<IotScan>(`/iot/scans/${id}`),
  searchCredentials: (params?: { device_type?: string; vendor?: string; model?: string; protocol?: string }) =>
    api.get<IotCredential[]>('/iot/credentials/search', { params }),
};

// ============================================================================
// OT/ICS Security API
// ============================================================================

export interface OtAsset {
  id: string;
  name: string;
  asset_type: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  ip_address?: string;
  mac_address?: string;
  protocols?: string[];
  purdue_level?: number;
  zone?: string;
  criticality?: string;
  last_seen?: string;
  first_seen?: string;
  risk_score: number;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface OtScan {
  id: string;
  name: string;
  scan_type: string;
  target_range: string;
  protocols_enabled?: string[];
  status: string;
  assets_discovered: number;
  vulnerabilities_found: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export const otAPI = {
  getDashboard: () => api.get('/ot/dashboard'),
  getAssets: (params?: { asset_type?: string; purdue_level?: number; criticality?: string; limit?: number; offset?: number }) =>
    api.get<OtAsset[]>('/ot/assets', { params }),
  getAsset: (id: string) => api.get<OtAsset>(`/ot/assets/${id}`),
  createAsset: (data: Partial<OtAsset>) => api.post<OtAsset>('/ot/assets', data),
  updateAsset: (id: string, data: Partial<OtAsset>) => api.put<OtAsset>(`/ot/assets/${id}`, data),
  deleteAsset: (id: string) => api.delete(`/ot/assets/${id}`),
  startScan: (data: { name: string; scan_type: string; target_range: string; protocols_enabled?: string[] }) =>
    api.post<OtScan>('/ot/scan', data),
  getScans: (params?: { scan_type?: string; status?: string; limit?: number; offset?: number }) =>
    api.get<OtScan[]>('/ot/scans', { params }),
  getScan: (id: string) => api.get<OtScan>(`/ot/scans/${id}`),
  getPurdueLevels: () => api.get('/ot/purdue/levels'),
  getPurdueView: (params?: { customer_id?: string }) => api.get('/ot/purdue/view', { params }),
  getPurdueCompliance: (params?: { customer_id?: string }) => api.get('/ot/purdue/compliance', { params }),
  classifyPurdueLevel: (data: { asset_type: string; protocols: string[] }) =>
    api.post('/ot/purdue/classify', data),
};

// ============================================================================
// CI/CD Integration API
// ============================================================================

export interface CicdPipeline {
  id: string;
  name: string;
  platform: 'github_actions' | 'gitlab_ci' | 'jenkins' | 'azure_devops' | 'circleci' | 'bitbucket';
  repository_url?: string;
  enabled: boolean;
  webhook_secret?: string;
  last_run_at?: string;
  last_run_status?: string;
  customer_id?: string;
  engagement_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CicdRun {
  id: string;
  pipeline_id: string;
  branch: string;
  commit_sha: string;
  trigger_type: string;
  pr_number?: number;
  status: string;
  gate_status?: string;
  findings_new: number;
  findings_fixed: number;
  findings_total: number;
  duration_seconds?: number;
  started_at: string;
  completed_at?: string;
}

export interface CicdPolicy {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  conditions: any;
  actions: any;
  created_at: string;
  updated_at: string;
}

export interface CicdTemplate {
  platform: string;
  content: string;
  description?: string;
}

export const cicdAPI = {
  // Pipelines
  getPipelines: () => api.get<CicdPipeline[]>('/cicd/pipelines'),
  getPipeline: (id: string) => api.get<CicdPipeline>(`/cicd/pipelines/${id}`),
  createPipeline: (data: { name: string; platform: string; repository_url?: string; customer_id?: string; engagement_id?: string }) =>
    api.post<CicdPipeline>('/cicd/pipelines', data),
  updatePipeline: (id: string, data: Partial<CicdPipeline>) =>
    api.put<CicdPipeline>(`/cicd/pipelines/${id}`, data),
  deletePipeline: (id: string) => api.delete(`/cicd/pipelines/${id}`),

  // Runs
  getRuns: (params?: { pipeline_id?: string; status?: string; branch?: string; limit?: number; offset?: number }) =>
    api.get<CicdRun[]>('/cicd/runs', { params }),
  getRun: (id: string) => api.get<CicdRun>(`/cicd/runs/${id}`),
  getGateStatus: (id: string) => api.get(`/cicd/runs/${id}/gate-status`),

  // Policies
  getPolicies: () => api.get<CicdPolicy[]>('/cicd/policies'),
  getPolicy: (id: string) => api.get<CicdPolicy>(`/cicd/policies/${id}`),
  createPolicy: (data: { name: string; description?: string; conditions: any; actions: any }) =>
    api.post<CicdPolicy>('/cicd/policies', data),
  updatePolicy: (id: string, data: Partial<CicdPolicy>) =>
    api.put<CicdPolicy>(`/cicd/policies/${id}`, data),
  deletePolicy: (id: string) => api.delete(`/cicd/policies/${id}`),

  // Templates
  getTemplates: () => api.get<CicdTemplate[]>('/cicd/templates'),
  getPlatforms: () => api.get<string[]>('/cicd/templates/platforms'),
  getTemplate: (platform: string) => api.get<CicdTemplate>(`/cicd/templates/${platform}`),
  generateTemplate: (data: { platform: string; features?: string[] }) =>
    api.post<CicdTemplate>('/cicd/templates/generate', data),
};

// ============================================================================
// SOAR (Security Orchestration, Automation, and Response) API
// ============================================================================

export interface SoarPlaybook {
  id: string;
  name: string;
  description?: string;
  category: string;
  trigger_type: string;
  status: string;
  version: number;
  run_count: number;
  success_rate?: number;
  avg_duration_seconds?: number;
  last_run_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SoarAction {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  category: string;
  action_type: string;
  risk_level: string;
  requires_approval: boolean;
}

export interface SoarRun {
  id: string;
  playbook_id: string;
  playbook_name?: string;
  trigger_type: string;
  status: string;
  current_step: number;
  total_steps: number;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  initiated_by?: string;
}

export interface SoarApproval {
  id: string;
  run_id: string;
  playbook_name?: string;
  step_name?: string;
  status: string;
  required_approvals: number;
  current_approvals: number;
  created_at: string;
}

export interface SoarIntegration {
  id: string;
  name: string;
  integration_type: string;
  vendor?: string;
  status: string;
  last_test_at?: string;
}

export const soarAPI = {
  // Playbooks (using green-team SOAR API)
  getPlaybooks: () => api.get<SoarPlaybook[]>('/green-team/playbooks'),
  getPlaybook: (id: string) => api.get<SoarPlaybook>(`/green-team/playbooks/${id}`),
  createPlaybook: (data: Partial<SoarPlaybook>) => api.post<SoarPlaybook>('/green-team/playbooks', data),
  updatePlaybook: (id: string, data: Partial<SoarPlaybook>) => api.put<SoarPlaybook>(`/green-team/playbooks/${id}`, data),
  deletePlaybook: (id: string) => api.delete(`/green-team/playbooks/${id}`),
  runPlaybook: (id: string, data?: { input_data?: any }) =>
    api.post(`/green-team/playbooks/${id}/execute`, data),

  // Runs
  getRuns: (params?: { status?: string; playbook_id?: string; limit?: number; offset?: number }) =>
    api.get<SoarRun[]>('/workflows/instances', { params }),
  getRun: (id: string) => api.get<SoarRun>(`/workflows/instances/${id}`),
  cancelRun: (id: string) => api.post(`/workflows/instances/${id}/cancel`),

  // Approvals
  getApprovals: (params?: { status?: string }) =>
    api.get<SoarApproval[]>('/workflows/approvals', { params }),
  approveStep: (approvalId: string, decision: string, notes?: string) =>
    api.post(`/workflows/approvals/${approvalId}/approve`, { decision, notes }),
  rejectStep: (approvalId: string, reason?: string) =>
    api.post(`/workflows/approvals/${approvalId}/reject`, { reason }),

  // Actions - from SOAR module
  getActions: () => api.get('/green-team/soar/actions'),

  // Integrations - from SOAR module
  getIntegrations: () => api.get('/green-team/soar/integrations'),
};

export default api;

// ============================================================================
// AI Security API
// ============================================================================

export interface AIModel {
  id: string;
  name: string;
  model_type: string;
  purpose: string;
  status: 'training' | 'active' | 'inactive' | 'failed';
  accuracy: number;
  precision_score?: number;
  recall_score?: number;
  f1_score?: number;
  trained_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface PrioritizedAlert {
  id: string;
  entity_id: string;
  priority: string;
  score: number;
  confidence: number;
  factors: string[];
  recommendations: string[];
  created_at: string;
}

export interface AnomalyDetection {
  id: string;
  entity_type: 'user' | 'host' | 'service';
  entity_id: string;
  anomaly_type: string;
  severity: string;
  score: number;
  detected_at: string;
  resolved: boolean;
}

export interface LLMTarget {
  id: string;
  name: string;
  endpoint: string;
  model_type: string;
  created_at: string;
}

export interface LLMTestRun {
  id: string;
  target_name: string;
  target_type: string;
  test_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  tests_run: number;
  vulnerabilities_found: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface LLMTestCase {
  id: string;
  category: string;
  name: string;
  description?: string;
  payload: string;
  severity: string;
  enabled: boolean;
}

export interface LLMTarget {
  id: string;
  user_id: string;
  name: string;
  endpoint: string;
  model_type: string;
  description?: string;
  api_key_encrypted?: string;
  headers?: Record<string, string>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AIDashboard {
  total_predictions: number;
  prediction_accuracy: number;
  active_models: number;
  llm_tests_run: number;
  llm_vulns_found: number;
  anomalies_detected: number;
  false_positive_rate: number;
}

// Conversation Test Types
export interface ConversationTurn {
  turn_number: number;
  role: 'user' | 'assistant' | 'system';
  content: string;
  wait_for_response: boolean;
  analyze_response: boolean;
  success_indicators: string[];
  abort_indicators: string[];
}

export interface SuccessCriteria {
  min_successful_turns: number;
  require_all_turns: boolean;
  critical_turn?: number;
  final_success_patterns: string[];
}

export interface ConversationTest {
  id: string;
  name: string;
  description: string;
  category: string;
  turns: ConversationTurn[];
  success_criteria: SuccessCriteria;
  severity: string;
  is_builtin: boolean;
  created_at: string;
}

export interface TurnResult {
  turn_number: number;
  prompt_sent: string;
  response_received: string;
  success_indicators_matched: string[];
  abort_triggered: boolean;
  analysis_result?: string;
}

export interface ConversationTestResult {
  test_id: string;
  test_name: string;
  category: string;
  turns_executed: TurnResult[];
  final_status: 'passed' | 'failed' | 'aborted' | 'error';
  vulnerability_detected_at_turn?: number;
  conversation_history: [string, string][];
  overall_confidence: number;
  severity: string;
  remediation?: string;
  duration_ms: number;
}

// Agent Test Types
export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, any>;
  dangerous: boolean;
}

export interface AgentTestConfig {
  id: string;
  target_id: string;
  tools: ToolDefinition[];
  rag_endpoint?: string;
  function_format: 'openai' | 'anthropic' | 'gemini' | 'custom';
  memory_enabled: boolean;
  created_at: string;
}

export interface AgentTestCase {
  id: string;
  category: string;
  name: string;
  description: string;
  prompt: string;
  expected_tool_calls?: { tool_name: string; malicious_parameters: string[] }[];
  severity: string;
  cwe_id?: string;
  is_builtin: boolean;
  enabled: boolean;
}

export interface AgentTestResult {
  test_id: string;
  test_name: string;
  category: string;
  status: 'passed' | 'failed' | 'error';
  tool_calls_detected: { tool_name: string; arguments: Record<string, any> }[];
  vulnerability_indicators: string[];
  confidence: number;
  severity: string;
  remediation: string;
  duration_ms: number;
}

// Model Fingerprint Types
export interface ModelFingerprint {
  likely_model_family: string;
  confidence: number;
  indicators: string[];
  estimated_context_window?: number;
  detected_safety_mechanisms: string[];
  known_vulnerabilities: string[];
  fingerprinted_at: string;
}

// LLM Security Report Types
export interface LLMSecurityReport {
  id: string;
  test_run_id: string;
  report_type: string;
  format: 'pdf' | 'html' | 'markdown' | 'json';
  executive_summary: {
    overall_risk_level: string;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    key_findings: string[];
    recommendations: string[];
  };
  created_at: string;
  file_path?: string;
}

// Remediation Types
export interface RemediationGuidance {
  category: string;
  severity: string;
  description: string;
  impact: string;
  steps: string[];
  code_examples: string[];
  references: { title: string; url: string }[];
  owasp_mapping?: string;
  cwe_mapping?: string;
}

export const aiSecurityAPI = {
  // Dashboard
  getDashboard: () => api.get<AIDashboard>('/ai-security/dashboard'),
  getRecommendations: () => api.get('/ai-security/recommendations'),

  // ML Models
  getModels: () => api.get<AIModel[]>('/ai-security/models'),
  getModel: (id: string) => api.get<AIModel>(`/ai-security/models/${id}`),
  trainModel: (id: string) => api.post(`/ai-security/models/${id}/train`),
  getModelMetrics: (id: string) => api.get(`/ai-security/models/${id}/metrics`),

  // Predictions & Alerts
  prioritizeAlert: (data: any) => api.post<PrioritizedAlert>('/ai-security/alerts/prioritize', data),
  batchPrioritizeAlerts: (data: any[]) => api.post<PrioritizedAlert[]>('/ai-security/alerts/prioritize/batch', data),

  // Anomaly Detection
  detectAnomalies: (data: { metric_name: string; current_value: number; previous_value?: number; historical_values?: number[] }) =>
    api.post('/ai-security/anomaly/detect', data),

  // LLM Security Testing
  startLLMTest: (data: { target_name: string; target_type: string; target_config: any; test_type: string; customer_id?: string; engagement_id?: string }) =>
    api.post<LLMTestRun>('/ai-security/llm-security/test', data),
  getLLMTests: (params?: { limit?: number; offset?: number }) =>
    api.get<LLMTestRun[]>('/ai-security/llm-security/tests', { params }),
  getLLMTest: (id: string) => api.get<LLMTestRun>(`/ai-security/llm-security/tests/${id}`),
  cancelLLMTest: (id: string) => api.post(`/ai-security/llm-security/tests/${id}/cancel`),

  // Test Cases
  getTestCases: (params?: { category?: string; enabled_only?: boolean }) =>
    api.get<LLMTestCase[]>('/ai-security/llm-security/test-cases', { params }),
  createTestCase: (data: { category: string; name: string; description?: string; payload: string; expected_behavior?: string; severity: string; cwe_id?: string }) =>
    api.post('/ai-security/llm-security/test-cases', data),

  // LLM Targets
  getLLMTargets: (params?: { limit?: number; offset?: number }) =>
    api.get<LLMTarget[]>('/ai-security/llm-security/targets', { params }),
  getLLMTarget: (id: string) => api.get<LLMTarget>(`/ai-security/llm-security/targets/${id}`),
  createLLMTarget: (data: { name: string; endpoint: string; model_type: string; description?: string; api_key?: string; headers?: Record<string, string> }) =>
    api.post<{ id: string; message: string }>('/ai-security/llm-security/targets', data),
  updateLLMTarget: (id: string, data: { name?: string; endpoint?: string; model_type?: string; description?: string; api_key?: string; headers?: Record<string, string>; enabled?: boolean }) =>
    api.put<{ id: string; message: string }>(`/ai-security/llm-security/targets/${id}`, data),
  deleteLLMTarget: (id: string) => api.delete(`/ai-security/llm-security/targets/${id}`),

  // Multi-Turn Conversation Tests
  getConversationTests: (params?: { category?: string; builtin_only?: boolean }) =>
    api.get<ConversationTest[]>('/ai-security/llm-security/conversation-tests', { params }),
  startConversationTest: (data: { target_id: string; test_id: string }) =>
    api.post<ConversationTestResult>('/ai-security/llm-security/conversation-test', data),

  // Agent/Tool Testing
  getAgentConfigs: (params?: { target_id?: string }) =>
    api.get<AgentTestConfig[]>('/ai-security/llm-security/agent-configs', { params }),
  getAgentConfig: (id: string) => api.get<AgentTestConfig>(`/ai-security/llm-security/agent-configs/${id}`),
  createAgentConfig: (data: { target_id: string; tools: ToolDefinition[]; rag_endpoint?: string; function_format: string; memory_enabled: boolean }) =>
    api.post<{ id: string; message: string }>('/ai-security/llm-security/agent-configs', data),
  updateAgentConfig: (id: string, data: Partial<{ tools: ToolDefinition[]; rag_endpoint?: string; function_format: string; memory_enabled: boolean }>) =>
    api.put<{ message: string }>(`/ai-security/llm-security/agent-configs/${id}`, data),
  deleteAgentConfig: (id: string) => api.delete(`/ai-security/llm-security/agent-configs/${id}`),
  getAgentTestCases: (params?: { category?: string; builtin_only?: boolean }) =>
    api.get<AgentTestCase[]>('/ai-security/llm-security/agent-test-cases', { params }),
  startAgentTest: (data: { target_id: string; agent_config_id: string; test_ids?: string[] }) =>
    api.post<AgentTestResult[]>('/ai-security/llm-security/agent-test', data),

  // Model Fingerprinting
  fingerprintModel: (targetId: string) =>
    api.post<ModelFingerprint>(`/ai-security/llm-security/fingerprint/${targetId}`),
  getFingerprint: (targetId: string) =>
    api.get<ModelFingerprint>(`/ai-security/llm-security/fingerprint/${targetId}`),

  // Reports
  generateLLMReport: (testRunId: string, data: { format: 'pdf' | 'html' | 'markdown' | 'json'; include_remediation?: boolean }) =>
    api.post<LLMSecurityReport>(`/ai-security/llm-security/tests/${testRunId}/report`, data),
  getLLMReport: (reportId: string) =>
    api.get<LLMSecurityReport>(`/ai-security/llm-security/reports/${reportId}`),
  downloadLLMReport: (reportId: string) =>
    api.get(`/ai-security/llm-security/reports/${reportId}/download`, { responseType: 'blob' }),

  // Remediation Guidance
  getRemediation: (category: string) =>
    api.get<RemediationGuidance>(`/ai-security/llm-security/remediation/${category}`),
};

// ============================================================================
// AI LLM Orchestrator API
// ============================================================================

export const aiLlmAPI = {
  // Report Generation
  generateExecutiveReport: (scanId: string) =>
    api.post(`/ai/llm/reports/executive/${scanId}`),
  generateTechnicalReport: (scanId: string) =>
    api.post(`/ai/llm/reports/technical/${scanId}`),

  // Scan Planning
  planScan: (data: { targets: string[]; objectives: string[] }) =>
    api.post('/ai/llm/scan-plan', data),

  // Exploit Analysis
  analyzeExploit: (data: { code: string; context?: string }) =>
    api.post('/ai/llm/analyze-exploit', data),

  // Policy Generation
  generatePolicy: (data: { policy_type: string; organization: string; compliance_frameworks: string[] }) =>
    api.post('/ai/llm/policy/generate', data),

  // Remediation Guidance
  getRemediationGuidance: (data: { vulnerability: string; context: string }) =>
    api.post('/ai/llm/remediation-guidance', data),
};

// ============================================================================
// ML Models API
// ============================================================================

export interface MLModelInfo {
  name: string;
  version: number;
  trained_at: string;
  status: string;
}

export const mlModelsAPI = {
  // Model Training
  trainThreatClassifier: () => api.post('/ml/train/threat-classifier'),
  trainAssetFingerprinter: () => api.post('/ml/train/asset-fingerprinter'),
  trainAttackDetector: () => api.post('/ml/train/attack-detector'),
  trainRemediationPredictor: () => api.post('/ml/train/remediation-predictor'),

  // Predictions
  predictThreat: (data: {
    features: {
      severity_score: number;
      has_cve: boolean;
      has_exploit: boolean;
      age_days: number;
      affected_hosts: number;
    };
  }) => api.post('/ml/predict/threat', data),

  predictRemediationTime: (data: {
    severity: string;
    complexity: string;
    team_size: number;
  }) => api.post('/ml/predict/remediation-time', data),

  // Model Management
  listModels: () => api.get<MLModelInfo[]>('/ml/models'),
  getModelInfo: (name: string) => api.get<MLModelInfo>(`/ml/models/${name}`),
  getModelMetrics: (name: string) => api.get(`/ml/models/${name}/metrics`),
};

// ============================================================================
// Client Compliance Types
// ============================================================================

export interface ClientComplianceChecklist {
  id: string;
  customer_id: string;
  engagement_id?: string;
  framework_id: string;
  name: string;
  description?: string;
  status: 'not_started' | 'in_progress' | 'under_review' | 'completed' | 'archived';
  due_date?: string;
  assigned_to?: string;
  reviewed_by?: string;
  reviewed_at?: string;
  overall_score: number;
  total_controls: number;
  completed_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  not_applicable_controls: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ClientComplianceItem {
  id: string;
  checklist_id: string;
  control_id: string;
  control_title: string;
  control_description?: string;
  category?: string;
  is_automated: boolean;
  status: 'not_assessed' | 'in_progress' | 'compliant' | 'non_compliant' | 'not_applicable';
  is_checked: boolean;
  is_applicable: boolean;
  rating_score?: number;
  notes?: string;
  findings?: string;
  remediation_steps?: string;
  compensating_controls?: string;
  assigned_to?: string;
  due_date?: string;
  completed_at?: string;
  completed_by?: string;
  verified_at?: string;
  verified_by?: string;
  created_at: string;
  updated_at: string;
}

export interface ClientComplianceEvidence {
  id: string;
  item_id: string;
  checklist_id: string;
  customer_id: string;
  title: string;
  description?: string;
  evidence_type: 'file' | 'image' | 'screenshot' | 'document' | 'link' | 'note';
  file_path?: string;
  file_name?: string;
  file_size?: number;
  mime_type?: string;
  external_url?: string;
  content_hash?: string;
  uploaded_by: string;
  uploaded_at: string;
  expires_at?: string;
  status: string;
  metadata?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateClientChecklistRequest {
  customer_id: string;
  engagement_id?: string;
  framework_id: string;
  name: string;
  description?: string;
  due_date?: string;
  assigned_to?: string;
}

export interface UpdateItemRequest {
  status?: 'not_assessed' | 'in_progress' | 'compliant' | 'non_compliant' | 'not_applicable';
  is_checked?: boolean;
  is_applicable?: boolean;
  rating_score?: number;
  notes?: string;
  findings?: string;
  remediation_steps?: string;
  compensating_controls?: string;
  assigned_to?: string;
  due_date?: string;
}

// ============================================================================
// Client Compliance API
// ============================================================================

export const clientComplianceAPI = {
  // Checklists
  listChecklists: (params?: { customer_id?: string; engagement_id?: string; limit?: number; offset?: number }) =>
    api.get<{ checklists: ClientComplianceChecklist[]; total: number }>('/client-compliance/checklists', { params }),
  getChecklist: (id: string) => api.get<ClientComplianceChecklist>(`/client-compliance/checklists/${id}`),
  createChecklist: (data: CreateClientChecklistRequest) =>
    api.post<ClientComplianceChecklist>('/client-compliance/checklists', data),
  updateChecklist: (id: string, data: Partial<CreateClientChecklistRequest & { status: string }>) =>
    api.put<ClientComplianceChecklist>(`/client-compliance/checklists/${id}`, data),
  deleteChecklist: (id: string) => api.delete(`/client-compliance/checklists/${id}`),
  populateFromFramework: (id: string, frameworkId: string) =>
    api.post(`/client-compliance/checklists/${id}/populate`, { framework_id: frameworkId }),
  getChecklistStats: (id: string) => api.get(`/client-compliance/checklists/${id}/stats`),
  exportChecklist: (id: string, format: 'json' | 'csv' | 'pdf') =>
    api.get(`/client-compliance/checklists/${id}/export`, { params: { format }, responseType: 'blob' }),

  // Items
  listItems: (checklistId: string, params?: { category?: string; status?: string }) =>
    api.get<{ items: ClientComplianceItem[]; total: number }>(`/client-compliance/checklists/${checklistId}/items`, { params }),
  getItem: (checklistId: string, itemId: string) =>
    api.get<ClientComplianceItem>(`/client-compliance/checklists/${checklistId}/items/${itemId}`),
  addItem: (checklistId: string, data: { control_id: string; control_title: string; control_description?: string; category?: string; is_automated?: boolean }) =>
    api.post<ClientComplianceItem>(`/client-compliance/checklists/${checklistId}/items`, data),
  updateItem: (checklistId: string, itemId: string, data: UpdateItemRequest) =>
    api.put<ClientComplianceItem>(`/client-compliance/checklists/${checklistId}/items/${itemId}`, data),
  deleteItem: (checklistId: string, itemId: string) =>
    api.delete(`/client-compliance/checklists/${checklistId}/items/${itemId}`),
  bulkUpdateCheckbox: (checklistId: string, data: { item_ids: string[]; is_checked: boolean }) =>
    api.post(`/client-compliance/checklists/${checklistId}/items/bulk-checkbox`, data),

  // Evidence
  listEvidence: (checklistId: string, itemId: string) =>
    api.get<{ evidence: ClientComplianceEvidence[]; total: number }>(`/client-compliance/checklists/${checklistId}/items/${itemId}/evidence`),
  listItemEvidence: (checklistId: string, itemId: string) =>
    api.get<{ evidence: ClientComplianceEvidence[]; total: number }>(`/client-compliance/checklists/${checklistId}/items/${itemId}/evidence`),
  uploadEvidence: (checklistId: string, itemId: string, formData: FormData) =>
    api.post<ClientComplianceEvidence>(`/client-compliance/checklists/${checklistId}/items/${itemId}/evidence`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  downloadEvidence: (checklistId: string, itemId: string, evidenceId: string) =>
    api.get(`/client-compliance/checklists/${checklistId}/items/${itemId}/evidence/${evidenceId}/download`, { responseType: 'blob' }),
  deleteEvidence: (checklistId: string, itemId: string, evidenceId: string) =>
    api.delete(`/client-compliance/checklists/${checklistId}/items/${itemId}/evidence/${evidenceId}`),

  // Aliases and additional methods
  populateChecklist: (checklistId: string, frameworkId: string, scanId?: string) =>
    api.post(`/client-compliance/checklists/${checklistId}/populate`, { framework_id: frameworkId, scan_id: scanId }),
  bulkUpdateCheckboxes: (checklistId: string, data: { item_ids: string[]; is_checked: boolean }) =>
    api.post(`/client-compliance/checklists/${checklistId}/items/bulk-checkbox`, data),
  syncScans: (checklistId: string) =>
    api.post<{ synced_count: number; updated_items: number; findings_count: number }>(`/client-compliance/checklists/${checklistId}/sync-scans`),

  // History
  getHistory: (checklistId: string, params?: { item_id?: string; limit?: number; offset?: number }) =>
    api.get(`/client-compliance/checklists/${checklistId}/history`, { params }),
};

// ============================================================================
// Remediation Roadmap API
// ============================================================================

export interface RemediationTask {
  id: string;
  vulnerability_id: string;
  title: string;
  description: string;
  severity: string;
  host: string;
  port: number | null;
  effort_hours: number;
  priority_score: number;
  dependencies: string[];
  suggested_assignee: string;
  required_skills: string[];
  requires_downtime: boolean;
  requires_testing: boolean;
  remediation_steps: string[];
  risk_before: number;
  risk_after: number;
}

export interface ParallelGroup {
  name: string;
  task_ids: string[];
  parallel_effort_hours: number;
}

export interface RemediationPhase {
  phase_number: number;
  name: string;
  start_date: string;
  end_date: string;
  tasks: RemediationTask[];
  total_effort_hours: number;
  expected_risk_reduction: number;
  parallel_groups: ParallelGroup[];
}

export interface CriticalPathItem {
  task_id: string;
  sequence: number;
  reason: string;
  delay_risk: string;
}

export interface WeeklyRisk {
  week: number;
  date: string;
  risk_score: number;
  reduction: number;
  completed_items: string[];
}

export interface RiskProjection {
  initial_risk: number;
  weekly_risk: WeeklyRisk[];
  final_risk: number;
  total_reduction_percent: number;
}

export interface ResourceSuggestion {
  resource_type: string;
  recommended_fte: number;
  total_hours: number;
  peak_week: number;
  peak_hours: number;
  skills_needed: string[];
}

export interface RoadmapSummary {
  total_tasks: number;
  total_effort_hours: number;
  total_phases: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  projected_completion: string;
  initial_risk_score: number;
  final_risk_score: number;
  risk_reduction_percent: number;
}

export interface RemediationRoadmap {
  id: string;
  scan_id: string;
  generated_at: string;
  phases: RemediationPhase[];
  summary: RoadmapSummary;
  critical_path: CriticalPathItem[];
  risk_projection: RiskProjection;
  resource_suggestions: ResourceSuggestion[];
}

export interface CreateRoadmapRequest {
  scan_id: string;
  hours_per_week?: number;
  available_resources?: number;
  include_low_severity?: boolean;
  max_weeks?: number;
}

export const remediationRoadmapAPI = {
  // Generate a new roadmap
  generate: (data: CreateRoadmapRequest) =>
    api.post<{ roadmap: RemediationRoadmap; message: string }>('/remediation/roadmaps', data),

  // Get a specific roadmap
  get: (id: string) =>
    api.get<{ roadmap: RemediationRoadmap }>(`/remediation/roadmaps/${id}`),

  // Get all roadmaps for a scan
  getByScan: (scanId: string) =>
    api.get<{ roadmaps: RemediationRoadmap[]; count: number; scan_id: string }>(
      `/remediation/roadmaps/scan/${scanId}`
    ),

  // Delete a roadmap
  delete: (id: string) =>
    api.delete<{ message: string; roadmap_id: string }>(`/remediation/roadmaps/${id}`),
};

// ============================================================================
// Integration Sync API (Bi-Directional JIRA/ServiceNow Sync)
// ============================================================================

import type {
  LinkTicketRequest,
  LinkedTicket,
  SyncAction,
  SyncStats,
  SyncConfig,
  UpdateSyncConfigRequest,
  SyncHistoryEntry,
  WebhookLogEntry,
  SyncResult,
  VerificationResult,
} from '../types/integration-sync';

export const integrationSyncAPI = {
  // Link a vulnerability to an external ticket
  linkTicket: (data: LinkTicketRequest) =>
    api.post<LinkedTicket>('/integration-sync/tickets', data),

  // Unlink a ticket
  unlinkTicket: (ticketId: string) =>
    api.delete<{ message: string }>(`/integration-sync/tickets/${ticketId}`),

  // Get linked tickets for a vulnerability
  getLinkedTickets: (vulnerabilityId: string) =>
    api.get<LinkedTicket[]>(`/integration-sync/vulnerabilities/${vulnerabilityId}/tickets`),

  // Sync a specific ticket
  syncTicket: (ticketId: string) =>
    api.post<SyncResult>(`/integration-sync/tickets/${ticketId}/sync`),

  // Sync all linked tickets
  syncAll: () =>
    api.post<SyncResult>('/integration-sync/sync'),

  // Get sync statistics
  getStats: () =>
    api.get<SyncStats>('/integration-sync/stats'),

  // Handle vulnerability verification (auto-close tickets)
  onVulnerabilityVerified: (vulnerabilityId: string) =>
    api.post<VerificationResult>(`/integration-sync/vulnerabilities/${vulnerabilityId}/verified`),

  // Get sync configuration for an integration
  getConfig: (integration: string) =>
    api.get<SyncConfig>(`/integration-sync/config/${integration}`),

  // Update sync configuration
  updateConfig: (integration: string, data: UpdateSyncConfigRequest) =>
    api.put<{ message: string }>(`/integration-sync/config/${integration}`, data),

  // Get sync action history
  getHistory: (params?: { limit?: number; offset?: number }) =>
    api.get<SyncHistoryEntry[]>('/integration-sync/history', { params }),

  // Get webhook logs
  getWebhookLogs: (params?: { limit?: number; integration?: string }) =>
    api.get<WebhookLogEntry[]>('/integration-sync/webhooks/logs', { params }),
};

// ============================================================================
// Engagement Templates API (Quick Setup)
// ============================================================================

import type {
  EngagementTemplate,
  CreateTemplateRequest,
  CreateFromTemplateRequest,
  EngagementSetupResult,
  EngagementType,
} from '../types/engagement-templates';

export const engagementTemplatesAPI = {
  // List all templates
  list: () =>
    api.get<EngagementTemplate[]>('/engagement-templates'),

  // Get template by ID
  get: (id: string) =>
    api.get<EngagementTemplate>(`/engagement-templates/${id}`),

  // Get templates by engagement type
  getByType: (type: string) =>
    api.get<EngagementTemplate[]>(`/engagement-templates/type/${type}`),

  // Get available engagement types
  getTypes: () =>
    api.get<EngagementType[]>('/engagement-templates/types'),

  // Create custom template
  create: (data: CreateTemplateRequest) =>
    api.post<EngagementTemplate>('/engagement-templates', data),

  // Delete custom template
  delete: (id: string) =>
    api.delete<{ message: string }>(`/engagement-templates/${id}`),

  // Initialize built-in templates (admin)
  initialize: () =>
    api.post<{ message: string }>('/engagement-templates/initialize'),

  // Create engagement from template (Quick Setup)
  createFromTemplate: (data: CreateFromTemplateRequest) =>
    api.post<{ message: string; result: EngagementSetupResult }>(
      '/engagement-templates/setup',
      data
    ),
};

// ============================================================================
// Finding Lifecycle Management API
// ============================================================================

export interface FindingLifecycle {
  id: string;
  finding_id: string;
  current_state: FindingState;
  severity: string;
  title: string;
  affected_asset: string;
  discovered_at: string;
  sla_due_at: string | null;
  sla_breached: boolean;
  assigned_to: string | null;
  customer_id: string | null;
  engagement_id: string | null;
  created_at: string;
  updated_at: string;
}

export type FindingState =
  | 'discovered'
  | 'triaged'
  | 'acknowledged'
  | 'in_remediation'
  | 'verification_pending'
  | 'verified'
  | 'closed';

export interface StateTransition {
  id: string;
  finding_id: string;
  from_state: FindingState;
  to_state: FindingState;
  transitioned_by: string;
  reason: string | null;
  transitioned_at: string;
}

export interface LifecycleMetrics {
  total_findings: number;
  by_state: Record<FindingState, number>;
  by_severity: Record<string, number>;
  sla_breached_count: number;
  average_time_to_close_hours: number | null;
  average_time_to_remediation_hours: number | null;
}

export interface SlaPolicy {
  id: string;
  name: string;
  description: string | null;
  critical_hours: number;
  high_hours: number;
  medium_hours: number;
  low_hours: number;
  info_hours: number | null;
  organization_id: string | null;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface InitLifecycleRequest {
  severity: string;
  title: string;
  affected_asset: string;
  customer_id?: string;
  engagement_id?: string;
  sla_policy_id?: string;
}

export interface TransitionStateRequest {
  to_state: FindingState;
  reason?: string;
}

export interface BulkTransitionRequest {
  finding_ids: string[];
  to_state: FindingState;
  reason?: string;
}

export interface CreateSlaPolicyRequest {
  name: string;
  description?: string;
  critical_hours: number;
  high_hours: number;
  medium_hours: number;
  low_hours: number;
  info_hours?: number;
}

export const findingLifecycleAPI = {
  // List all lifecycles with filters
  list: (params?: {
    state?: FindingState;
    severity?: string;
    sla_breached?: boolean;
    assigned_to?: string;
    limit?: number;
    offset?: number;
  }) => api.get<{ lifecycles: FindingLifecycle[]; total: number }>('/finding-lifecycle', { params }),

  // Get lifecycle metrics
  getMetrics: () =>
    api.get<LifecycleMetrics>('/finding-lifecycle/metrics'),

  // Get SLA breached findings
  getSlaBreached: () =>
    api.get<{ lifecycles: FindingLifecycle[] }>('/finding-lifecycle/sla-breached'),

  // Get findings by state
  getByState: (state: FindingState) =>
    api.get<{ lifecycles: FindingLifecycle[] }>(`/finding-lifecycle/by-state/${state}`),

  // Get lifecycle for a specific finding
  get: (findingId: string) =>
    api.get<FindingLifecycle>(`/finding-lifecycle/${findingId}`),

  // Initialize lifecycle for a finding
  init: (findingId: string, data: InitLifecycleRequest) =>
    api.post<FindingLifecycle>(`/finding-lifecycle/${findingId}`, data),

  // Transition finding to new state
  transition: (findingId: string, data: TransitionStateRequest) =>
    api.post<FindingLifecycle>(`/finding-lifecycle/${findingId}/transition`, data),

  // Get state transition history for a finding
  getHistory: (findingId: string) =>
    api.get<{ transitions: StateTransition[] }>(`/finding-lifecycle/${findingId}/history`),

  // Bulk transition multiple findings
  bulkTransition: (data: BulkTransitionRequest) =>
    api.post<{ success_count: number; failed_count: number; results: Array<{ finding_id: string; success: boolean; error?: string }> }>(
      '/finding-lifecycle/bulk-transition',
      data
    ),

  // SLA Policies
  listSlaPolicies: () =>
    api.get<{ policies: SlaPolicy[] }>('/finding-lifecycle/sla-policies'),

  createSlaPolicy: (data: CreateSlaPolicyRequest) =>
    api.post<SlaPolicy>('/finding-lifecycle/sla-policies', data),

  // Update SLA status for all findings (check for breaches)
  updateSlaStatus: () =>
    api.post<{ updated_count: number }>('/finding-lifecycle/update-sla-status'),
};

// ============================================================================
// Passive Reconnaissance API
// ============================================================================

export interface SubdomainResult {
  subdomain: string;
  sources: string[];
  first_seen: string;
  ip_addresses?: string[];
}

export interface HistoricalUrl {
  url: string;
  timestamp: string | null;
  mime_type: string | null;
  status_code: number | null;
}

export interface CodeSearchResult {
  repository: string;
  file_path: string;
  matched_content: string;
  url: string;
  search_type: string;
}

export interface PassiveDnsRecord {
  record_type: string;
  name: string;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface CertificateInfo {
  serial_number: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  names: string[];
}

export interface PassiveReconResult {
  id: string;
  domain: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  sources_used: string[];
  total_subdomains: number;
  total_urls: number;
  total_code_results: number;
  total_dns_records: number;
  subdomains: SubdomainResult[];
  historical_urls: HistoricalUrl[];
  code_search_results: CodeSearchResult[];
  dns_records: PassiveDnsRecord[];
  sensitive_paths: string[];
  certificates: CertificateInfo[];
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface RunPassiveReconRequest {
  domain: string;
  sources?: string[];
  github_token?: string;
  securitytrails_key?: string;
  wayback_url_limit?: number;
}

export interface DomainRequest {
  domain: string;
}

export interface GitHubSearchRequest {
  domain: string;
  token?: string;
}

export interface SecurityTrailsRequest {
  domain: string;
  api_key?: string;
}

export interface WaybackRequest {
  domain: string;
  limit?: number;
}

export const passiveReconAPI = {
  // Run full passive reconnaissance
  run: (data: RunPassiveReconRequest) =>
    api.post<PassiveReconResult>('/passive-recon/run', data),

  // Discover subdomains only
  discoverSubdomains: (data: DomainRequest) =>
    api.post<{ subdomains: SubdomainResult[] }>('/passive-recon/subdomains', data),

  // Query crt.sh for certificates
  queryCrtsh: (data: DomainRequest) =>
    api.post<{ subdomains: string[]; certificates: CertificateInfo[] }>('/passive-recon/crtsh', data),

  // Query Wayback Machine for historical URLs
  queryWayback: (data: WaybackRequest) =>
    api.post<{ urls: HistoricalUrl[]; subdomains: string[] }>('/passive-recon/wayback', data),

  // Find sensitive paths from Wayback
  findSensitivePaths: (data: DomainRequest) =>
    api.post<{ sensitive_paths: string[] }>('/passive-recon/wayback/sensitive', data),

  // Search GitHub for domain references
  searchGithub: (data: GitHubSearchRequest) =>
    api.post<{ results: CodeSearchResult[] }>('/passive-recon/github', data),

  // Search GitHub for exposed secrets
  searchGithubSecrets: (data: GitHubSearchRequest) =>
    api.post<{ results: CodeSearchResult[] }>('/passive-recon/github/secrets', data),

  // Query SecurityTrails
  querySecurityTrails: (data: SecurityTrailsRequest) =>
    api.post<{ subdomains: string[]; dns_records: PassiveDnsRecord[] }>('/passive-recon/securitytrails', data),

  // Get a specific result
  getResult: (id: string) =>
    api.get<PassiveReconResult>(`/passive-recon/results/${id}`),

  // List all results
  listResults: (params?: { domain?: string; limit?: number; offset?: number }) =>
    api.get<{ results: PassiveReconResult[]; total: number }>('/passive-recon/results', { params }),
};
