import axios from 'axios';
import type {
  LoginRequest,
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
  FindingTemplate,
  CreateFindingTemplateRequest,
  UpdateFindingTemplateRequest,
  CloneTemplateRequest,
  FindingTemplateCategory,
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
} from '../types';

const api = axios.create({
  baseURL: '/api',
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authAPI = {
  // Public auth routes (at /api/auth)
  register: (data: LoginRequest & { email: string }) =>
    api.post<LoginResponse>('/auth/register', data),
  login: (data: LoginRequest) => api.post<MfaLoginResponse>('/auth/login', data),
  // Protected user routes (at /api/user)
  me: () => api.get<User>('/user/me'),
  updateProfile: (data: UpdateProfileRequest) =>
    api.put<User>('/user/profile', data),
  changePassword: (data: ChangePasswordRequest) =>
    api.put<{ message: string }>('/user/password', data),
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

import type { RateLimitDashboardData } from '../types';

export const adminAPI = {
  // User management
  getUsers: () => api.get<User[]>('/admin/users'),
  getUser: (id: string) => api.get<User>(`/admin/users/${id}`),
  updateUser: (id: string, data: Partial<User>) =>
    api.patch(`/admin/users/${id}`, data),
  deleteUser: (id: string) => api.delete(`/admin/users/${id}`),
  assignRole: (userId: string, roleId: string) =>
    api.post(`/admin/users/${userId}/roles`, { role_id: roleId }),
  removeRole: (userId: string, roleId: string) =>
    api.delete(`/admin/users/${userId}/roles/${roleId}`),
  unlockUser: (userId: string) =>
    api.post<{ message: string }>(`/admin/users/${userId}/unlock`),

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
  clone: (id: string, data?: CloneTemplateRequest) =>
    api.post<FindingTemplate>(`/finding-templates/${id}/clone`, data || {}),

  // Get categories with counts
  getCategories: () => api.get<FindingTemplateCategory[]>('/finding-templates/categories'),
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

export const cicdAPI = {
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
};

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

export default api;
