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
  UpdateVulnerabilityRequest,
  BulkUpdateVulnerabilitiesRequest,
  BulkAssignVulnerabilitiesRequest,
  VerifyVulnerabilityRequest,
  RemediationTimelineEvent,
  VulnerabilityStats,
  RequestRetestRequest,
  BulkRetestRequest,
  CompleteRetestRequest,
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
  TemplateCategory,
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
  // Asset Tags types
  AssetTag,
  AssetTagWithCount,
  CreateAssetTagRequest,
  UpdateAssetTagRequest,
  AddAssetTagsRequest,
  Asset,
  AssetDetailWithTags,
  // SSL Report types
  SslReportSummary,
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

  // Tag-scan associations
  getTagsForScan: (scanId: string) => api.get<ScanTag[]>(`/scans/${scanId}/tags`),
  addTagsToScan: (scanId: string, data: AddTagsToScanRequest) =>
    api.post<ScanTag[]>(`/scans/${scanId}/tags`, data),
  removeTagFromScan: (scanId: string, tagId: string) =>
    api.delete<{ message: string }>(`/scans/${scanId}/tags/${tagId}`),
};

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
  getAll: () => api.get<ScanTemplate[]>('/templates'),
  getById: (id: string) => api.get<ScanTemplate>(`/templates/${id}`),
  create: (data: CreateTemplateRequest) => api.post<ScanTemplate>('/templates', data),
  update: (id: string, data: UpdateTemplateRequest) => api.put<ScanTemplate>(`/templates/${id}`, data),
  delete: (id: string) => api.delete(`/templates/${id}`),
  createScan: (id: string, name: string) => api.post<ScanResult>(`/templates/${id}/scan`, { name }),
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
  getCategories: () => api.get<TemplateCategory[]>('/finding-templates/categories'),
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
};

export default api;
