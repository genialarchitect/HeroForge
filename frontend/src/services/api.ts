import axios from 'axios';
import type {
  LoginRequest,
  LoginResponse,
  User,
  CreateScanRequest,
  ScanResult,
  HostInfo,
  AuditLog,
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
  register: (data: LoginRequest & { email: string }) =>
    api.post<LoginResponse>('/auth/register', data),
  login: (data: LoginRequest) => api.post<MfaLoginResponse>('/auth/login', data),
  me: () => api.get<User>('/auth/me'),
  updateProfile: (data: UpdateProfileRequest) =>
    api.put<User>('/auth/profile', data),
  changePassword: (data: ChangePasswordRequest) =>
    api.put<{ message: string }>('/auth/password', data),
};

export const mfaAPI = {
  // Setup MFA - returns secret, QR code URL, and recovery codes
  setup: () => api.post<MfaSetupResponse>('/auth/mfa/setup'),

  // Verify setup with TOTP code
  verifySetup: (data: MfaVerifySetupRequest) =>
    api.post<{ message: string }>('/auth/mfa/verify-setup', data),

  // Disable MFA (requires password + TOTP or recovery code)
  disable: (data: MfaDisableRequest) =>
    api.delete<{ message: string }>('/auth/mfa', { data }),

  // Regenerate recovery codes (requires password + TOTP)
  regenerateRecoveryCodes: (data: MfaRegenerateRecoveryCodesRequest) =>
    api.post<MfaRegenerateRecoveryCodesResponse>('/auth/mfa/recovery-codes', data),

  // Verify MFA during login (with mfa_token from initial login)
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
  getAuditLogs: (limit = 100, offset = 0) =>
    api.get<AuditLog[]>(`/admin/audit-logs?limit=${limit}&offset=${offset}`),

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

export default api;
