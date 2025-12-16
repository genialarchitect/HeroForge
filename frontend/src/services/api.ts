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
  VulnerabilityStats,
  ComplianceFramework,
  ComplianceControlList,
  ComplianceAnalyzeRequest,
  ComplianceAnalyzeResponse,
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

  getStats: (scan_id?: string) => {
    const queryParams = scan_id ? `?scan_id=${scan_id}` : '';
    return api.get<VulnerabilityStats>(`/vulnerabilities/stats${queryParams}`);
  },
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
};

export default api;
