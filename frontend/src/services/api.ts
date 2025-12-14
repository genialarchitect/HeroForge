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
  login: (data: LoginRequest) => api.post<LoginResponse>('/auth/login', data),
  me: () => api.get<User>('/auth/me'),
};

export const scanAPI = {
  create: (data: CreateScanRequest) => api.post<ScanResult>('/scans', data),
  getAll: () => api.get<ScanResult[]>('/scans'),
  getById: (id: string) => api.get<ScanResult>(`/scans/${id}`),
  getResults: (id: string) => api.get<HostInfo[]>(`/scans/${id}/results`),
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

export default api;
