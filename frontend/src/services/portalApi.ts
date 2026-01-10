import axios from 'axios';
import type {
  PortalLoginRequest,
  PortalLoginResponse,
  PortalUserInfo,
  PortalChangePasswordRequest,
  PortalProfile,
  PortalUpdateProfileRequest,
  PortalDashboardStats,
  PortalEngagement,
  PortalEngagementDetail,
  PortalMilestone,
  PortalVulnerabilitiesResponse,
  PortalVulnerabilityDetail,
  PortalVulnerabilityQuery,
  PortalReport,
} from '../types';

// Create a separate axios instance for portal API
const portalApi = axios.create({
  baseURL: '/api/portal',
});

// Portal token key (separate from main app)
const PORTAL_TOKEN_KEY = 'portal_token';
const PORTAL_USER_KEY = 'portal_user';

// Add auth token to portal requests
portalApi.interceptors.request.use((config) => {
  const token = localStorage.getItem(PORTAL_TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 errors by redirecting to portal login
portalApi.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem(PORTAL_TOKEN_KEY);
      localStorage.removeItem(PORTAL_USER_KEY);
      // Only redirect if we're on a portal page
      if (window.location.pathname.startsWith('/portal') &&
          !window.location.pathname.includes('/login')) {
        window.location.href = '/portal/login';
      }
    }
    return Promise.reject(error);
  }
);

// Auth functions
export const portalAuthAPI = {
  login: async (data: PortalLoginRequest): Promise<PortalLoginResponse> => {
    const response = await portalApi.post<PortalLoginResponse>('/auth/login', data);
    // Store token and user info
    localStorage.setItem(PORTAL_TOKEN_KEY, response.data.token);
    localStorage.setItem(PORTAL_USER_KEY, JSON.stringify(response.data.user));
    return response.data;
  },

  logout: () => {
    localStorage.removeItem(PORTAL_TOKEN_KEY);
    localStorage.removeItem(PORTAL_USER_KEY);
  },

  getCurrentUser: () => portalApi.get<PortalUserInfo>('/auth/me'),

  changePassword: (data: PortalChangePasswordRequest) =>
    portalApi.post<{ message: string }>('/auth/change-password', data),

  forgotPassword: (email: string) =>
    portalApi.post<{ message: string }>('/auth/forgot-password', { email }),

  resetPassword: (token: string, new_password: string) =>
    portalApi.post<{ message: string }>('/auth/reset-password', { token, new_password }),

  getToken: () => localStorage.getItem(PORTAL_TOKEN_KEY),

  getStoredUser: (): PortalUserInfo | null => {
    const userStr = localStorage.getItem(PORTAL_USER_KEY);
    if (userStr) {
      try {
        return JSON.parse(userStr);
      } catch {
        return null;
      }
    }
    return null;
  },

  isAuthenticated: () => !!localStorage.getItem(PORTAL_TOKEN_KEY),
};

// Profile API
export const portalProfileAPI = {
  getProfile: () => portalApi.get<PortalProfile>('/profile'),
  updateProfile: (data: PortalUpdateProfileRequest) =>
    portalApi.put<PortalProfile>('/profile', data),
};

// Dashboard API
export const portalDashboardAPI = {
  getDashboard: () => portalApi.get<PortalDashboardStats>('/dashboard'),
};

// Engagements API
export const portalEngagementsAPI = {
  getAll: () => portalApi.get<PortalEngagement[]>('/engagements'),
  getById: (id: string) => portalApi.get<PortalEngagementDetail>(`/engagements/${id}`),
  getMilestones: (engagementId: string) =>
    portalApi.get<PortalMilestone[]>(`/engagements/${engagementId}/milestones`),
  updateMilestone: (engagementId: string, milestoneId: string, data: { status?: string; notes?: string }) =>
    portalApi.put<PortalMilestone>(`/engagements/${engagementId}/milestones/${milestoneId}`, data),
};

// Vulnerability comment type
export interface VulnerabilityComment {
  id: string;
  vulnerability_id: string;
  user_id: string;
  user_email: string;
  comment: string;
  created_at: string;
}

// Vulnerabilities API
export const portalVulnerabilitiesAPI = {
  getAll: (query?: PortalVulnerabilityQuery) => {
    const params = new URLSearchParams();
    if (query?.severity) params.append('severity', query.severity);
    if (query?.status) params.append('status', query.status);
    if (query?.engagement_id) params.append('engagement_id', query.engagement_id);
    if (query?.limit) params.append('limit', query.limit.toString());
    if (query?.offset) params.append('offset', query.offset.toString());

    return portalApi.get<PortalVulnerabilitiesResponse>(`/vulnerabilities?${params.toString()}`);
  },
  getById: (id: string) => portalApi.get<PortalVulnerabilityDetail>(`/vulnerabilities/${id}`),
  updateStatus: (id: string, status: string, comment?: string) =>
    portalApi.put<{ message: string; status: string }>(`/vulnerabilities/${id}/status`, { status, comment }),
  getComments: (id: string) =>
    portalApi.get<{ comments: VulnerabilityComment[] }>(`/vulnerabilities/${id}/comments`),
  addComment: (id: string, comment: string) =>
    portalApi.post<VulnerabilityComment>(`/vulnerabilities/${id}/comments`, { comment }),
};

// Reports API
export const portalReportsAPI = {
  getAll: () => portalApi.get<PortalReport[]>('/reports'),
  getById: (id: string) => portalApi.get<PortalReport>(`/reports/${id}`),
  download: (id: string) =>
    portalApi.get(`/reports/${id}/download`, { responseType: 'blob' }),
};
