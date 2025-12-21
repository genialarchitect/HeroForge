import axios from 'axios';
import type {
  Plugin,
  PluginListResponse,
  PluginStats,
  PluginTypeInfo,
  InstallPluginRequest,
  InstallPluginResponse,
  PluginValidationResult,
  PluginListQuery,
} from '../types/plugins';

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

export const pluginsAPI = {
  // List all installed plugins with optional filters
  list: (query?: PluginListQuery) => {
    const params = new URLSearchParams();
    if (query?.plugin_type) params.append('plugin_type', query.plugin_type);
    if (query?.status) params.append('status', query.status);
    if (query?.search) params.append('search', query.search);

    return api.get<PluginListResponse>(`/plugins?${params.toString()}`);
  },

  // Get plugin statistics
  getStats: () => api.get<PluginStats>('/plugins/stats'),

  // Get available plugin types
  getTypes: () => api.get<PluginTypeInfo[]>('/plugins/types'),

  // Get a specific plugin by ID
  get: (id: string) => api.get<Plugin>(`/plugins/${id}`),

  // Install a plugin from URL
  installFromUrl: (request: InstallPluginRequest) =>
    api.post<InstallPluginResponse>('/plugins/install', request),

  // Upload and install a plugin file
  uploadPlugin: (file: File, enable: boolean = true) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('enable', enable.toString());

    return api.post<InstallPluginResponse>('/plugins/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },

  // Validate a plugin without installing
  validatePlugin: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    return api.post<PluginValidationResult>('/plugins/validate', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },

  // Enable a plugin
  enable: (id: string) => api.post<Plugin>(`/plugins/${id}/enable`),

  // Disable a plugin
  disable: (id: string) => api.post<Plugin>(`/plugins/${id}/disable`),

  // Uninstall a plugin
  uninstall: (id: string) => api.delete(`/plugins/${id}`),

  // Get plugin settings for current user
  getSettings: (id: string) => api.get<Record<string, unknown>>(`/plugins/${id}/settings`),

  // Update plugin settings for current user
  updateSettings: (id: string, settings: Record<string, unknown>) =>
    api.put<Record<string, unknown>>(`/plugins/${id}/settings`, { settings }),

  // Delete plugin settings for current user
  deleteSettings: (id: string) => api.delete(`/plugins/${id}/settings`),
};
