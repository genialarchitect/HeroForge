// Evidence API Client

import axios from 'axios';
import type {
  Evidence,
  EvidenceListResponse,
  ListEvidenceQuery,
  CreateEvidenceRequest,
  CreateMappingRequest,
  UpdateMappingRequest,
  CreateScheduleRequest,
  UpdateScheduleRequest,
  UpdateEvidenceStatusRequest,
  CollectEvidenceRequest,
  CollectEvidenceResponse,
  EvidenceControlMapping,
  EvidenceCollectionSchedule,
  ControlEvidenceSummary,
  MappingsResponse,
  SchedulesResponse,
  VersionHistory,
  VersionComparison,
} from '../types/evidence';

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

export const evidenceAPI = {
  // List evidence with optional filters
  list: (query?: ListEvidenceQuery) => {
    const params = new URLSearchParams();
    if (query?.control_id) params.append('control_id', query.control_id);
    if (query?.framework_id) params.append('framework_id', query.framework_id);
    if (query?.evidence_type) params.append('evidence_type', query.evidence_type);
    if (query?.status) params.append('status', query.status);
    if (query?.collection_source) params.append('collection_source', query.collection_source);
    if (query?.include_expired !== undefined)
      params.append('include_expired', query.include_expired.toString());
    if (query?.include_superseded !== undefined)
      params.append('include_superseded', query.include_superseded.toString());
    if (query?.limit !== undefined) params.append('limit', query.limit.toString());
    if (query?.offset !== undefined) params.append('offset', query.offset.toString());
    const queryString = params.toString();
    return api.get<EvidenceListResponse>(`/evidence${queryString ? `?${queryString}` : ''}`);
  },

  // Create new evidence manually
  create: (data: CreateEvidenceRequest) => api.post<{ id: string; message: string }>('/evidence', data),

  // Get evidence by ID
  get: (id: string) => api.get<Evidence>(`/evidence/${id}`),

  // Delete evidence
  delete: (id: string) => api.delete<{ message: string }>(`/evidence/${id}`),

  // Update evidence status
  updateStatus: (id: string, data: UpdateEvidenceStatusRequest) =>
    api.put<{ message: string }>(`/evidence/${id}/status`, data),

  // Get evidence version history
  getHistory: (id: string) => api.get<VersionHistory>(`/evidence/${id}/history`),

  // Get version history (alternate method name)
  getVersionHistory: (id: string) => api.get<VersionHistory>(`/evidence/${id}/versions`),

  // Compare two versions
  compareVersions: (id: string, compareToId: string) =>
    api.get<VersionComparison>(`/evidence/${id}/compare/${compareToId}`),

  // Rollback to a previous version
  rollback: (id: string, targetVersionId: string) =>
    api.post<Evidence>(`/evidence/${id}/rollback`, { target_version_id: targetVersionId }),

  // Trigger evidence collection
  collect: (data: CollectEvidenceRequest) =>
    api.post<CollectEvidenceResponse>('/evidence/collect', data),

  // Get control evidence summary
  getSummary: (frameworkId: string, controlId: string) =>
    api.get<ControlEvidenceSummary>(`/evidence/summary/${frameworkId}/${controlId}`),

  // Alternative method name for control summary (used by linter-updated code)
  getControlSummary: (controlId: string, frameworkId: string) =>
    api.get<ControlEvidenceSummary>(`/evidence/summary/${frameworkId}/${controlId}`),

  // Control-specific evidence
  getForControl: (frameworkId: string, controlId: string) =>
    api.get<{
      control_id: string;
      framework_id: string;
      summary: ControlEvidenceSummary;
      evidence: Evidence[];
    }>(`/controls/${frameworkId}/${controlId}/evidence`),

  // Flat mapping methods
  getMappings: (evidenceId?: string, controlId?: string, frameworkId?: string) => {
    const params = new URLSearchParams();
    if (evidenceId) params.append('evidence_id', evidenceId);
    if (controlId) params.append('control_id', controlId);
    if (frameworkId) params.append('framework_id', frameworkId);
    const query = params.toString();
    return api.get<MappingsResponse>(`/evidence/mappings${query ? `?${query}` : ''}`);
  },

  createMapping: (data: CreateMappingRequest) =>
    api.post<EvidenceControlMapping>('/evidence/mappings', data),

  updateMapping: (id: string, data: UpdateMappingRequest) =>
    api.patch<EvidenceControlMapping>(`/evidence/mappings/${id}`, data),

  deleteMapping: (id: string) =>
    api.delete<{ message: string }>(`/evidence/mappings/${id}`),

  // Mappings (nested object - legacy)
  mappings: {
    // Get mappings with filters
    list: (params?: { framework_id?: string; control_id?: string; evidence_id?: string }) => {
      const queryParams = new URLSearchParams();
      if (params?.framework_id) queryParams.append('framework_id', params.framework_id);
      if (params?.control_id) queryParams.append('control_id', params.control_id);
      if (params?.evidence_id) queryParams.append('evidence_id', params.evidence_id);
      const query = queryParams.toString();
      return api.get<MappingsResponse>(`/evidence/mappings${query ? `?${query}` : ''}`);
    },

    // Create a new mapping
    create: (data: CreateMappingRequest) =>
      api.post<{ id: string; message: string }>('/evidence/mappings', data),

    // Delete a mapping
    delete: (id: string) => api.delete<{ message: string }>(`/evidence/mappings/${id}`),
  },

  // Flat schedule methods (used by linter-updated code)
  getSchedules: () => api.get<SchedulesResponse>('/evidence/schedules'),

  createSchedule: (data: CreateScheduleRequest) =>
    api.post<{ id: string; message: string }>('/evidence/schedules', data),

  updateSchedule: (id: string, data: UpdateScheduleRequest) =>
    api.put<{ message: string; schedule: EvidenceCollectionSchedule }>(
      `/evidence/schedules/${id}`,
      data
    ),

  deleteSchedule: (id: string) => api.delete<{ message: string }>(`/evidence/schedules/${id}`),

  // Nested schedules object (original structure)
  schedules: {
    // List all schedules
    list: () => api.get<SchedulesResponse>('/evidence/schedules'),

    // Create a new schedule
    create: (data: CreateScheduleRequest) =>
      api.post<{ id: string; message: string }>('/evidence/schedules', data),

    // Update a schedule
    update: (id: string, data: UpdateScheduleRequest) =>
      api.put<{ message: string; schedule: EvidenceCollectionSchedule }>(
        `/evidence/schedules/${id}`,
        data
      ),

    // Delete a schedule
    delete: (id: string) => api.delete<{ message: string }>(`/evidence/schedules/${id}`),
  },
};

export default evidenceAPI;
