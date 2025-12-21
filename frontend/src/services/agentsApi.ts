import axios from 'axios';
import type {
  PeerInfo,
  AgentCluster,
  AgentMeshConfig,
  ClusterWithDetails,
  MeshDashboardStats,
  CreateClusterRequest,
  UpdateClusterRequest,
  CreateMeshConfigRequest,
  UpdateMeshConfigRequest,
  AgentListResponse,
  ClusterListResponse,
  TaskQueueResponse,
  QueuedTask,
  PeerConnectionStats,
  WorkStealingStats,
  ClusterConfig,
} from '../types/agents';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ============================================================================
// Dashboard & Stats
// ============================================================================

/**
 * Get mesh dashboard statistics
 */
export const getDashboardStats = () =>
  api.get<MeshDashboardStats>('/agents/mesh/dashboard');

/**
 * Get work stealing statistics
 */
export const getWorkStealingStats = () =>
  api.get<WorkStealingStats>('/agents/mesh/work-stealing/stats');

// ============================================================================
// Agents
// ============================================================================

/**
 * List all agents in the mesh
 */
export const listAgents = (params?: {
  status?: string;
  cluster_id?: string;
  limit?: number;
  offset?: number;
}) => api.get<AgentListResponse>('/agents/mesh/agents', { params });

/**
 * Get a specific agent by ID
 */
export const getAgent = (agentId: string) =>
  api.get<PeerInfo>(`/agents/mesh/agents/${agentId}`);

/**
 * Get agent mesh configuration
 */
export const getAgentMeshConfig = (agentId: string) =>
  api.get<AgentMeshConfig>(`/agents/mesh/agents/${agentId}/config`);

/**
 * Create mesh configuration for an agent
 */
export const createMeshConfig = (data: CreateMeshConfigRequest) =>
  api.post<AgentMeshConfig>('/agents/mesh/config', data);

/**
 * Update mesh configuration for an agent
 */
export const updateMeshConfig = (agentId: string, data: UpdateMeshConfigRequest) =>
  api.patch<AgentMeshConfig>(`/agents/mesh/agents/${agentId}/config`, data);

/**
 * Delete mesh configuration for an agent
 */
export const deleteMeshConfig = (agentId: string) =>
  api.delete(`/agents/mesh/agents/${agentId}/config`);

/**
 * Get peer connection stats for an agent
 */
export const getAgentPeerStats = (agentId: string) =>
  api.get<PeerConnectionStats>(`/agents/mesh/agents/${agentId}/peer-stats`);

/**
 * Ping an agent to check connectivity
 */
export const pingAgent = (agentId: string) =>
  api.post<{ latency_ms: number; status: string }>(`/agents/mesh/agents/${agentId}/ping`);

/**
 * Remove an agent from the mesh
 */
export const removeAgent = (agentId: string) =>
  api.delete(`/agents/mesh/agents/${agentId}`);

// ============================================================================
// Clusters
// ============================================================================

/**
 * List all clusters
 */
export const listClusters = (params?: {
  limit?: number;
  offset?: number;
}) => api.get<ClusterListResponse>('/agents/mesh/clusters', { params });

/**
 * Get a specific cluster with full details
 */
export const getCluster = (clusterId: string) =>
  api.get<ClusterWithDetails>(`/agents/mesh/clusters/${clusterId}`);

/**
 * Create a new cluster
 */
export const createCluster = (data: CreateClusterRequest) =>
  api.post<AgentCluster>('/agents/mesh/clusters', data);

/**
 * Update a cluster
 */
export const updateCluster = (clusterId: string, data: UpdateClusterRequest) =>
  api.patch<AgentCluster>(`/agents/mesh/clusters/${clusterId}`, data);

/**
 * Delete a cluster
 */
export const deleteCluster = (clusterId: string) =>
  api.delete(`/agents/mesh/clusters/${clusterId}`);

/**
 * Get cluster configuration
 */
export const getClusterConfig = (clusterId: string) =>
  api.get<ClusterConfig>(`/agents/mesh/clusters/${clusterId}/config`);

/**
 * Update cluster configuration
 */
export const updateClusterConfig = (clusterId: string, config: Partial<ClusterConfig>) =>
  api.patch<ClusterConfig>(`/agents/mesh/clusters/${clusterId}/config`, config);

/**
 * Add an agent to a cluster
 */
export const addAgentToCluster = (clusterId: string, agentId: string) =>
  api.post(`/agents/mesh/clusters/${clusterId}/agents/${agentId}`);

/**
 * Remove an agent from a cluster
 */
export const removeAgentFromCluster = (clusterId: string, agentId: string) =>
  api.delete(`/agents/mesh/clusters/${clusterId}/agents/${agentId}`);

/**
 * Set cluster leader
 */
export const setClusterLeader = (clusterId: string, agentId: string) =>
  api.post(`/agents/mesh/clusters/${clusterId}/leader`, { agent_id: agentId });

/**
 * Trigger leader election for a cluster
 */
export const triggerLeaderElection = (clusterId: string) =>
  api.post(`/agents/mesh/clusters/${clusterId}/elect-leader`);

// ============================================================================
// Task Queue
// ============================================================================

/**
 * Get all tasks in the queue
 */
export const getTaskQueue = (params?: {
  status?: string;
  agent_id?: string;
  cluster_id?: string;
  limit?: number;
  offset?: number;
}) => api.get<TaskQueueResponse>('/agents/mesh/tasks', { params });

/**
 * Get a specific task
 */
export const getTask = (taskId: string) =>
  api.get<QueuedTask>(`/agents/mesh/tasks/${taskId}`);

/**
 * Cancel a task
 */
export const cancelTask = (taskId: string) =>
  api.post(`/agents/mesh/tasks/${taskId}/cancel`);

/**
 * Retry a failed task
 */
export const retryTask = (taskId: string) =>
  api.post(`/agents/mesh/tasks/${taskId}/retry`);

/**
 * Reassign a task to a different agent
 */
export const reassignTask = (taskId: string, agentId: string) =>
  api.post(`/agents/mesh/tasks/${taskId}/reassign`, { agent_id: agentId });

/**
 * Bulk cancel tasks
 */
export const bulkCancelTasks = (taskIds: string[]) =>
  api.post('/agents/mesh/tasks/bulk-cancel', { task_ids: taskIds });

// ============================================================================
// Discovery
// ============================================================================

/**
 * Trigger peer discovery
 */
export const triggerDiscovery = () =>
  api.post('/agents/mesh/discovery/trigger');

/**
 * Get discovery status
 */
export const getDiscoveryStatus = () =>
  api.get<{
    is_running: boolean;
    last_run: string | null;
    peers_discovered: number;
  }>('/agents/mesh/discovery/status');

// ============================================================================
// Export all as a single object
// ============================================================================

export const agentsAPI = {
  // Dashboard
  getDashboardStats,
  getWorkStealingStats,

  // Agents
  listAgents,
  getAgent,
  getAgentMeshConfig,
  createMeshConfig,
  updateMeshConfig,
  deleteMeshConfig,
  getAgentPeerStats,
  pingAgent,
  removeAgent,

  // Clusters
  listClusters,
  getCluster,
  createCluster,
  updateCluster,
  deleteCluster,
  getClusterConfig,
  updateClusterConfig,
  addAgentToCluster,
  removeAgentFromCluster,
  setClusterLeader,
  triggerLeaderElection,

  // Task Queue
  getTaskQueue,
  getTask,
  cancelTask,
  retryTask,
  reassignTask,
  bulkCancelTasks,

  // Discovery
  triggerDiscovery,
  getDiscoveryStatus,
};

export default agentsAPI;
