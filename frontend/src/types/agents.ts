// Types for Distributed Scanning Agents / Mesh Networking

// ============================================================================
// Peer Information
// ============================================================================

/**
 * Status of a peer in the mesh network
 */
export type PeerStatus =
  | 'unknown'
  | 'online'
  | 'busy'
  | 'offline'
  | 'joining'
  | 'leaving'
  | 'disconnected';

/**
 * Information about a peer agent in the mesh network
 */
export interface PeerInfo {
  agent_id: string;
  name: string;
  address: string;
  mesh_port: number;
  status: PeerStatus;
  load: number;
  capabilities: string[];
  network_zones: string[];
  max_tasks: number;
  current_tasks: number;
  protocol_version: string;
  last_seen: string;
  latency_ms: number | null;
  cluster_id: string | null;
}

// ============================================================================
// Cluster Information
// ============================================================================

/**
 * Cluster configuration settings
 */
export interface ClusterConfig {
  min_quorum_size: number;
  auto_elect_leader: boolean;
  heartbeat_interval_secs: number;
  peer_timeout_secs: number;
  enable_work_stealing: boolean;
  max_steal_batch: number;
  enable_gossip: boolean;
  gossip_fanout: number;
  enable_mdns: boolean;
  registry_url: string | null;
}

/**
 * Cluster health metrics
 */
export interface ClusterHealth {
  online_members: number;
  offline_members: number;
  total_tasks: number;
  average_load: number;
  is_healthy: boolean;
  last_check: string | null;
}

/**
 * Information about a cluster of agents
 */
export interface ClusterInfo {
  id: string;
  name: string;
  description: string | null;
  leader_id: string | null;
  members: string[];
  config: ClusterConfig;
  health: ClusterHealth;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Database Models (matching Rust types)
// ============================================================================

/**
 * Agent mesh configuration stored in database
 */
export interface AgentMeshConfig {
  id: string;
  agent_id: string;
  enabled: boolean;
  mesh_port: number;
  external_address: string | null;
  cluster_id: string | null;
  cluster_role: string | null;
  config_json: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Agent cluster stored in database
 */
export interface AgentCluster {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  leader_agent_id: string | null;
  config_json: string | null;
  health_json: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Peer connection history stored in database
 */
export interface AgentPeerConnection {
  id: string;
  agent_id: string;
  peer_agent_id: string;
  peer_address: string;
  peer_port: number;
  status: string;
  latency_ms: number | null;
  successful_pings: number;
  failed_pings: number;
  last_connected_at: string | null;
  last_attempt_at: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Task Types
// ============================================================================

/**
 * Information about a task that can be delegated to peers
 */
export interface AgentTaskInfo {
  id: string;
  scan_id: string;
  task_type: string;
  targets: string[];
  priority: number;
  timeout_seconds: number;
  config: Record<string, unknown>;
  required_zones: string[];
  required_capabilities: string[];
}

/**
 * A queued task in the local queue
 */
export interface QueuedTask {
  task: AgentTaskInfo;
  queued_at: string;
  attempts: number;
  last_error: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed';
  assigned_agent_id: string | null;
}

/**
 * Work stealing statistics
 */
export interface WorkStealingStats {
  tasks_stolen: number;
  tasks_offered: number;
  tasks_delegated: number;
  delegation_failures: number;
  avg_peer_find_time_ms: number;
}

// ============================================================================
// Peer Connection Stats
// ============================================================================

/**
 * Peer connection statistics for an agent
 */
export interface PeerConnectionStats {
  total_peers: number;
  online_peers: number;
  disconnected_peers: number;
  average_latency_ms: number | null;
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface CreateClusterRequest {
  name: string;
  description?: string;
  config?: Partial<ClusterConfig>;
}

export interface UpdateClusterRequest {
  name?: string;
  description?: string;
  config?: Partial<ClusterConfig>;
}

export interface CreateMeshConfigRequest {
  agent_id: string;
  enabled: boolean;
  mesh_port: number;
  external_address?: string;
  cluster_id?: string;
}

export interface UpdateMeshConfigRequest {
  enabled?: boolean;
  mesh_port?: number;
  external_address?: string;
  cluster_id?: string;
  cluster_role?: string;
}

export interface AgentListResponse {
  agents: PeerInfo[];
  total: number;
}

export interface ClusterListResponse {
  clusters: AgentCluster[];
  total: number;
}

export interface TaskQueueResponse {
  tasks: QueuedTask[];
  total: number;
  pending_count: number;
  running_count: number;
}

export interface ClusterWithDetails extends AgentCluster {
  members: PeerInfo[];
  health: ClusterHealth;
  config: ClusterConfig;
}

export interface MeshDashboardStats {
  total_agents: number;
  online_agents: number;
  busy_agents: number;
  offline_agents: number;
  total_clusters: number;
  total_tasks_queued: number;
  total_tasks_running: number;
  average_cluster_load: number;
  work_stealing_stats: WorkStealingStats;
}

// ============================================================================
// Agent Capabilities (predefined)
// ============================================================================

export const AGENT_CAPABILITIES = [
  'tcp_scan',
  'udp_scan',
  'syn_scan',
  'service_detection',
  'os_fingerprint',
  'vuln_scan',
  'web_scan',
  'dns_scan',
  'smb_enumeration',
  'ssh_enumeration',
  'snmp_enumeration',
  'ldap_enumeration',
  'container_scan',
  'iac_scan',
] as const;

export type AgentCapability = typeof AGENT_CAPABILITIES[number];

// ============================================================================
// Network Zones (predefined)
// ============================================================================

export const NETWORK_ZONES = [
  'internal',
  'dmz',
  'external',
  'cloud-aws',
  'cloud-azure',
  'cloud-gcp',
  'on-premise',
  'vpn',
] as const;

export type NetworkZone = typeof NETWORK_ZONES[number];
