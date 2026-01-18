// Integration Sync Types for Bi-Directional JIRA/ServiceNow Sync

export type IntegrationType = 'jira' | 'servicenow';

export interface LinkTicketRequest {
  vulnerability_id: string;
  integration_type: IntegrationType;
  external_id: string;
  external_key: string;
  external_url: string;
}

export interface LinkedTicket {
  id: string;
  vulnerability_id: string;
  integration_type: string;
  external_id: string;
  external_key: string;
  external_url: string;
  status: string;
  last_synced_at: string;
  local_updated_at: string;
  remote_updated_at?: string;
  sync_enabled: boolean;
  created_at: string;
}

export interface SyncAction {
  linked_ticket_id: string;
  action_type: string;
  details: string;
  success: boolean;
  error?: string;
  timestamp: string;
}

export interface SyncStats {
  total_synced: number;
  status_updates: number;
  comments_synced: number;
  tickets_closed: number;
  conflicts_resolved: number;
  errors: number;
  last_sync_at?: string;
}

export interface SyncConfig {
  enabled: boolean;
  poll_interval_secs: number;
  sync_comments: boolean;
  auto_close_on_verify: boolean;
  conflict_strategy: string;
}

export interface UpdateSyncConfigRequest {
  sync_enabled?: boolean;
  sync_interval_seconds?: number;
  sync_status?: boolean;
  sync_comments?: boolean;
  auto_close_on_verify?: boolean;
  conflict_strategy?: string;
  webhook_secret?: string;
}

export interface SyncHistoryEntry {
  id: string;
  linked_ticket_id?: string;
  action_type: string;
  direction: string;
  details?: string;
  success: boolean;
  error_message?: string;
  executed_at: string;
}

export interface WebhookLogEntry {
  id: string;
  integration_type: string;
  event_type: string;
  signature_valid?: boolean;
  processed: boolean;
  process_result?: string;
  error_message?: string;
  received_at: string;
  processed_at?: string;
}

export interface SyncResult {
  message: string;
  actions: SyncAction[];
  actions_count?: number;
}

export interface VerificationResult {
  message: string;
  tickets_closed: number;
  actions: SyncAction[];
}
