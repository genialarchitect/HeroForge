// Evidence Types for Compliance Evidence Collection

export type EvidenceStatus =
  | 'active'
  | 'superseded'
  | 'archived'
  | 'pending_review'
  | 'approved'
  | 'rejected';

export type CollectionSource =
  | 'automated_scan'
  | 'scheduled_collection'
  | 'manual_upload'
  | 'external_import'
  | 'api_integration'
  | 'derived';

export type RetentionPolicy =
  | { type: 'indefinite' }
  | { type: 'days'; days: number }
  | { type: 'until_date'; date: string }
  | { type: 'framework_default' };

// Evidence type with discriminated union for type-specific data
export type EvidenceType =
  | { type: 'scan_result'; scan_id: string }
  | { type: 'vulnerability_scan'; scan_id: string; finding_count?: number }
  | { type: 'policy_document'; document_type: string; document_name?: string }
  | { type: 'screenshot'; url: string; description?: string }
  | { type: 'manual_upload'; file_path: string; original_filename?: string }
  | { type: 'configuration_export'; system_name: string; config_type: string }
  | { type: 'audit_log'; log_source: string; time_range_start: string; time_range_end: string }
  | { type: 'api_snapshot'; endpoint: string; method: string }
  | { type: 'container_scan'; scan_id: string; image_count?: number }
  | { type: 'cloud_security_posture'; provider: string; scan_id: string }
  | { type: 'compliance_report'; framework_id: string; scan_id: string };

// Evidence content with discriminated union
export type EvidenceContent =
  | { content_type: 'json'; data: Record<string, unknown> }
  | { content_type: 'text'; text: string }
  | { content_type: 'file'; file_path: string; mime_type: string; size_bytes: number }
  | { content_type: 'external_url'; url: string }
  | { content_type: 'none' };

export interface EvidenceMetadata {
  tags: Record<string, string>;
  related_evidence_ids: string[];
  custom_fields: Record<string, unknown>;
  period_start?: string;
  period_end?: string;
}

export interface Evidence {
  id: string;
  evidence_type: EvidenceType;
  control_ids: string[];
  framework_ids: string[];
  title: string;
  description?: string;
  content_hash: string;
  content: EvidenceContent;
  collection_source: CollectionSource;
  status: EvidenceStatus;
  version: number;
  previous_version_id?: string;
  collected_at: string;
  collected_by: string;
  expires_at?: string;
  retention_policy: RetentionPolicy;
  metadata: EvidenceMetadata;
  created_at: string;
  updated_at: string;
}

export interface EvidenceControlMapping {
  id: string;
  evidence_id: string;
  control_id: string;
  framework_id: string;
  coverage_score: number;
  notes?: string;
  created_at: string;
  created_by: string;
}

export interface EvidenceCollectionSchedule {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  collection_source: CollectionSource;
  cron_expression: string;
  control_ids: string[];
  framework_ids: string[];
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ControlEvidenceSummary {
  control_id: string;
  framework_id: string;
  total_evidence: number;
  active_evidence: number;
  latest_collection?: string;
  last_collected_at?: string;
  coverage_score: number;
  is_current: boolean;
  days_since_collection?: number;
  approved_evidence?: number;
  pending_review?: number;
  rejected?: number;
  expired?: number;
  evidence_types?: string[];
}

// Version-related types
export interface EvidenceVersion {
  version: number;
  evidence_id: string;
  content_hash: string;
  content_summary?: string;
  created_by: string;
  created_at: string;
  change_description?: string;
  content_size: number;
}

export interface VersionChange {
  change_type: 'added' | 'modified' | 'removed' | 'content_updated';
  field: string;
  old_value?: string;
  new_value?: string;
}

export interface VersionComparison {
  base_version_id: string;
  compare_version_id: string;
  base_version: number;
  compare_version: number;
  changes: VersionChange[];
  content_changed: boolean;
  summary: string;
}

export interface VersionHistory {
  original_id: string;
  current_id: string;
  total_versions: number;
  versions: EvidenceVersion[];
}

// Request/Response types
export interface CreateEvidenceRequest {
  evidence_type: string;
  control_ids: string[];
  framework_ids: string[];
  title: string;
  description?: string;
  params?: Record<string, unknown>;
  retention_days?: number;
  content?: { text: string } | Record<string, unknown>;
}

export interface CollectEvidenceRequest {
  evidence_type: string;
  control_ids: string[];
  framework_ids: string[];
  title: string;
  description?: string;
  params: Record<string, unknown>;
}

export interface CollectEvidenceResponse {
  success: boolean;
  evidence_id?: string;
  message: string;
  job_id?: string;
}

export interface ListEvidenceQuery {
  control_id?: string;
  framework_id?: string;
  evidence_type?: string;
  status?: string;
  collection_source?: string;
  include_expired?: boolean;
  include_superseded?: boolean;
  limit?: number;
  offset?: number;
}

export interface EvidenceListResponse {
  evidence: Evidence[];
  total: number;
  offset: number;
  limit: number;
}

export interface CreateMappingRequest {
  evidence_id: string;
  control_id: string;
  framework_id: string;
  coverage_score?: number;
  notes?: string;
}

export interface UpdateMappingRequest {
  coverage_score?: number;
  notes?: string;
}

export interface MappingsResponse {
  mappings: EvidenceControlMapping[];
  total: number;
}

export interface CreateScheduleRequest {
  name: string;
  description?: string;
  collection_source: CollectionSource | string;
  cron_expression: string;
  control_ids: string[];
  framework_ids: string[];
  config?: Record<string, unknown>;
}

export interface UpdateScheduleRequest {
  name?: string;
  description?: string;
  cron_expression?: string;
  control_ids?: string[];
  framework_ids?: string[];
  enabled?: boolean;
  config?: Record<string, unknown>;
}

export interface SchedulesResponse {
  schedules: EvidenceCollectionSchedule[];
  total: number;
}

export interface UpdateEvidenceStatusRequest {
  status: EvidenceStatus;
  notes?: string;
}

export interface CreateVersionRequest {
  content?: Record<string, unknown>;
  change_description?: string;
}

// Utility functions
export function getEvidenceTypeLabel(type: EvidenceType): string {
  switch (type.type) {
    case 'scan_result':
      return 'Scan Result';
    case 'vulnerability_scan':
      return 'Vulnerability Scan';
    case 'policy_document':
      return 'Policy Document';
    case 'screenshot':
      return 'Screenshot';
    case 'manual_upload':
      return 'Manual Upload';
    case 'configuration_export':
      return 'Configuration Export';
    case 'audit_log':
      return 'Audit Log';
    case 'api_snapshot':
      return 'API Snapshot';
    case 'container_scan':
      return 'Container Scan';
    case 'cloud_security_posture':
      return 'Cloud Security Posture';
    case 'compliance_report':
      return 'Compliance Report';
    default:
      return 'Unknown';
  }
}

export function getCollectionSourceLabel(source: CollectionSource): string {
  switch (source) {
    case 'automated_scan':
      return 'Automated Scan';
    case 'scheduled_collection':
      return 'Scheduled Collection';
    case 'manual_upload':
      return 'Manual Upload';
    case 'external_import':
      return 'External Import';
    case 'api_integration':
      return 'API Integration';
    case 'derived':
      return 'Derived';
    default:
      return 'Unknown';
  }
}

export function getStatusLabel(status: EvidenceStatus): string {
  switch (status) {
    case 'active':
      return 'Active';
    case 'superseded':
      return 'Superseded';
    case 'archived':
      return 'Archived';
    case 'pending_review':
      return 'Pending Review';
    case 'approved':
      return 'Approved';
    case 'rejected':
      return 'Rejected';
    default:
      return 'Unknown';
  }
}

export function getStatusVariant(status: EvidenceStatus): 'success' | 'warning' | 'danger' | 'info' | 'secondary' {
  switch (status) {
    case 'active':
    case 'approved':
      return 'success';
    case 'pending_review':
      return 'warning';
    case 'rejected':
      return 'danger';
    case 'superseded':
    case 'archived':
      return 'secondary';
    default:
      return 'info';
  }
}
