// ============================================================================
// CRM Types - Customer Relationship Management
// ============================================================================

export type CustomerStatus = 'active' | 'inactive' | 'prospect';
export type CompanySize = 'small' | 'medium' | 'enterprise';
export type EngagementType = 'pentest' | 'vuln_assessment' | 'red_team' | 'compliance_audit' | 'consulting';
export type EngagementStatus = 'planning' | 'in_progress' | 'on_hold' | 'completed' | 'cancelled';
export type MilestoneStatus = 'pending' | 'in_progress' | 'completed' | 'overdue';
export type ContractType = 'msa' | 'sow' | 'nda' | 'amendment';
export type ContractStatus = 'draft' | 'pending_signature' | 'active' | 'expired' | 'terminated';
export type CommunicationType = 'email' | 'call' | 'meeting' | 'note';

export interface Customer {
  id: string;
  user_id: string;
  name: string;
  industry: string | null;
  company_size: CompanySize | null;
  website: string | null;
  address: string | null;
  notes: string | null;
  status: CustomerStatus;
  created_at: string;
  updated_at: string;
}

export interface Contact {
  id: string;
  customer_id: string;
  first_name: string;
  last_name: string;
  email: string | null;
  phone: string | null;
  title: string | null;
  is_primary: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface Engagement {
  id: string;
  customer_id: string;
  name: string;
  engagement_type: EngagementType;
  status: EngagementStatus;
  scope: string | null;
  start_date: string | null;
  end_date: string | null;
  budget: number | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface EngagementMilestone {
  id: string;
  engagement_id: string;
  name: string;
  description: string | null;
  due_date: string | null;
  completed_at: string | null;
  status: MilestoneStatus;
  created_at: string;
}

export interface Contract {
  id: string;
  customer_id: string;
  engagement_id: string | null;
  contract_type: ContractType;
  name: string;
  value: number | null;
  start_date: string | null;
  end_date: string | null;
  status: ContractStatus;
  file_path: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface SlaDefinition {
  id: string;
  customer_id: string | null;
  name: string;
  description: string | null;
  response_time_critical: number | null;
  response_time_high: number | null;
  response_time_medium: number | null;
  response_time_low: number | null;
  resolution_time_critical: number | null;
  resolution_time_high: number | null;
  resolution_time_medium: number | null;
  resolution_time_low: number | null;
  is_template: boolean;
  created_at: string;
  updated_at: string;
}

export interface TimeEntry {
  id: string;
  engagement_id: string;
  user_id: string;
  description: string;
  hours: number;
  billable: boolean;
  date: string;
  created_at: string;
}

export interface Communication {
  id: string;
  customer_id: string;
  engagement_id: string | null;
  contact_id: string | null;
  user_id: string;
  comm_type: CommunicationType;
  subject: string | null;
  content: string | null;
  comm_date: string;
  created_at: string;
}

export interface CrmDashboardStats {
  total_customers: number;
  active_customers: number;
  total_engagements: number;
  active_engagements: number;
  total_contracts_value: number;
  upcoming_milestones: EngagementMilestone[];
  overdue_milestones: number;
  recent_communications: Communication[];
  total_hours_this_month: number;
  billable_hours_this_month: number;
}

export interface CustomerSummary {
  customer: Customer;
  contact_count: number;
  engagement_count: number;
  active_engagement_count: number;
  contract_count: number;
  total_contract_value: number;
  scan_count: number;
  vulnerability_count: number;
}

// CRM Request Types
export interface CreateCustomerRequest {
  name: string;
  industry?: string;
  company_size?: CompanySize;
  website?: string;
  address?: string;
  notes?: string;
  status?: CustomerStatus;
}

export interface UpdateCustomerRequest {
  name?: string;
  industry?: string;
  company_size?: CompanySize;
  website?: string;
  address?: string;
  notes?: string;
  status?: CustomerStatus;
}

export interface CreateContactRequest {
  first_name: string;
  last_name: string;
  email?: string;
  phone?: string;
  title?: string;
  is_primary?: boolean;
  notes?: string;
}

export interface UpdateContactRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
  phone?: string;
  title?: string;
  is_primary?: boolean;
  notes?: string;
}

export interface CreateEngagementRequest {
  name: string;
  engagement_type: EngagementType;
  status?: EngagementStatus;
  scope?: string;
  start_date?: string;
  end_date?: string;
  budget?: number;
  notes?: string;
}

export interface UpdateEngagementRequest {
  name?: string;
  engagement_type?: EngagementType;
  status?: EngagementStatus;
  scope?: string;
  start_date?: string;
  end_date?: string;
  budget?: number;
  notes?: string;
}

// CRM Discovered Assets (auto-populated from recon scans)
export type CrmAssetType =
  | 'domain'
  | 'subdomain'
  | 'ip_address'
  | 'service'
  | 'port'
  | 'certificate'
  | 'email_address'
  | 'repository'
  | 'dns_record'
  | 'technology'
  | 'endpoint'
  | 'api_endpoint'
  | 'credential'
  | 'secret';

export interface CrmDiscoveredAsset {
  id: string;
  customer_id: string;
  engagement_id: string | null;
  asset_type: CrmAssetType;
  value: string;
  first_seen_at: string;
  last_seen_at: string;
  source: string;
  source_scan_id: string | null;
  source_scan_type: string | null;
  metadata: Record<string, unknown> | null;
  is_in_scope: boolean;
  is_verified: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface DiscoveredAssetsSummary {
  total_assets: number;
  in_scope_assets: number;
  verified_assets: number;
  assets_by_type: [string, number][];
  assets_by_source: [string, number][];
  recent_discoveries: CrmDiscoveredAsset[];
}

export interface CreateDiscoveredAssetRequest {
  asset_type: CrmAssetType;
  value: string;
  engagement_id?: string;
  source?: string;
  metadata?: Record<string, unknown>;
  is_in_scope?: boolean;
  notes?: string;
}

export interface UpdateDiscoveredAssetRequest {
  is_in_scope?: boolean;
  is_verified?: boolean;
  notes?: string;
  engagement_id?: string;
}

export interface BulkScopeRequest {
  asset_ids: string[];
  is_in_scope: boolean;
}

export interface CreateMilestoneRequest {
  name: string;
  description?: string;
  due_date?: string;
  status?: MilestoneStatus;
}

export interface UpdateMilestoneRequest {
  name?: string;
  description?: string;
  due_date?: string;
  status?: MilestoneStatus;
  completed_at?: string;
}

export interface CreateContractRequest {
  name: string;
  contract_type: ContractType;
  engagement_id?: string;
  value?: number;
  start_date?: string;
  end_date?: string;
  status?: ContractStatus;
  notes?: string;
}

export interface UpdateContractRequest {
  name?: string;
  contract_type?: ContractType;
  engagement_id?: string;
  value?: number;
  start_date?: string;
  end_date?: string;
  status?: ContractStatus;
  notes?: string;
}

export interface CreateSlaRequest {
  name: string;
  description?: string;
  response_time_critical?: number;
  response_time_high?: number;
  response_time_medium?: number;
  response_time_low?: number;
  resolution_time_critical?: number;
  resolution_time_high?: number;
  resolution_time_medium?: number;
  resolution_time_low?: number;
  is_template?: boolean;
}

export interface CreateTimeEntryRequest {
  description: string;
  hours: number;
  billable?: boolean;
  date: string;
}

export interface CreateCommunicationRequest {
  comm_type: CommunicationType;
  subject?: string;
  content?: string;
  comm_date: string;
  engagement_id?: string;
  contact_id?: string;
}

// CRM Portal User Management Types
export type PortalUserRole = 'admin' | 'member' | 'viewer';

export interface CrmPortalUser {
  id: string;
  customer_id: string;
  contact_id?: string;
  email: string;
  is_active: boolean;
  last_login?: string;
  role: PortalUserRole;
  created_at: string;
  updated_at: string;
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
}

export interface CreatePortalUserRequest {
  email: string;
  password: string;
  contact_id?: string;
  role?: PortalUserRole;
}

export interface UpdatePortalUserRequest {
  contact_id?: string;
  is_active?: boolean;
  role?: PortalUserRole;
}

export interface ResetPortalUserPasswordRequest {
  new_password: string;
}
