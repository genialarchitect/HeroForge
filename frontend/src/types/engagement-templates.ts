// Engagement Template Types for Quick Setup

export interface MilestoneTemplate {
  name: string;
  description?: string;
  days_offset: number;
  is_required: boolean;
}

export interface ScanConfigTemplate {
  scan_types: string[];
  port_ranges?: string;
  intensity: 'light' | 'normal' | 'aggressive';
  include_web_scan: boolean;
  include_vuln_scan: boolean;
  enumeration_depth: 'passive' | 'light' | 'aggressive';
}

export interface EngagementTemplate {
  id: string;
  name: string;
  description: string;
  engagement_type: string;
  default_duration_days: number;
  default_budget?: number;
  scope_template?: string;
  compliance_frameworks?: string[];
  milestones?: MilestoneTemplate[];
  scan_config?: ScanConfigTemplate;
  is_system: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateEngagementTemplateRequest {
  name: string;
  description: string;
  engagement_type: string;
  default_duration_days: number;
  default_budget?: number;
  scope_template?: string;
  compliance_frameworks?: string[];
  milestones?: MilestoneTemplate[];
  scan_config?: ScanConfigTemplate;
}

export interface CreateFromTemplateRequest {
  template_id: string;
  customer_id: string;
  engagement_name: string;
  start_date?: string;
  end_date?: string;
  budget?: number;
  scope?: string;
  notes?: string;
  compliance_frameworks?: string[];
  auto_create_portal_user: boolean;
  create_default_milestones: boolean;
}

export interface EngagementSetupResult {
  engagement_id: string;
  engagement_name: string;
  milestones_created: number;
  portal_user_created: boolean;
  scan_config?: ScanConfigTemplate;
}

export interface EngagementType {
  id: string;
  name: string;
  description: string;
}
