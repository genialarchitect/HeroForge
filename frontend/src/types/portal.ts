// ============================================================================
// Portal Types - Customer Portal
// ============================================================================

import type { PortalUserRole } from './crm';

export interface PortalLoginRequest {
  email: string;
  password: string;
}

export interface PortalLoginResponse {
  token: string;
  user: PortalUserInfo;
}

export interface PortalUserInfo {
  id: string;
  email: string;
  customer_id: string;
  customer_name?: string;
  role: PortalUserRole;
}

export interface PortalChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface PortalProfile {
  id: string;
  email: string;
  customer_id: string;
  customer_name?: string;
  role: PortalUserRole;
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
  last_login?: string;
  created_at: string;
}

export interface PortalUpdateProfileRequest {
  first_name?: string;
  last_name?: string;
  phone?: string;
  title?: string;
}

export interface PortalDashboardStats {
  customer_name: string;
  active_engagements: number;
  total_engagements: number;
  open_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  available_reports: number;
  recent_scans: PortalRecentScan[];
  upcoming_milestones: PortalUpcomingMilestone[];
}

export interface PortalRecentScan {
  id: string;
  name: string;
  status: string;
  created_at: string;
  total_hosts?: number;
}

export interface PortalUpcomingMilestone {
  id: string;
  name: string;
  engagement_name: string;
  due_date?: string;
  status: string;
}

export interface PortalEngagement {
  id: string;
  name: string;
  engagement_type: string;
  status: string;
  scope?: string;
  start_date?: string;
  end_date?: string;
  created_at: string;
}

export interface PortalEngagementDetail {
  engagement: PortalEngagement;
  milestones: PortalMilestone[];
  scan_count: number;
  vulnerability_count: number;
}

export interface PortalMilestone {
  id: string;
  name: string;
  description?: string;
  due_date?: string;
  completed_at?: string;
  status: string;
}

export interface PortalVulnerability {
  id: string;
  scan_id: string;
  host: string;
  port?: number;
  service?: string;
  title: string;
  severity: string;
  status: string;
  cve_ids?: string;
  cvss_score?: number;
  discovered_at: string;
}

export interface PortalVulnerabilityDetail {
  vulnerability: PortalVulnerability;
  description?: string;
  remediation?: string;
  references?: string;
  engagement_name?: string;
  scan_name: string;
}

export interface PortalVulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  in_progress: number;
  resolved: number;
}

export interface PortalVulnerabilityQuery {
  severity?: string;
  status?: string;
  engagement_id?: string;
  limit?: number;
  offset?: number;
}

export interface PortalVulnerabilitiesResponse {
  vulnerabilities: PortalVulnerability[];
  stats: PortalVulnerabilityStats;
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface PortalReport {
  id: string;
  name: string;
  report_type: string;
  format: string;
  status: string;
  created_at: string;
  engagement_id?: string;
  engagement_name?: string;
}
