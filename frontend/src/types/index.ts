export type UserRole = 'admin' | 'user' | 'auditor' | 'viewer';

export interface User {
  id: string;
  username: string;
  email: string;
  roles?: UserRole[]; // Added for admin console
  is_active?: boolean; // Added for admin console
  created_at?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
}

export interface ScanResult {
  id: string;
  user_id: string;
  name: string;
  targets: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  results: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export type EnumDepth = 'passive' | 'light' | 'aggressive';

export type EnumService =
  | 'http'
  | 'https'
  | 'dns'
  | 'smb'
  | 'ftp'
  | 'ssh'
  | 'smtp'
  | 'ldap'
  | 'mysql'
  | 'postgresql'
  | 'mongodb'
  | 'redis'
  | 'elasticsearch';

export interface CreateScanRequest {
  name: string;
  targets: string[];
  port_range: [number, number];
  threads: number;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  // Enumeration options
  enable_enumeration?: boolean;
  enum_depth?: EnumDepth;
  enum_services?: EnumService[];
}

export interface HostInfo {
  target: {
    ip: string;
    hostname: string | null;
  };
  is_alive: boolean;
  os_guess: {
    os_family: string;
    os_version: string | null;
    confidence: number;
  } | null;
  ports: PortInfo[];
  vulnerabilities: Vulnerability[];
  scan_duration: {
    secs: number;
    nanos: number;
  };
}

export interface PortInfo {
  port: number;
  protocol: string;
  state: string;
  service: {
    name: string;
    version: string | null;
    banner: string | null;
  } | null;
}

export interface Vulnerability {
  cve_id: string | null;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  affected_service: string | null;
}

// Admin Console Types

export interface Role {
  id: string;
  name: string;
  description?: string;
  can_manage_users: boolean;
  can_manage_scans: boolean;
  can_view_all_scans: boolean;
  can_delete_any_scan: boolean;
  can_view_audit_logs: boolean;
  can_manage_settings: boolean;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  target_type?: string;
  target_id?: string;
  details?: string;
  ip_address?: string;
  created_at: string;
}

export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  updated_by?: string;
  updated_at: string;
}
