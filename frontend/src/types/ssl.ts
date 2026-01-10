// ============================================================================
// SSL/TLS Types - SSL certificates, grading, and vulnerability scanning
// ============================================================================

export interface SslInfo {
  cert_valid: boolean;
  cert_expired: boolean;
  days_until_expiry: number | null;
  self_signed: boolean;
  hostname_mismatch: boolean;
  issuer: string;
  subject: string;
  valid_from: string;
  valid_until: string;
  protocols: string[];
  cipher_suites: string[];
  weak_ciphers: string[];
  weak_protocols: string[];
  hsts_enabled: boolean;
  hsts_max_age: number | null;
  chain_issues: string[];
  ssl_grade?: SslGrade;
}

// SSL/TLS Grading Types
// T = Trust issues (self-signed, untrusted CA)
// M = Hostname mismatch
export type SslGradeLevel = 'A+' | 'A' | 'A-' | 'B+' | 'B' | 'B-' | 'C' | 'D' | 'F' | 'T' | 'M' | 'Unknown';

export type SslVulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface SslVulnerability {
  id: string;
  name: string;
  severity: SslVulnerabilitySeverity;
  description: string;
  cve: string | null;
}

export interface SslGrade {
  grade: SslGradeLevel;
  overall_score: number;
  protocol_score: number;
  cipher_score: number;
  certificate_score: number;
  key_exchange_score: number;
  vulnerabilities_found: SslVulnerability[];
  recommendations: string[];
  grade_capped: boolean;
  cap_reason: string | null;
}

// SSL Report Types
export interface SslReportEntry {
  host: string;
  port: number;
  service: string | null;
  grade: SslGradeLevel;
  overall_score: number;
  protocol_score: number;
  cipher_score: number;
  certificate_score: number;
  key_exchange_score: number;
  vulnerabilities_count: number;
  recommendations_count: number;
  ssl_info: SslInfo;
}

export interface SslReportSummary {
  scan_id: string;
  scan_name: string;
  total_ssl_services: number;
  grade_distribution: Record<string, number>;
  average_score: number;
  services_with_critical_issues: number;
  services_with_high_issues: number;
  entries: SslReportEntry[];
}
