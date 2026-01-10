// ============================================================================
// Report Types - Report generation, templates, and formats
// ============================================================================

export type ReportFormat = 'pdf' | 'html' | 'json';

export type ReportTemplateId = 'executive' | 'technical' | 'compliance';

export type ReportStatus = 'pending' | 'generating' | 'completed' | 'failed';

export type ReportSectionId =
  | 'tableOfContents'
  | 'executiveSummary'
  | 'riskOverview'
  | 'hostInventory'
  | 'portAnalysis'
  | 'vulnerabilityFindings'
  | 'serviceEnumeration'
  | 'remediationRecommendations'
  | 'appendix';

export interface ReportOptions {
  include_charts?: boolean;
  company_name?: string;
  assessor_name?: string;
  classification?: string;
}

export interface CreateReportRequest {
  scan_id: string;
  name: string;
  description?: string;
  format: ReportFormat;
  template_id: ReportTemplateId;
  sections: string[];
  options?: ReportOptions;
}

export interface Report {
  id: string;
  user_id: string;
  scan_id: string;
  name: string;
  description?: string;
  format: string;
  template_id: string;
  sections: string;
  file_path?: string;
  file_size?: number;
  status: ReportStatus;
  error_message?: string;
  metadata?: string;
  created_at: string;
  completed_at?: string;
  expires_at?: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  default_sections: string[];
  supports_formats: string[];
}
