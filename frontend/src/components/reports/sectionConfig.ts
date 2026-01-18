/**
 * Report Section Configuration
 *
 * Provides consistent section definitions used across report creation components.
 * Section IDs match the backend ReportSection enum in src/reports/types.rs.
 */

export interface ReportSectionDef {
  id: string;
  label: string;
  description?: string;
  // Which templates include this section by default
  defaultInTemplates: string[];
}

/**
 * All available report sections with their metadata.
 * Order matters - this is the order they appear in reports.
 */
export const REPORT_SECTIONS: ReportSectionDef[] = [
  {
    id: 'Table of Contents',
    label: 'Table of Contents',
    description: 'Navigation index for the report',
    defaultInTemplates: ['technical', 'compliance'],
  },
  {
    id: 'Executive Summary',
    label: 'Executive Summary',
    description: 'High-level overview for stakeholders',
    defaultInTemplates: ['executive', 'technical', 'compliance'],
  },
  {
    id: 'Risk Overview',
    label: 'Risk Overview',
    description: 'Risk assessment and severity breakdown',
    defaultInTemplates: ['executive', 'technical'],
  },
  {
    id: 'Host Inventory',
    label: 'Host Inventory',
    description: 'List of discovered hosts and systems',
    defaultInTemplates: ['technical'],
  },
  {
    id: 'Port Analysis',
    label: 'Port Analysis',
    description: 'Open ports and network services',
    defaultInTemplates: ['technical'],
  },
  {
    id: 'Vulnerability Findings',
    label: 'Vulnerability Findings',
    description: 'Detailed vulnerability analysis',
    defaultInTemplates: ['executive', 'technical', 'compliance'],
  },
  {
    id: 'Service Enumeration',
    label: 'Service Enumeration',
    description: 'Service detection and version information',
    defaultInTemplates: ['technical'],
  },
  {
    id: 'Secret Findings',
    label: 'Secret Findings',
    description: 'Exposed credentials and sensitive data',
    defaultInTemplates: ['technical'],
  },
  {
    id: 'Screenshots',
    label: 'Screenshots',
    description: 'Visual evidence of findings',
    defaultInTemplates: ['technical', 'compliance'],
  },
  {
    id: 'Remediation Recommendations',
    label: 'Remediation Recommendations',
    description: 'Prioritized fix recommendations',
    defaultInTemplates: ['executive', 'technical', 'compliance'],
  },
  {
    id: 'Compliance Mapping',
    label: 'Compliance Mapping',
    description: 'Map findings to compliance frameworks',
    defaultInTemplates: ['compliance'],
  },
  {
    id: 'Appendix',
    label: 'Appendix',
    description: 'Technical details and raw data',
    defaultInTemplates: ['technical'],
  },
];

/**
 * Get section labels mapped by ID for quick lookup
 */
export const SECTION_LABELS: Record<string, string> = REPORT_SECTIONS.reduce(
  (acc, section) => {
    acc[section.id] = section.label;
    return acc;
  },
  {} as Record<string, string>
);

/**
 * Get default sections for a given template ID
 */
export function getDefaultSections(templateId: string): string[] {
  return REPORT_SECTIONS.filter((section) =>
    section.defaultInTemplates.includes(templateId)
  ).map((section) => section.id);
}

/**
 * Template definitions with metadata
 */
export interface TemplateDef {
  id: string;
  name: string;
  description: string;
  icon?: string;
  supportsFormats: string[];
}

export const REPORT_TEMPLATES: TemplateDef[] = [
  {
    id: 'executive',
    name: 'Executive',
    description: 'High-level summary for leadership',
    supportsFormats: ['pdf', 'html'],
  },
  {
    id: 'technical',
    name: 'Technical',
    description: 'Detailed findings for security teams',
    supportsFormats: ['pdf', 'html', 'json', 'markdown'],
  },
  {
    id: 'compliance',
    name: 'Compliance',
    description: 'Audit-ready with framework mappings',
    supportsFormats: ['pdf', 'html', 'csv'],
  },
];

/**
 * Get template by ID
 */
export function getTemplate(templateId: string): TemplateDef | undefined {
  return REPORT_TEMPLATES.find((t) => t.id === templateId);
}
