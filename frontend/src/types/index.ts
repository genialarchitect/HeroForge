// =============================================================================
// HeroForge Frontend Types - Barrel Export
// =============================================================================
// This file re-exports all types from domain-specific modules.
// Import types from '../types' to get access to all type definitions.
// =============================================================================

// Common types (UserRole, BadgeType, helper functions)
export * from './common';

// Authentication types (User, Login, Register, MFA)
export * from './auth';

// SSL/TLS types (certificates, grading, vulnerability scanning)
export * from './ssl';

// Scan types (results, configuration, scheduling, comparison)
export * from './scan';

// Vulnerability management types
export * from './vulnerability';

// Report generation types
export * from './report';

// Admin console types (roles, audit logs, API keys, rate limits)
export * from './admin';

// Compliance framework types (including manual assessments)
export * from './compliance';

// CRM types (customers, contacts, engagements)
export * from './crm';

// Customer portal types (Note: PortalUpdateProfileRequest is the portal-specific profile update type)
export type {
  PortalLoginRequest,
  PortalLoginResponse,
  PortalUserInfo,
  PortalChangePasswordRequest,
  PortalProfile,
  PortalUpdateProfileRequest,
  PortalDashboardStats,
  PortalRecentScan,
  PortalUpcomingMilestone,
  PortalEngagement,
  PortalEngagementDetail,
  PortalMilestone,
  PortalVulnerability,
  PortalVulnerabilityDetail,
  PortalVulnerabilityStats,
  PortalVulnerabilityQuery,
  PortalVulnerabilitiesResponse,
  PortalReport,
} from './portal';

// Threat intelligence and attack path analysis types
export * from './threat-intel';

// Asset inventory, finding templates, methodology checklists, webhooks
// Note: CloneFindingTemplateRequest is for finding templates (uses new_title)
export * from './asset';

// SIEM types (log sources, rules, alerts)
export * from './siem';

// DevSecOps / Yellow Team types (SAST, SBOM, architecture reviews, binary analysis)
export * from './devsecops';

// Exploitation types (password cracking, ASM, BAS, agents)
export * from './exploitation';

// Advanced types (AI, SSO, CI/CD, Container/K8s, IaC, workflows, Purple Team, SOAR, Fuzzing, UEBA)
export * from './advanced';

// AI Red Team Advisor types
export * from './red-team-advisor';
