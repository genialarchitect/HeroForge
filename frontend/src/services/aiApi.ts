/**
 * AI API service for AI-specific endpoints
 */

const API_BASE = '/api';

export interface RemediationStep {
  step_number: number;
  title: string;
  description: string;
  code_snippet?: string;
  code_language?: string;
  estimated_time?: string;
  risk_level?: 'low' | 'medium' | 'high';
  requires_reboot?: boolean;
  requires_downtime?: boolean;
}

export interface RemediationSuggestion {
  vulnerability_id: string;
  platform: string;
  steps: RemediationStep[];
  code_snippets: CodeSnippet[];
  estimated_effort: string;
  risk_notes: string[];
  prerequisites: string[];
  verification_steps: string[];
  rollback_steps?: string[];
  generated_at: string;
}

export interface CodeSnippet {
  title: string;
  language: string;
  code: string;
  description?: string;
  filename?: string;
}

export interface GenerateRemediationRequest {
  vulnerability_id: string;
  platform?: string;
  include_rollback?: boolean;
  verbose?: boolean;
}

export interface AIVulnerabilityScore {
  vulnerability_id: string;
  effective_risk_score: number;
  base_cvss_score: number;
  exploitability_score: number;
  asset_criticality_score: number;
  network_exposure_score: number;
  data_sensitivity_score: number;
  remediation_priority: number;
  remediation_effort_estimate: string;
  explanation?: string;
  key_factors?: KeyFactor[];
  epss_score?: number;
  epss_percentile?: number;
}

export interface KeyFactor {
  name: string;
  description: string;
  contribution: number;
  value: string;
}

export interface TopRisksResponse {
  vulnerabilities: AIVulnerabilityScore[];
  generated_at: string;
  total_count: number;
}

export interface AttackPathInfo {
  path_count: number;
  most_critical_path?: string;
  affected_assets: string[];
}

export const aiAPI = {
  /**
   * Generate AI-powered remediation suggestions
   */
  generateRemediation: async (request: GenerateRemediationRequest): Promise<RemediationSuggestion> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/remediation/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to generate remediation suggestions');
    }

    return response.json();
  },

  /**
   * Get top AI-prioritized risks
   */
  getTopRisks: async (limit: number = 5): Promise<TopRisksResponse> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/ai/top-risks?limit=${limit}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch top risks');
    }

    return response.json();
  },

  /**
   * Get AI score for a specific vulnerability
   */
  getVulnerabilityScore: async (vulnerabilityId: string): Promise<AIVulnerabilityScore> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/ai/scores/vulnerability/${vulnerabilityId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch vulnerability score');
    }

    return response.json();
  },

  /**
   * Get attack paths involving a vulnerability
   */
  getAttackPathsForVulnerability: async (vulnerabilityId: string): Promise<AttackPathInfo> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/attack-paths/vulnerability/${vulnerabilityId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      // Return empty info if no attack paths found
      if (response.status === 404) {
        return {
          path_count: 0,
          affected_assets: [],
        };
      }
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to fetch attack paths');
    }

    return response.json();
  },

  /**
   * Trigger AI prioritization for a scan
   */
  prioritizeScan: async (scanId: string, forceRecalculate: boolean = false): Promise<void> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/ai/prioritize/${scanId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ force_recalculate: forceRecalculate }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || 'Failed to prioritize scan');
    }
  },
};

export default aiAPI;
