// Plugin Types for HeroForge Plugin Marketplace

export type PluginType = 'scanner' | 'detector' | 'reporter' | 'integration';
export type PluginStatus = 'enabled' | 'disabled' | 'error' | 'installing' | 'updating';

export interface PluginPermissions {
  network: boolean;
  filesystem: boolean;
  environment: boolean;
  subprocess: boolean;
  scan_results: boolean;
  vulnerabilities: boolean;
  assets: boolean;
  reports: boolean;
}

export interface Plugin {
  id: string;
  plugin_id: string;
  name: string;
  version: string;
  plugin_type: PluginType;
  status: PluginStatus;
  description: string;
  author: string;
  permissions: PluginPermissions;
  installed_at: string;
  updated_at: string;
  error_message?: string;
}

export interface PluginListResponse {
  plugins: Plugin[];
  total: number;
}

export interface PluginStats {
  total: number;
  enabled: number;
  disabled: number;
  error: number;
  by_type: Record<string, number>;
}

export interface PluginTypeInfo {
  id: string;
  name: string;
  description: string;
}

export interface InstallPluginRequest {
  url?: string;
  file_path?: string;
  enable?: boolean;
}

export interface InstallPluginResponse {
  plugin: Plugin;
  message: string;
}

export interface UpdatePluginSettingsRequest {
  settings: Record<string, unknown>;
}

export interface PluginValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface PluginListQuery {
  plugin_type?: string;
  status?: string;
  search?: string;
}
