import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Shield,
  Search,
  Code,
  Plus,
  RefreshCw,
  Eye,
  Edit,
  CheckCircle,
  XCircle,
  AlertCircle,
  X,
  FileText,
  Play,
  BarChart3,
  Download,
  Upload,
  Trash2,
  Clock,
  Tag,
  Layers,
  Globe,
  Package,
  FolderOpen,
  Copy,
  AlertTriangle,
  Zap,
  List,
  Grid,
  ExternalLink,
  Settings,
  Database,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'dashboard' | 'rules' | 'builder' | 'community' | 'scans';

// ============================================================================
// Types
// ============================================================================

interface YaraRule {
  id: string;
  name: string;
  description?: string;
  rule_text: string;
  category: string;
  severity?: string;
  enabled: boolean;
  is_builtin: boolean;
  tags: string[];
  metadata?: Record<string, string>;
  match_count: number;
  created_at: string;
  updated_at: string;
}

interface YaraScan {
  id: string;
  name: string;
  target_path: string;
  target_type: string;
  status: string;
  rules_used: number;
  files_scanned: number;
  matches_found: number;
  bytes_scanned: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  created_at: string;
}

interface YaraMatch {
  id: string;
  rule_name: string;
  file_path?: string;
  matched_strings: string[];
  metadata: Record<string, string>;
  matched_at: string;
}

interface YaraStats {
  total_rules: number;
  enabled_rules: number;
  builtin_rules: number;
  custom_rules: number;
  total_scans: number;
  total_matches: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
}

interface CommunitySource {
  id: string;
  name: string;
  description: string;
  url: string;
  source_type: string;
  rules_count: number;
  last_updated?: string;
}

interface ValidationResult {
  is_valid: boolean;
  errors: string[];
  warnings: string[];
}

// Visual Builder Types
interface StringDefinition {
  identifier: string;
  string_type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers: {
    nocase: boolean;
    wide: boolean;
    ascii: boolean;
    fullword: boolean;
    xor: boolean;
    base64: boolean;
  };
}

// ============================================================================
// API Functions
// ============================================================================

const yaraAPI = {
  // Stats
  getStats: () => api.get<YaraStats>('/detection/yara/rules/stats').then(r => r.data),
  getCategories: () => api.get<string[]>('/detection/yara/rules/categories').then(r => r.data),

  // Rules CRUD
  listRules: (params?: Record<string, string>) =>
    api.get<YaraRule[]>('/detection/yara/rules', { params }).then(r => r.data),
  createRule: (data: { name: string; rule_text: string; category?: string }) =>
    api.post<YaraRule>('/detection/yara/rules', data).then(r => r.data),
  getRule: (id: string) => api.get<YaraRule>(`/detection/yara/rules/${id}`).then(r => r.data),
  updateRule: (id: string, data: Partial<YaraRule>) =>
    api.put<YaraRule>(`/detection/yara/rules/${id}`, data).then(r => r.data),
  deleteRule: (id: string) => api.delete(`/detection/yara/rules/${id}`),

  // Visual Builder
  buildRule: (data: {
    name: string;
    description?: string;
    tags: string[];
    metadata: Array<{ key: string; value: string }>;
    strings: StringDefinition[];
    condition: { condition_type: string; custom_condition?: string };
  }) => api.post<{ rule_content: string; validation: ValidationResult }>('/detection/yara/rules/build', data).then(r => r.data),

  // Validation
  validateRule: (content: string) =>
    api.post<ValidationResult>('/detection/yara/validate', { rule_content: content }).then(r => r.data),

  // Scanning
  scanPath: (data: { path: string; recursive?: boolean; rule_ids?: string[] }) =>
    api.post<YaraScan>('/detection/yara/scan', data).then(r => r.data),
  bulkScan: (data: { paths: string[]; recursive?: boolean; rule_ids?: string[]; categories?: string[] }) =>
    api.post<YaraScan>('/detection/yara/scan/bulk', data).then(r => r.data),
  listScans: () => api.get<YaraScan[]>('/detection/yara/scans').then(r => r.data),
  getScan: (id: string) => api.get<YaraScan & { matches: YaraMatch[] }>(`/detection/yara/scans/${id}`).then(r => r.data),
  deleteScan: (id: string) => api.delete(`/detection/yara/scans/${id}`),

  // Community Sources
  getCommunitySourcesList: () => api.get<CommunitySource[]>('/detection/yara/community/sources').then(r => r.data),
  fetchFromCommunity: (sourceId: string) =>
    api.post<{ rules_fetched: number }>(`/detection/yara/community/fetch/${sourceId}`).then(r => r.data),
  importRules: (data: { content: string; source?: string; category?: string; overwrite_existing: boolean }) =>
    api.post<{ imported: number; skipped: number; errors: string[] }>('/detection/yara/rules/import', data).then(r => r.data),
};

// ============================================================================
// Badge Components
// ============================================================================

const severityColors: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  running: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const categoryColors: Record<string, { bg: string; text: string }> = {
  malware: { bg: 'bg-red-500/20', text: 'text-red-400' },
  ransomware: { bg: 'bg-red-600/20', text: 'text-red-300' },
  apt: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  packer: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  webshell: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  exploit: { bg: 'bg-pink-500/20', text: 'text-pink-400' },
  miner: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  rat: { bg: 'bg-violet-500/20', text: 'text-violet-400' },
  backdoor: { bg: 'bg-rose-500/20', text: 'text-rose-400' },
  generic: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  custom: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const colors = severityColors[severity.toLowerCase()] || severityColors.info;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.pending;
  const Icon = status === 'completed' ? CheckCircle : status === 'failed' ? XCircle : status === 'running' ? RefreshCw : Clock;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      <Icon className={`h-3 w-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  );
}

function CategoryBadge({ category }: { category: string }) {
  const colors = categoryColors[category.toLowerCase()] || categoryColors.generic;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {category}
    </span>
  );
}

// ============================================================================
// Dashboard Tab
// ============================================================================

function DashboardTab() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['yara', 'stats'],
    queryFn: yaraAPI.getStats,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="h-8 w-8 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <FileText className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats?.total_rules || 0}</p>
              <p className="text-sm text-gray-400">Total Rules</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <CheckCircle className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats?.enabled_rules || 0}</p>
              <p className="text-sm text-gray-400">Enabled</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <Search className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats?.total_scans || 0}</p>
              <p className="text-sm text-gray-400">Total Scans</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/20 rounded-lg">
              <AlertCircle className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{stats?.total_matches || 0}</p>
              <p className="text-sm text-gray-400">Matches Found</p>
            </div>
          </div>
        </div>
      </div>

      {/* Category Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-white mb-4">Rules by Category</h3>
          <div className="space-y-2">
            {stats?.by_category && Object.entries(stats.by_category).map(([category, count]) => (
              <div key={category} className="flex items-center justify-between">
                <CategoryBadge category={category} />
                <span className="text-gray-300">{count}</span>
              </div>
            ))}
            {(!stats?.by_category || Object.keys(stats.by_category).length === 0) && (
              <p className="text-gray-500 text-sm">No rules yet</p>
            )}
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-white mb-4">Rules by Source</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-gray-300">Built-in Rules</span>
              <span className="text-cyan-400 font-semibold">{stats?.builtin_rules || 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-300">Custom Rules</span>
              <span className="text-green-400 font-semibold">{stats?.custom_rules || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Rules Tab
// ============================================================================

function RulesTab() {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedRule, setSelectedRule] = useState<YaraRule | null>(null);
  const [showViewModal, setShowViewModal] = useState(false);

  const { data: rules, isLoading } = useQuery({
    queryKey: ['yara', 'rules', { category: categoryFilter, search: searchQuery }],
    queryFn: () => yaraAPI.listRules({
      ...(categoryFilter && { category: categoryFilter }),
      ...(searchQuery && { search: searchQuery })
    }),
  });

  const { data: categories } = useQuery({
    queryKey: ['yara', 'categories'],
    queryFn: yaraAPI.getCategories,
  });

  const deleteMutation = useMutation({
    mutationFn: yaraAPI.deleteRule,
    onSuccess: () => {
      toast.success('Rule deleted');
      queryClient.invalidateQueries({ queryKey: ['yara'] });
    },
    onError: () => toast.error('Failed to delete rule'),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      yaraAPI.updateRule(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['yara'] });
    },
  });

  const filteredRules = rules?.filter(rule => {
    if (searchQuery && !rule.name.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    return true;
  }) || [];

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap gap-4 items-center justify-between">
        <div className="flex gap-2 items-center">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search rules..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">All Categories</option>
            {categories?.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4" />
          Add Rule
        </button>
      </div>

      {/* Rules List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-cyan-400" />
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="text-center py-12">
          <FileText className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">No YARA rules found</p>
        </div>
      ) : (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Category</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Matches</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredRules.map(rule => (
                <tr key={rule.id} className="hover:bg-gray-750">
                  <td className="px-4 py-3">
                    <div>
                      <p className="text-white font-medium">{rule.name}</p>
                      {rule.description && (
                        <p className="text-gray-400 text-sm truncate max-w-xs">{rule.description}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <CategoryBadge category={rule.category || 'generic'} />
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${rule.is_builtin ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'}`}>
                      {rule.is_builtin ? 'Built-in' : 'Custom'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-300">{rule.match_count}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMutation.mutate({ id: rule.id, enabled: !rule.enabled })}
                      className={`text-xs px-2 py-0.5 rounded ${rule.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}
                    >
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => {
                          setSelectedRule(rule);
                          setShowViewModal(true);
                        }}
                        className="p-1 text-gray-400 hover:text-white"
                        title="View"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      {!rule.is_builtin && (
                        <button
                          onClick={() => deleteMutation.mutate(rule.id)}
                          className="p-1 text-gray-400 hover:text-red-400"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Rule Modal */}
      {showCreateModal && (
        <CreateRuleModal onClose={() => setShowCreateModal(false)} />
      )}

      {/* View Rule Modal */}
      {showViewModal && selectedRule && (
        <ViewRuleModal rule={selectedRule} onClose={() => setShowViewModal(false)} />
      )}
    </div>
  );
}

// ============================================================================
// Visual Builder Tab
// ============================================================================

function BuilderTab() {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [strings, setStrings] = useState<StringDefinition[]>([]);
  const [conditionType, setConditionType] = useState('any');
  const [customCondition, setCustomCondition] = useState('');
  const [generatedRule, setGeneratedRule] = useState('');
  const [validation, setValidation] = useState<ValidationResult | null>(null);

  const buildMutation = useMutation({
    mutationFn: yaraAPI.buildRule,
    onSuccess: (data) => {
      setGeneratedRule(data.rule_content);
      setValidation(data.validation);
      if (data.validation.is_valid) {
        toast.success('Rule generated successfully');
      } else {
        toast.warning('Rule has validation warnings');
      }
    },
    onError: () => toast.error('Failed to build rule'),
  });

  const addString = () => {
    setStrings([...strings, {
      identifier: `str${strings.length + 1}`,
      string_type: 'text',
      value: '',
      modifiers: { nocase: false, wide: false, ascii: true, fullword: false, xor: false, base64: false },
    }]);
  };

  const updateString = (index: number, updates: Partial<StringDefinition>) => {
    const newStrings = [...strings];
    newStrings[index] = { ...newStrings[index], ...updates };
    setStrings(newStrings);
  };

  const removeString = (index: number) => {
    setStrings(strings.filter((_, i) => i !== index));
  };

  const addTag = () => {
    if (tagInput && !tags.includes(tagInput)) {
      setTags([...tags, tagInput]);
      setTagInput('');
    }
  };

  const handleBuild = () => {
    if (!name || strings.length === 0) {
      toast.error('Please provide a name and at least one string');
      return;
    }
    buildMutation.mutate({
      name,
      description: description || undefined,
      tags,
      metadata: [],
      strings,
      condition: {
        condition_type: conditionType,
        custom_condition: conditionType === 'custom' ? customCondition : undefined,
      },
    });
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Builder Form */}
        <div className="space-y-4">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-white mb-4">Rule Details</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Rule Name *</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Detect_Malware_XYZ"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Describe what this rule detects..."
                  rows={2}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Tags</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addTag()}
                    placeholder="Add tag..."
                    className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                  />
                  <button
                    onClick={addTag}
                    className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
                  >
                    Add
                  </button>
                </div>
                {tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {tags.map(tag => (
                      <span key={tag} className="flex items-center gap-1 px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-sm">
                        {tag}
                        <button onClick={() => setTags(tags.filter(t => t !== tag))}>
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Strings</h3>
              <button
                onClick={addString}
                className="flex items-center gap-1 px-2 py-1 bg-cyan-600 hover:bg-cyan-700 text-white rounded text-sm"
              >
                <Plus className="h-3 w-3" /> Add String
              </button>
            </div>
            <div className="space-y-4">
              {strings.map((str, index) => (
                <div key={index} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      type="text"
                      value={str.identifier}
                      onChange={(e) => updateString(index, { identifier: e.target.value })}
                      placeholder="$identifier"
                      className="w-24 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    />
                    <select
                      value={str.string_type}
                      onChange={(e) => updateString(index, { string_type: e.target.value as 'text' | 'hex' | 'regex' })}
                      className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    >
                      <option value="text">Text</option>
                      <option value="hex">Hex</option>
                      <option value="regex">Regex</option>
                    </select>
                    <button
                      onClick={() => removeString(index)}
                      className="ml-auto p-1 text-gray-400 hover:text-red-400"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                  <input
                    type="text"
                    value={str.value}
                    onChange={(e) => updateString(index, { value: e.target.value })}
                    placeholder={str.string_type === 'hex' ? '{ 4D 5A 90 00 }' : 'Enter string value...'}
                    className="w-full px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm mb-2"
                  />
                  <div className="flex flex-wrap gap-2">
                    {['nocase', 'wide', 'ascii', 'fullword', 'xor', 'base64'].map(mod => (
                      <label key={mod} className="flex items-center gap-1 text-xs text-gray-400">
                        <input
                          type="checkbox"
                          checked={str.modifiers[mod as keyof typeof str.modifiers]}
                          onChange={(e) => updateString(index, {
                            modifiers: { ...str.modifiers, [mod]: e.target.checked }
                          })}
                          className="rounded border-gray-600"
                        />
                        {mod}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
              {strings.length === 0 && (
                <p className="text-gray-500 text-sm text-center py-4">No strings defined. Click "Add String" to begin.</p>
              )}
            </div>
          </div>

          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-white mb-4">Condition</h3>
            <div className="space-y-3">
              <select
                value={conditionType}
                onChange={(e) => setConditionType(e.target.value)}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
              >
                <option value="any">Any of them</option>
                <option value="all">All of them</option>
                <option value="count">At least N matches</option>
                <option value="custom">Custom condition</option>
              </select>
              {conditionType === 'custom' && (
                <input
                  type="text"
                  value={customCondition}
                  onChange={(e) => setCustomCondition(e.target.value)}
                  placeholder="e.g., $str1 and ($str2 or $str3)"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                />
              )}
            </div>
          </div>

          <button
            onClick={handleBuild}
            disabled={buildMutation.isPending}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-800 text-white rounded-lg transition-colors"
          >
            {buildMutation.isPending ? (
              <RefreshCw className="h-5 w-5 animate-spin" />
            ) : (
              <Zap className="h-5 w-5" />
            )}
            Generate Rule
          </button>
        </div>

        {/* Generated Rule Preview */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Generated Rule</h3>
            {generatedRule && (
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedRule);
                  toast.success('Copied to clipboard');
                }}
                className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
              >
                <Copy className="h-3 w-3" /> Copy
              </button>
            )}
          </div>
          {generatedRule ? (
            <>
              <pre className="bg-gray-900 p-4 rounded-lg overflow-x-auto text-sm text-gray-300 font-mono">
                {generatedRule}
              </pre>
              {validation && (
                <div className="mt-4 space-y-2">
                  {validation.is_valid ? (
                    <div className="flex items-center gap-2 text-green-400">
                      <CheckCircle className="h-4 w-4" />
                      <span>Rule is valid</span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2 text-red-400">
                      <XCircle className="h-4 w-4" />
                      <span>Rule has errors</span>
                    </div>
                  )}
                  {validation.errors.map((err, i) => (
                    <p key={i} className="text-red-400 text-sm">{err}</p>
                  ))}
                  {validation.warnings.map((warn, i) => (
                    <p key={i} className="text-yellow-400 text-sm">{warn}</p>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <Code className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Fill in the form and click "Generate Rule"</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Community Tab
// ============================================================================

function CommunityTab() {
  const queryClient = useQueryClient();
  const [importContent, setImportContent] = useState('');
  const [showImportModal, setShowImportModal] = useState(false);

  const { data: sources, isLoading } = useQuery({
    queryKey: ['yara', 'community', 'sources'],
    queryFn: yaraAPI.getCommunitySourcesList,
  });

  const fetchMutation = useMutation({
    mutationFn: yaraAPI.fetchFromCommunity,
    onSuccess: (data) => {
      toast.success(`Fetched ${data.rules_fetched} rules`);
      queryClient.invalidateQueries({ queryKey: ['yara'] });
    },
    onError: () => toast.error('Failed to fetch rules'),
  });

  const importMutation = useMutation({
    mutationFn: yaraAPI.importRules,
    onSuccess: (data) => {
      toast.success(`Imported ${data.imported} rules, skipped ${data.skipped}`);
      if (data.errors.length > 0) {
        data.errors.forEach(err => toast.warning(err));
      }
      queryClient.invalidateQueries({ queryKey: ['yara'] });
      setShowImportModal(false);
      setImportContent('');
    },
    onError: () => toast.error('Failed to import rules'),
  });

  return (
    <div className="space-y-6">
      {/* Actions Bar */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowImportModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg"
        >
          <Upload className="h-4 w-4" />
          Import Rules
        </button>
      </div>

      {/* Community Sources */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-white mb-4">Community Sources</h3>
        {isLoading ? (
          <div className="flex justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
          </div>
        ) : sources && sources.length > 0 ? (
          <div className="grid gap-4">
            {sources.map(source => (
              <div key={source.id} className="bg-gray-900 border border-gray-700 rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className="p-2 bg-cyan-500/20 rounded-lg">
                      <Globe className="h-5 w-5 text-cyan-400" />
                    </div>
                    <div>
                      <h4 className="text-white font-medium">{source.name}</h4>
                      <p className="text-gray-400 text-sm">{source.description}</p>
                      <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                        <span className="flex items-center gap-1">
                          <FileText className="h-4 w-4" />
                          {source.rules_count} rules
                        </span>
                        <span className="flex items-center gap-1">
                          <Tag className="h-4 w-4" />
                          {source.source_type}
                        </span>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => fetchMutation.mutate(source.id)}
                    disabled={fetchMutation.isPending}
                    className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 text-white rounded-lg text-sm"
                  >
                    {fetchMutation.isPending ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Download className="h-4 w-4" />
                    )}
                    Fetch
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8 text-gray-500">
            <Globe className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No community sources configured</p>
          </div>
        )}
      </div>

      {/* Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <h3 className="text-lg font-semibold text-white">Import YARA Rules</h3>
              <button onClick={() => setShowImportModal(false)} className="text-gray-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Paste YARA rules content</label>
                <textarea
                  value={importContent}
                  onChange={(e) => setImportContent(e.target.value)}
                  placeholder="rule example { strings: $a = &quot;test&quot; condition: $a }"
                  rows={12}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono text-sm"
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
                >
                  Cancel
                </button>
                <button
                  onClick={() => importMutation.mutate({ content: importContent, overwrite_existing: false })}
                  disabled={!importContent || importMutation.isPending}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-800 text-white rounded-lg"
                >
                  {importMutation.isPending ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Upload className="h-4 w-4" />
                  )}
                  Import
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Scans Tab
// ============================================================================

function ScansTab() {
  const queryClient = useQueryClient();
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedScan, setSelectedScan] = useState<YaraScan | null>(null);

  const { data: scans, isLoading } = useQuery({
    queryKey: ['yara', 'scans'],
    queryFn: yaraAPI.listScans,
    refetchInterval: 5000, // Poll every 5s for running scans
  });

  const deleteMutation = useMutation({
    mutationFn: yaraAPI.deleteScan,
    onSuccess: () => {
      toast.success('Scan deleted');
      queryClient.invalidateQueries({ queryKey: ['yara', 'scans'] });
    },
  });

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowScanModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg"
        >
          <Play className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {/* Scans List */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-cyan-400" />
        </div>
      ) : scans && scans.length > 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Files</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Matches</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {scans.map(scan => (
                <tr key={scan.id} className="hover:bg-gray-750">
                  <td className="px-4 py-3 text-white font-medium">{scan.name || 'Unnamed Scan'}</td>
                  <td className="px-4 py-3 text-gray-300 truncate max-w-xs">{scan.target_path}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-3 text-gray-300">{scan.files_scanned}</td>
                  <td className="px-4 py-3">
                    <span className={scan.matches_found > 0 ? 'text-red-400 font-semibold' : 'text-gray-400'}>
                      {scan.matches_found}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-sm">
                    {new Date(scan.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setSelectedScan(scan)}
                        className="p-1 text-gray-400 hover:text-white"
                        title="View Details"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteMutation.mutate(scan.id)}
                        className="p-1 text-gray-400 hover:text-red-400"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center py-12">
          <Search className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">No YARA scans yet</p>
          <button
            onClick={() => setShowScanModal(true)}
            className="mt-4 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg"
          >
            Start Your First Scan
          </button>
        </div>
      )}

      {/* New Scan Modal */}
      {showScanModal && (
        <NewScanModal onClose={() => setShowScanModal(false)} />
      )}

      {/* Scan Details Modal */}
      {selectedScan && (
        <ScanDetailsModal scan={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </div>
  );
}

// ============================================================================
// Modal Components
// ============================================================================

function CreateRuleModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [ruleText, setRuleText] = useState('');
  const [category, setCategory] = useState('custom');

  const createMutation = useMutation({
    mutationFn: yaraAPI.createRule,
    onSuccess: () => {
      toast.success('Rule created');
      queryClient.invalidateQueries({ queryKey: ['yara'] });
      onClose();
    },
    onError: (err: Error) => toast.error(err.message || 'Failed to create rule'),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">Create YARA Rule</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Rule Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Detect_Ransomware_LockBit"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Category</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            >
              <option value="custom">Custom</option>
              <option value="malware">Malware</option>
              <option value="ransomware">Ransomware</option>
              <option value="apt">APT</option>
              <option value="packer">Packer</option>
              <option value="webshell">Webshell</option>
              <option value="exploit">Exploit</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Rule Content</label>
            <textarea
              value={ruleText}
              onChange={(e) => setRuleText(e.target.value)}
              placeholder={`rule example {\n  strings:\n    $a = "malicious"\n  condition:\n    $a\n}`}
              rows={12}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono text-sm"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
            >
              Cancel
            </button>
            <button
              onClick={() => createMutation.mutate({ name, rule_text: ruleText, category })}
              disabled={!name || !ruleText || createMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-800 text-white rounded-lg"
            >
              {createMutation.isPending && <RefreshCw className="h-4 w-4 animate-spin" />}
              Create Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ViewRuleModal({ rule, onClose }: { rule: YaraRule; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg w-full max-w-3xl max-h-[80vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-white">{rule.name}</h3>
            <CategoryBadge category={rule.category} />
            {rule.is_builtin && <span className="text-xs px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">Built-in</span>}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4 overflow-y-auto max-h-[60vh]">
          {rule.description && (
            <div>
              <label className="block text-sm text-gray-400 mb-1">Description</label>
              <p className="text-gray-300">{rule.description}</p>
            </div>
          )}
          <div className="flex items-center gap-4 text-sm">
            <span className="text-gray-400">Match Count: <span className="text-white">{rule.match_count}</span></span>
            <span className="text-gray-400">Created: <span className="text-white">{new Date(rule.created_at).toLocaleDateString()}</span></span>
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm text-gray-400">Rule Content</label>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(rule.rule_text);
                  toast.success('Copied to clipboard');
                }}
                className="flex items-center gap-1 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs"
              >
                <Copy className="h-3 w-3" /> Copy
              </button>
            </div>
            <pre className="bg-gray-900 p-4 rounded-lg overflow-x-auto text-sm text-gray-300 font-mono">
              {rule.rule_text}
            </pre>
          </div>
          {rule.tags && rule.tags.length > 0 && (
            <div>
              <label className="block text-sm text-gray-400 mb-1">Tags</label>
              <div className="flex flex-wrap gap-2">
                {rule.tags.map(tag => (
                  <span key={tag} className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-sm">{tag}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function NewScanModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState('');
  const [recursive, setRecursive] = useState(true);

  const scanMutation = useMutation({
    mutationFn: yaraAPI.scanPath,
    onSuccess: () => {
      toast.success('Scan started');
      queryClient.invalidateQueries({ queryKey: ['yara', 'scans'] });
      onClose();
    },
    onError: (err: Error) => toast.error(err.message || 'Failed to start scan'),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h3 className="text-lg font-semibold text-white">New YARA Scan</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Target Path</label>
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/path/to/scan"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
            />
          </div>
          <label className="flex items-center gap-2 text-gray-300">
            <input
              type="checkbox"
              checked={recursive}
              onChange={(e) => setRecursive(e.target.checked)}
              className="rounded border-gray-600"
            />
            Scan recursively
          </label>
          <div className="flex justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
            >
              Cancel
            </button>
            <button
              onClick={() => scanMutation.mutate({ path, recursive })}
              disabled={!path || scanMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-800 text-white rounded-lg"
            >
              {scanMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              Start Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ScanDetailsModal({ scan, onClose }: { scan: YaraScan; onClose: () => void }) {
  const { data: scanDetails, isLoading } = useQuery({
    queryKey: ['yara', 'scan', scan.id],
    queryFn: () => yaraAPI.getScan(scan.id),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg w-full max-w-3xl max-h-[80vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-white">{scan.name || 'Scan Details'}</h3>
            <StatusBadge status={scan.status} />
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4 overflow-y-auto max-h-[60vh]">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Target:</span>
              <p className="text-white">{scan.target_path}</p>
            </div>
            <div>
              <span className="text-gray-400">Rules Used:</span>
              <p className="text-white">{scan.rules_used}</p>
            </div>
            <div>
              <span className="text-gray-400">Files Scanned:</span>
              <p className="text-white">{scan.files_scanned}</p>
            </div>
            <div>
              <span className="text-gray-400">Matches Found:</span>
              <p className={scan.matches_found > 0 ? 'text-red-400 font-semibold' : 'text-white'}>{scan.matches_found}</p>
            </div>
          </div>

          {scan.error_message && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <p className="text-red-400 text-sm">{scan.error_message}</p>
            </div>
          )}

          {isLoading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
            </div>
          ) : scanDetails?.matches && scanDetails.matches.length > 0 ? (
            <div>
              <h4 className="text-white font-medium mb-3">Matches</h4>
              <div className="space-y-2">
                {scanDetails.matches.map((match, i) => (
                  <div key={i} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-cyan-400 font-medium">{match.rule_name}</span>
                      <span className="text-gray-400 text-xs">
                        {new Date(match.matched_at).toLocaleString()}
                      </span>
                    </div>
                    {match.file_path && (
                      <p className="text-gray-300 text-sm truncate">{match.file_path}</p>
                    )}
                    {match.matched_strings && match.matched_strings.length > 0 && (
                      <div className="mt-2">
                        <span className="text-gray-400 text-xs">Matched Strings:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {match.matched_strings.map((s, j) => (
                            <span key={j} className="px-1.5 py-0.5 bg-gray-800 text-gray-300 rounded text-xs font-mono">
                              {s}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No matches found</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function YaraPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 className="h-4 w-4" /> },
    { id: 'rules', label: 'Rules', icon: <FileText className="h-4 w-4" /> },
    { id: 'builder', label: 'Visual Builder', icon: <Code className="h-4 w-4" /> },
    { id: 'community', label: 'Community', icon: <Globe className="h-4 w-4" /> },
    { id: 'scans', label: 'Scans', icon: <Search className="h-4 w-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-lg">
              <Shield className="h-6 w-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">YARA Rule Management</h1>
              <p className="text-gray-400">Create, manage, and scan with YARA detection rules</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <div className="flex gap-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'dashboard' && <DashboardTab />}
          {activeTab === 'rules' && <RulesTab />}
          {activeTab === 'builder' && <BuilderTab />}
          {activeTab === 'community' && <CommunityTab />}
          {activeTab === 'scans' && <ScansTab />}
        </div>
      </div>
    </Layout>
  );
}
