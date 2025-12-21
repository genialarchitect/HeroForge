import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Plus,
  Edit2,
  Trash2,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  Code,
  X,
  Save,
  Lock,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { iacAPI } from '../../services/api';
import type { IacRule, CreateIacRuleRequest, UpdateIacRuleRequest } from '../../types';
import Button from '../ui/Button';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];

const CATEGORY_OPTIONS = [
  { value: 'hardcoded_secret', label: 'Hardcoded Secret' },
  { value: 'iam_misconfiguration', label: 'IAM Misconfiguration' },
  { value: 'public_storage', label: 'Public Storage' },
  { value: 'missing_encryption', label: 'Missing Encryption' },
  { value: 'missing_logging', label: 'Missing Logging' },
  { value: 'network_exposure', label: 'Network Exposure' },
  { value: 'missing_tags', label: 'Missing Tags' },
  { value: 'deprecated_resource', label: 'Deprecated Resource' },
  { value: 'weak_cryptography', label: 'Weak Cryptography' },
  { value: 'insecure_default', label: 'Insecure Default' },
  { value: 'compliance_violation', label: 'Compliance Violation' },
  { value: 'best_practice', label: 'Best Practice' },
];

const PLATFORM_OPTIONS = ['Terraform', 'CloudFormation', 'AzureArm'];
const PROVIDER_OPTIONS = ['Aws', 'Azure', 'Gcp'];

const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500/20 text-red-400';
    case 'high':
      return 'bg-orange-500/20 text-orange-400';
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400';
    case 'low':
      return 'bg-blue-500/20 text-blue-400';
    case 'info':
      return 'bg-gray-500/20 text-gray-400';
    default:
      return 'bg-gray-500/20 text-gray-400';
  }
};

interface RuleFormData {
  name: string;
  description: string;
  severity: string;
  category: string;
  platforms: string[];
  providers: string[];
  pattern: string;
  pattern_type: string;
  remediation: string;
  documentation_url: string;
}

const emptyFormData: RuleFormData = {
  name: '',
  description: '',
  severity: 'medium',
  category: 'best_practice',
  platforms: [],
  providers: [],
  pattern: '',
  pattern_type: 'regex',
  remediation: '',
  documentation_url: '',
};

export default function IacRulesManager() {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [showBuiltin, setShowBuiltin] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [editingRule, setEditingRule] = useState<IacRule | null>(null);
  const [formData, setFormData] = useState<RuleFormData>(emptyFormData);

  // Fetch rules
  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['iac-rules'],
    queryFn: async () => {
      const response = await iacAPI.listRules();
      return response.data;
    },
  });

  // Create rule mutation
  const createMutation = useMutation({
    mutationFn: (data: CreateIacRuleRequest) => iacAPI.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iac-rules'] });
      toast.success('Rule created successfully');
      closeEditor();
    },
    onError: (error: Error) => {
      toast.error(`Failed to create rule: ${error.message}`);
    },
  });

  // Update rule mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateIacRuleRequest }) =>
      iacAPI.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iac-rules'] });
      toast.success('Rule updated successfully');
      closeEditor();
    },
    onError: (error: Error) => {
      toast.error(`Failed to update rule: ${error.message}`);
    },
  });

  // Delete rule mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => iacAPI.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iac-rules'] });
      toast.success('Rule deleted successfully');
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete rule: ${error.message}`);
    },
  });

  // Filter rules
  const filteredRules = rules.filter((rule) => {
    if (!showBuiltin && rule.is_builtin) return false;
    if (filterSeverity !== 'all' && rule.severity !== filterSeverity) return false;
    if (filterCategory !== 'all' && rule.category !== filterCategory) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        rule.name.toLowerCase().includes(query) ||
        rule.description.toLowerCase().includes(query)
      );
    }
    return true;
  });

  const openEditor = (rule?: IacRule) => {
    if (rule) {
      setEditingRule(rule);
      setFormData({
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        category: rule.category,
        platforms: rule.platforms,
        providers: rule.providers,
        pattern: rule.pattern,
        pattern_type: rule.pattern_type,
        remediation: rule.remediation,
        documentation_url: rule.documentation_url || '',
      });
    } else {
      setEditingRule(null);
      setFormData(emptyFormData);
    }
    setIsEditing(true);
  };

  const closeEditor = () => {
    setIsEditing(false);
    setEditingRule(null);
    setFormData(emptyFormData);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const data: CreateIacRuleRequest = {
      name: formData.name,
      description: formData.description,
      severity: formData.severity,
      category: formData.category,
      platforms: formData.platforms,
      providers: formData.providers,
      pattern: formData.pattern,
      pattern_type: formData.pattern_type,
      remediation: formData.remediation,
      documentation_url: formData.documentation_url || undefined,
    };

    if (editingRule) {
      updateMutation.mutate({
        id: editingRule.id,
        data: {
          name: formData.name,
          description: formData.description,
          severity: formData.severity,
          category: formData.category,
          pattern: formData.pattern,
          remediation: formData.remediation,
        },
      });
    } else {
      createMutation.mutate(data);
    }
  };

  const handleDelete = (rule: IacRule) => {
    if (confirm(`Are you sure you want to delete the rule "${rule.name}"?`)) {
      deleteMutation.mutate(rule.id);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Security Rules</h2>
          <p className="text-sm text-gray-400 mt-1">
            Manage IaC security scanning rules
          </p>
        </div>
        <Button onClick={() => openEditor()}>
          <Plus className="w-4 h-4 mr-2" />
          New Rule
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules..."
            className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white"
        >
          <option value="all">All Severities</option>
          {SEVERITY_OPTIONS.map((sev) => (
            <option key={sev} value={sev}>
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </option>
          ))}
        </select>

        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white"
        >
          <option value="all">All Categories</option>
          {CATEGORY_OPTIONS.map((cat) => (
            <option key={cat.value} value={cat.value}>
              {cat.label}
            </option>
          ))}
        </select>

        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={showBuiltin}
            onChange={(e) => setShowBuiltin(e.target.checked)}
            className="rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
          />
          Show built-in rules
        </label>
      </div>

      {/* Rules List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
          <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">No Rules Found</h3>
          <p className="text-gray-400">
            {searchQuery || filterSeverity !== 'all' || filterCategory !== 'all'
              ? 'No rules match the current filters.'
              : 'Create your first custom rule to get started.'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {filteredRules.map((rule) => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={() => openEditor(rule)}
              onDelete={() => handleDelete(rule)}
            />
          ))}
        </div>
      )}

      {/* Rule Editor Modal */}
      {isEditing && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-auto border border-gray-700">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 className="text-lg font-semibold text-white">
                {editingRule ? 'Edit Rule' : 'Create New Rule'}
              </h3>
              <button
                onClick={closeEditor}
                className="p-1 text-gray-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Rule Name *
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    required
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Description *
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) =>
                      setFormData({ ...formData, description: e.target.value })
                    }
                    required
                    rows={2}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Severity *
                  </label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  >
                    {SEVERITY_OPTIONS.map((sev) => (
                      <option key={sev} value={sev}>
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Category *
                  </label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  >
                    {CATEGORY_OPTIONS.map((cat) => (
                      <option key={cat.value} value={cat.value}>
                        {cat.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Platforms
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {PLATFORM_OPTIONS.map((platform) => (
                      <label key={platform} className="flex items-center gap-1">
                        <input
                          type="checkbox"
                          checked={formData.platforms.includes(platform)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setFormData({
                                ...formData,
                                platforms: [...formData.platforms, platform],
                              });
                            } else {
                              setFormData({
                                ...formData,
                                platforms: formData.platforms.filter((p) => p !== platform),
                              });
                            }
                          }}
                          className="rounded border-gray-600 bg-gray-700 text-cyan-500"
                        />
                        <span className="text-sm text-gray-300">{platform}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Providers
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {PROVIDER_OPTIONS.map((provider) => (
                      <label key={provider} className="flex items-center gap-1">
                        <input
                          type="checkbox"
                          checked={formData.providers.includes(provider)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setFormData({
                                ...formData,
                                providers: [...formData.providers, provider],
                              });
                            } else {
                              setFormData({
                                ...formData,
                                providers: formData.providers.filter((p) => p !== provider),
                              });
                            }
                          }}
                          className="rounded border-gray-600 bg-gray-700 text-cyan-500"
                        />
                        <span className="text-sm text-gray-300">{provider}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Detection Pattern (Regex) *
                  </label>
                  <input
                    type="text"
                    value={formData.pattern}
                    onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                    required
                    placeholder={"(?i)password\\s*=\\s*['\"][^'\"]+['\"]"}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Regular expression to match security issues in IaC files
                  </p>
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Remediation *
                  </label>
                  <textarea
                    value={formData.remediation}
                    onChange={(e) =>
                      setFormData({ ...formData, remediation: e.target.value })
                    }
                    required
                    rows={3}
                    placeholder="Describe how to fix this security issue..."
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  />
                </div>

                <div className="col-span-2">
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Documentation URL (optional)
                  </label>
                  <input
                    type="url"
                    value={formData.documentation_url}
                    onChange={(e) =>
                      setFormData({ ...formData, documentation_url: e.target.value })
                    }
                    placeholder="https://example.com/security-best-practices"
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                <Button type="button" variant="outline" onClick={closeEditor}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                >
                  {createMutation.isPending || updateMutation.isPending ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4 mr-2" />
                      {editingRule ? 'Update Rule' : 'Create Rule'}
                    </>
                  )}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function RuleCard({
  rule,
  onEdit,
  onDelete,
}: {
  rule: IacRule;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const categoryLabel =
    CATEGORY_OPTIONS.find((c) => c.value === rule.category)?.label || rule.category;

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className={`text-xs px-2 py-0.5 rounded ${getSeverityColor(rule.severity)}`}>
              {rule.severity.toUpperCase()}
            </span>
            <span className="text-xs text-gray-500">{categoryLabel}</span>
            {rule.is_builtin && (
              <span className="flex items-center gap-1 text-xs text-gray-500">
                <Lock className="w-3 h-3" />
                Built-in
              </span>
            )}
          </div>
          <h3 className="font-medium text-white mt-2">{rule.name}</h3>
          <p className="text-sm text-gray-400 mt-1">{rule.description}</p>
          <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
            {rule.platforms.length > 0 && (
              <span>Platforms: {rule.platforms.join(', ')}</span>
            )}
            {rule.providers.length > 0 && (
              <span>Providers: {rule.providers.join(', ')}</span>
            )}
          </div>
        </div>

        {!rule.is_builtin && (
          <div className="flex items-center gap-2">
            <button
              onClick={onEdit}
              className="p-2 text-gray-400 hover:text-white transition-colors"
              title="Edit rule"
            >
              <Edit2 className="w-4 h-4" />
            </button>
            <button
              onClick={onDelete}
              className="p-2 text-gray-400 hover:text-red-400 transition-colors"
              title="Delete rule"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
