import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { findingTemplatesAPI } from '../../services/api';
import { FindingTemplate, CreateFindingTemplateRequest, FindingTemplateCategory } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import {
  FileText, Edit2, Trash2, Save, X, Copy, Plus,
  Search, Filter, ChevronDown, BookOpen, AlertTriangle,
  Shield, Info, ExternalLink
} from 'lucide-react';

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORY_OPTIONS = ['web', 'network', 'infrastructure', 'cloud', 'api', 'mobile', 'other'];

const FindingTemplates: React.FC = () => {
  const [templates, setTemplates] = useState<FindingTemplate[]>([]);
  const [categories, setCategories] = useState<FindingTemplateCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<FindingTemplate | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<FindingTemplate | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [includeSystem, setIncludeSystem] = useState(true);

  // Form data
  const [formData, setFormData] = useState<CreateFindingTemplateRequest>({
    category: 'web',
    title: '',
    severity: 'medium',
    description: '',
    impact: '',
    remediation: '',
    references: [],
    cwe_ids: [],
    cvss_vector: '',
    cvss_score: undefined,
    tags: [],
  });

  useEffect(() => {
    loadTemplates();
    loadCategories();
  }, [filterCategory, filterSeverity, searchQuery, includeSystem]);

  const loadTemplates = async () => {
    setLoading(true);
    try {
      const response = await findingTemplatesAPI.list({
        category: filterCategory || undefined,
        severity: filterSeverity || undefined,
        search: searchQuery || undefined,
        include_system: includeSystem,
      });
      setTemplates(response.data);
    } catch (error) {
      toast.error('Failed to load finding templates');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const loadCategories = async () => {
    try {
      const response = await findingTemplatesAPI.getCategories();
      setCategories(response.data);
    } catch (error) {
      console.error('Failed to load categories:', error);
    }
  };

  const resetForm = () => {
    setFormData({
      category: 'web',
      title: '',
      severity: 'medium',
      description: '',
      impact: '',
      remediation: '',
      references: [],
      cwe_ids: [],
      cvss_vector: '',
      cvss_score: undefined,
      tags: [],
    });
    setEditingTemplate(null);
    setShowForm(false);
  };

  const handleEdit = (template: FindingTemplate) => {
    setFormData({
      category: template.category,
      title: template.title,
      severity: template.severity,
      description: template.description,
      impact: template.impact || '',
      remediation: template.remediation || '',
      references: template.references ? JSON.parse(template.references) : [],
      cwe_ids: template.cwe_ids ? JSON.parse(template.cwe_ids) : [],
      cvss_vector: template.cvss_vector || '',
      cvss_score: template.cvss_score || undefined,
      tags: template.tags ? JSON.parse(template.tags) : [],
    });
    setEditingTemplate(template);
    setShowForm(true);
  };

  const handleClone = async (template: FindingTemplate) => {
    const newTitle = prompt(`Enter name for cloned template:`, `${template.title} (Copy)`);
    if (!newTitle) return;

    try {
      await findingTemplatesAPI.clone(template.id, { new_title: newTitle });
      toast.success('Template cloned successfully');
      loadTemplates();
      loadCategories();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to clone template');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.title.trim()) {
      toast.error('Title is required');
      return;
    }

    if (!formData.description.trim()) {
      toast.error('Description is required');
      return;
    }

    setIsSaving(true);
    try {
      if (editingTemplate) {
        await findingTemplatesAPI.update(editingTemplate.id, formData);
        toast.success('Template updated successfully');
      } else {
        await findingTemplatesAPI.create(formData);
        toast.success('Template created successfully');
      }
      resetForm();
      loadTemplates();
      loadCategories();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save template');
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await findingTemplatesAPI.delete(deleteConfirm.id);
      toast.success(`Template "${deleteConfirm.title}" deleted`);
      loadTemplates();
      loadCategories();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete template');
    } finally {
      setIsDeleting(false);
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="h-4 w-4" />;
      case 'medium':
        return <Shield className="h-4 w-4" />;
      default:
        return <Info className="h-4 w-4" />;
    }
  };

  const getSeverityBadgeType = (severity: string): 'critical' | 'high' | 'medium' | 'low' => {
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'critical';
    if (sev === 'high') return 'high';
    if (sev === 'medium') return 'medium';
    // Map 'info' and 'low' to 'low' badge type
    return 'low';
  };

  const parseJsonArray = (jsonStr: string | null): string[] => {
    if (!jsonStr) return [];
    try {
      return JSON.parse(jsonStr);
    } catch {
      return [];
    }
  };

  const formatDate = (dateStr: string): string => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  if (loading && templates.length === 0) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Finding Templates</h3>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-400">
              {templates.length} template{templates.length !== 1 ? 's' : ''}
            </span>
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowForm(true)}
            >
              <Plus className="h-4 w-4 mr-1.5" />
              New Template
            </Button>
          </div>
        </div>
      </Card>

      {/* Filters */}
      <Card>
        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search templates..."
                className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>
          </div>

          {/* Category filter */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="bg-dark-bg border border-dark-border rounded-lg pl-10 pr-8 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent appearance-none cursor-pointer"
            >
              <option value="">All Categories</option>
              {categories.map((cat) => (
                <option key={cat.category} value={cat.category}>
                  {cat.category.charAt(0).toUpperCase() + cat.category.slice(1)} ({cat.count})
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
          </div>

          {/* Severity filter */}
          <div className="relative">
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent appearance-none cursor-pointer pr-8"
            >
              <option value="">All Severities</option>
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 pointer-events-none" />
          </div>

          {/* Include system toggle */}
          <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={includeSystem}
              onChange={(e) => setIncludeSystem(e.target.checked)}
              className="rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
            />
            Include system templates
          </label>
        </div>
      </Card>

      {/* Create/Edit Form */}
      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">
                {editingTemplate ? 'Edit Template' : 'New Template'}
              </h4>
              <button type="button" onClick={resetForm} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Category */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  {CATEGORY_OPTIONS.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat.charAt(0).toUpperCase() + cat.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              {/* Severity */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Severity</label>
                <select
                  value={formData.severity}
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  {SEVERITY_OPTIONS.map((sev) => (
                    <option key={sev} value={sev}>
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </option>
                  ))}
                </select>
              </div>

              {/* CVSS Score */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">CVSS Score</label>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={formData.cvss_score || ''}
                  onChange={(e) => setFormData({ ...formData, cvss_score: e.target.value ? parseFloat(e.target.value) : undefined })}
                  placeholder="0.0 - 10.0"
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>

            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Title *</label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                placeholder="e.g., SQL Injection in Login Form"
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Description *</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                rows={4}
                placeholder="Detailed description of the vulnerability..."
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            {/* Impact */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Impact</label>
              <textarea
                value={formData.impact || ''}
                onChange={(e) => setFormData({ ...formData, impact: e.target.value })}
                rows={2}
                placeholder="Potential impact if exploited..."
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            {/* Remediation */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Remediation</label>
              <textarea
                value={formData.remediation || ''}
                onChange={(e) => setFormData({ ...formData, remediation: e.target.value })}
                rows={3}
                placeholder="Recommended steps to fix..."
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* CVSS Vector */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">CVSS Vector</label>
                <input
                  type="text"
                  value={formData.cvss_vector || ''}
                  onChange={(e) => setFormData({ ...formData, cvss_vector: e.target.value })}
                  placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent font-mono text-sm"
                />
              </div>

              {/* CWE IDs */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">CWE IDs (comma-separated)</label>
                <input
                  type="text"
                  value={formData.cwe_ids?.join(', ') || ''}
                  onChange={(e) => {
                    const ids = e.target.value.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id));
                    setFormData({ ...formData, cwe_ids: ids });
                  }}
                  placeholder="e.g., 89, 564"
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>

            {/* References */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">References (one URL per line)</label>
              <textarea
                value={formData.references?.join('\n') || ''}
                onChange={(e) => {
                  const refs = e.target.value.split('\n').map(r => r.trim()).filter(r => r);
                  setFormData({ ...formData, references: refs });
                }}
                rows={2}
                placeholder="https://owasp.org/..."
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent font-mono text-sm"
              />
            </div>

            {/* Tags */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Tags (comma-separated)</label>
              <input
                type="text"
                value={formData.tags?.join(', ') || ''}
                onChange={(e) => {
                  const tags = e.target.value.split(',').map(t => t.trim()).filter(t => t);
                  setFormData({ ...formData, tags: tags });
                }}
                placeholder="e.g., owasp, web, injection"
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="secondary" onClick={resetForm}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" loading={isSaving} disabled={isSaving}>
                <Save className="h-4 w-4 mr-2" />
                {editingTemplate ? 'Update' : 'Create'}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Templates List */}
      {templates.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No finding templates found</p>
            <p className="text-sm text-slate-500 mt-1">
              {filterCategory || filterSeverity || searchQuery
                ? 'Try adjusting your filters'
                : 'Create your first template or include system templates'}
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {templates.map((template) => {
            const isExpanded = expandedId === template.id;
            const references = parseJsonArray(template.references);
            const cweIds = parseJsonArray(template.cwe_ids);
            const tags = parseJsonArray(template.tags);

            return (
              <Card key={template.id} className={isExpanded ? 'ring-1 ring-primary' : ''}>
                <div className="space-y-3">
                  {/* Header row */}
                  <div className="flex items-start justify-between">
                    <div
                      className="flex-1 cursor-pointer"
                      onClick={() => setExpandedId(isExpanded ? null : template.id)}
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant="severity" type={getSeverityBadgeType(template.severity)}>
                          {getSeverityIcon(template.severity)}
                          <span className="ml-1">{template.severity}</span>
                        </Badge>
                        <Badge variant="status" type="pending">
                          {template.category}
                        </Badge>
                        {template.is_system && (
                          <Badge variant="status" type="completed">
                            System
                          </Badge>
                        )}
                      </div>
                      <h4 className="font-semibold text-white text-lg mt-2">{template.title}</h4>
                      {!isExpanded && (
                        <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                          {template.description}
                        </p>
                      )}
                    </div>
                    <div className="flex gap-1 ml-4">
                      <button
                        onClick={() => handleClone(template)}
                        className="p-1.5 text-slate-400 hover:text-primary transition-colors"
                        title="Clone template"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                      {!template.is_system && (
                        <>
                          <button
                            onClick={() => handleEdit(template)}
                            className="p-1.5 text-slate-400 hover:text-primary transition-colors"
                            title="Edit template"
                          >
                            <Edit2 className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(template)}
                            className="p-1.5 text-slate-400 hover:text-red-400 transition-colors"
                            title="Delete template"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Expanded details */}
                  {isExpanded && (
                    <div className="border-t border-dark-border pt-4 space-y-4">
                      {/* Description */}
                      <div>
                        <h5 className="text-sm font-medium text-slate-300 mb-1">Description</h5>
                        <p className="text-sm text-slate-400 whitespace-pre-wrap">{template.description}</p>
                      </div>

                      {/* Impact */}
                      {template.impact && (
                        <div>
                          <h5 className="text-sm font-medium text-slate-300 mb-1">Impact</h5>
                          <p className="text-sm text-slate-400 whitespace-pre-wrap">{template.impact}</p>
                        </div>
                      )}

                      {/* Remediation */}
                      {template.remediation && (
                        <div>
                          <h5 className="text-sm font-medium text-slate-300 mb-1">Remediation</h5>
                          <p className="text-sm text-slate-400 whitespace-pre-wrap">{template.remediation}</p>
                        </div>
                      )}

                      {/* Metadata row */}
                      <div className="flex flex-wrap gap-4 text-sm">
                        {template.cvss_score !== null && (
                          <div>
                            <span className="text-slate-500">CVSS:</span>{' '}
                            <span className="text-white font-medium">{template.cvss_score.toFixed(1)}</span>
                          </div>
                        )}
                        {template.cvss_vector && (
                          <div>
                            <span className="text-slate-500">Vector:</span>{' '}
                            <code className="text-slate-300 text-xs">{template.cvss_vector}</code>
                          </div>
                        )}
                        {cweIds.length > 0 && (
                          <div>
                            <span className="text-slate-500">CWE:</span>{' '}
                            {cweIds.map((id, i) => (
                              <span key={id}>
                                {i > 0 && ', '}
                                <a
                                  href={`https://cwe.mitre.org/data/definitions/${id}.html`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-primary hover:underline"
                                >
                                  CWE-{id}
                                </a>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* References */}
                      {references.length > 0 && (
                        <div>
                          <h5 className="text-sm font-medium text-slate-300 mb-2">References</h5>
                          <div className="space-y-1">
                            {references.map((ref, idx) => (
                              <a
                                key={idx}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center gap-1 text-sm text-primary hover:underline"
                              >
                                <ExternalLink className="h-3 w-3" />
                                {ref}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Tags */}
                      {tags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {tags.map((tag) => (
                            <span
                              key={tag}
                              className="px-2 py-0.5 bg-dark-border rounded text-xs text-slate-300"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Footer */}
                      <div className="text-xs text-slate-500 pt-2 border-t border-dark-border">
                        Created {formatDate(template.created_at)}
                        {template.updated_at !== template.created_at && (
                          <> · Updated {formatDate(template.updated_at)}</>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Template"
        message={`Are you sure you want to delete the template "${deleteConfirm?.title}"? This action cannot be undone.`}
        confirmLabel="Delete Template"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

export default FindingTemplates;
