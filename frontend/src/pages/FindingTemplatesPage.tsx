import React, { useState, useEffect, useCallback } from 'react';
import Layout from '../components/layout/Layout';
import { findingTemplatesAPI } from '../services/api';
import type {
  FindingTemplate,
  FindingTemplateCategory,
  EvidencePlaceholder,
  ComplianceMapping,
  CreateFindingTemplateRequest,
  UpdateFindingTemplateRequest,
} from '../types';
import { toast } from 'react-toastify';
import {
  FileText,
  Search,
  Plus,
  Edit2,
  Trash2,
  Copy,
  Download,
  Upload,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Shield,
  Target,
  Filter,
  Star,
  X,
  Check,
} from 'lucide-react';

// Severity badge colors
const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

// OWASP Top 10 2021 categories
const owaspCategories = [
  { id: 'A01:2021', name: 'Broken Access Control' },
  { id: 'A02:2021', name: 'Cryptographic Failures' },
  { id: 'A03:2021', name: 'Injection' },
  { id: 'A04:2021', name: 'Insecure Design' },
  { id: 'A05:2021', name: 'Security Misconfiguration' },
  { id: 'A06:2021', name: 'Vulnerable Components' },
  { id: 'A07:2021', name: 'Authentication Failures' },
  { id: 'A08:2021', name: 'Software and Data Integrity Failures' },
  { id: 'A09:2021', name: 'Security Logging and Monitoring Failures' },
  { id: 'A10:2021', name: 'Server-Side Request Forgery' },
];

const FindingTemplatesPage: React.FC = () => {
  const [templates, setTemplates] = useState<FindingTemplate[]>([]);
  const [categories, setCategories] = useState<FindingTemplateCategory[]>([]);
  const [popularTemplates, setPopularTemplates] = useState<FindingTemplate[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedOwasp, setSelectedOwasp] = useState<string>('');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<FindingTemplate | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [exportSelection, setExportSelection] = useState<string[]>([]);
  const [isExporting, setIsExporting] = useState(false);

  // Editor state
  const [editingTemplate, setEditingTemplate] = useState<Partial<CreateFindingTemplateRequest> | null>(null);
  const [isEditMode, setIsEditMode] = useState(false);

  // Load data on mount
  useEffect(() => {
    loadData();
  }, []);

  // Search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery || selectedCategory || selectedSeverity || selectedOwasp) {
        searchTemplates();
      } else {
        loadTemplates();
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, selectedCategory, selectedSeverity, selectedOwasp]);

  const loadData = async () => {
    setIsLoading(true);
    try {
      await Promise.all([
        loadTemplates(),
        loadCategories(),
        loadPopularTemplates(),
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const loadTemplates = async () => {
    try {
      const response = await findingTemplatesAPI.list({ include_system: true });
      setTemplates(response.data);
    } catch (error) {
      console.error('Failed to load templates:', error);
      toast.error('Failed to load finding templates');
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

  const loadPopularTemplates = async () => {
    try {
      const response = await findingTemplatesAPI.getPopular(5);
      setPopularTemplates(response.data);
    } catch (error) {
      console.error('Failed to load popular templates:', error);
    }
  };

  const searchTemplates = async () => {
    setIsLoading(true);
    try {
      const response = await findingTemplatesAPI.search({
        query: searchQuery || undefined,
        category: selectedCategory || undefined,
        severity: selectedSeverity || undefined,
        owasp: selectedOwasp || undefined,
      });
      setTemplates(response.data);
    } catch (error) {
      console.error('Failed to search templates:', error);
      toast.error('Failed to search templates');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingTemplate({
      category: '',
      title: '',
      severity: 'medium',
      description: '',
      impact: '',
      remediation: '',
      references: [],
      cwe_ids: [],
      tags: [],
    });
    setIsEditMode(false);
    setShowEditor(true);
  };

  const handleEdit = (template: FindingTemplate) => {
    setEditingTemplate({
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
      testing_steps: template.testing_steps || '',
      owasp_category: template.owasp_category || '',
      mitre_attack_ids: template.mitre_attack_ids ? JSON.parse(template.mitre_attack_ids) : [],
    });
    setSelectedTemplate(template);
    setIsEditMode(true);
    setShowEditor(true);
  };

  const handleSave = async () => {
    if (!editingTemplate?.title || !editingTemplate?.category || !editingTemplate?.description) {
      toast.error('Please fill in required fields: Title, Category, and Description');
      return;
    }

    setIsLoading(true);
    try {
      if (isEditMode && selectedTemplate) {
        await findingTemplatesAPI.update(selectedTemplate.id, editingTemplate as UpdateFindingTemplateRequest);
        toast.success('Template updated successfully');
      } else {
        await findingTemplatesAPI.create(editingTemplate as CreateFindingTemplateRequest);
        toast.success('Template created successfully');
      }
      setShowEditor(false);
      setEditingTemplate(null);
      setSelectedTemplate(null);
      await loadData();
    } catch (error) {
      console.error('Failed to save template:', error);
      toast.error('Failed to save template');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (template: FindingTemplate) => {
    if (template.is_system) {
      toast.error('Cannot delete system templates');
      return;
    }

    if (!confirm(`Are you sure you want to delete "${template.title}"?`)) {
      return;
    }

    try {
      await findingTemplatesAPI.delete(template.id);
      toast.success('Template deleted successfully');
      await loadData();
    } catch (error) {
      console.error('Failed to delete template:', error);
      toast.error('Failed to delete template');
    }
  };

  const handleClone = async (template: FindingTemplate) => {
    try {
      await findingTemplatesAPI.clone(template.id, {
        new_title: `${template.title} (Copy)`,
      });
      toast.success('Template cloned successfully');
      await loadData();
    } catch (error) {
      console.error('Failed to clone template:', error);
      toast.error('Failed to clone template');
    }
  };

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const response = await findingTemplatesAPI.exportTemplates(
        exportSelection.length > 0 ? exportSelection : undefined
      );
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `finding-templates-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success('Templates exported successfully');
      setExportSelection([]);
    } catch (error) {
      console.error('Failed to export templates:', error);
      toast.error('Failed to export templates');
    } finally {
      setIsExporting(false);
    }
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const templates = JSON.parse(text);
      const response = await findingTemplatesAPI.importTemplates({
        templates: Array.isArray(templates) ? templates : [templates],
        overwrite_existing: false,
      });
      toast.success(`Imported ${response.data.imported} templates (${response.data.skipped} skipped)`);
      if (response.data.errors.length > 0) {
        response.data.errors.forEach(err => toast.warning(err));
      }
      setShowImportDialog(false);
      await loadData();
    } catch (error) {
      console.error('Failed to import templates:', error);
      toast.error('Failed to import templates. Please check the file format.');
    }
  };

  const toggleExportSelection = (templateId: string) => {
    setExportSelection(prev =>
      prev.includes(templateId)
        ? prev.filter(id => id !== templateId)
        : [...prev, templateId]
    );
  };

  const clearFilters = () => {
    setSearchQuery('');
    setSelectedCategory('');
    setSelectedSeverity('');
    setSelectedOwasp('');
  };

  const parseEvidencePlaceholders = (template: FindingTemplate): EvidencePlaceholder[] => {
    if (!template.evidence_placeholders) return [];
    try {
      return JSON.parse(template.evidence_placeholders);
    } catch {
      return [];
    }
  };

  const parseComplianceMappings = (template: FindingTemplate): ComplianceMapping => {
    if (!template.compliance_mappings) return {};
    try {
      return JSON.parse(template.compliance_mappings);
    } catch {
      return {};
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <FileText className="h-6 w-6 text-cyan-400" />
              Finding Templates
            </h1>
            <p className="text-gray-400 mt-1">
              Reusable vulnerability templates with evidence placeholders and compliance mappings
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowImportDialog(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
            >
              <Upload className="h-4 w-4" />
              Import
            </button>
            <button
              onClick={handleExport}
              disabled={isExporting}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 disabled:opacity-50"
            >
              <Download className="h-4 w-4" />
              Export{exportSelection.length > 0 ? ` (${exportSelection.length})` : ''}
            </button>
            <button
              onClick={handleCreate}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500"
            >
              <Plus className="h-4 w-4" />
              New Template
            </button>
          </div>
        </div>

        {/* Popular Templates */}
        {popularTemplates.length > 0 && !searchQuery && !selectedCategory && !selectedSeverity && !selectedOwasp && (
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <h2 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
              <Star className="h-4 w-4 text-yellow-400" />
              Popular Templates
            </h2>
            <div className="flex flex-wrap gap-2">
              {popularTemplates.map(template => (
                <button
                  key={template.id}
                  onClick={() => setSelectedTemplate(template)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 text-sm"
                >
                  <span className={`inline-block w-2 h-2 rounded-full ${
                    template.severity === 'critical' ? 'bg-red-500' :
                    template.severity === 'high' ? 'bg-orange-500' :
                    template.severity === 'medium' ? 'bg-yellow-500' :
                    template.severity === 'low' ? 'bg-blue-500' : 'bg-gray-500'
                  }`} />
                  {template.title}
                  <span className="text-gray-500 text-xs">({template.use_count || 0})</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Search and Filters */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Search */}
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-500" />
              <input
                type="text"
                placeholder="Search templates..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
              />
            </div>

            {/* Filter toggle */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg border ${
                showFilters || selectedCategory || selectedSeverity || selectedOwasp
                  ? 'bg-cyan-600/20 text-cyan-400 border-cyan-500/30'
                  : 'bg-gray-700 text-gray-300 border-gray-600'
              }`}
            >
              <Filter className="h-4 w-4" />
              Filters
              {(selectedCategory || selectedSeverity || selectedOwasp) && (
                <span className="bg-cyan-500 text-white text-xs px-1.5 py-0.5 rounded-full">
                  {[selectedCategory, selectedSeverity, selectedOwasp].filter(Boolean).length}
                </span>
              )}
            </button>
          </div>

          {/* Filter dropdowns */}
          {showFilters && (
            <div className="mt-4 flex flex-wrap gap-4 pt-4 border-t border-gray-700">
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
              >
                <option value="">All Categories</option>
                {categories.map(cat => (
                  <option key={cat.category} value={cat.category}>
                    {cat.category} ({cat.count})
                  </option>
                ))}
              </select>

              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>

              <select
                value={selectedOwasp}
                onChange={(e) => setSelectedOwasp(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
              >
                <option value="">All OWASP Categories</option>
                {owaspCategories.map(cat => (
                  <option key={cat.id} value={cat.id}>
                    {cat.id} - {cat.name}
                  </option>
                ))}
              </select>

              {(selectedCategory || selectedSeverity || selectedOwasp) && (
                <button
                  onClick={clearFilters}
                  className="flex items-center gap-1 px-3 py-2 text-gray-400 hover:text-white"
                >
                  <X className="h-4 w-4" />
                  Clear
                </button>
              )}
            </div>
          )}
        </div>

        {/* Templates Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {isLoading ? (
            <div className="col-span-full flex justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400" />
            </div>
          ) : templates.length === 0 ? (
            <div className="col-span-full text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
              <FileText className="h-12 w-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No templates found</p>
              <button
                onClick={handleCreate}
                className="mt-4 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500"
              >
                Create your first template
              </button>
            </div>
          ) : (
            templates.map(template => (
              <div
                key={template.id}
                className={`bg-gray-800 rounded-lg border ${
                  selectedTemplate?.id === template.id
                    ? 'border-cyan-500'
                    : 'border-gray-700'
                } hover:border-gray-600 transition-colors cursor-pointer`}
                onClick={() => setSelectedTemplate(template)}
              >
                <div className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        {template.is_system && (
                          <span title="System Template">
                            <Shield className="h-4 w-4 text-cyan-400" />
                          </span>
                        )}
                        <h3 className="font-medium text-white truncate">{template.title}</h3>
                      </div>
                      <p className="text-sm text-gray-400 mt-1">{template.category}</p>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded-full border ${severityColors[template.severity] || severityColors.info}`}>
                      {template.severity}
                    </span>
                  </div>

                  <p className="text-sm text-gray-400 line-clamp-2 mb-3">
                    {template.description}
                  </p>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1 mb-3">
                    {template.owasp_category && (
                      <span className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded">
                        {template.owasp_category}
                      </span>
                    )}
                    {template.cwe_ids && JSON.parse(template.cwe_ids).slice(0, 2).map((cwe: number) => (
                      <span key={cwe} className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded">
                        CWE-{cwe}
                      </span>
                    ))}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-between pt-3 border-t border-gray-700">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={exportSelection.includes(template.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          toggleExportSelection(template.id);
                        }}
                        className="rounded border-gray-600 bg-gray-700 text-cyan-600 focus:ring-cyan-500"
                      />
                      <span className="text-xs text-gray-500">
                        Used {template.use_count || 0} times
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleClone(template);
                        }}
                        className="p-1.5 text-gray-400 hover:text-cyan-400"
                        title="Clone"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                      {!template.is_system && (
                        <>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleEdit(template);
                            }}
                            className="p-1.5 text-gray-400 hover:text-cyan-400"
                            title="Edit"
                          >
                            <Edit2 className="h-4 w-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDelete(template);
                            }}
                            className="p-1.5 text-gray-400 hover:text-red-400"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Template Detail Panel */}
        {selectedTemplate && !showEditor && (
          <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-gray-900 border-l border-gray-700 shadow-xl z-50 overflow-y-auto">
            <div className="sticky top-0 bg-gray-900 p-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">{selectedTemplate.title}</h2>
              <button
                onClick={() => setSelectedTemplate(null)}
                className="p-2 text-gray-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Header info */}
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 text-sm rounded-full border ${severityColors[selectedTemplate.severity]}`}>
                  {selectedTemplate.severity}
                </span>
                <span className="text-gray-400">{selectedTemplate.category}</span>
                {selectedTemplate.is_system && (
                  <span className="flex items-center gap-1 text-cyan-400 text-sm">
                    <Shield className="h-4 w-4" />
                    System Template
                  </span>
                )}
              </div>

              {/* Description */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Description</h3>
                <p className="text-white whitespace-pre-wrap">{selectedTemplate.description}</p>
              </div>

              {/* Impact */}
              {selectedTemplate.impact && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Impact</h3>
                  <p className="text-white whitespace-pre-wrap">{selectedTemplate.impact}</p>
                </div>
              )}

              {/* Remediation */}
              {selectedTemplate.remediation && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Remediation</h3>
                  <p className="text-white whitespace-pre-wrap">{selectedTemplate.remediation}</p>
                </div>
              )}

              {/* Testing Steps */}
              {selectedTemplate.testing_steps && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Testing Steps</h3>
                  <p className="text-white whitespace-pre-wrap">{selectedTemplate.testing_steps}</p>
                </div>
              )}

              {/* Evidence Placeholders */}
              {parseEvidencePlaceholders(selectedTemplate).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Evidence Placeholders</h3>
                  <div className="space-y-2">
                    {parseEvidencePlaceholders(selectedTemplate).map((ep) => (
                      <div key={ep.id} className="bg-gray-800 rounded p-3 border border-gray-700">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-white">{ep.label}</span>
                          <span className="text-xs text-gray-400">{ep.placeholder_type}</span>
                        </div>
                        {ep.description && (
                          <p className="text-sm text-gray-400 mt-1">{ep.description}</p>
                        )}
                        {ep.required && (
                          <span className="text-xs text-red-400">Required</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* CVSS Score */}
              {selectedTemplate.cvss_score && (
                <div className="flex items-center gap-4">
                  <div>
                    <h3 className="text-sm font-medium text-gray-400">CVSS Score</h3>
                    <span className={`text-2xl font-bold ${
                      selectedTemplate.cvss_score >= 9.0 ? 'text-red-400' :
                      selectedTemplate.cvss_score >= 7.0 ? 'text-orange-400' :
                      selectedTemplate.cvss_score >= 4.0 ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      {selectedTemplate.cvss_score}
                    </span>
                  </div>
                  {selectedTemplate.cvss_vector && (
                    <div className="flex-1">
                      <h3 className="text-sm font-medium text-gray-400">CVSS Vector</h3>
                      <code className="text-xs text-gray-300 bg-gray-800 px-2 py-1 rounded">
                        {selectedTemplate.cvss_vector}
                      </code>
                    </div>
                  )}
                </div>
              )}

              {/* Compliance Mappings */}
              {Object.keys(parseComplianceMappings(selectedTemplate)).length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Compliance Mappings</h3>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(parseComplianceMappings(selectedTemplate)).map(([framework, controls]) => (
                      <div key={framework} className="bg-gray-800 rounded px-3 py-2 border border-gray-700">
                        <span className="text-xs text-gray-400 uppercase">{framework.replace('_', ' ')}</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(controls as string[]).map((ctrl: string) => (
                            <span key={ctrl} className="text-xs text-cyan-400">{ctrl}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* CWE IDs */}
              {selectedTemplate.cwe_ids && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">CWE References</h3>
                  <div className="flex flex-wrap gap-2">
                    {JSON.parse(selectedTemplate.cwe_ids).map((cwe: number) => (
                      <a
                        key={cwe}
                        href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-1 text-sm bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30"
                      >
                        CWE-{cwe}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {selectedTemplate.mitre_attack_ids && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK Techniques</h3>
                  <div className="flex flex-wrap gap-2">
                    {JSON.parse(selectedTemplate.mitre_attack_ids).map((technique: string) => (
                      <a
                        key={technique}
                        href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-2 py-1 text-sm bg-red-500/20 text-red-400 rounded hover:bg-red-500/30"
                      >
                        {technique}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {selectedTemplate.references && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">References</h3>
                  <ul className="space-y-1">
                    {JSON.parse(selectedTemplate.references).map((ref: string, idx: number) => (
                      <li key={idx}>
                        <a
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline text-sm break-all"
                        >
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-2 pt-4 border-t border-gray-700">
                <button
                  onClick={() => handleClone(selectedTemplate)}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600"
                >
                  <Copy className="h-4 w-4" />
                  Clone Template
                </button>
                {!selectedTemplate.is_system && (
                  <button
                    onClick={() => handleEdit(selectedTemplate)}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500"
                  >
                    <Edit2 className="h-4 w-4" />
                    Edit Template
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Template Editor Modal */}
        {showEditor && editingTemplate && (
          <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div className="bg-gray-900 rounded-xl border border-gray-700 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-gray-900 p-4 border-b border-gray-700 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">
                  {isEditMode ? 'Edit Template' : 'Create Template'}
                </h2>
                <button
                  onClick={() => {
                    setShowEditor(false);
                    setEditingTemplate(null);
                  }}
                  className="p-2 text-gray-400 hover:text-white"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="p-6 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">Title *</label>
                    <input
                      type="text"
                      value={editingTemplate.title || ''}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, title: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                      placeholder="e.g., SQL Injection in Login Form"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">Category *</label>
                    <input
                      type="text"
                      value={editingTemplate.category || ''}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, category: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                      placeholder="e.g., Web Application"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">Severity *</label>
                    <select
                      value={editingTemplate.severity || 'medium'}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, severity: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">OWASP Category</label>
                    <select
                      value={editingTemplate.owasp_category || ''}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, owasp_category: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    >
                      <option value="">Select OWASP Category</option>
                      {owaspCategories.map(cat => (
                        <option key={cat.id} value={cat.id}>
                          {cat.id} - {cat.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Description *</label>
                  <textarea
                    value={editingTemplate.description || ''}
                    onChange={(e) => setEditingTemplate({ ...editingTemplate, description: e.target.value })}
                    rows={4}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    placeholder="Detailed description of the vulnerability..."
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Impact</label>
                  <textarea
                    value={editingTemplate.impact || ''}
                    onChange={(e) => setEditingTemplate({ ...editingTemplate, impact: e.target.value })}
                    rows={3}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    placeholder="What is the potential impact of this vulnerability..."
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Remediation</label>
                  <textarea
                    value={editingTemplate.remediation || ''}
                    onChange={(e) => setEditingTemplate({ ...editingTemplate, remediation: e.target.value })}
                    rows={3}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    placeholder="Steps to fix this vulnerability..."
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Testing Steps</label>
                  <textarea
                    value={editingTemplate.testing_steps || ''}
                    onChange={(e) => setEditingTemplate({ ...editingTemplate, testing_steps: e.target.value })}
                    rows={3}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                    placeholder="Step-by-step testing methodology..."
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">CVSS Vector</label>
                    <input
                      type="text"
                      value={editingTemplate.cvss_vector || ''}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, cvss_vector: e.target.value })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                      placeholder="CVSS:3.1/AV:N/AC:L/..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-400 mb-1">CVSS Score</label>
                    <input
                      type="number"
                      min="0"
                      max="10"
                      step="0.1"
                      value={editingTemplate.cvss_score || ''}
                      onChange={(e) => setEditingTemplate({ ...editingTemplate, cvss_score: parseFloat(e.target.value) || undefined })}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
                      placeholder="0.0 - 10.0"
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                  <button
                    onClick={() => {
                      setShowEditor(false);
                      setEditingTemplate(null);
                    }}
                    className="px-4 py-2 text-gray-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={isLoading}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500 disabled:opacity-50"
                  >
                    <Check className="h-4 w-4" />
                    {isEditMode ? 'Update Template' : 'Create Template'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Import Dialog */}
        {showImportDialog && (
          <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div className="bg-gray-900 rounded-xl border border-gray-700 w-full max-w-md p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Import Templates</h2>
              <p className="text-gray-400 mb-4">
                Upload a JSON file containing finding templates to import.
              </p>
              <input
                type="file"
                accept=".json"
                onChange={handleImport}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
              />
              <div className="flex justify-end gap-3 mt-4">
                <button
                  onClick={() => setShowImportDialog(false)}
                  className="px-4 py-2 text-gray-400 hover:text-white"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default FindingTemplatesPage;
