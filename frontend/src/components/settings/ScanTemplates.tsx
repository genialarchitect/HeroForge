import React, { useEffect, useState, useMemo } from 'react';
import { toast } from 'react-toastify';
import { templateAPI } from '../../services/api';
import { ScanTemplate, TemplateCategory, ScanTemplateConfig } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import {
  FileText, Edit2, Trash2, Save, X, PlayCircle,
  Hash, Search, Radio, Clock, Star, Copy,
  Zap, Shield, Globe, EyeOff, Settings, Lock
} from 'lucide-react';

interface TemplateFormData {
  name: string;
  description: string;
  category: TemplateCategory;
  estimated_duration_mins: number | '';
}

const CATEGORY_INFO: Record<TemplateCategory, { label: string; icon: React.ElementType; color: string }> = {
  quick: { label: 'Quick', icon: Zap, color: 'text-yellow-400' },
  standard: { label: 'Standard', icon: Settings, color: 'text-blue-400' },
  comprehensive: { label: 'Comprehensive', icon: Shield, color: 'text-purple-400' },
  web: { label: 'Web', icon: Globe, color: 'text-green-400' },
  stealth: { label: 'Stealth', icon: EyeOff, color: 'text-slate-400' },
  custom: { label: 'Custom', icon: FileText, color: 'text-cyan-400' },
};

const ScanTemplates: React.FC = () => {
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<TemplateFormData>({
    name: '',
    description: '',
    category: 'custom',
    estimated_duration_mins: '',
  });
  const [creatingScans, setCreatingScans] = useState<Set<string>>(new Set());
  const [cloningTemplates, setCloningTemplates] = useState<Set<string>>(new Set());
  const [deleteConfirm, setDeleteConfirm] = useState<ScanTemplate | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [settingDefault, setSettingDefault] = useState<string | null>(null);

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    setLoading(true);
    try {
      const response = await templateAPI.getAll();
      setTemplates(response.data);
    } catch (error) {
      toast.error('Failed to load templates');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  // Group templates by category
  const templatesByCategory = useMemo(() => {
    const groups: Record<string, ScanTemplate[]> = {};
    templates.forEach((t) => {
      const cat = t.category || 'custom';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(t);
    });
    // Sort within each category: system templates first, then by use count
    Object.keys(groups).forEach((key) => {
      groups[key].sort((a, b) => {
        if (a.is_system !== b.is_system) return a.is_system ? -1 : 1;
        if (a.is_default !== b.is_default) return a.is_default ? -1 : 1;
        return b.use_count - a.use_count;
      });
    });
    return groups;
  }, [templates]);

  // Get category order and filter
  const categories = useMemo(() => {
    const order: TemplateCategory[] = ['quick', 'standard', 'comprehensive', 'web', 'stealth', 'custom'];
    return order.filter((cat) => templatesByCategory[cat]?.length > 0);
  }, [templatesByCategory]);

  // Filter templates based on active category
  const filteredTemplates = useMemo(() => {
    if (!activeCategory) return templates;
    return templatesByCategory[activeCategory] || [];
  }, [templates, activeCategory, templatesByCategory]);

  const resetForm = () => {
    setFormData({ name: '', description: '', category: 'custom', estimated_duration_mins: '' });
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (template: ScanTemplate) => {
    if (template.is_system) {
      toast.error('System templates cannot be edited. Clone it to create your own version.');
      return;
    }
    setFormData({
      name: template.name,
      description: template.description || '',
      category: template.category,
      estimated_duration_mins: template.estimated_duration_mins || '',
    });
    setEditingId(template.id);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }

    if (!editingId) {
      toast.error('Cannot create templates from this form. Use "Save as Template" in the scan form.');
      return;
    }

    try {
      await templateAPI.update(editingId, {
        name: formData.name,
        description: formData.description || undefined,
        category: formData.category,
        estimated_duration_mins: formData.estimated_duration_mins || undefined,
      });
      toast.success('Template updated');
      resetForm();
      loadTemplates();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update template');
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await templateAPI.delete(deleteConfirm.id);
      toast.success(`Template "${deleteConfirm.name}" deleted`);
      loadTemplates();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleClone = async (template: ScanTemplate) => {
    const newName = prompt(`Enter name for the cloned template:`, `${template.name} (Copy)`);
    if (!newName) return;

    setCloningTemplates((prev) => new Set([...prev, template.id]));
    try {
      await templateAPI.clone(template.id, newName);
      toast.success('Template cloned successfully');
      loadTemplates();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to clone template');
    } finally {
      setCloningTemplates((prev) => {
        const next = new Set(prev);
        next.delete(template.id);
        return next;
      });
    }
  };

  const handleSetDefault = async (template: ScanTemplate) => {
    setSettingDefault(template.id);
    try {
      await templateAPI.setDefault(template.id);
      toast.success(`"${template.name}" set as default template`);
      loadTemplates();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to set default');
    } finally {
      setSettingDefault(null);
    }
  };

  const handleCreateScan = async (template: ScanTemplate) => {
    const scanName = prompt(
      `Enter name for new scan (based on "${template.name}"):`,
      `${template.name} - ${new Date().toLocaleDateString()}`
    );
    if (!scanName) return;

    const targetsInput = prompt('Enter target(s) to scan (comma-separated IPs or hostnames):');
    if (!targetsInput) return;

    const targets = targetsInput.split(',').map((t) => t.trim()).filter(Boolean);
    if (targets.length === 0) {
      toast.error('At least one target is required');
      return;
    }

    setCreatingScans(new Set([...creatingScans, template.id]));
    try {
      await templateAPI.createScan(template.id, scanName, targets);
      toast.success('Scan started from template!');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to create scan');
    } finally {
      setCreatingScans((prev) => {
        const next = new Set(prev);
        next.delete(template.id);
        return next;
      });
    }
  };

  const formatDuration = (mins: number | null): string => {
    if (!mins) return '-';
    if (mins < 60) return `~${mins}m`;
    const hours = Math.floor(mins / 60);
    const remaining = mins % 60;
    return remaining ? `~${hours}h ${remaining}m` : `~${hours}h`;
  };

  const formatDate = (dateStr: string): string => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const renderConfigBadges = (config: ScanTemplateConfig) => (
    <div className="flex flex-wrap gap-1.5">
      {config.enable_os_detection && (
        <Badge variant="status" type="completed">OS</Badge>
      )}
      {config.enable_service_detection && (
        <Badge variant="status" type="completed">Services</Badge>
      )}
      {config.enable_vuln_scan && (
        <Badge variant="status" type="running">Vuln Scan</Badge>
      )}
      {config.enable_enumeration && (
        <Badge variant="status" type="pending">Enum</Badge>
      )}
    </div>
  );

  if (loading) {
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
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Scan Templates</h3>
          </div>
          <div className="text-sm text-slate-400">
            Reusable scan profiles for quick configuration
          </div>
        </div>

        {/* Category Tabs */}
        {categories.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              onClick={() => setActiveCategory(null)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                activeCategory === null
                  ? 'bg-primary text-white'
                  : 'bg-dark-bg text-slate-400 hover:text-white hover:bg-slate-700'
              }`}
            >
              All ({templates.length})
            </button>
            {categories.map((cat) => {
              const info = CATEGORY_INFO[cat];
              const Icon = info.icon;
              const count = templatesByCategory[cat]?.length || 0;
              return (
                <button
                  key={cat}
                  onClick={() => setActiveCategory(cat)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5 ${
                    activeCategory === cat
                      ? 'bg-primary text-white'
                      : 'bg-dark-bg text-slate-400 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  <Icon className={`h-4 w-4 ${activeCategory === cat ? 'text-white' : info.color}`} />
                  {info.label} ({count})
                </button>
              );
            })}
          </div>
        )}
      </Card>

      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">Edit Template</h4>
              <button type="button" onClick={resetForm} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="My Custom Template"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Category</label>
                <select
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value as TemplateCategory })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  {Object.entries(CATEGORY_INFO).map(([key, info]) => (
                    <option key={key} value={key}>{info.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                rows={2}
                placeholder="Optional description of the template"
              />
            </div>

            <div className="w-48">
              <label className="block text-sm font-medium text-slate-300 mb-1">Est. Duration (mins)</label>
              <input
                type="number"
                value={formData.estimated_duration_mins}
                onChange={(e) => setFormData({ ...formData, estimated_duration_mins: e.target.value ? parseInt(e.target.value) : '' })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="30"
                min="1"
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="secondary" onClick={resetForm}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                <Save className="h-4 w-4 mr-2" />
                Update
              </Button>
            </div>
          </form>
        </Card>
      )}

      {filteredTemplates.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">
              {activeCategory ? `No ${CATEGORY_INFO[activeCategory as TemplateCategory]?.label || ''} templates` : 'No scan templates yet'}
            </p>
            <p className="text-sm text-slate-500 mt-1">
              Save scan configurations using "Save as Template" when creating a scan
            </p>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredTemplates.map((template) => {
            const config = template.config;
            const isCreating = creatingScans.has(template.id);
            const isCloning = cloningTemplates.has(template.id);
            const isSettingDefault = settingDefault === template.id;
            const catInfo = CATEGORY_INFO[template.category] || CATEGORY_INFO.custom;
            const CatIcon = catInfo.icon;

            return (
              <Card key={template.id} className="relative">
                {/* System template badge */}
                {template.is_system && (
                  <div className="absolute top-2 right-2" title="System template (read-only)">
                    <Lock className="h-4 w-4 text-slate-500" />
                  </div>
                )}

                <div className="space-y-3">
                  {/* Header */}
                  <div className="flex items-start gap-3">
                    <div className={`p-2 rounded-lg bg-dark-bg ${catInfo.color}`}>
                      <CatIcon className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h4 className="font-semibold text-white truncate">{template.name}</h4>
                        {template.is_default && (
                          <span title="Default template">
                            <Star className="h-4 w-4 text-yellow-400 flex-shrink-0" />
                          </span>
                        )}
                      </div>
                      {template.description && (
                        <p className="text-sm text-slate-400 line-clamp-2 mt-0.5">{template.description}</p>
                      )}
                    </div>
                  </div>

                  {/* Config Summary */}
                  <div className="space-y-2 border-t border-dark-border pt-3">
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="flex items-center gap-2">
                        <Hash className="h-4 w-4 text-slate-500" />
                        <span className="text-slate-400">
                          Ports: {config.port_range[0]}-{config.port_range[1]}
                        </span>
                      </div>
                      {config.scan_type && (
                        <div className="flex items-center gap-2">
                          <Radio className="h-4 w-4 text-slate-500" />
                          <span className="text-slate-400 capitalize">
                            {config.scan_type.replace('_', ' ')}
                          </span>
                        </div>
                      )}
                      {config.enable_enumeration && (
                        <div className="flex items-center gap-2">
                          <Search className="h-4 w-4 text-slate-500" />
                          <span className="text-slate-400">
                            Enum: {config.enum_depth || 'light'}
                          </span>
                        </div>
                      )}
                      {template.estimated_duration_mins && (
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-slate-500" />
                          <span className="text-slate-400">
                            {formatDuration(template.estimated_duration_mins)}
                          </span>
                        </div>
                      )}
                    </div>

                    {renderConfigBadges(config)}
                  </div>

                  {/* Stats */}
                  <div className="flex items-center justify-between text-xs text-slate-500 border-t border-dark-border pt-3">
                    <span>Used {template.use_count} times</span>
                    {template.last_used_at ? (
                      <span>Last: {formatDate(template.last_used_at)}</span>
                    ) : (
                      <span>Created {formatDate(template.created_at)}</span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-between border-t border-dark-border pt-3">
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleClone(template)}
                        disabled={isCloning}
                        className="p-1.5 text-slate-400 hover:text-primary transition-colors disabled:opacity-50"
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
                      {!template.is_default && (
                        <button
                          onClick={() => handleSetDefault(template)}
                          disabled={isSettingDefault}
                          className="p-1.5 text-slate-400 hover:text-yellow-400 transition-colors disabled:opacity-50"
                          title="Set as default"
                        >
                          <Star className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => handleCreateScan(template)}
                      loading={isCreating}
                      disabled={isCreating}
                    >
                      <PlayCircle className="h-4 w-4 mr-1.5" />
                      Use
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Delete Template Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Template"
        message={`Are you sure you want to delete the template "${deleteConfirm?.name}"? This will not affect any scans previously created from this template.`}
        confirmLabel="Delete Template"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

export default ScanTemplates;
