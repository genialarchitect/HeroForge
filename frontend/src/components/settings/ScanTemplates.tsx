import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { templateAPI } from '../../services/api';
import { ScanTemplate, ScheduledScanConfig } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import { useScanStore } from '../../store/scanStore';
import {
  FileText, Edit2, Trash2, Save, X, PlayCircle,
  Target, Hash, Search, Radio
} from 'lucide-react';

interface TemplateFormData {
  name: string;
  description: string;
}

const ScanTemplates: React.FC = () => {
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<TemplateFormData>({
    name: '',
    description: '',
  });
  const [creatingScans, setCreatingScans] = useState<Set<string>>(new Set());
  const [deleteConfirm, setDeleteConfirm] = useState<ScanTemplate | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const { addScan } = useScanStore();

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

  const resetForm = () => {
    setFormData({ name: '', description: '' });
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (template: ScanTemplate) => {
    setFormData({
      name: template.name,
      description: template.description || '',
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
      });
      toast.success('Template updated');
      resetForm();
      loadTemplates();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to update template');
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
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleCreateScan = async (templateId: string, templateName: string) => {
    const scanName = prompt(`Enter name for new scan (based on "${templateName}"):`, `${templateName} - ${new Date().toLocaleDateString()}`);
    if (!scanName) return;

    setCreatingScans(new Set([...creatingScans, templateId]));
    try {
      const response = await templateAPI.createScan(templateId, scanName);
      addScan(response.data);
      toast.success('Scan started from template!');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to create scan');
    } finally {
      setCreatingScans((prev) => {
        const next = new Set(prev);
        next.delete(templateId);
        return next;
      });
    }
  };

  const parseConfig = (configJson: string): ScheduledScanConfig | null => {
    try {
      return JSON.parse(configJson);
    } catch {
      return null;
    }
  };

  const formatDate = (dateStr: string): string => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

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
            Save scan configurations for quick reuse
          </div>
        </div>
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

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="Production Network Template"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                rows={3}
                placeholder="Optional description"
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

      {templates.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FileText className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No scan templates yet</p>
            <p className="text-sm text-slate-500 mt-1">
              Save scan configurations using "Save as Template" when creating a scan
            </p>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {templates.map((template) => {
            const config = parseConfig(template.config);
            const isCreating = creatingScans.has(template.id);

            return (
              <Card key={template.id}>
                <div className="space-y-4">
                  {/* Header */}
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-semibold text-white text-lg">{template.name}</h4>
                      {template.description && (
                        <p className="text-sm text-slate-400 mt-1">{template.description}</p>
                      )}
                    </div>
                    <div className="flex gap-1">
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
                        aria-label={`Delete template ${template.name}`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  {/* Config Summary */}
                  {config && (
                    <div className="space-y-2 border-t border-dark-border pt-4">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div className="flex items-center gap-2">
                          <Target className="h-4 w-4 text-slate-500" />
                          <span className="text-slate-400">
                            {config.targets.length} target{config.targets.length !== 1 ? 's' : ''}
                          </span>
                        </div>
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
                              Enumeration: {config.enum_depth || 'light'}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Feature badges */}
                      <div className="flex flex-wrap gap-1.5">
                        {config.enable_os_detection && (
                          <Badge variant="status" type="completed">OS Detection</Badge>
                        )}
                        {config.enable_service_detection && (
                          <Badge variant="status" type="completed">Services</Badge>
                        )}
                        {config.enable_vuln_scan && (
                          <Badge variant="status" type="running">Vuln Scan</Badge>
                        )}
                        {config.enable_enumeration && (
                          <Badge variant="status" type="pending">Enumeration</Badge>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex items-center justify-between border-t border-dark-border pt-4">
                    <span className="text-xs text-slate-500">
                      Created {formatDate(template.created_at)}
                    </span>
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={() => handleCreateScan(template.id, template.name)}
                      loading={isCreating}
                      disabled={isCreating}
                    >
                      <PlayCircle className="h-4 w-4 mr-1.5" />
                      Create Scan
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
