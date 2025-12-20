import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { exclusionsAPI } from '../../services/api';
import { ScanExclusion, ExclusionType, CreateExclusionRequest } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import { Ban, Plus, Edit2, Trash2, Save, X, Globe, Server, Network, Hash, FolderOpen, Info } from 'lucide-react';

const EXCLUSION_TYPES: { id: ExclusionType; label: string; description: string; placeholder: string; icon: React.ReactNode }[] = [
  {
    id: 'host',
    label: 'Single Host',
    description: 'Exclude a single IP address',
    placeholder: '192.168.1.1',
    icon: <Server className="h-4 w-4" />
  },
  {
    id: 'cidr',
    label: 'CIDR Range',
    description: 'Exclude a network range',
    placeholder: '192.168.1.0/24',
    icon: <Network className="h-4 w-4" />
  },
  {
    id: 'hostname',
    label: 'Hostname Pattern',
    description: 'Exclude by hostname (supports wildcards)',
    placeholder: '*.internal.example.com',
    icon: <Globe className="h-4 w-4" />
  },
  {
    id: 'port',
    label: 'Single Port',
    description: 'Exclude a specific port',
    placeholder: '22',
    icon: <Hash className="h-4 w-4" />
  },
  {
    id: 'port_range',
    label: 'Port Range',
    description: 'Exclude a range of ports',
    placeholder: '1-1000',
    icon: <Hash className="h-4 w-4" />
  },
];

interface ExclusionFormData {
  name: string;
  description: string;
  exclusion_type: ExclusionType;
  value: string;
  is_global: boolean;
}

const ExclusionsSettings: React.FC = () => {
  const [exclusions, setExclusions] = useState<ScanExclusion[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<ExclusionFormData>({
    name: '',
    description: '',
    exclusion_type: 'host',
    value: '',
    is_global: true,
  });
  const [deleteConfirm, setDeleteConfirm] = useState<ScanExclusion | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    loadExclusions();
  }, []);

  const loadExclusions = async () => {
    setLoading(true);
    try {
      const response = await exclusionsAPI.getAll();
      setExclusions(response.data);
    } catch (error) {
      toast.error('Failed to load exclusions');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      exclusion_type: 'host',
      value: '',
      is_global: true,
    });
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (exclusion: ScanExclusion) => {
    setFormData({
      name: exclusion.name,
      description: exclusion.description || '',
      exclusion_type: exclusion.exclusion_type,
      value: exclusion.value,
      is_global: exclusion.is_global,
    });
    setEditingId(exclusion.id);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }
    if (!formData.value.trim()) {
      toast.error('Value is required');
      return;
    }

    try {
      const request: CreateExclusionRequest = {
        name: formData.name.trim(),
        description: formData.description.trim() || undefined,
        exclusion_type: formData.exclusion_type,
        value: formData.value.trim(),
        is_global: formData.is_global,
      };

      if (editingId) {
        await exclusionsAPI.update(editingId, request);
        toast.success('Exclusion updated');
      } else {
        await exclusionsAPI.create(request);
        toast.success('Exclusion created');
      }
      resetForm();
      loadExclusions();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save exclusion');
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await exclusionsAPI.delete(deleteConfirm.id);
      toast.success(`Exclusion "${deleteConfirm.name}" deleted`);
      loadExclusions();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const getExclusionTypeInfo = (type: ExclusionType) => {
    return EXCLUSION_TYPES.find((t) => t.id === type) || EXCLUSION_TYPES[0];
  };

  const globalExclusions = exclusions.filter((e) => e.is_global);
  const perScanExclusions = exclusions.filter((e) => !e.is_global);

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
            <Ban className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Scan Exclusions</h3>
          </div>
          {!showForm && (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Exclusion
            </Button>
          )}
        </div>
        <p className="text-sm text-slate-400 mt-2">
          Configure hosts and ports to exclude from scans. Global exclusions apply to all scans automatically.
        </p>
      </Card>

      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">
                {editingId ? 'Edit Exclusion' : 'Create Exclusion'}
              </h4>
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
                  placeholder="Development Servers"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Type</label>
                <select
                  value={formData.exclusion_type}
                  onChange={(e) => setFormData({ ...formData, exclusion_type: e.target.value as ExclusionType })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  {EXCLUSION_TYPES.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Value</label>
              <input
                type="text"
                value={formData.value}
                onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent font-mono"
                placeholder={getExclusionTypeInfo(formData.exclusion_type).placeholder}
              />
              <p className="text-xs text-slate-500 mt-1">
                {getExclusionTypeInfo(formData.exclusion_type).description}
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Description (optional)</label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="Why is this excluded?"
              />
            </div>

            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.is_global}
                  onChange={(e) => setFormData({ ...formData, is_global: e.target.checked })}
                  className="w-4 h-4 rounded bg-dark-bg border-dark-border text-primary focus:ring-primary focus:ring-offset-dark-bg"
                />
                <span className="text-sm text-slate-300">Apply to all scans (global exclusion)</span>
              </label>
              <div className="flex items-center gap-1 text-xs text-slate-500">
                <Info className="h-3 w-3" />
                <span>Non-global exclusions can be selected per-scan</span>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="secondary" onClick={resetForm}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                <Save className="h-4 w-4 mr-2" />
                {editingId ? 'Update' : 'Create'}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {exclusions.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FolderOpen className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No exclusions configured</p>
            <p className="text-sm text-slate-500 mt-1">
              Create exclusions to skip specific hosts or ports during scans
            </p>
          </div>
        </Card>
      ) : (
        <>
          {/* Global Exclusions */}
          {globalExclusions.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Globe className="h-4 w-4 text-green-400" />
                <h4 className="font-medium text-white">Global Exclusions</h4>
                <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">
                  Applied to all scans
                </span>
              </div>
              <div className="space-y-2">
                {globalExclusions.map((exclusion) => (
                  <ExclusionItem
                    key={exclusion.id}
                    exclusion={exclusion}
                    onEdit={handleEdit}
                    onDelete={setDeleteConfirm}
                  />
                ))}
              </div>
            </Card>
          )}

          {/* Per-Scan Exclusions */}
          {perScanExclusions.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Server className="h-4 w-4 text-blue-400" />
                <h4 className="font-medium text-white">Per-Scan Exclusions</h4>
                <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">
                  Select when creating scans
                </span>
              </div>
              <div className="space-y-2">
                {perScanExclusions.map((exclusion) => (
                  <ExclusionItem
                    key={exclusion.id}
                    exclusion={exclusion}
                    onEdit={handleEdit}
                    onDelete={setDeleteConfirm}
                  />
                ))}
              </div>
            </Card>
          )}
        </>
      )}

      {/* Delete Exclusion Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Exclusion"
        message={`Are you sure you want to delete the exclusion "${deleteConfirm?.name}"? This cannot be undone.`}
        confirmLabel="Delete Exclusion"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

// Sub-component for displaying an exclusion item
interface ExclusionItemProps {
  exclusion: ScanExclusion;
  onEdit: (exclusion: ScanExclusion) => void;
  onDelete: (exclusion: ScanExclusion) => void;
}

const ExclusionItem: React.FC<ExclusionItemProps> = ({ exclusion, onEdit, onDelete }) => {
  const typeInfo = EXCLUSION_TYPES.find((t) => t.id === exclusion.exclusion_type);

  const getTypeBadgeColor = (type: ExclusionType) => {
    switch (type) {
      case 'host':
      case 'cidr':
        return 'bg-purple-500/20 text-purple-400';
      case 'hostname':
        return 'bg-cyan-500/20 text-cyan-400';
      case 'port':
      case 'port_range':
        return 'bg-orange-500/20 text-orange-400';
      default:
        return 'bg-slate-500/20 text-slate-400';
    }
  };

  return (
    <div className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border">
      <div className="flex items-center gap-3 flex-1">
        <div className="text-slate-400">
          {typeInfo?.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-white">{exclusion.name}</span>
            <span className={`text-xs px-2 py-0.5 rounded ${getTypeBadgeColor(exclusion.exclusion_type)}`}>
              {typeInfo?.label || exclusion.exclusion_type}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <code className="text-sm font-mono text-slate-300 bg-dark-surface px-2 py-0.5 rounded">
              {exclusion.value}
            </code>
            {exclusion.description && (
              <span className="text-xs text-slate-500 truncate">{exclusion.description}</span>
            )}
          </div>
        </div>
      </div>
      <div className="flex gap-1 ml-4">
        <button
          onClick={() => onEdit(exclusion)}
          className="p-1.5 text-slate-400 hover:text-primary transition-colors"
          title="Edit exclusion"
        >
          <Edit2 className="h-4 w-4" />
        </button>
        <button
          onClick={() => onDelete(exclusion)}
          className="p-1.5 text-slate-400 hover:text-red-400 transition-colors"
          title="Delete exclusion"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};

export default ExclusionsSettings;
