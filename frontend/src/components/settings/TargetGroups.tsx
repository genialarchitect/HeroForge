import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { targetGroupAPI } from '../../services/api';
import { TargetGroup } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import { Target, Plus, Edit2, Trash2, Save, X, FolderOpen } from 'lucide-react';

const PRESET_COLORS = [
  '#ef4444', '#f97316', '#eab308', '#22c55e', '#14b8a6',
  '#3b82f6', '#8b5cf6', '#ec4899', '#6366f1', '#64748b',
];

interface TargetGroupFormData {
  name: string;
  description: string;
  targets: string;
  color: string;
}

const TargetGroups: React.FC = () => {
  const [groups, setGroups] = useState<TargetGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<TargetGroupFormData>({
    name: '',
    description: '',
    targets: '',
    color: PRESET_COLORS[0],
  });
  const [deleteConfirm, setDeleteConfirm] = useState<TargetGroup | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    loadGroups();
  }, []);

  const loadGroups = async () => {
    setLoading(true);
    try {
      const response = await targetGroupAPI.getAll();
      setGroups(response.data);
    } catch (error) {
      toast.error('Failed to load target groups');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({ name: '', description: '', targets: '', color: PRESET_COLORS[0] });
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (group: TargetGroup) => {
    const targets = JSON.parse(group.targets || '[]');
    setFormData({
      name: group.name,
      description: group.description || '',
      targets: targets.join('\n'),
      color: group.color,
    });
    setEditingId(group.id);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const targets = formData.targets
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }
    if (targets.length === 0) {
      toast.error('At least one target is required');
      return;
    }

    try {
      if (editingId) {
        await targetGroupAPI.update(editingId, {
          name: formData.name,
          description: formData.description || undefined,
          targets,
          color: formData.color,
        });
        toast.success('Target group updated');
      } else {
        await targetGroupAPI.create({
          name: formData.name,
          description: formData.description || undefined,
          targets,
          color: formData.color,
        });
        toast.success('Target group created');
      }
      resetForm();
      loadGroups();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save target group');
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await targetGroupAPI.delete(deleteConfirm.id);
      toast.success(`Target group "${deleteConfirm.name}" deleted`);
      loadGroups();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const parseTargets = (targetsJson: string): string[] => {
    try {
      return JSON.parse(targetsJson || '[]');
    } catch {
      return [];
    }
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
            <Target className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Target Groups</h3>
          </div>
          {!showForm && (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Group
            </Button>
          )}
        </div>
      </Card>

      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">
                {editingId ? 'Edit Target Group' : 'Create Target Group'}
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
                  placeholder="Production Servers"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Color</label>
                <div className="flex gap-2">
                  {PRESET_COLORS.map((color) => (
                    <button
                      key={color}
                      type="button"
                      onClick={() => setFormData({ ...formData, color })}
                      className={`w-8 h-8 rounded-full border-2 transition-all ${
                        formData.color === color ? 'border-white scale-110' : 'border-transparent'
                      }`}
                      style={{ backgroundColor: color }}
                    />
                  ))}
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder="Optional description"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">
                Targets (one per line)
              </label>
              <textarea
                value={formData.targets}
                onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent font-mono text-sm"
                rows={5}
                placeholder="192.168.1.0/24&#10;10.0.0.1&#10;example.com"
              />
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

      {groups.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <FolderOpen className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No target groups yet</p>
            <p className="text-sm text-slate-500 mt-1">
              Create groups to organize your scan targets
            </p>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {groups.map((group) => {
            const targets = parseTargets(group.targets);
            return (
              <Card key={group.id}>
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-4 h-4 rounded-full"
                      style={{ backgroundColor: group.color }}
                    />
                    <h4 className="font-medium text-white">{group.name}</h4>
                  </div>
                  <div className="flex gap-1">
                    <button
                      onClick={() => handleEdit(group)}
                      className="p-1.5 text-slate-400 hover:text-primary transition-colors"
                    >
                      <Edit2 className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(group)}
                      className="p-1.5 text-slate-400 hover:text-red-400 transition-colors"
                      aria-label={`Delete target group ${group.name}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                {group.description && (
                  <p className="text-sm text-slate-400 mb-3">{group.description}</p>
                )}
                <div className="space-y-1">
                  <p className="text-xs text-slate-500 uppercase tracking-wide">
                    {targets.length} target{targets.length !== 1 ? 's' : ''}
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {targets.slice(0, 5).map((t, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 text-xs bg-dark-bg rounded text-slate-300 font-mono"
                      >
                        {t}
                      </span>
                    ))}
                    {targets.length > 5 && (
                      <span className="px-2 py-0.5 text-xs bg-dark-bg rounded text-slate-500">
                        +{targets.length - 5} more
                      </span>
                    )}
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Delete Target Group Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Target Group"
        message={`Are you sure you want to delete the target group "${deleteConfirm?.name}"? Scheduled scans using this group will need to be updated.`}
        confirmLabel="Delete Group"
        variant="danger"
        loading={isDeleting}
      />
    </div>
  );
};

export default TargetGroups;
