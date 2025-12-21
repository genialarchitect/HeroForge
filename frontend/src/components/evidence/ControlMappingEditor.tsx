import React, { useState, useEffect } from 'react';
import {
  Link,
  Plus,
  Trash2,
  Edit2,
  Save,
  X,
  Shield,
  AlertCircle,
  CheckCircle,
} from 'lucide-react';
import { toast } from 'react-toastify';
import type {
  EvidenceControlMapping,
  CreateMappingRequest,
  UpdateMappingRequest,
} from '../../types/evidence';
import { evidenceAPI } from '../../services/evidenceApi';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

interface ControlMappingEditorProps {
  evidenceId: string;
  onMappingsChange?: () => void;
}

const ControlMappingEditor: React.FC<ControlMappingEditorProps> = ({
  evidenceId,
  onMappingsChange,
}) => {
  const [mappings, setMappings] = useState<EvidenceControlMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [editingMapping, setEditingMapping] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);

  // Edit form state
  const [editCoverage, setEditCoverage] = useState(0);
  const [editNotes, setEditNotes] = useState('');

  // Add form state
  const [newControlId, setNewControlId] = useState('');
  const [newFrameworkId, setNewFrameworkId] = useState('');
  const [newCoverage, setNewCoverage] = useState(0.8);
  const [newNotes, setNewNotes] = useState('');

  // Available frameworks (could be fetched from API)
  const frameworks = [
    { id: 'pci_dss', name: 'PCI-DSS' },
    { id: 'nist_800_53', name: 'NIST 800-53' },
    { id: 'nist_csf', name: 'NIST CSF' },
    { id: 'cis', name: 'CIS Benchmarks' },
    { id: 'hipaa', name: 'HIPAA' },
    { id: 'soc2', name: 'SOC 2' },
    { id: 'owasp_top10', name: 'OWASP Top 10' },
  ];

  useEffect(() => {
    loadMappings();
  }, [evidenceId]);

  const loadMappings = async () => {
    setLoading(true);
    try {
      const response = await evidenceAPI.getMappings(evidenceId);
      setMappings(response.data.mappings);
    } catch (err) {
      console.error('Failed to load mappings:', err);
      toast.error('Failed to load control mappings');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMapping = async () => {
    if (!newControlId.trim() || !newFrameworkId) {
      toast.error('Please enter control ID and select a framework');
      return;
    }

    setSaving(true);
    try {
      const request: CreateMappingRequest = {
        evidence_id: evidenceId,
        control_id: newControlId.trim(),
        framework_id: newFrameworkId,
        coverage_score: newCoverage,
        notes: newNotes.trim() || undefined,
      };

      await evidenceAPI.createMapping(request);
      toast.success('Mapping added successfully');
      setShowAddForm(false);
      setNewControlId('');
      setNewFrameworkId('');
      setNewCoverage(0.8);
      setNewNotes('');
      loadMappings();
      onMappingsChange?.();
    } catch (err) {
      console.error('Failed to add mapping:', err);
      toast.error('Failed to add mapping');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateMapping = async (mappingId: string) => {
    setSaving(true);
    try {
      const request: UpdateMappingRequest = {
        coverage_score: editCoverage,
        notes: editNotes.trim() || undefined,
      };

      await evidenceAPI.updateMapping(mappingId, request);
      toast.success('Mapping updated successfully');
      setEditingMapping(null);
      loadMappings();
      onMappingsChange?.();
    } catch (err) {
      console.error('Failed to update mapping:', err);
      toast.error('Failed to update mapping');
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteMapping = async (mappingId: string) => {
    if (!confirm('Are you sure you want to remove this control mapping?')) {
      return;
    }

    try {
      await evidenceAPI.deleteMapping(mappingId);
      toast.success('Mapping removed successfully');
      loadMappings();
      onMappingsChange?.();
    } catch (err) {
      console.error('Failed to delete mapping:', err);
      toast.error('Failed to remove mapping');
    }
  };

  const startEditing = (mapping: EvidenceControlMapping) => {
    setEditingMapping(mapping.id);
    setEditCoverage(mapping.coverage_score);
    setEditNotes(mapping.notes || '');
  };

  const cancelEditing = () => {
    setEditingMapping(null);
    setEditCoverage(0);
    setEditNotes('');
  };

  const getCoverageColor = (score: number): 'green' | 'yellow' | 'red' | 'gray' => {
    if (score >= 0.8) return 'green';
    if (score >= 0.5) return 'yellow';
    if (score > 0) return 'red';
    return 'gray';
  };

  const getCoverageLabel = (score: number): string => {
    if (score >= 0.8) return 'Strong';
    if (score >= 0.5) return 'Partial';
    if (score > 0) return 'Weak';
    return 'None';
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <LoadingSpinner />
        <span className="ml-2 text-slate-500">Loading control mappings...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link className="h-5 w-5 text-primary" />
          <h3 className="font-semibold text-slate-900 dark:text-white">
            Control Mappings
          </h3>
          <Badge variant="secondary">{mappings.length} mapped</Badge>
        </div>
        {!showAddForm && (
          <Button variant="outline" size="sm" onClick={() => setShowAddForm(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Mapping
          </Button>
        )}
      </div>

      {/* Add Form */}
      {showAddForm && (
        <div className="p-4 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg space-y-4">
          <h4 className="font-medium text-slate-900 dark:text-white">
            Add Control Mapping
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Framework */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Framework
              </label>
              <select
                value={newFrameworkId}
                onChange={(e) => setNewFrameworkId(e.target.value)}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">Select framework...</option>
                {frameworks.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Control ID */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Control ID
              </label>
              <input
                type="text"
                value={newControlId}
                onChange={(e) => setNewControlId(e.target.value)}
                placeholder="e.g., AC-1, 1.1.1"
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </div>

          {/* Coverage */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Coverage Score: {Math.round(newCoverage * 100)}%
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={newCoverage}
              onChange={(e) => setNewCoverage(parseFloat(e.target.value))}
              className="w-full"
            />
            <div className="flex justify-between text-xs text-slate-500">
              <span>None (0%)</span>
              <span>Weak (10-49%)</span>
              <span>Partial (50-79%)</span>
              <span>Strong (80-100%)</span>
            </div>
          </div>

          {/* Notes */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Notes (optional)
            </label>
            <textarea
              value={newNotes}
              onChange={(e) => setNewNotes(e.target.value)}
              placeholder="Explain how this evidence supports the control..."
              rows={2}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
            />
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setShowAddForm(false);
                setNewControlId('');
                setNewFrameworkId('');
                setNewCoverage(0.8);
                setNewNotes('');
              }}
            >
              Cancel
            </Button>
            <Button size="sm" onClick={handleAddMapping} disabled={saving}>
              {saving ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-1">Adding...</span>
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-1" />
                  Add Mapping
                </>
              )}
            </Button>
          </div>
        </div>
      )}

      {/* Mappings List */}
      {mappings.length === 0 ? (
        <div className="text-center py-8 text-slate-500">
          <AlertCircle className="h-12 w-12 mx-auto mb-3 opacity-50" />
          <p>No control mappings defined</p>
          <p className="text-sm mt-1">
            Add mappings to link this evidence to compliance controls
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {mappings.map((mapping) => (
            <div
              key={mapping.id}
              className="p-3 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg"
            >
              {editingMapping === mapping.id ? (
                /* Edit Mode */
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    <span className="font-medium text-slate-900 dark:text-white">
                      {mapping.framework_id.toUpperCase()}
                    </span>
                    <span className="text-slate-500">-</span>
                    <span className="text-slate-700 dark:text-slate-300">
                      {mapping.control_id}
                    </span>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                      Coverage: {Math.round(editCoverage * 100)}%
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="1"
                      step="0.1"
                      value={editCoverage}
                      onChange={(e) => setEditCoverage(parseFloat(e.target.value))}
                      className="w-full"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                      Notes
                    </label>
                    <textarea
                      value={editNotes}
                      onChange={(e) => setEditNotes(e.target.value)}
                      rows={2}
                      className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
                    />
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button variant="ghost" size="sm" onClick={cancelEditing}>
                      <X className="h-4 w-4 mr-1" />
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => handleUpdateMapping(mapping.id)}
                      disabled={saving}
                    >
                      {saving ? (
                        <>
                          <LoadingSpinner />
                          <span className="ml-1">Saving...</span>
                        </>
                      ) : (
                        <>
                          <Save className="h-4 w-4 mr-1" />
                          Save
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              ) : (
                /* View Mode */
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-primary" />
                      <Badge variant="blue">{mapping.framework_id.toUpperCase()}</Badge>
                      <span className="font-medium text-slate-900 dark:text-white">
                        {mapping.control_id}
                      </span>
                    </div>
                    <Badge variant={getCoverageColor(mapping.coverage_score)}>
                      {Math.round(mapping.coverage_score * 100)}%{' '}
                      {getCoverageLabel(mapping.coverage_score)}
                    </Badge>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">
                      {formatDate(mapping.created_at)}
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => startEditing(mapping)}
                    >
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDeleteMapping(mapping.id)}
                      className="text-red-500 hover:text-red-600"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}

              {/* Notes (shown when not editing) */}
              {!editingMapping && mapping.notes && (
                <div className="mt-2 text-sm text-slate-600 dark:text-slate-400 pl-6">
                  {mapping.notes}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Summary */}
      {mappings.length > 0 && (
        <div className="p-3 bg-light-hover dark:bg-dark-hover rounded-lg text-sm">
          <div className="flex items-center justify-between">
            <span className="text-slate-600 dark:text-slate-400">
              <CheckCircle className="h-4 w-4 inline mr-1 text-green-500" />
              Mapped to {mappings.length} control{mappings.length !== 1 ? 's' : ''} across{' '}
              {new Set(mappings.map((m) => m.framework_id)).size} framework
              {new Set(mappings.map((m) => m.framework_id)).size !== 1 ? 's' : ''}
            </span>
            <span className="text-slate-500">
              Avg coverage:{' '}
              {Math.round(
                (mappings.reduce((sum, m) => sum + m.coverage_score, 0) / mappings.length) *
                  100
              )}
              %
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default ControlMappingEditor;
