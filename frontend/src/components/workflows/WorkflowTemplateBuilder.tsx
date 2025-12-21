import React, { useState, useEffect } from 'react';
import { Plus, Save, X, AlertCircle, Info } from 'lucide-react';
import { toast } from 'react-toastify';
import { workflowAPI, adminAPI } from '../../services/api';
import { WorkflowStageEditor } from './WorkflowStageEditor';
import type {
  WorkflowTemplateWithStages,
  CreateWorkflowTemplateRequest,
  CreateWorkflowStageRequest,
} from '../../types';

interface WorkflowTemplateBuilderProps {
  template?: WorkflowTemplateWithStages;
  onSave?: (template: WorkflowTemplateWithStages) => void;
  onCancel?: () => void;
}

const DEFAULT_STAGE: CreateWorkflowStageRequest = {
  name: '',
  stage_type: 'work',
  required_approvals: 0,
  notify_on_enter: true,
  notify_on_sla_breach: true,
};

export const WorkflowTemplateBuilder: React.FC<WorkflowTemplateBuilderProps> = ({
  template,
  onSave,
  onCancel,
}) => {
  const [name, setName] = useState(template?.name || '');
  const [description, setDescription] = useState(template?.description || '');
  const [stages, setStages] = useState<CreateWorkflowStageRequest[]>(
    template?.stages?.map((s) => ({
      name: s.name,
      description: s.description || undefined,
      stage_type: s.stage_type,
      required_approvals: s.required_approvals,
      approver_role: s.approver_role || undefined,
      approver_user_ids: s.approver_user_ids ? JSON.parse(s.approver_user_ids) : undefined,
      sla_hours: s.sla_hours || undefined,
      notify_on_enter: s.notify_on_enter,
      notify_on_sla_breach: s.notify_on_sla_breach,
      auto_advance_conditions: s.auto_advance_conditions
        ? JSON.parse(s.auto_advance_conditions)
        : undefined,
    })) || [{ ...DEFAULT_STAGE, name: 'Initial Stage' }]
  );
  const [availableRoles, setAvailableRoles] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    // Fetch available roles
    adminAPI
      .getRoles()
      .then((res) => {
        setAvailableRoles(res.data.map((r) => r.name));
      })
      .catch(() => {
        // Default roles if API fails
        setAvailableRoles(['admin', 'user', 'auditor', 'viewer']);
      });
  }, []);

  const addStage = () => {
    setStages([
      ...stages,
      { ...DEFAULT_STAGE, name: `Stage ${stages.length + 1}` },
    ]);
  };

  const removeStage = (index: number) => {
    if (stages.length <= 1) {
      toast.error('Template must have at least one stage');
      return;
    }
    setStages(stages.filter((_, i) => i !== index));
  };

  const updateStage = (index: number, stage: CreateWorkflowStageRequest) => {
    const newStages = [...stages];
    newStages[index] = stage;
    setStages(newStages);
  };

  const moveStageUp = (index: number) => {
    if (index === 0) return;
    const newStages = [...stages];
    [newStages[index - 1], newStages[index]] = [newStages[index], newStages[index - 1]];
    setStages(newStages);
  };

  const moveStageDown = (index: number) => {
    if (index === stages.length - 1) return;
    const newStages = [...stages];
    [newStages[index], newStages[index + 1]] = [newStages[index + 1], newStages[index]];
    setStages(newStages);
  };

  const validate = (): boolean => {
    const newErrors: string[] = [];

    if (!name.trim()) {
      newErrors.push('Template name is required');
    }

    if (stages.length === 0) {
      newErrors.push('Template must have at least one stage');
    }

    stages.forEach((stage, index) => {
      if (!stage.name.trim()) {
        newErrors.push(`Stage ${index + 1} must have a name`);
      }
    });

    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSave = async () => {
    if (!validate()) return;

    setSaving(true);
    try {
      const request: CreateWorkflowTemplateRequest = {
        name,
        description: description || undefined,
        stages,
      };

      let result: WorkflowTemplateWithStages;

      if (template) {
        const response = await workflowAPI.templates.update(template.id, {
          name,
          description: description || undefined,
          stages,
        });
        result = response.data;
        toast.success('Template updated successfully');
      } else {
        const response = await workflowAPI.templates.create(request);
        result = response.data;
        toast.success('Template created successfully');
      }

      onSave?.(result);
    } catch (error: unknown) {
      const err = error as { response?: { data?: { error?: string } } };
      toast.error(err.response?.data?.error || 'Failed to save template');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-900 rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white">
          {template ? 'Edit Workflow Template' : 'Create Workflow Template'}
        </h2>
        {onCancel && (
          <button
            onClick={onCancel}
            className="p-2 text-gray-400 hover:text-white"
            title="Cancel"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Errors */}
      {errors.length > 0 && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-500/50 rounded-lg">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              {errors.map((error, index) => (
                <p key={index} className="text-sm text-red-400">
                  {error}
                </p>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Template Info */}
      <div className="space-y-4 mb-6">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Template Name *</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
            placeholder="e.g., Standard Remediation Workflow"
          />
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            className="w-full bg-gray-800 border border-gray-700 rounded px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
            placeholder="Describe when to use this workflow template..."
          />
        </div>
      </div>

      {/* Info Box */}
      <div className="mb-6 p-3 bg-blue-900/20 border border-blue-500/30 rounded-lg">
        <div className="flex items-start gap-2">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-blue-300">
            <p className="font-medium mb-1">Workflow stages are executed in order.</p>
            <p className="text-blue-400">
              Stages with required approvals &gt; 0 will wait for approval before advancing.
              Use SLA hours to set deadlines for each stage.
            </p>
          </div>
        </div>
      </div>

      {/* Stages */}
      <div className="space-y-4 mb-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium text-white">Stages ({stages.length})</h3>
          <button
            type="button"
            onClick={addStage}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded text-sm"
          >
            <Plus className="w-4 h-4" />
            Add Stage
          </button>
        </div>

        <div className="space-y-3">
          {stages.map((stage, index) => (
            <WorkflowStageEditor
              key={index}
              stage={stage}
              index={index}
              onChange={updateStage}
              onRemove={removeStage}
              onMoveUp={moveStageUp}
              onMoveDown={moveStageDown}
              isFirst={index === 0}
              isLast={index === stages.length - 1}
              availableRoles={availableRoles}
            />
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-end gap-3 pt-4 border-t border-gray-700">
        {onCancel && (
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded"
          >
            Cancel
          </button>
        )}
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {saving ? 'Saving...' : template ? 'Update Template' : 'Create Template'}
        </button>
      </div>
    </div>
  );
};

export default WorkflowTemplateBuilder;
