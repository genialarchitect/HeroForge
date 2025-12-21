import React from 'react';
import {
  GripVertical,
  Trash2,
  Users,
  Clock,
  Bell,
  CheckCircle,
  FileCheck,
  Shield,
  Briefcase,
  Wrench,
  X,
} from 'lucide-react';
import type { CreateWorkflowStageRequest } from '../../types';

interface WorkflowStageEditorProps {
  stage: CreateWorkflowStageRequest;
  index: number;
  onChange: (index: number, stage: CreateWorkflowStageRequest) => void;
  onRemove: (index: number) => void;
  onMoveUp: (index: number) => void;
  onMoveDown: (index: number) => void;
  isFirst: boolean;
  isLast: boolean;
  availableRoles: string[];
}

const STAGE_TYPES = [
  { value: 'assignment', label: 'Assignment', icon: Users, description: 'Assign to team member' },
  { value: 'work', label: 'Work', icon: Wrench, description: 'Remediation work stage' },
  { value: 'review', label: 'Review', icon: FileCheck, description: 'Peer review stage' },
  { value: 'verification', label: 'Verification', icon: CheckCircle, description: 'Security team verification' },
  { value: 'cab_approval', label: 'CAB Approval', icon: Briefcase, description: 'Change Advisory Board' },
  { value: 'deployment', label: 'Deployment', icon: Shield, description: 'Deploy fix to production' },
  { value: 'closure', label: 'Closure', icon: X, description: 'Final closure stage' },
];

export const WorkflowStageEditor: React.FC<WorkflowStageEditorProps> = ({
  stage,
  index,
  onChange,
  onRemove,
  onMoveUp,
  onMoveDown,
  isFirst,
  isLast,
  availableRoles,
}) => {
  const handleChange = (field: keyof CreateWorkflowStageRequest, value: unknown) => {
    onChange(index, { ...stage, [field]: value });
  };

  const stageTypeInfo = STAGE_TYPES.find((t) => t.value === stage.stage_type);
  const StageIcon = stageTypeInfo?.icon || Wrench;

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <div className="flex items-start gap-3">
        {/* Drag Handle */}
        <div className="flex flex-col items-center gap-1 pt-2">
          <button
            type="button"
            onClick={() => onMoveUp(index)}
            disabled={isFirst}
            className="p-1 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            title="Move up"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
            </svg>
          </button>
          <GripVertical className="w-5 h-5 text-gray-500" />
          <button
            type="button"
            onClick={() => onMoveDown(index)}
            disabled={isLast}
            className="p-1 text-gray-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            title="Move down"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Stage Content */}
        <div className="flex-1 space-y-4">
          {/* Header Row */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-cyan-400">
              <StageIcon className="w-5 h-5" />
              <span className="text-sm font-medium">Stage {index + 1}</span>
            </div>
            <button
              type="button"
              onClick={() => onRemove(index)}
              className="ml-auto p-1 text-red-400 hover:text-red-300"
              title="Remove stage"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>

          {/* Name and Type */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Stage Name</label>
              <input
                type="text"
                value={stage.name}
                onChange={(e) => handleChange('name', e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                placeholder="e.g., Security Review"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Stage Type</label>
              <select
                value={stage.stage_type}
                onChange={(e) => handleChange('stage_type', e.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              >
                {STAGE_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label} - {type.description}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">Description (optional)</label>
            <input
              type="text"
              value={stage.description || ''}
              onChange={(e) => handleChange('description', e.target.value || undefined)}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              placeholder="Describe what happens in this stage..."
            />
          </div>

          {/* Approval Settings */}
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1 flex items-center gap-1">
                <Users className="w-4 h-4" />
                Required Approvals
              </label>
              <input
                type="number"
                min="0"
                value={stage.required_approvals}
                onChange={(e) => handleChange('required_approvals', parseInt(e.target.value) || 0)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              />
              <p className="text-xs text-gray-500 mt-1">0 = auto-advance</p>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1 flex items-center gap-1">
                <Clock className="w-4 h-4" />
                SLA (hours)
              </label>
              <input
                type="number"
                min="0"
                value={stage.sla_hours || ''}
                onChange={(e) => handleChange('sla_hours', e.target.value ? parseInt(e.target.value) : undefined)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                placeholder="Optional"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Approver Role</label>
              <select
                value={stage.approver_role || ''}
                onChange={(e) => handleChange('approver_role', e.target.value || undefined)}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
              >
                <option value="">Any authenticated user</option>
                {availableRoles.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Notification Settings */}
          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={stage.notify_on_enter !== false}
                onChange={(e) => handleChange('notify_on_enter', e.target.checked)}
                className="w-4 h-4 rounded border-gray-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-900"
              />
              <Bell className="w-4 h-4 text-gray-400" />
              <span className="text-sm text-gray-300">Notify on stage entry</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={stage.notify_on_sla_breach !== false}
                onChange={(e) => handleChange('notify_on_sla_breach', e.target.checked)}
                className="w-4 h-4 rounded border-gray-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-900"
              />
              <Clock className="w-4 h-4 text-orange-400" />
              <span className="text-sm text-gray-300">Notify on SLA breach</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WorkflowStageEditor;
