import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Briefcase,
  Workflow,
  Database,
  BarChart3,
  AlertCircle,
  Plus,
  RefreshCw,
  Play,
  Eye,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronRight,
  Pause,
  MessageSquare,
  ListTodo,
  Timer,
  Shield,
  Target,
  TrendingUp,
  Users,
  X,
  Trash2,
  Edit,
  ExternalLink,
  Rss,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { greenTeamAPI } from '../services/api';
import type {
  SoarCase,
  Playbook,
  PlaybookRun,
  IocFeed,
  CaseTask,
  CaseComment,
  CaseTimelineEvent,
  MetricsOverview,
  CaseSeverity,
  CaseStatus,
  CasePriority,
  CaseType,
  CaseTlp,
  CreateCaseRequest,
  CreatePlaybookRequest,
  CreateIocFeedRequest,
} from '../types';

type TabType = 'cases' | 'playbooks' | 'feeds' | 'metrics';

// ============================================================================
// Badge Components
// ============================================================================

const severityColors: Record<string, { bg: string; text: string }> = {
  informational: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  open: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  in_progress: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  pending: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  resolved: { bg: 'bg-green-500/20', text: 'text-green-400' },
  closed: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  running: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  cancelled: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  waiting_approval: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
};

const priorityColors: Record<string, { bg: string; text: string }> = {
  low: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  medium: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  urgent: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const tlpColors: Record<string, { bg: string; text: string; border: string }> = {
  white: { bg: 'bg-white/10', text: 'text-white', border: 'border-white/30' },
  green: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
  amber: { bg: 'bg-amber-500/20', text: 'text-amber-400', border: 'border-amber-500/30' },
  red: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const colors = severityColors[severity.toLowerCase()] || severityColors.low;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.open;
  const displayStatus = status.replace(/_/g, ' ');
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1)}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const colors = priorityColors[priority.toLowerCase()] || priorityColors.medium;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {priority.charAt(0).toUpperCase() + priority.slice(1)}
    </span>
  );
}

function TlpBadge({ tlp }: { tlp: string }) {
  const colors = tlpColors[tlp.toLowerCase()] || tlpColors.white;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${colors.bg} ${colors.text} ${colors.border}`}>
      TLP:{tlp.toUpperCase()}
    </span>
  );
}

// ============================================================================
// Modal Component
// ============================================================================

const Modal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}> = ({ isOpen, onClose, title, children, size = 'md' }) => {
  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-2xl',
    lg: 'max-w-4xl',
    xl: 'max-w-6xl',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className={`relative bg-gray-800 border border-gray-700 rounded-lg shadow-xl w-full ${sizeClasses[size]} max-h-[90vh] overflow-y-auto mx-4`}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

// ============================================================================
// Create Case Form
// ============================================================================

interface CreateCaseFormData {
  title: string;
  description: string;
  severity: CaseSeverity;
  case_type: CaseType;
  priority: CasePriority;
  tlp: CaseTlp;
}

const CreateCaseForm: React.FC<{
  onSubmit: (data: CreateCaseRequest) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState<CreateCaseFormData>({
    title: '',
    description: '',
    severity: 'medium',
    case_type: 'incident',
    priority: 'medium',
    tlp: 'amber',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Title *</label>
        <input
          type="text"
          required
          value={formData.title}
          onChange={(e) => setFormData({ ...formData, title: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          placeholder="Case title..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          rows={3}
          placeholder="Describe the security case..."
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Severity</label>
          <select
            value={formData.severity}
            onChange={(e) => setFormData({ ...formData, severity: e.target.value as CaseSeverity })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="informational">Informational</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Case Type</label>
          <select
            value={formData.case_type}
            onChange={(e) => setFormData({ ...formData, case_type: e.target.value as CaseType })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="incident">Incident</option>
            <option value="investigation">Investigation</option>
            <option value="threat_hunt">Threat Hunt</option>
            <option value="vulnerability">Vulnerability</option>
            <option value="compliance">Compliance</option>
            <option value="other">Other</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Priority</label>
          <select
            value={formData.priority}
            onChange={(e) => setFormData({ ...formData, priority: e.target.value as CasePriority })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="urgent">Urgent</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">TLP</label>
          <select
            value={formData.tlp}
            onChange={(e) => setFormData({ ...formData, tlp: e.target.value as CaseTlp })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="white">TLP:WHITE</option>
            <option value="green">TLP:GREEN</option>
            <option value="amber">TLP:AMBER</option>
            <option value="red">TLP:RED</option>
          </select>
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
        <button
          type="button"
          onClick={onCancel}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
          Create Case
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Create Playbook Form
// ============================================================================

interface CreatePlaybookFormData {
  name: string;
  description: string;
  category: string;
  trigger_type: string;
  steps: PlaybookStepInput[];
}

interface PlaybookStepInput {
  id: string;
  name: string;
  action_type: string;
  timeout_seconds: number;
}

const CreatePlaybookForm: React.FC<{
  onSubmit: (data: CreatePlaybookFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState<CreatePlaybookFormData>({
    name: '',
    description: '',
    category: 'incident_response',
    trigger_type: 'manual',
    steps: [{ id: 'step_1', name: 'Initial Step', action_type: 'send_notification', timeout_seconds: 300 }],
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  const addStep = () => {
    const newStep: PlaybookStepInput = {
      id: `step_${formData.steps.length + 1}`,
      name: `Step ${formData.steps.length + 1}`,
      action_type: 'send_notification',
      timeout_seconds: 300,
    };
    setFormData({ ...formData, steps: [...formData.steps, newStep] });
  };

  const removeStep = (index: number) => {
    if (formData.steps.length > 1) {
      const newSteps = formData.steps.filter((_, i) => i !== index);
      setFormData({ ...formData, steps: newSteps });
    }
  };

  const updateStep = (index: number, field: keyof PlaybookStepInput, value: string | number) => {
    const newSteps = [...formData.steps];
    newSteps[index] = { ...newSteps[index], [field]: value };
    setFormData({ ...formData, steps: newSteps });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
          <input
            type="text"
            required
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
            placeholder="Playbook name..."
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
          <select
            value={formData.category}
            onChange={(e) => setFormData({ ...formData, category: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="incident_response">Incident Response</option>
            <option value="threat_hunting">Threat Hunting</option>
            <option value="compliance">Compliance</option>
            <option value="enrichment">Enrichment</option>
            <option value="remediation">Remediation</option>
            <option value="notification">Notification</option>
            <option value="custom">Custom</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          rows={2}
          placeholder="What does this playbook do?"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Trigger Type</label>
        <select
          value={formData.trigger_type}
          onChange={(e) => setFormData({ ...formData, trigger_type: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
        >
          <option value="manual">Manual</option>
          <option value="alert">Alert-Based</option>
          <option value="schedule">Scheduled</option>
          <option value="webhook">Webhook</option>
          <option value="ioc">IOC Match</option>
          <option value="event">Event-Based</option>
        </select>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-medium text-gray-300">Steps</label>
          <button
            type="button"
            onClick={addStep}
            className="text-cyan-400 hover:text-cyan-300 text-sm flex items-center gap-1"
          >
            <Plus className="w-4 h-4" /> Add Step
          </button>
        </div>
        <div className="space-y-2 max-h-60 overflow-y-auto">
          {formData.steps.map((step, index) => (
            <div key={step.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
              <div className="flex items-start gap-3">
                <span className="text-gray-500 text-sm font-mono mt-2">{index + 1}</span>
                <div className="flex-1 grid grid-cols-3 gap-2">
                  <input
                    type="text"
                    value={step.name}
                    onChange={(e) => updateStep(index, 'name', e.target.value)}
                    className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    placeholder="Step name"
                  />
                  <select
                    value={step.action_type}
                    onChange={(e) => updateStep(index, 'action_type', e.target.value)}
                    className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                  >
                    <option value="http_request">HTTP Request</option>
                    <option value="send_notification">Send Notification</option>
                    <option value="create_case">Create Case</option>
                    <option value="enrich_ioc">Enrich IOC</option>
                    <option value="run_script">Run Script</option>
                    <option value="block_ip">Block IP</option>
                    <option value="isolate_host">Isolate Host</option>
                    <option value="create_ticket">Create Ticket</option>
                    <option value="wait_approval">Wait for Approval</option>
                    <option value="set_variable">Set Variable</option>
                    <option value="wait">Wait</option>
                  </select>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      value={step.timeout_seconds}
                      onChange={(e) => updateStep(index, 'timeout_seconds', parseInt(e.target.value) || 300)}
                      className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-white text-sm w-20"
                      min={1}
                    />
                    <span className="text-gray-500 text-xs">sec</span>
                    {formData.steps.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeStep(index)}
                        className="p-1 hover:bg-red-500/20 rounded text-gray-400 hover:text-red-400"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
        <button
          type="button"
          onClick={onCancel}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
          Create Playbook
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Create Feed Form
// ============================================================================

interface CreateFeedFormData {
  name: string;
  feed_type: string;
  url: string;
  poll_interval_minutes: number;
}

const CreateFeedForm: React.FC<{
  onSubmit: (data: CreateFeedFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState<CreateFeedFormData>({
    name: '',
    feed_type: 'stix',
    url: '',
    poll_interval_minutes: 60,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Feed Name *</label>
        <input
          type="text"
          required
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          placeholder="e.g., AlienVault OTX"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Feed Type</label>
          <select
            value={formData.feed_type}
            onChange={(e) => setFormData({ ...formData, feed_type: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          >
            <option value="stix">STIX</option>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="taxii">TAXII</option>
            <option value="misp">MISP</option>
            <option value="openioc">OpenIOC</option>
            <option value="custom">Custom</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Poll Interval</label>
          <div className="flex items-center gap-2">
            <input
              type="number"
              value={formData.poll_interval_minutes}
              onChange={(e) => setFormData({ ...formData, poll_interval_minutes: parseInt(e.target.value) || 60 })}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
              min={5}
            />
            <span className="text-gray-400 text-sm whitespace-nowrap">minutes</span>
          </div>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Feed URL *</label>
        <input
          type="url"
          required
          value={formData.url}
          onChange={(e) => setFormData({ ...formData, url: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
          placeholder="https://example.com/feed.json"
        />
      </div>

      <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
        <button
          type="button"
          onClick={onCancel}
          disabled={isLoading}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
          Create Feed
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Case Detail Modal
// ============================================================================

const CaseDetailModal: React.FC<{
  caseData: SoarCase;
  onClose: () => void;
}> = ({ caseData, onClose }) => {
  const queryClient = useQueryClient();
  const [newComment, setNewComment] = useState('');
  const [isInternalComment, setIsInternalComment] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'details' | 'tasks' | 'comments' | 'timeline'>('details');

  // Fetch tasks
  const { data: tasks } = useQuery({
    queryKey: ['case-tasks', caseData.id],
    queryFn: () => greenTeamAPI.getCaseTasks(caseData.id).then((r) => r.data),
  });

  // Fetch comments
  const { data: comments } = useQuery({
    queryKey: ['case-comments', caseData.id],
    queryFn: () => greenTeamAPI.getCaseComments(caseData.id).then((r) => r.data),
  });

  // Fetch timeline
  const { data: timeline } = useQuery({
    queryKey: ['case-timeline', caseData.id],
    queryFn: () => greenTeamAPI.getCaseTimeline(caseData.id).then((r) => r.data),
  });

  // Add comment mutation
  const addCommentMutation = useMutation({
    mutationFn: (data: { content: string; is_internal: boolean }) =>
      greenTeamAPI.addCaseComment(caseData.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-comments', caseData.id] });
      queryClient.invalidateQueries({ queryKey: ['case-timeline', caseData.id] });
      setNewComment('');
      toast.success('Comment added');
    },
    onError: () => toast.error('Failed to add comment'),
  });

  const handleAddComment = (e: React.FormEvent) => {
    e.preventDefault();
    if (newComment.trim()) {
      addCommentMutation.mutate({ content: newComment, is_internal: isInternalComment });
    }
  };

  return (
    <div className="space-y-4">
      {/* Case Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-gray-500 font-mono text-sm">{caseData.case_number}</span>
            <TlpBadge tlp={caseData.tlp} />
          </div>
          <h3 className="text-xl font-semibold text-white">{caseData.title}</h3>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={caseData.severity} />
          <StatusBadge status={caseData.status} />
          <PriorityBadge priority={caseData.priority} />
        </div>
      </div>

      {/* Sub-tabs */}
      <div className="border-b border-gray-700">
        <nav className="flex gap-4">
          {(['details', 'tasks', 'comments', 'timeline'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveSubTab(tab)}
              className={`px-3 py-2 border-b-2 transition-colors text-sm ${
                activeSubTab === tab
                  ? 'border-cyan-500 text-cyan-500'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              {tab === 'tasks' && tasks && <span className="ml-1 text-gray-500">({tasks.length})</span>}
              {tab === 'comments' && comments && <span className="ml-1 text-gray-500">({comments.length})</span>}
            </button>
          ))}
        </nav>
      </div>

      {/* Sub-tab content */}
      <div className="min-h-[300px]">
        {activeSubTab === 'details' && (
          <div className="space-y-4">
            {caseData.description && (
              <div>
                <label className="text-sm text-gray-500">Description</label>
                <p className="text-gray-300 mt-1">{caseData.description}</p>
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Case Type</label>
                <p className="text-white mt-1">{caseData.case_type.replace(/_/g, ' ')}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Source</label>
                <p className="text-white mt-1">{caseData.source || 'Manual'}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Created</label>
                <p className="text-white mt-1">{new Date(caseData.created_at).toLocaleString()}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Last Updated</label>
                <p className="text-white mt-1">{new Date(caseData.updated_at).toLocaleString()}</p>
              </div>
            </div>
            {caseData.tags.length > 0 && (
              <div>
                <label className="text-sm text-gray-500">Tags</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {caseData.tags.map((tag, i) => (
                    <span key={i} className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'tasks' && (
          <div className="space-y-2">
            {tasks && tasks.length > 0 ? (
              tasks.map((task: CaseTask) => (
                <div key={task.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="text-white font-medium">{task.title}</h4>
                      {task.description && (
                        <p className="text-gray-400 text-sm mt-1">{task.description}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <StatusBadge status={task.status} />
                      <PriorityBadge priority={task.priority} />
                    </div>
                  </div>
                  {task.due_at && (
                    <p className="text-gray-500 text-xs mt-2">
                      Due: {new Date(task.due_at).toLocaleString()}
                    </p>
                  )}
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <ListTodo className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No tasks yet</p>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'comments' && (
          <div className="space-y-4">
            <form onSubmit={handleAddComment} className="flex gap-2">
              <input
                type="text"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                placeholder="Add a comment..."
              />
              <label className="flex items-center gap-1 text-gray-400 text-sm">
                <input
                  type="checkbox"
                  checked={isInternalComment}
                  onChange={(e) => setIsInternalComment(e.target.checked)}
                  className="rounded border-gray-600 bg-gray-800 text-cyan-500"
                />
                Internal
              </label>
              <button
                type="submit"
                disabled={!newComment.trim() || addCommentMutation.isPending}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                Add
              </button>
            </form>
            <div className="space-y-2">
              {comments && comments.length > 0 ? (
                comments.map((comment: CaseComment) => (
                  <div
                    key={comment.id}
                    className={`bg-gray-900 border rounded-lg p-3 ${
                      comment.is_internal ? 'border-yellow-500/30' : 'border-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
                      <span>{new Date(comment.created_at).toLocaleString()}</span>
                      {comment.is_internal && (
                        <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 rounded">
                          Internal
                        </span>
                      )}
                    </div>
                    <p className="text-gray-300">{comment.content}</p>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <MessageSquare className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No comments yet</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeSubTab === 'timeline' && (
          <div className="space-y-2">
            {timeline && timeline.length > 0 ? (
              timeline.map((event: CaseTimelineEvent) => (
                <div key={event.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 bg-cyan-500 rounded-full mt-2" />
                    <div className="flex-1 w-px bg-gray-700" />
                  </div>
                  <div className="pb-4">
                    <p className="text-xs text-gray-500 mb-1">
                      {new Date(event.created_at).toLocaleString()}
                    </p>
                    <p className="text-gray-300">{event.event_type.replace(/_/g, ' ')}</p>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Clock className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No timeline events</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

export default function GreenTeamPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('cases');
  const [showCreateCaseModal, setShowCreateCaseModal] = useState(false);
  const [showCreatePlaybookModal, setShowCreatePlaybookModal] = useState(false);
  const [showCreateFeedModal, setShowCreateFeedModal] = useState(false);
  const [selectedCase, setSelectedCase] = useState<SoarCase | null>(null);
  const [caseStatusFilter, setCaseStatusFilter] = useState<string>('');
  const [caseSeverityFilter, setCaseSeverityFilter] = useState<string>('');

  // Fetch cases
  const { data: cases, isLoading: casesLoading } = useQuery({
    queryKey: ['green-team-cases', caseStatusFilter, caseSeverityFilter],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (caseStatusFilter) params.status = caseStatusFilter;
      if (caseSeverityFilter) params.severity = caseSeverityFilter;
      return greenTeamAPI.listCases(params).then((r) => r.data);
    },
    enabled: activeTab === 'cases',
  });

  // Fetch playbooks
  const { data: playbooks, isLoading: playbooksLoading } = useQuery({
    queryKey: ['green-team-playbooks'],
    queryFn: () => greenTeamAPI.listPlaybooks().then((r) => r.data),
    enabled: activeTab === 'playbooks',
  });

  // Fetch feeds
  const { data: feeds, isLoading: feedsLoading } = useQuery({
    queryKey: ['green-team-feeds'],
    queryFn: () => greenTeamAPI.listFeeds().then((r) => r.data),
    enabled: activeTab === 'feeds',
  });

  // Fetch metrics
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    queryKey: ['green-team-metrics'],
    queryFn: () => greenTeamAPI.getMetricsOverview().then((r) => r.data),
    enabled: activeTab === 'metrics',
  });

  // Create case mutation
  const createCaseMutation = useMutation({
    mutationFn: (data: CreateCaseRequest) => greenTeamAPI.createCase(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['green-team-cases'] });
      queryClient.invalidateQueries({ queryKey: ['green-team-metrics'] });
      setShowCreateCaseModal(false);
      toast.success('Case created successfully');
    },
    onError: () => toast.error('Failed to create case'),
  });

  // Create playbook mutation
  const createPlaybookMutation = useMutation({
    mutationFn: (data: CreatePlaybookFormData) => greenTeamAPI.createPlaybook({
      name: data.name,
      description: data.description,
      category: data.category,
      trigger_type: data.trigger_type,
      steps: data.steps.map(s => ({
        id: s.id,
        name: s.name,
        action: { type: s.action_type },
        timeout_seconds: s.timeout_seconds,
      })),
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['green-team-playbooks'] });
      setShowCreatePlaybookModal(false);
      toast.success('Playbook created successfully');
    },
    onError: () => toast.error('Failed to create playbook'),
  });

  // Create feed mutation
  const createFeedMutation = useMutation({
    mutationFn: (data: CreateFeedFormData) => greenTeamAPI.createFeed(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['green-team-feeds'] });
      setShowCreateFeedModal(false);
      toast.success('Feed created successfully');
    },
    onError: () => toast.error('Failed to create feed'),
  });

  // Run playbook mutation
  const runPlaybookMutation = useMutation({
    mutationFn: (id: string) => greenTeamAPI.runPlaybook(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['green-team-playbooks'] });
      toast.success('Playbook execution started');
    },
    onError: () => toast.error('Failed to run playbook'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'cases', label: 'Cases', icon: <Briefcase className="w-4 h-4" /> },
    { id: 'playbooks', label: 'Playbooks', icon: <Workflow className="w-4 h-4" /> },
    { id: 'feeds', label: 'IOC Feeds', icon: <Database className="w-4 h-4" /> },
    { id: 'metrics', label: 'Metrics', icon: <BarChart3 className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-500" />
              Green Team - SOAR
            </h1>
            <p className="text-gray-400 mt-1">
              Security Orchestration, Automation & Response
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-500'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div>
          {/* Cases Tab */}
          {activeTab === 'cases' && (
            <div className="space-y-4">
              {/* Filters and Actions */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <select
                    value={caseStatusFilter}
                    onChange={(e) => setCaseStatusFilter(e.target.value)}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                  >
                    <option value="">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="pending">Pending</option>
                    <option value="resolved">Resolved</option>
                    <option value="closed">Closed</option>
                  </select>
                  <select
                    value={caseSeverityFilter}
                    onChange={(e) => setCaseSeverityFilter(e.target.value)}
                    className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500"
                  >
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="informational">Informational</option>
                  </select>
                </div>
                <button
                  onClick={() => setShowCreateCaseModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  New Case
                </button>
              </div>

              {/* Cases List */}
              {casesLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : cases && cases.length > 0 ? (
                <div className="space-y-3">
                  {cases.map((c: SoarCase) => (
                    <div
                      key={c.id}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors"
                      onClick={() => setSelectedCase(c)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-gray-500 font-mono text-sm">{c.case_number}</span>
                            <TlpBadge tlp={c.tlp} />
                          </div>
                          <h3 className="text-lg font-medium text-white">{c.title}</h3>
                          {c.description && (
                            <p className="text-sm text-gray-400 mt-1 line-clamp-2">{c.description}</p>
                          )}
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(c.created_at).toLocaleDateString()}
                            </span>
                            <span>{c.case_type.replace(/_/g, ' ')}</span>
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={c.severity} />
                            <StatusBadge status={c.status} />
                          </div>
                          <PriorityBadge priority={c.priority} />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Briefcase className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Cases Found</h3>
                  <p className="text-gray-400 mb-6">
                    Create your first security case to start managing incidents
                  </p>
                  <button
                    onClick={() => setShowCreateCaseModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Create Case
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Playbooks Tab */}
          {activeTab === 'playbooks' && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => setShowCreatePlaybookModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  New Playbook
                </button>
              </div>

              {playbooksLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : playbooks && playbooks.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {playbooks.map((pb: Playbook) => (
                    <div
                      key={pb.id}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="text-lg font-medium text-white">{pb.name}</h3>
                          {pb.description && (
                            <p className="text-sm text-gray-400 mt-1">{pb.description}</p>
                          )}
                        </div>
                        <span className={`px-2 py-0.5 rounded text-xs ${pb.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                          {pb.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-500 mb-3">
                        <span className="px-2 py-0.5 bg-gray-700 rounded">{pb.category.replace(/_/g, ' ')}</span>
                        <span>{pb.steps.length} steps</span>
                        <span>v{pb.version}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => runPlaybookMutation.mutate(pb.id)}
                          disabled={!pb.is_active || runPlaybookMutation.isPending}
                          className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded transition-colors disabled:opacity-50"
                        >
                          <Play className="w-3 h-3" />
                          Run
                        </button>
                        <button className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded transition-colors">
                          <Eye className="w-3 h-3" />
                          View
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Workflow className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Playbooks</h3>
                  <p className="text-gray-400 mb-6">
                    Create automation playbooks to streamline your security operations
                  </p>
                  <button
                    onClick={() => setShowCreatePlaybookModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Create Playbook
                  </button>
                </div>
              )}
            </div>
          )}

          {/* IOC Feeds Tab */}
          {activeTab === 'feeds' && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button
                  onClick={() => setShowCreateFeedModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Add Feed
                </button>
              </div>

              {feedsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : feeds && feeds.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Name</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Type</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">IOCs</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Poll Interval</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Last Poll</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {feeds.map((feed: IocFeed) => (
                        <tr key={feed.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4">
                            <div>
                              <p className="font-medium text-white">{feed.name}</p>
                              {feed.description && (
                                <p className="text-xs text-gray-500 truncate max-w-xs">{feed.description}</p>
                              )}
                            </div>
                          </td>
                          <td className="p-4">
                            <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                              {feed.feed_type.toUpperCase()}
                            </span>
                          </td>
                          <td className="p-4 text-gray-400">{feed.ioc_count.toLocaleString()}</td>
                          <td className="p-4 text-gray-400">{feed.poll_interval_minutes}m</td>
                          <td className="p-4 text-gray-500 text-sm">
                            {feed.last_poll_at ? new Date(feed.last_poll_at).toLocaleString() : 'Never'}
                          </td>
                          <td className="p-4">
                            <span className={`px-2 py-0.5 rounded text-xs ${feed.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>
                              {feed.is_active ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                          <td className="p-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button className="p-2 hover:bg-gray-700 rounded-lg text-gray-400 hover:text-white">
                                <RefreshCw className="w-4 h-4" />
                              </button>
                              <button className="p-2 hover:bg-gray-700 rounded-lg text-gray-400 hover:text-white">
                                <ExternalLink className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Rss className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No IOC Feeds</h3>
                  <p className="text-gray-400 mb-6">
                    Add threat intelligence feeds to automatically ingest IOCs
                  </p>
                  <button
                    onClick={() => setShowCreateFeedModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Add Feed
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Metrics Tab */}
          {activeTab === 'metrics' && (
            <div className="space-y-6">
              {metricsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : metrics ? (
                <>
                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div
                      onClick={() => setActiveTab('cases')}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer hover:border-cyan-500/50 hover:bg-gray-750 transition-all group"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-blue-500/20 rounded-lg">
                          <Briefcase className="w-6 h-6 text-blue-400" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm text-gray-400">Total Cases</p>
                          <p className="text-2xl font-bold text-white">{metrics.total_cases}</p>
                          <p className="text-xs text-yellow-400">{metrics.open_cases} open</p>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />
                      </div>
                    </div>

                    <div
                      onClick={() => {
                        setCaseStatusFilter('resolved');
                        setActiveTab('cases');
                      }}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer hover:border-cyan-500/50 hover:bg-gray-750 transition-all group"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-green-500/20 rounded-lg">
                          <CheckCircle className="w-6 h-6 text-green-400" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm text-gray-400">Resolved Today</p>
                          <p className="text-2xl font-bold text-white">{metrics.resolved_today}</p>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-cyan-500/20 rounded-lg">
                          <Timer className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-sm text-gray-400">Avg MTTR</p>
                          <p className="text-2xl font-bold text-white">
                            {metrics.avg_mttr_minutes < 60
                              ? `${Math.round(metrics.avg_mttr_minutes)}m`
                              : `${(metrics.avg_mttr_minutes / 60).toFixed(1)}h`}
                          </p>
                          <p className="text-xs text-gray-500">Mean Time to Resolve</p>
                        </div>
                      </div>
                    </div>

                    <div
                      onClick={() => setActiveTab('playbooks')}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer hover:border-cyan-500/50 hover:bg-gray-750 transition-all group"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-purple-500/20 rounded-lg">
                          <TrendingUp className="w-6 h-6 text-purple-400" />
                        </div>
                        <div className="flex-1">
                          <p className="text-sm text-gray-400">SLA Compliance</p>
                          <p className="text-2xl font-bold text-white">
                            {(metrics.sla_compliance_rate * 100).toFixed(1)}%
                          </p>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />
                      </div>
                    </div>
                  </div>

                  {/* Additional Metrics */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Response Metrics</h3>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400">Mean Time to Detect (MTTD)</span>
                          <span className="text-white font-medium">
                            {metrics.avg_mttd_minutes < 60
                              ? `${Math.round(metrics.avg_mttd_minutes)} min`
                              : `${(metrics.avg_mttd_minutes / 60).toFixed(1)} hours`}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400">Mean Time to Respond (MTTR)</span>
                          <span className="text-white font-medium">
                            {metrics.avg_mttr_minutes < 60
                              ? `${Math.round(metrics.avg_mttr_minutes)} min`
                              : `${(metrics.avg_mttr_minutes / 60).toFixed(1)} hours`}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400">Playbooks Executed</span>
                          <span className="text-white font-medium">{metrics.playbooks_executed}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-gray-400">Automation Rate</span>
                          <span className="text-white font-medium">
                            {(metrics.automation_rate * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Case Distribution</h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-green-400">{metrics.resolved_today}</p>
                          <p className="text-sm text-gray-400">Resolved Today</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-yellow-400">{metrics.open_cases}</p>
                          <p className="text-sm text-gray-400">Open Cases</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-cyan-400">{metrics.playbooks_executed}</p>
                          <p className="text-sm text-gray-400">Playbooks Run</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-purple-400">
                            {(metrics.sla_compliance_rate * 100).toFixed(0)}%
                          </p>
                          <p className="text-sm text-gray-400">SLA Met</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <BarChart3 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Metrics Available</h3>
                  <p className="text-gray-400">
                    Start creating cases and running playbooks to see metrics
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showCreateCaseModal}
          onClose={() => setShowCreateCaseModal(false)}
          title="Create New Case"
        >
          <CreateCaseForm
            onSubmit={(data) => createCaseMutation.mutate(data)}
            onCancel={() => setShowCreateCaseModal(false)}
            isLoading={createCaseMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={showCreatePlaybookModal}
          onClose={() => setShowCreatePlaybookModal(false)}
          title="Create New Playbook"
          size="lg"
        >
          <CreatePlaybookForm
            onSubmit={(data) => createPlaybookMutation.mutate(data)}
            onCancel={() => setShowCreatePlaybookModal(false)}
            isLoading={createPlaybookMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={showCreateFeedModal}
          onClose={() => setShowCreateFeedModal(false)}
          title="Add IOC Feed"
        >
          <CreateFeedForm
            onSubmit={(data) => createFeedMutation.mutate(data)}
            onCancel={() => setShowCreateFeedModal(false)}
            isLoading={createFeedMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={!!selectedCase}
          onClose={() => setSelectedCase(null)}
          title="Case Details"
          size="lg"
        >
          {selectedCase && (
            <CaseDetailModal caseData={selectedCase} onClose={() => setSelectedCase(null)} />
          )}
        </Modal>
      </div>
    </Layout>
  );
}
