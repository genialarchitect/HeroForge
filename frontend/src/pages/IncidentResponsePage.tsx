import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  AlertTriangle,
  Clock,
  Shield,
  Users,
  Plus,
  RefreshCw,
  Eye,
  CheckCircle,
  XCircle,
  AlertCircle,
  X,
  FileText,
  Play,
  Pause,
  ChevronRight,
  MessageSquare,
  Upload,
  Link2,
  Activity,
  BarChart3,
  Zap,
  Target,
  TrendingUp,
  Calendar,
  Filter,
  Search,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'dashboard' | 'incidents' | 'timeline' | 'playbooks';

// ============================================================================
// Types
// ============================================================================

interface Incident {
  id: string;
  incident_number: string;
  title: string;
  description?: string;
  severity: string; // P1, P2, P3, P4
  status: string; // detected, triaged, contained, eradicated, recovered, closed
  classification?: string;
  source?: string;
  affected_systems: string[];
  assigned_to?: string;
  commander_id?: string;
  tags: string[];
  detected_at: string;
  reported_at: string;
  triaged_at?: string;
  contained_at?: string;
  eradicated_at?: string;
  recovered_at?: string;
  closed_at?: string;
  created_at: string;
  updated_at: string;
}

interface TimelineEvent {
  id: string;
  incident_id: string;
  event_type: string;
  title: string;
  description?: string;
  occurred_at: string;
  recorded_by: string;
  evidence_ids: string[];
  metadata?: Record<string, unknown>;
  created_at: string;
}

interface Evidence {
  id: string;
  incident_id: string;
  name: string;
  evidence_type: string;
  description?: string;
  file_path?: string;
  file_hash?: string;
  source?: string;
  collected_by: string;
  collected_at: string;
  chain_of_custody: CustodyRecord[];
  created_at: string;
}

interface CustodyRecord {
  action: string;
  user_id: string;
  timestamp: string;
  notes?: string;
}

interface IrPlaybook {
  id: string;
  name: string;
  description?: string;
  incident_types: string[];
  severity_levels: string[];
  steps: PlaybookStep[];
  is_active: boolean;
  version: string;
  created_at: string;
}

interface PlaybookStep {
  order: number;
  title: string;
  description: string;
  action_type: string;
  responsible_role?: string;
  estimated_duration_minutes?: number;
  required: boolean;
}

interface ResponseAction {
  id: string;
  incident_id: string;
  action_type: string;
  title: string;
  description?: string;
  status: string;
  assigned_to?: string;
  requires_approval: boolean;
  approved_by?: string;
  approved_at?: string;
  started_at?: string;
  completed_at?: string;
  result?: string;
  created_at: string;
}

interface IncidentDashboard {
  total_incidents: number;
  open_incidents: number;
  incidents_by_severity: Array<{ severity: string; count: number }>;
  incidents_by_status: Array<{ status: string; count: number }>;
  incidents_by_classification: Array<{ classification: string; count: number }>;
  sla_breaches: number;
  mean_time_to_contain_hours: number | null;
  mean_time_to_close_hours: number | null;
  recent_incidents: Incident[];
  pending_actions: number;
}

// ============================================================================
// API Functions
// ============================================================================

const incidentAPI = {
  getDashboard: () => api.get<IncidentDashboard>('/incidents/dashboard').then(r => r.data),

  // Incidents
  listIncidents: (params?: Record<string, string>) =>
    api.get<Incident[]>('/incidents', { params }).then(r => r.data),
  createIncident: (data: { title: string; description?: string; severity: string; classification?: string; affected_systems?: string[] }) =>
    api.post<Incident>('/incidents', data).then(r => r.data),
  getIncident: (id: string) => api.get<Incident>(`/incidents/${id}`).then(r => r.data),
  updateIncident: (id: string, data: Partial<Incident>) =>
    api.put<Incident>(`/incidents/${id}`, data).then(r => r.data),
  transitionIncident: (id: string, status: string, notes?: string) =>
    api.post<Incident>(`/incidents/${id}/transition`, { status, notes }).then(r => r.data),
  assignIncident: (id: string, userId: string) =>
    api.post<Incident>(`/incidents/${id}/assign`, { user_id: userId }).then(r => r.data),

  // Timeline
  getTimeline: (incidentId: string) =>
    api.get<TimelineEvent[]>(`/incidents/${incidentId}/timeline`).then(r => r.data),
  addTimelineEvent: (incidentId: string, data: { event_type: string; title: string; description?: string; occurred_at: string }) =>
    api.post<TimelineEvent>(`/incidents/${incidentId}/timeline`, data).then(r => r.data),

  // Evidence
  listEvidence: (incidentId: string) =>
    api.get<Evidence[]>(`/incidents/${incidentId}/evidence`).then(r => r.data),
  addEvidence: (incidentId: string, data: { name: string; evidence_type: string; description?: string; source?: string }) =>
    api.post<Evidence>(`/incidents/${incidentId}/evidence`, data).then(r => r.data),

  // Playbooks
  listPlaybooks: () => api.get<IrPlaybook[]>('/incidents/playbooks').then(r => r.data),
  createPlaybook: (data: { name: string; description?: string; incident_types: string[]; severity_levels: string[]; steps: PlaybookStep[] }) =>
    api.post<IrPlaybook>('/incidents/playbooks', data).then(r => r.data),
  activatePlaybook: (incidentId: string, playbookId: string) =>
    api.post(`/incidents/${incidentId}/playbooks/${playbookId}/activate`).then(r => r.data),

  // Actions
  listActions: (incidentId: string) =>
    api.get<ResponseAction[]>(`/incidents/${incidentId}/actions`).then(r => r.data),
  createAction: (incidentId: string, data: { action_type: string; title: string; description?: string; requires_approval?: boolean }) =>
    api.post<ResponseAction>(`/incidents/${incidentId}/actions`, data).then(r => r.data),
  approveAction: (incidentId: string, actionId: string) =>
    api.post(`/incidents/${incidentId}/actions/${actionId}/approve`).then(r => r.data),
  completeAction: (incidentId: string, actionId: string, result: string) =>
    api.post(`/incidents/${incidentId}/actions/${actionId}/complete`, { result }).then(r => r.data),
};

// ============================================================================
// Badge Components
// ============================================================================

const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  p1: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
  p2: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  p3: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  p4: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  detected: { bg: 'bg-red-500/20', text: 'text-red-400' },
  triaged: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  contained: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  eradicated: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  recovered: { bg: 'bg-green-500/20', text: 'text-green-400' },
  closed: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
};

const actionStatusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  pending_approval: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  approved: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  in_progress: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

function SeverityBadge({ severity }: { severity: string }) {
  const colors = severityColors[severity.toLowerCase()] || severityColors.p4;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold ${colors.bg} ${colors.text} border ${colors.border}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.detected;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function ActionStatusBadge({ status }: { status: string }) {
  const colors = actionStatusColors[status.toLowerCase()] || actionStatusColors.pending;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
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
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

// ============================================================================
// Create Incident Form
// ============================================================================

const CreateIncidentForm: React.FC<{
  onSubmit: (data: { title: string; description?: string; severity: string; classification?: string; affected_systems?: string[] }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'p3',
    classification: '',
    affected_systems: '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      ...formData,
      affected_systems: formData.affected_systems ? formData.affected_systems.split(',').map(s => s.trim()) : [],
    });
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
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="Brief incident title..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          rows={3}
          placeholder="Detailed incident description..."
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Severity *</label>
          <select
            value={formData.severity}
            onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          >
            <option value="p1">P1 - Critical (Business Impact)</option>
            <option value="p2">P2 - High (Major Disruption)</option>
            <option value="p3">P3 - Medium (Limited Impact)</option>
            <option value="p4">P4 - Low (Minimal Impact)</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Classification</label>
          <select
            value={formData.classification}
            onChange={(e) => setFormData({ ...formData, classification: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">Select classification...</option>
            <option value="malware">Malware</option>
            <option value="phishing">Phishing</option>
            <option value="ransomware">Ransomware</option>
            <option value="data_breach">Data Breach</option>
            <option value="unauthorized_access">Unauthorized Access</option>
            <option value="dos">Denial of Service</option>
            <option value="insider_threat">Insider Threat</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Affected Systems</label>
        <input
          type="text"
          value={formData.affected_systems}
          onChange={(e) => setFormData({ ...formData, affected_systems: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="server1.example.com, db-prod-01 (comma-separated)"
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
          className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
          Declare Incident
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Incident Detail View
// ============================================================================

const IncidentDetailView: React.FC<{
  incident: Incident;
  onClose: () => void;
}> = ({ incident, onClose }) => {
  const queryClient = useQueryClient();
  const [activeSubTab, setActiveSubTab] = useState<'details' | 'timeline' | 'evidence' | 'actions'>('details');
  const [newEventTitle, setNewEventTitle] = useState('');

  // Fetch timeline
  const { data: timeline } = useQuery({
    queryKey: ['incident-timeline', incident.id],
    queryFn: () => incidentAPI.getTimeline(incident.id),
  });

  // Fetch evidence
  const { data: evidence } = useQuery({
    queryKey: ['incident-evidence', incident.id],
    queryFn: () => incidentAPI.listEvidence(incident.id),
  });

  // Fetch actions
  const { data: actions } = useQuery({
    queryKey: ['incident-actions', incident.id],
    queryFn: () => incidentAPI.listActions(incident.id),
  });

  // Transition mutation
  const transitionMutation = useMutation({
    mutationFn: ({ status, notes }: { status: string; notes?: string }) =>
      incidentAPI.transitionIncident(incident.id, status, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['incident-timeline', incident.id] });
      toast.success('Incident status updated');
    },
    onError: () => toast.error('Failed to update incident status'),
  });

  // Add timeline event mutation
  const addEventMutation = useMutation({
    mutationFn: (data: { event_type: string; title: string; occurred_at: string }) =>
      incidentAPI.addTimelineEvent(incident.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident-timeline', incident.id] });
      setNewEventTitle('');
      toast.success('Timeline event added');
    },
    onError: () => toast.error('Failed to add event'),
  });

  const getNextStatus = (current: string): string | null => {
    const flow: Record<string, string> = {
      detected: 'triaged',
      triaged: 'contained',
      contained: 'eradicated',
      eradicated: 'recovered',
      recovered: 'closed',
    };
    return flow[current] || null;
  };

  const nextStatus = getNextStatus(incident.status);

  return (
    <div className="space-y-4">
      {/* Incident Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-gray-500 font-mono text-sm">{incident.incident_number}</span>
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
          <h3 className="text-xl font-semibold text-white">{incident.title}</h3>
        </div>
        {nextStatus && incident.status !== 'closed' && (
          <button
            onClick={() => transitionMutation.mutate({ status: nextStatus })}
            disabled={transitionMutation.isPending}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <ChevronRight className="w-4 h-4" />
            Move to {nextStatus.charAt(0).toUpperCase() + nextStatus.slice(1)}
          </button>
        )}
      </div>

      {/* Status Timeline Bar */}
      <div className="flex items-center gap-1 p-4 bg-gray-900 rounded-lg">
        {['detected', 'triaged', 'contained', 'eradicated', 'recovered', 'closed'].map((status, i, arr) => {
          const isActive = incident.status === status;
          const isPast = arr.indexOf(incident.status) > i;
          return (
            <React.Fragment key={status}>
              <div
                className={`flex-1 h-2 rounded-full ${
                  isActive ? 'bg-cyan-500' : isPast ? 'bg-green-500' : 'bg-gray-700'
                }`}
              />
              {i < arr.length - 1 && <ChevronRight className="w-4 h-4 text-gray-600" />}
            </React.Fragment>
          );
        })}
      </div>

      {/* Sub-tabs */}
      <div className="border-b border-gray-700">
        <nav className="flex gap-4">
          {(['details', 'timeline', 'evidence', 'actions'] as const).map((tab) => (
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
              {tab === 'timeline' && timeline && <span className="ml-1 text-gray-500">({timeline.length})</span>}
              {tab === 'evidence' && evidence && <span className="ml-1 text-gray-500">({evidence.length})</span>}
              {tab === 'actions' && actions && <span className="ml-1 text-gray-500">({actions.length})</span>}
            </button>
          ))}
        </nav>
      </div>

      {/* Sub-tab content */}
      <div className="min-h-[300px]">
        {activeSubTab === 'details' && (
          <div className="space-y-4">
            {incident.description && (
              <div>
                <label className="text-sm text-gray-500">Description</label>
                <p className="text-gray-300 mt-1">{incident.description}</p>
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-500">Classification</label>
                <p className="text-white mt-1">{incident.classification || 'Not classified'}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Source</label>
                <p className="text-white mt-1">{incident.source || 'Unknown'}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Detected At</label>
                <p className="text-white mt-1">{new Date(incident.detected_at).toLocaleString()}</p>
              </div>
              <div>
                <label className="text-sm text-gray-500">Assigned To</label>
                <p className="text-white mt-1">{incident.assigned_to || 'Unassigned'}</p>
              </div>
            </div>
            {incident.affected_systems.length > 0 && (
              <div>
                <label className="text-sm text-gray-500">Affected Systems</label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {incident.affected_systems.map((system, i) => (
                    <span key={i} className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                      {system}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'timeline' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                value={newEventTitle}
                onChange={(e) => setNewEventTitle(e.target.value)}
                className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                placeholder="Add timeline event..."
              />
              <button
                onClick={() => {
                  if (newEventTitle.trim()) {
                    addEventMutation.mutate({
                      event_type: 'note',
                      title: newEventTitle,
                      occurred_at: new Date().toISOString(),
                    });
                  }
                }}
                disabled={!newEventTitle.trim() || addEventMutation.isPending}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
              >
                Add
              </button>
            </div>
            <div className="space-y-2">
              {timeline && timeline.length > 0 ? (
                timeline.map((event) => (
                  <div key={event.id} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="w-2 h-2 bg-cyan-500 rounded-full mt-2" />
                      <div className="flex-1 w-px bg-gray-700" />
                    </div>
                    <div className="pb-4 flex-1">
                      <div className="flex items-center gap-2 text-xs text-gray-500 mb-1">
                        <Clock className="w-3 h-3" />
                        {new Date(event.occurred_at).toLocaleString()}
                        <span className="px-1.5 py-0.5 bg-gray-700 rounded">{event.event_type}</span>
                      </div>
                      <p className="text-white font-medium">{event.title}</p>
                      {event.description && (
                        <p className="text-gray-400 text-sm mt-1">{event.description}</p>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Clock className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No timeline events yet</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeSubTab === 'evidence' && (
          <div className="space-y-2">
            {evidence && evidence.length > 0 ? (
              evidence.map((e) => (
                <div key={e.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="text-white font-medium">{e.name}</h4>
                      <p className="text-gray-400 text-sm mt-1">{e.evidence_type}</p>
                      {e.description && <p className="text-gray-500 text-sm">{e.description}</p>}
                    </div>
                    <span className="text-xs text-gray-500">
                      {new Date(e.collected_at).toLocaleString()}
                    </span>
                  </div>
                  {e.chain_of_custody.length > 0 && (
                    <div className="mt-2 pt-2 border-t border-gray-700">
                      <p className="text-xs text-gray-500">Chain of Custody: {e.chain_of_custody.length} records</p>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <FileText className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No evidence collected</p>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'actions' && (
          <div className="space-y-2">
            {actions && actions.length > 0 ? (
              actions.map((action) => (
                <div key={action.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-white font-medium">{action.title}</h4>
                        <ActionStatusBadge status={action.status} />
                      </div>
                      <p className="text-gray-400 text-sm mt-1">{action.action_type}</p>
                      {action.description && <p className="text-gray-500 text-sm">{action.description}</p>}
                    </div>
                    {action.requires_approval && !action.approved_at && (
                      <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs">
                        Needs Approval
                      </span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Zap className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No response actions</p>
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

export default function IncidentResponsePage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  // Fetch dashboard
  const { data: dashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ['incident-dashboard'],
    queryFn: () => incidentAPI.getDashboard(),
    enabled: activeTab === 'dashboard',
  });

  // Fetch incidents
  const { data: incidents, isLoading: incidentsLoading } = useQuery({
    queryKey: ['incidents', statusFilter, severityFilter],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      return incidentAPI.listIncidents(params);
    },
    enabled: activeTab === 'incidents',
  });

  // Fetch playbooks
  const { data: playbooks, isLoading: playbooksLoading } = useQuery({
    queryKey: ['ir-playbooks'],
    queryFn: () => incidentAPI.listPlaybooks(),
    enabled: activeTab === 'playbooks',
  });

  // Create incident mutation
  const createIncidentMutation = useMutation({
    mutationFn: incidentAPI.createIncident,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['incident-dashboard'] });
      setShowCreateModal(false);
      toast.success('Incident declared');
    },
    onError: () => toast.error('Failed to create incident'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 className="w-4 h-4" /> },
    { id: 'incidents', label: 'Incidents', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'timeline', label: 'Timeline', icon: <Clock className="w-4 h-4" /> },
    { id: 'playbooks', label: 'Playbooks', icon: <FileText className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-500" />
              Incident Response
            </h1>
            <p className="text-gray-400 mt-1">
              Manage security incidents from detection to resolution
            </p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Declare Incident
          </button>
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
          {/* Dashboard Tab */}
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {dashboardLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : dashboard ? (
                <>
                  {/* Key Metrics */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-red-500/20 rounded-lg">
                          <AlertTriangle className="w-6 h-6 text-red-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.open_incidents}</p>
                          <p className="text-xs text-gray-400">Open Incidents</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-orange-500/20 rounded-lg">
                          <Zap className="w-6 h-6 text-orange-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">
                            {dashboard.incidents_by_severity
                              .filter(s => s.severity.toLowerCase() === 'p1' || s.severity.toLowerCase() === 'p2')
                              .reduce((sum, s) => sum + s.count, 0)}
                          </p>
                          <p className="text-xs text-gray-400">P1/P2 Active</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-cyan-500/20 rounded-lg">
                          <Clock className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">
                            {dashboard.mean_time_to_contain_hours
                              ? (dashboard.mean_time_to_contain_hours < 1
                                  ? `${Math.round(dashboard.mean_time_to_contain_hours * 60)}m`
                                  : `${dashboard.mean_time_to_contain_hours.toFixed(1)}h`)
                              : 'N/A'}
                          </p>
                          <p className="text-xs text-gray-400">Avg MTTC</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-green-500/20 rounded-lg">
                          <CheckCircle className="w-6 h-6 text-green-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.total_incidents}</p>
                          <p className="text-xs text-gray-400">Total Incidents</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Distribution Charts */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">By Status</h3>
                      <div className="space-y-3">
                        {dashboard.incidents_by_status.map(({ status, count }) => (
                          <div key={status} className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <StatusBadge status={status} />
                            </div>
                            <span className="text-white font-medium">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">By Severity</h3>
                      <div className="space-y-3">
                        {dashboard.incidents_by_severity.map(({ severity, count }) => (
                          <div key={severity} className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={severity} />
                            </div>
                            <span className="text-white font-medium">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <BarChart3 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Dashboard Data</h3>
                  <p className="text-gray-400">Start tracking incidents to see metrics</p>
                </div>
              )}
            </div>
          )}

          {/* Incidents Tab */}
          {activeTab === 'incidents' && (
            <div className="space-y-4">
              {/* Filters */}
              <div className="flex items-center gap-4">
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Statuses</option>
                  <option value="detected">Detected</option>
                  <option value="triaged">Triaged</option>
                  <option value="contained">Contained</option>
                  <option value="eradicated">Eradicated</option>
                  <option value="recovered">Recovered</option>
                  <option value="closed">Closed</option>
                </select>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Severities</option>
                  <option value="p1">P1 - Critical</option>
                  <option value="p2">P2 - High</option>
                  <option value="p3">P3 - Medium</option>
                  <option value="p4">P4 - Low</option>
                </select>
              </div>

              {/* Incidents List */}
              {incidentsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : incidents && incidents.length > 0 ? (
                <div className="space-y-3">
                  {incidents.map((incident) => (
                    <div
                      key={incident.id}
                      onClick={() => setSelectedIncident(incident)}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-gray-500 font-mono text-sm">{incident.incident_number}</span>
                            <SeverityBadge severity={incident.severity} />
                            <StatusBadge status={incident.status} />
                          </div>
                          <h3 className="text-lg font-medium text-white">{incident.title}</h3>
                          {incident.description && (
                            <p className="text-sm text-gray-400 mt-1 line-clamp-2">{incident.description}</p>
                          )}
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(incident.detected_at).toLocaleString()}
                            </span>
                            {incident.classification && (
                              <span>{incident.classification.replace(/_/g, ' ')}</span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {incident.affected_systems.length > 0 && (
                            <span className="text-xs text-gray-500">
                              {incident.affected_systems.length} systems
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <AlertTriangle className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Incidents</h3>
                  <p className="text-gray-400 mb-6">No security incidents matching your filters</p>
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Declare Incident
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Playbooks Tab */}
          {activeTab === 'playbooks' && (
            <div className="space-y-4">
              {playbooksLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : playbooks && playbooks.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {playbooks.map((pb) => (
                    <div key={pb.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
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
                      <div className="flex flex-wrap gap-2 mb-3">
                        {pb.incident_types.map((type, i) => (
                          <span key={i} className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                            {type}
                          </span>
                        ))}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>{pb.steps.length} steps</span>
                        <span>v{pb.version}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Playbooks</h3>
                  <p className="text-gray-400">Create incident response playbooks to standardize your processes</p>
                </div>
              )}
            </div>
          )}

          {/* Timeline Tab */}
          {activeTab === 'timeline' && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
              <Clock className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-300 mb-2">Global Timeline</h3>
              <p className="text-gray-400">Select an incident to view its timeline</p>
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          title="Declare Security Incident"
        >
          <CreateIncidentForm
            onSubmit={(data) => createIncidentMutation.mutate(data)}
            onCancel={() => setShowCreateModal(false)}
            isLoading={createIncidentMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          title="Incident Details"
          size="lg"
        >
          {selectedIncident && (
            <IncidentDetailView incident={selectedIncident} onClose={() => setSelectedIncident(null)} />
          )}
        </Modal>
      </div>
    </Layout>
  );
}
