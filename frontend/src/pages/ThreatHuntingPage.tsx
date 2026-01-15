import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Crosshair,
  Search,
  Database,
  FileText,
  BarChart3,
  Plus,
  RefreshCw,
  Eye,
  Edit,
  CheckCircle,
  XCircle,
  AlertCircle,
  X,
  Upload,
  Download,
  Play,
  Target,
  Clock,
  Grid,
  AlertTriangle,
  Hash,
  Globe,
  Mail,
  Server,
  Link2,
  Filter,
  Trash2,
  Copy,
  Activity,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'iocs' | 'playbooks' | 'sessions' | 'mitre' | 'retrospective';

// ============================================================================
// Types
// ============================================================================

interface Ioc {
  id: string;
  ioc_type: string; // ip, domain, hash, url, email, registry
  value: string;
  severity: string;
  status: string; // active, expired, false_positive
  source?: string;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  tags: string[];
  enrichment_data?: Record<string, unknown>;
  created_by: string;
  created_at: string;
  expires_at?: string;
}

interface PlaybookStep {
  title: string;
  description: string;
  queries: PlaybookQuery[];
  expected_results: string[];
  evidence_checklist: string[];
  indicators: string[];
  decision_points: DecisionPoint[];
  duration_estimate: string;
}

interface PlaybookQuery {
  name: string;
  query: string;
  platform: string;
  description?: string;
}

interface DecisionPoint {
  condition: string;
  if_true: string;
  if_false: string;
}

interface HuntingPlaybook {
  id: string;
  name: string;
  description: string;
  category: string;
  difficulty: string;
  estimated_duration: string;
  steps: PlaybookStep[];
  tags: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  is_builtin: boolean;
  user_id?: string;
  version: string;
  created_at: string;
  updated_at: string;
}

interface HuntingSession {
  id: string;
  name: string;
  description?: string;
  playbook_id?: string;
  playbook_name?: string;
  status: string; // active, paused, completed, cancelled
  hunter_id: string;
  hypothesis: string;
  data_sources: string[];
  start_time: string;
  end_time?: string;
  findings_count: number;
  notes: string[];
  created_at: string;
}

interface HuntingFinding {
  id: string;
  session_id: string;
  title: string;
  description: string;
  severity: string;
  finding_type: string;
  evidence: string;
  iocs_found: string[];
  mitre_techniques: string[];
  recommendations: string;
  created_at: string;
}

interface MitreCoverage {
  tactic: string;
  tactic_name: string;
  techniques: TechniqueCoverage[];
}

interface TechniqueCoverage {
  id: string;
  name: string;
  playbook_count: number;
  hunt_count: number;
  last_hunted?: string;
}

interface RetrospectiveSearch {
  id: string;
  name: string;
  query: string;
  time_range_start: string;
  time_range_end: string;
  data_sources: string[];
  status: string;
  results_count: number;
  created_by: string;
  created_at: string;
  completed_at?: string;
}

interface IocStats {
  total: number;
  active: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  added_today: number;
  expired_today: number;
}

// ============================================================================
// API Functions
// ============================================================================

const huntingAPI = {
  // IOCs
  listIocs: (params?: Record<string, string>) =>
    api.get<Ioc[]>('/hunting/iocs', { params }).then(r => r.data),
  getIocStats: () => api.get<IocStats>('/hunting/iocs/stats').then(r => r.data),
  createIoc: (data: { ioc_type: string; value: string; severity: string; source?: string; tags?: string[]; expires_at?: string }) =>
    api.post<Ioc>('/hunting/iocs', data).then(r => r.data),
  updateIoc: (id: string, data: Partial<Ioc>) =>
    api.put<Ioc>(`/hunting/iocs/${id}`, data).then(r => r.data),
  deleteIoc: (id: string) => api.delete(`/hunting/iocs/${id}`),
  importIocs: (format: string, data: string) =>
    api.post('/hunting/iocs/import', { format, data }).then(r => r.data),
  exportIocs: (format: string, params?: Record<string, string>) =>
    api.get(`/hunting/iocs/export/${format}`, { params, responseType: 'blob' }),
  matchIocs: (data: string) =>
    api.post<{ matches: Ioc[] }>('/hunting/iocs/match', { data }).then(r => r.data),

  // Playbooks
  listPlaybooks: (params?: Record<string, string>) =>
    api.get<{ playbooks: HuntingPlaybook[]; count: number }>('/hunting/playbooks', { params }).then(r => r.data.playbooks),
  createPlaybook: (data: { name: string; description?: string; category: string; hypothesis: string; data_sources: string[]; queries: PlaybookQuery[]; mitre_techniques?: string[]; success_criteria: string }) =>
    api.post<HuntingPlaybook>('/hunting/playbooks', data).then(r => r.data),
  getPlaybook: (id: string) => api.get<HuntingPlaybook>(`/hunting/playbooks/${id}`).then(r => r.data),
  updatePlaybook: (id: string, data: Partial<HuntingPlaybook>) =>
    api.put<HuntingPlaybook>(`/hunting/playbooks/${id}`, data).then(r => r.data),

  // Sessions
  listSessions: (params?: Record<string, string>) =>
    api.get<HuntingSession[]>('/hunting/sessions', { params }).then(r => r.data),
  createSession: (data: { name: string; description?: string; playbook_id?: string; hypothesis: string; data_sources: string[] }) =>
    api.post<HuntingSession>('/hunting/sessions', data).then(r => r.data),
  getSession: (id: string) => api.get<HuntingSession>(`/hunting/sessions/${id}`).then(r => r.data),
  updateSession: (id: string, data: Partial<HuntingSession>) =>
    api.put<HuntingSession>(`/hunting/sessions/${id}`, data).then(r => r.data),
  addSessionNote: (id: string, note: string) =>
    api.post(`/hunting/sessions/${id}/notes`, { note }).then(r => r.data),
  getSessionFindings: (id: string) =>
    api.get<HuntingFinding[]>(`/hunting/sessions/${id}/findings`).then(r => r.data),
  addSessionFinding: (id: string, data: { title: string; description: string; severity: string; finding_type: string; evidence: string; iocs_found?: string[]; mitre_techniques?: string[]; recommendations: string }) =>
    api.post<HuntingFinding>(`/hunting/sessions/${id}/findings`, data).then(r => r.data),

  // MITRE
  getMitreCoverage: () => api.get<MitreCoverage[]>('/hunting/mitre/coverage').then(r => r.data),
  getMitreMatrix: () => api.get('/hunting/mitre/matrix').then(r => r.data),

  // Retrospective
  listRetrospectives: () => api.get<RetrospectiveSearch[]>('/hunting/retrospective').then(r => r.data),
  createRetrospective: (data: { name: string; query: string; time_range_start: string; time_range_end: string; data_sources: string[] }) =>
    api.post<RetrospectiveSearch>('/hunting/retrospective', data).then(r => r.data),
  getRetrospective: (id: string) => api.get<RetrospectiveSearch>(`/hunting/retrospective/${id}`).then(r => r.data),
};

// ============================================================================
// Badge Components
// ============================================================================

const severityColors: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  informational: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  active: { bg: 'bg-green-500/20', text: 'text-green-400' },
  expired: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  false_positive: { bg: 'bg-red-500/20', text: 'text-red-400' },
  paused: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  completed: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  cancelled: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  pending: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  running: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
};

const iocTypeIcons: Record<string, React.ReactNode> = {
  ip: <Server className="w-4 h-4" />,
  domain: <Globe className="w-4 h-4" />,
  hash: <Hash className="w-4 h-4" />,
  url: <Link2 className="w-4 h-4" />,
  email: <Mail className="w-4 h-4" />,
  registry: <Database className="w-4 h-4" />,
};

function SeverityBadge({ severity }: { severity: string }) {
  const colors = severityColors[severity.toLowerCase()] || severityColors.medium;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.active;
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
// Create IOC Form
// ============================================================================

const CreateIocForm: React.FC<{
  onSubmit: (data: { ioc_type: string; value: string; severity: string; source?: string; tags?: string[] }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    ioc_type: 'ip',
    value: '',
    severity: 'medium',
    source: '',
    tags: '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      ...formData,
      tags: formData.tags ? formData.tags.split(',').map(s => s.trim()) : [],
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">IOC Type *</label>
          <select
            value={formData.ioc_type}
            onChange={(e) => setFormData({ ...formData, ioc_type: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          >
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="url">URL</option>
            <option value="email">Email</option>
            <option value="registry">Registry Key</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Severity</label>
          <select
            value={formData.severity}
            onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Value *</label>
        <input
          type="text"
          required
          value={formData.value}
          onChange={(e) => setFormData({ ...formData, value: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono focus:ring-2 focus:ring-cyan-500"
          placeholder={
            formData.ioc_type === 'ip' ? '192.168.1.1' :
            formData.ioc_type === 'domain' ? 'malicious.example.com' :
            formData.ioc_type === 'hash' ? 'abc123def456...' :
            formData.ioc_type === 'url' ? 'https://malicious.example.com/payload' :
            formData.ioc_type === 'email' ? 'attacker@malicious.com' :
            'HKLM\\Software\\Malicious'
          }
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Source</label>
        <input
          type="text"
          value={formData.source}
          onChange={(e) => setFormData({ ...formData, source: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="Threat intel feed, incident, etc."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Tags</label>
        <input
          type="text"
          value={formData.tags}
          onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="apt29, ransomware, c2 (comma-separated)"
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
          Add IOC
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Create Session Form
// ============================================================================

const CreateSessionForm: React.FC<{
  playbooks: HuntingPlaybook[];
  onSubmit: (data: { name: string; description?: string; playbook_id?: string; hypothesis: string; data_sources: string[] }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ playbooks, onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    playbook_id: '',
    hypothesis: '',
    data_sources: '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      ...formData,
      playbook_id: formData.playbook_id || undefined,
      data_sources: formData.data_sources ? formData.data_sources.split(',').map(s => s.trim()) : [],
    });
  };

  const handlePlaybookChange = (playbookId: string) => {
    setFormData({ ...formData, playbook_id: playbookId });
    if (playbookId) {
      const pb = playbooks.find(p => p.id === playbookId);
      if (pb) {
        // Extract data sources from query platforms in steps
        const dataSources = new Set<string>();
        pb.steps.forEach(step => {
          step.queries.forEach(q => dataSources.add(q.platform));
        });
        setFormData(prev => ({
          ...prev,
          playbook_id: playbookId,
          hypothesis: pb.description,
          data_sources: Array.from(dataSources).join(', '),
        }));
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Hunt Name *</label>
        <input
          type="text"
          required
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="Hunt session name..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Based on Playbook</label>
        <select
          value={formData.playbook_id}
          onChange={(e) => handlePlaybookChange(e.target.value)}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
        >
          <option value="">No playbook (custom hunt)</option>
          {playbooks.map((pb) => (
            <option key={pb.id} value={pb.id}>{pb.name}</option>
          ))}
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Hypothesis *</label>
        <textarea
          required
          value={formData.hypothesis}
          onChange={(e) => setFormData({ ...formData, hypothesis: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          rows={3}
          placeholder="What are you looking for? What behavior suggests compromise?"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          rows={2}
          placeholder="Additional context for this hunt..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Data Sources</label>
        <input
          type="text"
          value={formData.data_sources}
          onChange={(e) => setFormData({ ...formData, data_sources: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="EDR, SIEM, DNS logs (comma-separated)"
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
          Start Hunt
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Session Detail View
// ============================================================================

const SessionDetailView: React.FC<{
  session: HuntingSession;
  onClose: () => void;
}> = ({ session, onClose }) => {
  const queryClient = useQueryClient();
  const [newNote, setNewNote] = useState('');
  const [activeSubTab, setActiveSubTab] = useState<'details' | 'findings' | 'notes'>('details');

  // Fetch findings
  const { data: findings } = useQuery({
    queryKey: ['session-findings', session.id],
    queryFn: () => huntingAPI.getSessionFindings(session.id),
  });

  // Add note mutation
  const addNoteMutation = useMutation({
    mutationFn: (note: string) => huntingAPI.addSessionNote(session.id, note),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      setNewNote('');
      toast.success('Note added');
    },
    onError: () => toast.error('Failed to add note'),
  });

  // Update session mutation
  const updateSessionMutation = useMutation({
    mutationFn: (status: string) => huntingAPI.updateSession(session.id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      toast.success('Session updated');
    },
    onError: () => toast.error('Failed to update session'),
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <StatusBadge status={session.status} />
            {session.playbook_name && (
              <span className="text-xs text-gray-500">from: {session.playbook_name}</span>
            )}
          </div>
          <h3 className="text-xl font-semibold text-white">{session.name}</h3>
          {session.description && (
            <p className="text-gray-400 mt-1">{session.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {session.status === 'active' && (
            <>
              <button
                onClick={() => updateSessionMutation.mutate('paused')}
                className="px-3 py-1.5 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg text-sm"
              >
                Pause
              </button>
              <button
                onClick={() => updateSessionMutation.mutate('completed')}
                className="px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
              >
                Complete
              </button>
            </>
          )}
          {session.status === 'paused' && (
            <button
              onClick={() => updateSessionMutation.mutate('active')}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
            >
              Resume
            </button>
          )}
        </div>
      </div>

      {/* Hypothesis */}
      <div className="p-4 bg-gray-900 rounded-lg border-l-4 border-cyan-500">
        <p className="text-sm text-gray-500 mb-1">Hypothesis</p>
        <p className="text-gray-300">{session.hypothesis}</p>
      </div>

      {/* Sub-tabs */}
      <div className="border-b border-gray-700">
        <nav className="flex gap-4">
          {(['details', 'findings', 'notes'] as const).map((tab) => (
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
              {tab === 'findings' && <span className="ml-1 text-gray-500">({session.findings_count})</span>}
              {tab === 'notes' && <span className="ml-1 text-gray-500">({session.notes.length})</span>}
            </button>
          ))}
        </nav>
      </div>

      {/* Sub-tab content */}
      <div className="min-h-[200px]">
        {activeSubTab === 'details' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-500">Started</p>
                <p className="text-white">{new Date(session.start_time).toLocaleString()}</p>
              </div>
              {session.end_time && (
                <div>
                  <p className="text-sm text-gray-500">Ended</p>
                  <p className="text-white">{new Date(session.end_time).toLocaleString()}</p>
                </div>
              )}
            </div>
            {session.data_sources.length > 0 && (
              <div>
                <p className="text-sm text-gray-500 mb-1">Data Sources</p>
                <div className="flex flex-wrap gap-1">
                  {session.data_sources.map((ds, i) => (
                    <span key={i} className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                      {ds}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'findings' && (
          <div className="space-y-2">
            {findings && findings.length > 0 ? (
              findings.map((finding) => (
                <div key={finding.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <span className="text-xs text-gray-500">{finding.finding_type}</span>
                    </div>
                    <span className="text-xs text-gray-500">
                      {new Date(finding.created_at).toLocaleString()}
                    </span>
                  </div>
                  <h4 className="text-white font-medium">{finding.title}</h4>
                  <p className="text-gray-400 text-sm mt-1">{finding.description}</p>
                  {finding.iocs_found.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {finding.iocs_found.map((ioc, i) => (
                        <span key={i} className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs font-mono">
                          {ioc}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Target className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No findings yet</p>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'notes' && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white"
                placeholder="Add a note..."
              />
              <button
                onClick={() => {
                  if (newNote.trim()) {
                    addNoteMutation.mutate(newNote);
                  }
                }}
                disabled={!newNote.trim() || addNoteMutation.isPending}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
              >
                Add
              </button>
            </div>
            <div className="space-y-2">
              {session.notes.length > 0 ? (
                session.notes.map((note, i) => (
                  <div key={i} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                    <p className="text-gray-300">{note}</p>
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <FileText className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p>No notes yet</p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

export default function ThreatHuntingPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('iocs');
  const [showCreateIocModal, setShowCreateIocModal] = useState(false);
  const [showCreateSessionModal, setShowCreateSessionModal] = useState(false);
  const [selectedSession, setSelectedSession] = useState<HuntingSession | null>(null);
  const [iocTypeFilter, setIocTypeFilter] = useState<string>('');
  const [iocStatusFilter, setIocStatusFilter] = useState<string>('');

  // Fetch IOC stats
  const { data: iocStats } = useQuery({
    queryKey: ['ioc-stats'],
    queryFn: () => huntingAPI.getIocStats(),
    enabled: activeTab === 'iocs',
  });

  // Fetch IOCs
  const { data: iocs, isLoading: iocsLoading } = useQuery({
    queryKey: ['iocs', iocTypeFilter, iocStatusFilter],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (iocTypeFilter) params.ioc_type = iocTypeFilter;
      if (iocStatusFilter) params.status = iocStatusFilter;
      return huntingAPI.listIocs(params);
    },
    enabled: activeTab === 'iocs',
  });

  // Fetch playbooks
  const { data: playbooks, isLoading: playbooksLoading } = useQuery({
    queryKey: ['hunting-playbooks'],
    queryFn: () => huntingAPI.listPlaybooks(),
    enabled: activeTab === 'playbooks' || activeTab === 'sessions',
  });

  // Fetch sessions
  const { data: sessions, isLoading: sessionsLoading } = useQuery({
    queryKey: ['hunting-sessions'],
    queryFn: () => huntingAPI.listSessions(),
    enabled: activeTab === 'sessions',
  });

  // Fetch MITRE coverage
  const { data: mitreCoverage, isLoading: mitreLoading } = useQuery({
    queryKey: ['mitre-coverage'],
    queryFn: () => huntingAPI.getMitreCoverage(),
    enabled: activeTab === 'mitre',
  });

  // Create IOC mutation
  const createIocMutation = useMutation({
    mutationFn: huntingAPI.createIoc,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] });
      queryClient.invalidateQueries({ queryKey: ['ioc-stats'] });
      setShowCreateIocModal(false);
      toast.success('IOC added');
    },
    onError: () => toast.error('Failed to add IOC'),
  });

  // Create session mutation
  const createSessionMutation = useMutation({
    mutationFn: huntingAPI.createSession,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      setShowCreateSessionModal(false);
      toast.success('Hunt session started');
    },
    onError: () => toast.error('Failed to start session'),
  });

  // Delete IOC mutation
  const deleteIocMutation = useMutation({
    mutationFn: huntingAPI.deleteIoc,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] });
      queryClient.invalidateQueries({ queryKey: ['ioc-stats'] });
      toast.success('IOC deleted');
    },
    onError: () => toast.error('Failed to delete IOC'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'iocs', label: 'IOCs', icon: <Database className="w-4 h-4" /> },
    { id: 'playbooks', label: 'Playbooks', icon: <FileText className="w-4 h-4" /> },
    { id: 'sessions', label: 'Hunt Sessions', icon: <Crosshair className="w-4 h-4" /> },
    { id: 'mitre', label: 'MITRE Coverage', icon: <Grid className="w-4 h-4" /> },
    { id: 'retrospective', label: 'Retrospective', icon: <Clock className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Crosshair className="w-8 h-8 text-purple-500" />
              Threat Hunting
            </h1>
            <p className="text-gray-400 mt-1">
              Proactively hunt for threats and manage IOCs
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowCreateIocModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              Add IOC
            </button>
            <button
              onClick={() => setShowCreateSessionModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
            >
              <Play className="w-4 h-4" />
              Start Hunt
            </button>
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
          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div className="space-y-4">
              {/* Stats */}
              {iocStats && (
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-white">{iocStats.total}</p>
                    <p className="text-xs text-gray-400">Total IOCs</p>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-green-400">{iocStats.active}</p>
                    <p className="text-xs text-gray-400">Active</p>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-cyan-400">{iocStats.added_today}</p>
                    <p className="text-xs text-gray-400">Added Today</p>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-gray-400">{iocStats.expired_today}</p>
                    <p className="text-xs text-gray-400">Expired Today</p>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-white">{iocStats.by_type?.ip || 0}</p>
                    <p className="text-xs text-gray-400">IPs</p>
                  </div>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                    <p className="text-2xl font-bold text-white">{iocStats.by_type?.domain || 0}</p>
                    <p className="text-xs text-gray-400">Domains</p>
                  </div>
                </div>
              )}

              {/* Filters */}
              <div className="flex items-center gap-4">
                <select
                  value={iocTypeFilter}
                  onChange={(e) => setIocTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Types</option>
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="hash">File Hash</option>
                  <option value="url">URL</option>
                  <option value="email">Email</option>
                </select>
                <select
                  value={iocStatusFilter}
                  onChange={(e) => setIocStatusFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="expired">Expired</option>
                  <option value="false_positive">False Positive</option>
                </select>
                <div className="flex-1" />
                <button className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                  <Upload className="w-4 h-4" />
                  Import
                </button>
                <button className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                  <Download className="w-4 h-4" />
                  Export
                </button>
              </div>

              {/* IOCs List */}
              {iocsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : iocs && iocs.length > 0 ? (
                <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Type</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Value</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Severity</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Status</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Source</th>
                        <th className="text-left p-4 text-sm font-medium text-gray-400">Added</th>
                        <th className="text-right p-4 text-sm font-medium text-gray-400">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.map((ioc) => (
                        <tr key={ioc.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                          <td className="p-4">
                            <div className="flex items-center gap-2">
                              {iocTypeIcons[ioc.ioc_type] || <Database className="w-4 h-4" />}
                              <span className="text-gray-400 text-sm">{ioc.ioc_type.toUpperCase()}</span>
                            </div>
                          </td>
                          <td className="p-4">
                            <div className="flex items-center gap-2">
                              <code className="text-white font-mono text-sm truncate max-w-xs">{ioc.value}</code>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(ioc.value);
                                  toast.success('Copied to clipboard');
                                }}
                                className="p-1 hover:bg-gray-600 rounded text-gray-400 hover:text-white"
                              >
                                <Copy className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                          <td className="p-4"><SeverityBadge severity={ioc.severity} /></td>
                          <td className="p-4"><StatusBadge status={ioc.status} /></td>
                          <td className="p-4 text-gray-400 text-sm">{ioc.source || '-'}</td>
                          <td className="p-4 text-gray-500 text-sm">
                            {new Date(ioc.created_at).toLocaleDateString()}
                          </td>
                          <td className="p-4 text-right">
                            <button
                              onClick={() => deleteIocMutation.mutate(ioc.id)}
                              className="p-2 hover:bg-red-500/20 rounded-lg text-gray-400 hover:text-red-400"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Database className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No IOCs</h3>
                  <p className="text-gray-400 mb-6">Add indicators of compromise to track threats</p>
                  <button
                    onClick={() => setShowCreateIocModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Add IOC
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
                          <div className="flex items-center gap-2 mb-1">
                            <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">
                              {pb.category}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs ${
                              pb.difficulty === 'Beginner' ? 'bg-green-500/20 text-green-400' :
                              pb.difficulty === 'Intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                              pb.difficulty === 'Advanced' ? 'bg-orange-500/20 text-orange-400' :
                              'bg-red-500/20 text-red-400'
                            }`}>
                              {pb.difficulty}
                            </span>
                            {pb.is_builtin && (
                              <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">
                                Built-in
                              </span>
                            )}
                          </div>
                          <h3 className="text-lg font-medium text-white">{pb.name}</h3>
                        </div>
                      </div>
                      {pb.description && (
                        <p className="text-sm text-gray-400 mb-3 line-clamp-2">{pb.description}</p>
                      )}
                      <div className="p-3 bg-gray-900 rounded-lg mb-3">
                        <p className="text-xs text-gray-500 mb-1">Estimated Duration</p>
                        <p className="text-gray-300 text-sm">{pb.estimated_duration}</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 mb-3">
                        {pb.tags.slice(0, 4).map((tag, i) => (
                          <span key={i} className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                            {tag}
                          </span>
                        ))}
                        {pb.tags.length > 4 && (
                          <span className="text-xs text-gray-500">+{pb.tags.length - 4} more</span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>{pb.steps.length} steps</span>
                        {pb.mitre_techniques.length > 0 && (
                          <span>{pb.mitre_techniques.length} techniques</span>
                        )}
                        {pb.mitre_tactics.length > 0 && (
                          <span>{pb.mitre_tactics.length} tactics</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Playbooks</h3>
                  <p className="text-gray-400">Create hunting playbooks to standardize your hunts</p>
                </div>
              )}
            </div>
          )}

          {/* Sessions Tab */}
          {activeTab === 'sessions' && (
            <div className="space-y-4">
              {sessionsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : sessions && sessions.length > 0 ? (
                <div className="space-y-3">
                  {sessions.map((session) => (
                    <div
                      key={session.id}
                      onClick={() => setSelectedSession(session)}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <StatusBadge status={session.status} />
                            {session.playbook_name && (
                              <span className="text-xs text-gray-500">from: {session.playbook_name}</span>
                            )}
                          </div>
                          <h3 className="text-lg font-medium text-white">{session.name}</h3>
                          {session.description && (
                            <p className="text-sm text-gray-400 mt-1">{session.description}</p>
                          )}
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(session.start_time).toLocaleString()}
                            </span>
                            <span>{session.findings_count} findings</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Crosshair className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Hunt Sessions</h3>
                  <p className="text-gray-400 mb-6">Start a new threat hunting session</p>
                  <button
                    onClick={() => setShowCreateSessionModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Play className="w-4 h-4 inline mr-2" />
                    Start Hunt
                  </button>
                </div>
              )}
            </div>
          )}

          {/* MITRE Coverage Tab */}
          {activeTab === 'mitre' && (
            <div className="space-y-4">
              {mitreLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : mitreCoverage && mitreCoverage.length > 0 ? (
                <div className="space-y-4">
                  {mitreCoverage.map((tactic) => (
                    <div key={tactic.tactic} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-white">{tactic.tactic_name}</h3>
                        <span className="text-sm text-gray-400">
                          {tactic.techniques.filter(t => t.playbook_count > 0).length} / {tactic.techniques.length} covered
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {tactic.techniques.map((technique) => (
                          <div
                            key={technique.id}
                            className={`p-2 rounded-lg text-sm ${
                              technique.playbook_count > 0
                                ? 'bg-green-500/20 border border-green-500/30'
                                : 'bg-gray-900 border border-gray-700'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className={technique.playbook_count > 0 ? 'text-green-400' : 'text-gray-400'}>
                                {technique.id}
                              </span>
                              {technique.playbook_count > 0 && (
                                <span className="text-xs text-green-400">{technique.playbook_count}</span>
                              )}
                            </div>
                            <p className="text-xs text-gray-500 truncate">{technique.name}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Grid className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Coverage Data</h3>
                  <p className="text-gray-400">Create playbooks with MITRE mappings to see coverage</p>
                </div>
              )}
            </div>
          )}

          {/* Retrospective Tab */}
          {activeTab === 'retrospective' && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
              <Clock className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-300 mb-2">Retrospective Search</h3>
              <p className="text-gray-400">Search historical data for newly discovered IOCs</p>
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showCreateIocModal}
          onClose={() => setShowCreateIocModal(false)}
          title="Add Indicator of Compromise"
        >
          <CreateIocForm
            onSubmit={(data) => createIocMutation.mutate(data)}
            onCancel={() => setShowCreateIocModal(false)}
            isLoading={createIocMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={showCreateSessionModal}
          onClose={() => setShowCreateSessionModal(false)}
          title="Start Hunt Session"
        >
          <CreateSessionForm
            playbooks={playbooks || []}
            onSubmit={(data) => createSessionMutation.mutate(data)}
            onCancel={() => setShowCreateSessionModal(false)}
            isLoading={createSessionMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={!!selectedSession}
          onClose={() => setSelectedSession(null)}
          title="Hunt Session Details"
          size="lg"
        >
          {selectedSession && (
            <SessionDetailView session={selectedSession} onClose={() => setSelectedSession(null)} />
          )}
        </Modal>
      </div>
    </Layout>
  );
}
