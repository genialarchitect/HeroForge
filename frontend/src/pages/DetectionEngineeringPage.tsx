import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Shield,
  Search,
  Code,
  TestTube,
  BarChart3,
  Plus,
  RefreshCw,
  Eye,
  Edit,
  CheckCircle,
  XCircle,
  AlertCircle,
  X,
  FileText,
  Play,
  Target,
  TrendingUp,
  Grid,
  AlertTriangle,
  Copy,
  Download,
  Upload,
  Trash2,
  Clock,
  Tag,
  Layers,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'dashboard' | 'detections' | 'testing' | 'coverage' | 'false_positives';

// ============================================================================
// Types
// ============================================================================

interface Detection {
  id: string;
  name: string;
  description?: string;
  logic_yaml: string;
  data_sources: DataSource[];
  severity: string;
  status: string; // draft, testing, production, deprecated
  version: number;
  mitre_techniques: string[];
  mitre_tactics: string[];
  quality_score: number;
  enabled: boolean;
  author?: string;
  created_at: string;
  updated_at: string;
}

interface DataSource {
  name: string;
  type: string;
  required: boolean;
}

interface DetectionTest {
  id: string;
  detection_id: string;
  test_name: string;
  test_type: string; // unit, integration, regression
  status: string; // pending, running, passed, failed
  expected_result: boolean;
  actual_result?: boolean;
  test_data: string;
  error_message?: string;
  duration_ms?: number;
  run_at?: string;
  created_at: string;
}

interface TestRun {
  id: string;
  detection_id: string;
  trigger: string; // manual, scheduled, ci
  status: string;
  total_tests: number;
  passed: number;
  failed: number;
  started_at: string;
  completed_at?: string;
}

interface FalsePositive {
  id: string;
  detection_id: string;
  detection_name: string;
  alert_id?: string;
  reported_by: string;
  status: string; // pending, confirmed, rejected, tuned
  description: string;
  sample_data?: string;
  resolution_notes?: string;
  tuning_applied?: string;
  created_at: string;
  resolved_at?: string;
}

interface CoverageAnalysis {
  total_techniques: number;
  covered_techniques: number;
  coverage_percentage: number;
  by_tactic: Record<string, TacticCoverage>;
  gaps: CoverageGap[];
}

interface TacticCoverage {
  name: string;
  total: number;
  covered: number;
  techniques: TechniqueCoverage[];
}

interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  covered: boolean;
  detection_count: number;
  detection_ids: string[];
}

interface CoverageGap {
  technique_id: string;
  technique_name: string;
  tactic: string;
  priority: string;
  recommendation?: string;
}

interface DetectionDashboard {
  total_detections: number;
  production_detections: number;
  draft_detections: number;
  deprecated_detections: number;
  pending_false_positives: number;
  test_pass_rate: number;
  avg_quality_score: number;
  coverage_percentage: number;
}

// ============================================================================
// API Functions
// ============================================================================

const detectionAPI = {
  getDashboard: () => api.get<DetectionDashboard>('/detection-engineering/dashboard').then(r => r.data),

  // Detections
  listDetections: (params?: Record<string, string>) =>
    api.get<Detection[]>('/detection-engineering/detections', { params }).then(r => r.data),
  createDetection: (data: { name: string; description?: string; logic_yaml: string; severity: string; mitre_techniques?: string[]; mitre_tactics?: string[] }) =>
    api.post<Detection>('/detection-engineering/detections', data).then(r => r.data),
  getDetection: (id: string) => api.get<Detection>(`/detection-engineering/detections/${id}`).then(r => r.data),
  updateDetection: (id: string, data: Partial<Detection>) =>
    api.put<Detection>(`/detection-engineering/detections/${id}`, data).then(r => r.data),
  deleteDetection: (id: string) => api.delete(`/detection-engineering/detections/${id}`),
  promoteDetection: (id: string, status: string) =>
    api.post<Detection>(`/detection-engineering/detections/${id}/promote`, { status }).then(r => r.data),

  // Testing
  listTests: (detectionId: string) =>
    api.get<DetectionTest[]>(`/detection-engineering/detections/${detectionId}/tests`).then(r => r.data),
  createTest: (detectionId: string, data: { test_name: string; test_type: string; expected_result: boolean; test_data: string }) =>
    api.post<DetectionTest>(`/detection-engineering/detections/${detectionId}/tests`, data).then(r => r.data),
  runTests: (detectionId: string) =>
    api.post<TestRun>(`/detection-engineering/detections/${detectionId}/tests/run`).then(r => r.data),
  listTestRuns: (detectionId: string) =>
    api.get<TestRun[]>(`/detection-engineering/detections/${detectionId}/test-runs`).then(r => r.data),

  // False Positives
  listFalsePositives: (params?: Record<string, string>) =>
    api.get<FalsePositive[]>('/detection-engineering/false-positives', { params }).then(r => r.data),
  reportFalsePositive: (data: { detection_id: string; description: string; sample_data?: string }) =>
    api.post<FalsePositive>('/detection-engineering/false-positives', data).then(r => r.data),
  resolveFalsePositive: (id: string, data: { status: string; resolution_notes?: string; tuning_applied?: string }) =>
    api.put<FalsePositive>(`/detection-engineering/false-positives/${id}`, data).then(r => r.data),

  // Coverage
  getCoverage: () => api.get<CoverageAnalysis>('/detection-engineering/coverage').then(r => r.data),
  getGaps: () => api.get<CoverageGap[]>('/detection-engineering/gaps').then(r => r.data),
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
  draft: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  testing: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  production: { bg: 'bg-green-500/20', text: 'text-green-400' },
  deprecated: { bg: 'bg-red-500/20', text: 'text-red-400' },
  pending: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  confirmed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  rejected: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  tuned: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  passed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
  running: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
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
  const colors = statusColors[status.toLowerCase()] || statusColors.draft;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
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
// Create Detection Form
// ============================================================================

const CreateDetectionForm: React.FC<{
  onSubmit: (data: { name: string; description?: string; logic_yaml: string; severity: string; mitre_techniques?: string[]; mitre_tactics?: string[] }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}> = ({ onSubmit, onCancel, isLoading }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    logic_yaml: `title: Detection Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\suspicious.exe'
  condition: selection
level: medium`,
    severity: 'medium',
    mitre_techniques: '',
    mitre_tactics: '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      ...formData,
      mitre_techniques: formData.mitre_techniques ? formData.mitre_techniques.split(',').map(s => s.trim()) : [],
      mitre_tactics: formData.mitre_tactics ? formData.mitre_tactics.split(',').map(s => s.trim()) : [],
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Name *</label>
        <input
          type="text"
          required
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="Detection rule name..."
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          rows={2}
          placeholder="What does this detection rule detect?"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">Detection Logic (YAML/Sigma) *</label>
        <textarea
          required
          value={formData.logic_yaml}
          onChange={(e) => setFormData({ ...formData, logic_yaml: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white font-mono text-sm focus:ring-2 focus:ring-cyan-500"
          rows={12}
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
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
            <option value="informational">Informational</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">MITRE Techniques</label>
          <input
            type="text"
            value={formData.mitre_techniques}
            onChange={(e) => setFormData({ ...formData, mitre_techniques: e.target.value })}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
            placeholder="T1059, T1055 (comma-separated)"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">MITRE Tactics</label>
        <input
          type="text"
          value={formData.mitre_tactics}
          onChange={(e) => setFormData({ ...formData, mitre_tactics: e.target.value })}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500"
          placeholder="execution, defense_evasion (comma-separated)"
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
          Create Detection
        </button>
      </div>
    </form>
  );
};

// ============================================================================
// Detection Detail View
// ============================================================================

const DetectionDetailView: React.FC<{
  detection: Detection;
  onClose: () => void;
}> = ({ detection, onClose }) => {
  const queryClient = useQueryClient();
  const [activeSubTab, setActiveSubTab] = useState<'logic' | 'tests' | 'history'>('logic');

  // Fetch tests
  const { data: tests } = useQuery({
    queryKey: ['detection-tests', detection.id],
    queryFn: () => detectionAPI.listTests(detection.id),
  });

  // Run tests mutation
  const runTestsMutation = useMutation({
    mutationFn: () => detectionAPI.runTests(detection.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-tests', detection.id] });
      toast.success('Tests started');
    },
    onError: () => toast.error('Failed to run tests'),
  });

  // Promote mutation
  const promoteMutation = useMutation({
    mutationFn: (status: string) => detectionAPI.promoteDetection(detection.id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      toast.success('Detection status updated');
    },
    onError: () => toast.error('Failed to update status'),
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={detection.severity} />
            <StatusBadge status={detection.status} />
            <span className="text-gray-500 text-sm">v{detection.version}</span>
          </div>
          <h3 className="text-xl font-semibold text-white">{detection.name}</h3>
          {detection.description && (
            <p className="text-gray-400 mt-1">{detection.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {detection.status === 'draft' && (
            <button
              onClick={() => promoteMutation.mutate('testing')}
              className="px-3 py-1.5 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg text-sm"
            >
              Move to Testing
            </button>
          )}
          {detection.status === 'testing' && (
            <button
              onClick={() => promoteMutation.mutate('production')}
              className="px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
            >
              Deploy to Production
            </button>
          )}
        </div>
      </div>

      {/* Quality Score */}
      <div className="flex items-center gap-4 p-4 bg-gray-900 rounded-lg">
        <div>
          <p className="text-sm text-gray-500">Quality Score</p>
          <p className={`text-2xl font-bold ${
            detection.quality_score >= 80 ? 'text-green-400' :
            detection.quality_score >= 60 ? 'text-yellow-400' : 'text-red-400'
          }`}>
            {detection.quality_score}%
          </p>
        </div>
        <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
          <div
            className={`h-full ${
              detection.quality_score >= 80 ? 'bg-green-500' :
              detection.quality_score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
            }`}
            style={{ width: `${detection.quality_score}%` }}
          />
        </div>
      </div>

      {/* MITRE Mappings */}
      {(detection.mitre_techniques.length > 0 || detection.mitre_tactics.length > 0) && (
        <div className="p-4 bg-gray-900 rounded-lg">
          <h4 className="text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK Mapping</h4>
          <div className="space-y-2">
            {detection.mitre_tactics.length > 0 && (
              <div className="flex flex-wrap gap-1">
                <span className="text-xs text-gray-500 mr-2">Tactics:</span>
                {detection.mitre_tactics.map((tactic, i) => (
                  <span key={i} className="px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded text-xs">
                    {tactic}
                  </span>
                ))}
              </div>
            )}
            {detection.mitre_techniques.length > 0 && (
              <div className="flex flex-wrap gap-1">
                <span className="text-xs text-gray-500 mr-2">Techniques:</span>
                {detection.mitre_techniques.map((technique, i) => (
                  <span key={i} className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">
                    {technique}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sub-tabs */}
      <div className="border-b border-gray-700">
        <nav className="flex gap-4">
          {(['logic', 'tests', 'history'] as const).map((tab) => (
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
              {tab === 'tests' && tests && <span className="ml-1 text-gray-500">({tests.length})</span>}
            </button>
          ))}
        </nav>
      </div>

      {/* Sub-tab content */}
      <div className="min-h-[200px]">
        {activeSubTab === 'logic' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-gray-400">Detection Logic</h4>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(detection.logic_yaml);
                  toast.success('Copied to clipboard');
                }}
                className="p-2 hover:bg-gray-700 rounded-lg text-gray-400 hover:text-white"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
            <pre className="p-4 bg-gray-900 rounded-lg text-sm text-gray-300 font-mono overflow-x-auto">
              {detection.logic_yaml}
            </pre>
          </div>
        )}

        {activeSubTab === 'tests' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button
                onClick={() => runTestsMutation.mutate()}
                disabled={runTestsMutation.isPending}
                className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
              >
                <Play className="w-4 h-4" />
                Run Tests
              </button>
            </div>
            {tests && tests.length > 0 ? (
              <div className="space-y-2">
                {tests.map((test) => (
                  <div key={test.id} className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {test.status === 'passed' ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : test.status === 'failed' ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <Clock className="w-4 h-4 text-gray-400" />
                        )}
                        <span className="text-white font-medium">{test.test_name}</span>
                        <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                          {test.test_type}
                        </span>
                      </div>
                      <StatusBadge status={test.status} />
                    </div>
                    {test.error_message && (
                      <p className="text-red-400 text-sm mt-2">{test.error_message}</p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <TestTube className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No tests defined</p>
              </div>
            )}
          </div>
        )}

        {activeSubTab === 'history' && (
          <div className="text-center py-8 text-gray-500">
            <Clock className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p>Version history coming soon</p>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

export default function DetectionEngineeringPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');

  // Fetch dashboard
  const { data: dashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ['detection-dashboard'],
    queryFn: () => detectionAPI.getDashboard(),
    enabled: activeTab === 'dashboard',
  });

  // Fetch detections
  const { data: detections, isLoading: detectionsLoading } = useQuery({
    queryKey: ['detections', statusFilter, severityFilter],
    queryFn: () => {
      const params: Record<string, string> = {};
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;
      return detectionAPI.listDetections(params);
    },
    enabled: activeTab === 'detections',
  });

  // Fetch false positives
  const { data: falsePositives, isLoading: fpLoading } = useQuery({
    queryKey: ['false-positives'],
    queryFn: () => detectionAPI.listFalsePositives(),
    enabled: activeTab === 'false_positives',
  });

  // Fetch coverage
  const { data: coverage, isLoading: coverageLoading } = useQuery({
    queryKey: ['detection-coverage'],
    queryFn: () => detectionAPI.getCoverage(),
    enabled: activeTab === 'coverage',
  });

  // Create detection mutation
  const createDetectionMutation = useMutation({
    mutationFn: detectionAPI.createDetection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['detection-dashboard'] });
      setShowCreateModal(false);
      toast.success('Detection created');
    },
    onError: () => toast.error('Failed to create detection'),
  });

  // Resolve FP mutation
  const resolveFpMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { status: string; resolution_notes?: string } }) =>
      detectionAPI.resolveFalsePositive(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['false-positives'] });
      toast.success('False positive resolved');
    },
    onError: () => toast.error('Failed to resolve'),
  });

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <BarChart3 className="w-4 h-4" /> },
    { id: 'detections', label: 'Detections', icon: <Shield className="w-4 h-4" /> },
    { id: 'testing', label: 'Testing', icon: <TestTube className="w-4 h-4" /> },
    { id: 'coverage', label: 'Coverage', icon: <Grid className="w-4 h-4" /> },
    { id: 'false_positives', label: 'False Positives', icon: <AlertTriangle className="w-4 h-4" /> },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Code className="w-8 h-8 text-cyan-500" />
              Detection Engineering
            </h1>
            <p className="text-gray-400 mt-1">
              Build, test, and manage detection rules
            </p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Detection
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
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-cyan-500/20 rounded-lg">
                          <Shield className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.total_detections}</p>
                          <p className="text-xs text-gray-400">Total Detections</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-green-500/20 rounded-lg">
                          <CheckCircle className="w-6 h-6 text-green-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.production_detections}</p>
                          <p className="text-xs text-gray-400">In Production</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-purple-500/20 rounded-lg">
                          <Target className="w-6 h-6 text-purple-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.coverage_percentage.toFixed(0)}%</p>
                          <p className="text-xs text-gray-400">ATT&CK Coverage</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-orange-500/20 rounded-lg">
                          <AlertTriangle className="w-6 h-6 text-orange-400" />
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-white">{dashboard.pending_false_positives}</p>
                          <p className="text-xs text-gray-400">Pending FPs</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Quality Metrics</h3>
                      <div className="space-y-4">
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-gray-400">Test Pass Rate</span>
                            <span className="text-white font-medium">{dashboard.test_pass_rate.toFixed(1)}%</span>
                          </div>
                          <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-green-500"
                              style={{ width: `${dashboard.test_pass_rate}%` }}
                            />
                          </div>
                        </div>
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-gray-400">Avg Quality Score</span>
                            <span className="text-white font-medium">{dashboard.avg_quality_score.toFixed(1)}%</span>
                          </div>
                          <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${
                                dashboard.avg_quality_score >= 80 ? 'bg-green-500' :
                                dashboard.avg_quality_score >= 60 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${dashboard.avg_quality_score}%` }}
                            />
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Detection Status</h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-gray-400">{dashboard.draft_detections}</p>
                          <p className="text-sm text-gray-500">Draft</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-green-400">{dashboard.production_detections}</p>
                          <p className="text-sm text-gray-500">Production</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-yellow-400">{dashboard.total_detections - dashboard.production_detections - dashboard.draft_detections - dashboard.deprecated_detections}</p>
                          <p className="text-sm text-gray-500">Testing</p>
                        </div>
                        <div className="bg-gray-900 rounded-lg p-3 text-center">
                          <p className="text-3xl font-bold text-red-400">{dashboard.deprecated_detections}</p>
                          <p className="text-sm text-gray-500">Deprecated</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <BarChart3 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Dashboard Data</h3>
                  <p className="text-gray-400">Start creating detections to see metrics</p>
                </div>
              )}
            </div>
          )}

          {/* Detections Tab */}
          {activeTab === 'detections' && (
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Statuses</option>
                  <option value="draft">Draft</option>
                  <option value="testing">Testing</option>
                  <option value="production">Production</option>
                  <option value="deprecated">Deprecated</option>
                </select>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                >
                  <option value="">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              {detectionsLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : detections && detections.length > 0 ? (
                <div className="space-y-3">
                  {detections.map((det) => (
                    <div
                      key={det.id}
                      onClick={() => setSelectedDetection(det)}
                      className="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 cursor-pointer transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <SeverityBadge severity={det.severity} />
                            <StatusBadge status={det.status} />
                            {!det.enabled && (
                              <span className="px-2 py-0.5 bg-gray-600 text-gray-400 rounded text-xs">Disabled</span>
                            )}
                          </div>
                          <h3 className="text-lg font-medium text-white">{det.name}</h3>
                          {det.description && (
                            <p className="text-sm text-gray-400 mt-1 line-clamp-2">{det.description}</p>
                          )}
                          <div className="flex items-center gap-3 mt-2">
                            {det.mitre_techniques.slice(0, 3).map((t, i) => (
                              <span key={i} className="text-xs text-cyan-400">{t}</span>
                            ))}
                            {det.mitre_techniques.length > 3 && (
                              <span className="text-xs text-gray-500">+{det.mitre_techniques.length - 3} more</span>
                            )}
                          </div>
                        </div>
                        <div className="text-right">
                          <div className={`text-lg font-bold ${
                            det.quality_score >= 80 ? 'text-green-400' :
                            det.quality_score >= 60 ? 'text-yellow-400' : 'text-red-400'
                          }`}>
                            {det.quality_score}%
                          </div>
                          <p className="text-xs text-gray-500">Quality</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Detections</h3>
                  <p className="text-gray-400 mb-6">Create your first detection rule</p>
                  <button
                    onClick={() => setShowCreateModal(true)}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4 inline mr-2" />
                    Create Detection
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Coverage Tab */}
          {activeTab === 'coverage' && (
            <div className="space-y-6">
              {coverageLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : coverage ? (
                <>
                  <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Coverage</h3>
                      <div className="text-right">
                        <p className={`text-3xl font-bold ${
                          coverage.coverage_percentage >= 70 ? 'text-green-400' :
                          coverage.coverage_percentage >= 40 ? 'text-yellow-400' : 'text-red-400'
                        }`}>
                          {coverage.coverage_percentage.toFixed(1)}%
                        </p>
                        <p className="text-sm text-gray-500">
                          {coverage.covered_techniques} / {coverage.total_techniques} techniques
                        </p>
                      </div>
                    </div>
                    <div className="h-4 bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          coverage.coverage_percentage >= 70 ? 'bg-green-500' :
                          coverage.coverage_percentage >= 40 ? 'bg-yellow-500' : 'bg-red-500'
                        }`}
                        style={{ width: `${coverage.coverage_percentage}%` }}
                      />
                    </div>
                  </div>

                  {coverage.gaps && coverage.gaps.length > 0 && (
                    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <h3 className="text-lg font-semibold text-white mb-4">Priority Gaps</h3>
                      <div className="space-y-2">
                        {coverage.gaps.slice(0, 10).map((gap, i) => (
                          <div key={i} className="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
                            <div className="flex items-center gap-3">
                              <span className="text-cyan-400 font-mono">{gap.technique_id}</span>
                              <span className="text-white">{gap.technique_name}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-gray-500">{gap.tactic}</span>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                gap.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                                gap.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                'bg-yellow-500/20 text-yellow-400'
                              }`}>
                                {gap.priority}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <Grid className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Coverage Data</h3>
                  <p className="text-gray-400">Add MITRE mappings to your detections</p>
                </div>
              )}
            </div>
          )}

          {/* False Positives Tab */}
          {activeTab === 'false_positives' && (
            <div className="space-y-4">
              {fpLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : falsePositives && falsePositives.length > 0 ? (
                <div className="space-y-3">
                  {falsePositives.map((fp) => (
                    <div key={fp.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <StatusBadge status={fp.status} />
                          </div>
                          <h3 className="text-lg font-medium text-white">{fp.detection_name}</h3>
                          <p className="text-sm text-gray-400 mt-1">{fp.description}</p>
                          <p className="text-xs text-gray-500 mt-2">
                            Reported {new Date(fp.created_at).toLocaleDateString()}
                          </p>
                        </div>
                        {fp.status === 'pending' && (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => resolveFpMutation.mutate({ id: fp.id, data: { status: 'confirmed' } })}
                              className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => resolveFpMutation.mutate({ id: fp.id, data: { status: 'rejected' } })}
                              className="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded-lg text-sm"
                            >
                              Reject
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
                  <AlertTriangle className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No False Positives</h3>
                  <p className="text-gray-400">No reported false positives to review</p>
                </div>
              )}
            </div>
          )}

          {/* Testing Tab */}
          {activeTab === 'testing' && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
              <TestTube className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-300 mb-2">Detection Testing</h3>
              <p className="text-gray-400">Select a detection to view and run its tests</p>
            </div>
          )}
        </div>

        {/* Modals */}
        <Modal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          title="Create Detection Rule"
          size="lg"
        >
          <CreateDetectionForm
            onSubmit={(data) => createDetectionMutation.mutate(data)}
            onCancel={() => setShowCreateModal(false)}
            isLoading={createDetectionMutation.isPending}
          />
        </Modal>

        <Modal
          isOpen={!!selectedDetection}
          onClose={() => setSelectedDetection(null)}
          title="Detection Details"
          size="lg"
        >
          {selectedDetection && (
            <DetectionDetailView detection={selectedDetection} onClose={() => setSelectedDetection(null)} />
          )}
        </Modal>
      </div>
    </Layout>
  );
}
