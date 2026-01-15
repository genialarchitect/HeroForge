import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Building2,
  FileText,
  AlertTriangle,
  Shield,
  ClipboardCheck,
  Users,
  Plus,
  RefreshCw,
  Eye,
  Edit,
  CheckCircle,
  XCircle,
  Clock,
  AlertCircle,
  Target,
  TrendingUp,
  TrendingDown,
  ChevronRight,
  X,
  Scale,
  Gavel,
  Briefcase,
  Calendar,
  BarChart3,
  FileCheck,
  Send,
  ThumbsUp,
  ThumbsDown,
  History,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import api from '../services/api';

type TabType = 'dashboard' | 'policies' | 'risks' | 'controls' | 'audits' | 'vendors';

// ============================================================================
// Types
// ============================================================================

interface Policy {
  id: string;
  policy_number: string;
  title: string;
  category: string;
  status: string;
  version: string;
  summary?: string;
  owner_id: string;
  effective_date?: string;
  review_date?: string;
  requires_acknowledgment: boolean;
  created_at: string;
  updated_at: string;
}

interface Risk {
  id: string;
  risk_id: string;
  title: string;
  description: string;
  category: string;
  status: string;
  owner_id: string;
  inherent_likelihood: number;
  inherent_impact: number;
  inherent_risk_score?: number;
  residual_likelihood?: number;
  residual_impact?: number;
  residual_risk_score?: number;
  treatment_strategy?: string;
  target_date?: string;
  last_assessed_at?: string;
  next_review_date?: string;
  created_at: string;
  updated_at: string;
}

interface Control {
  id: string;
  control_id: string;
  title: string;
  description: string;
  category: string;
  type: string;
  domain: string;
  owner_id?: string;
  implementation_status: string;
  effectiveness?: string;
  testing_frequency?: string;
  last_tested_at?: string;
  next_test_date?: string;
  automation_status: string;
  created_at: string;
  updated_at: string;
}

interface Audit {
  id: string;
  audit_number: string;
  title: string;
  audit_type: string;
  scope: string;
  status: string;
  lead_auditor_id: string;
  planned_start_date?: string;
  planned_end_date?: string;
  actual_start_date?: string;
  actual_end_date?: string;
  created_at: string;
  updated_at: string;
}

interface Vendor {
  id: string;
  vendor_id: string;
  name: string;
  category: string;
  tier: string;
  status: string;
  primary_contact_name?: string;
  primary_contact_email?: string;
  services_provided?: string;
  data_access_level?: string;
  inherent_risk_score?: number;
  residual_risk_score?: number;
  last_assessment_date?: string;
  next_assessment_date?: string;
  soc2_report: boolean;
  iso_27001_certified: boolean;
  created_at: string;
  updated_at: string;
}

interface GrcDashboard {
  policies?: {
    total: number;
    active: number;
    pending_review: number;
    pending_approval: number;
  };
  risks?: {
    total: number;
    open: number;
    critical: number;
    high: number;
  };
  controls?: {
    total: number;
    implemented: number;
    effective: number;
  };
  audits?: {
    active_audits: number;
    open_findings: number;
  };
  vendors?: {
    total: number;
    active: number;
    high_risk: number;
  };
}

// ============================================================================
// API Functions
// ============================================================================

const whiteTeamAPI = {
  getDashboard: () => api.get<GrcDashboard>('/white-team/dashboard').then(r => r.data),

  // Policies
  listPolicies: () => api.get<{ policies: Policy[] }>('/white-team/policies').then(r => r.data.policies),
  createPolicy: (data: { title: string; category: string; content: string; summary?: string }) =>
    api.post('/white-team/policies', data).then(r => r.data),
  submitForReview: (id: string) => api.post(`/white-team/policies/${id}/submit-review`).then(r => r.data),
  submitForApproval: (id: string, approverIds: string[]) =>
    api.post(`/white-team/policies/${id}/submit-approval`, { approver_ids: approverIds }).then(r => r.data),
  acknowledgePolicy: (id: string) => api.post(`/white-team/policies/${id}/acknowledge`).then(r => r.data),

  // Risks
  listRisks: () => api.get<{ risks: Risk[] }>('/white-team/risks').then(r => r.data.risks),
  createRisk: (data: { title: string; description: string; category: string; inherent_likelihood: number; inherent_impact: number }) =>
    api.post('/white-team/risks', data).then(r => r.data),
  assessRisk: (id: string, data: { assessment_type: string; likelihood: number; impact: number }) =>
    api.post(`/white-team/risks/${id}/assess`, data).then(r => r.data),
  setTreatment: (id: string, data: { strategy: string; plan?: string; target_date?: string }) =>
    api.post(`/white-team/risks/${id}/treatment`, data).then(r => r.data),

  // Controls
  listControls: () => api.get<{ controls: Control[] }>('/white-team/controls').then(r => r.data.controls),
  createControl: (data: { title: string; description: string; category: string; control_type: string; domain: string }) =>
    api.post('/white-team/controls', data).then(r => r.data),
  addMapping: (id: string, data: { framework: string; framework_control_id: string }) =>
    api.post(`/white-team/controls/${id}/mappings`, data).then(r => r.data),
  recordTest: (id: string, data: { test_type: string; test_procedure: string; result: string }) =>
    api.post(`/white-team/controls/${id}/tests`, data).then(r => r.data),

  // Audits
  listAudits: () => api.get<{ audits: Audit[] }>('/white-team/audits').then(r => r.data.audits),
  createAudit: (data: { title: string; audit_type: string; scope: string }) =>
    api.post('/white-team/audits', data).then(r => r.data),
  createFinding: (auditId: string, data: { title: string; description: string; severity: string; recommendation: string }) =>
    api.post(`/white-team/audits/${auditId}/findings`, data).then(r => r.data),

  // Vendors
  listVendors: () => api.get<{ vendors: Vendor[] }>('/white-team/vendors').then(r => r.data.vendors),
  createVendor: (data: { name: string; category: string; tier: string; data_access_level: string }) =>
    api.post('/white-team/vendors', data).then(r => r.data),
  assessVendor: (id: string, data: { assessment_type: string; questionnaire_score?: number }) =>
    api.post(`/white-team/vendors/${id}/assessments`, data).then(r => r.data),
};

// ============================================================================
// Badge Components
// ============================================================================

const statusColors: Record<string, { bg: string; text: string }> = {
  draft: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  pending_review: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  pending_approval: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  approved: { bg: 'bg-green-500/20', text: 'text-green-400' },
  retired: { bg: 'bg-gray-500/20', text: 'text-gray-500' },
  open: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  mitigating: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  accepted: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  transferred: { bg: 'bg-cyan-500/20', text: 'text-cyan-400' },
  closed: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  planning: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  fieldwork: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  reporting: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  follow_up: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  prospective: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  active: { bg: 'bg-green-500/20', text: 'text-green-400' },
  on_hold: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  terminated: { bg: 'bg-red-500/20', text: 'text-red-400' },
  implemented: { bg: 'bg-green-500/20', text: 'text-green-400' },
  partially_implemented: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  not_implemented: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const riskScoreColors = (score: number) => {
  if (score >= 20) return { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' };
  if (score >= 15) return { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'High' };
  if (score >= 9) return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Medium' };
  return { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Low' };
};

const tierColors: Record<string, { bg: string; text: string }> = {
  tier1: { bg: 'bg-red-500/20', text: 'text-red-400' },
  tier2: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  tier3: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
};

function StatusBadge({ status }: { status: string }) {
  const colors = statusColors[status.toLowerCase()] || statusColors.draft;
  const displayStatus = status.replace(/_/g, ' ');
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text} capitalize`}>
      {displayStatus}
    </span>
  );
}

function RiskScoreBadge({ score }: { score: number }) {
  const colors = riskScoreColors(score);
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text}`}>
      {score} ({colors.label})
    </span>
  );
}

function TierBadge({ tier }: { tier: string }) {
  const colors = tierColors[tier.toLowerCase()] || tierColors.tier3;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.bg} ${colors.text} uppercase`}>
      {tier.replace('tier', 'Tier ')}
    </span>
  );
}

// ============================================================================
// Modal Component
// ============================================================================

function Modal({ isOpen, onClose, title, children }: {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/50" onClick={onClose} />
      <div className="relative bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

// ============================================================================
// Stats Card Component
// ============================================================================

function StatsCard({ icon: Icon, title, value, subtitle, color = 'cyan', onClick }: {
  icon: React.ElementType;
  title: string;
  value: number | string;
  subtitle?: string;
  color?: 'cyan' | 'green' | 'yellow' | 'red' | 'purple' | 'orange';
  onClick?: () => void;
}) {
  const colorClasses = {
    cyan: 'text-cyan-400 bg-cyan-500/20',
    green: 'text-green-400 bg-green-500/20',
    yellow: 'text-yellow-400 bg-yellow-500/20',
    red: 'text-red-400 bg-red-500/20',
    purple: 'text-purple-400 bg-purple-500/20',
    orange: 'text-orange-400 bg-orange-500/20',
  };

  return (
    <div
      onClick={onClick}
      className={`bg-gray-800 rounded-lg p-4 border border-gray-700 ${onClick ? 'cursor-pointer hover:border-cyan-500/50 hover:bg-gray-750 transition-all group' : ''}`}
    >
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-lg ${colorClasses[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <p className="text-sm text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-white">{value}</p>
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
        </div>
        {onClick && <ChevronRight className="w-5 h-5 text-gray-500 group-hover:text-cyan-400 transition-colors" />}
      </div>
    </div>
  );
}

// ============================================================================
// Dashboard Tab
// ============================================================================

function DashboardTab({ onTabChange }: { onTabChange?: (tab: TabType) => void }) {
  const { data: dashboard, isLoading, refetch } = useQuery({
    queryKey: ['grc-dashboard'],
    queryFn: whiteTeamAPI.getDashboard,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">GRC Dashboard</h2>
          <p className="text-sm text-gray-400">Governance, Risk & Compliance Overview</p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatsCard
          icon={FileText}
          title="Active Policies"
          value={dashboard?.policies?.active || 0}
          subtitle={`${dashboard?.policies?.pending_review || 0} pending review`}
          color="cyan"
          onClick={() => onTabChange?.('policies')}
        />
        <StatsCard
          icon={AlertTriangle}
          title="Open Risks"
          value={dashboard?.risks?.open || 0}
          subtitle={`${dashboard?.risks?.critical || 0} critical`}
          color="red"
          onClick={() => onTabChange?.('risks')}
        />
        <StatsCard
          icon={Shield}
          title="Controls"
          value={dashboard?.controls?.total || 0}
          subtitle={`${dashboard?.controls?.effective || 0} effective`}
          color="green"
          onClick={() => onTabChange?.('controls')}
        />
        <StatsCard
          icon={ClipboardCheck}
          title="Active Audits"
          value={dashboard?.audits?.active_audits || 0}
          subtitle={`${dashboard?.audits?.open_findings || 0} open findings`}
          color="yellow"
          onClick={() => onTabChange?.('audits')}
        />
        <StatsCard
          icon={Building2}
          title="Vendors"
          value={dashboard?.vendors?.active || 0}
          subtitle={`${dashboard?.vendors?.high_risk || 0} high risk`}
          color="purple"
          onClick={() => onTabChange?.('vendors')}
        />
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Policy Summary */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-cyan-500/20">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Policies</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Total Policies</span>
              <span className="text-white">{dashboard?.policies?.total || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Active</span>
              <span className="text-green-400">{dashboard?.policies?.active || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Pending Approval</span>
              <span className="text-orange-400">{dashboard?.policies?.pending_approval || 0}</span>
            </div>
          </div>
        </div>

        {/* Risk Summary */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-red-500/20">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Risks</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Total Risks</span>
              <span className="text-white">{dashboard?.risks?.total || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Critical</span>
              <span className="text-red-400">{dashboard?.risks?.critical || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">High</span>
              <span className="text-orange-400">{dashboard?.risks?.high || 0}</span>
            </div>
          </div>
        </div>

        {/* Control Summary */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-green-500/20">
              <Shield className="w-5 h-5 text-green-400" />
            </div>
            <h3 className="text-lg font-semibold text-white">Controls</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Total Controls</span>
              <span className="text-white">{dashboard?.controls?.total || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Implemented</span>
              <span className="text-green-400">{dashboard?.controls?.implemented || 0}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Effective</span>
              <span className="text-cyan-400">{dashboard?.controls?.effective || 0}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Policies Tab
// ============================================================================

function PoliciesTab() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    category: 'information_security',
    content: '',
    summary: '',
  });

  const { data: policies, isLoading } = useQuery({
    queryKey: ['policies'],
    queryFn: whiteTeamAPI.listPolicies,
  });

  const createMutation = useMutation({
    mutationFn: whiteTeamAPI.createPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      setShowCreateModal(false);
      setFormData({ title: '', category: 'information_security', content: '', summary: '' });
      toast.success('Policy created successfully');
    },
    onError: () => toast.error('Failed to create policy'),
  });

  const submitForReviewMutation = useMutation({
    mutationFn: whiteTeamAPI.submitForReview,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
      toast.success('Policy submitted for review');
    },
    onError: () => toast.error('Failed to submit policy'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const categories = [
    { value: 'information_security', label: 'Information Security' },
    { value: 'acceptable_use', label: 'Acceptable Use' },
    { value: 'data_protection', label: 'Data Protection' },
    { value: 'access_control', label: 'Access Control' },
    { value: 'incident_response', label: 'Incident Response' },
    { value: 'business_continuity', label: 'Business Continuity' },
    { value: 'privacy', label: 'Privacy' },
    { value: 'compliance', label: 'Compliance' },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Policy Management</h2>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      {/* Policies Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-900/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Policy</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Category</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Version</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Review Date</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {policies?.map((policy) => (
              <tr key={policy.id} className="hover:bg-gray-700/50">
                <td className="px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-white">{policy.title}</p>
                    <p className="text-xs text-gray-500">{policy.policy_number}</p>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">
                    {policy.category.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={policy.status} />
                </td>
                <td className="px-4 py-3 text-sm text-gray-300">{policy.version}</td>
                <td className="px-4 py-3 text-sm text-gray-400">
                  {policy.review_date || 'Not set'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button className="p-1 text-gray-400 hover:text-white" title="View">
                      <Eye className="w-4 h-4" />
                    </button>
                    {policy.status === 'draft' && (
                      <button
                        onClick={() => submitForReviewMutation.mutate(policy.id)}
                        className="p-1 text-cyan-400 hover:text-cyan-300"
                        title="Submit for Review"
                      >
                        <Send className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {(!policies || policies.length === 0) && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                  No policies found. Create your first policy to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Policy Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Create Policy">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
            <select
              value={formData.category}
              onChange={(e) => setFormData({ ...formData, category: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              {categories.map((cat) => (
                <option key={cat.value} value={cat.value}>{cat.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Summary</label>
            <input
              type="text"
              value={formData.summary}
              onChange={(e) => setFormData({ ...formData, summary: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              placeholder="Brief summary of the policy"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Content</label>
            <textarea
              value={formData.content}
              onChange={(e) => setFormData({ ...formData, content: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white h-40"
              placeholder="Policy content (Markdown supported)"
              required
            />
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Create Policy'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ============================================================================
// Risks Tab
// ============================================================================

function RisksTab() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: 'operational',
    inherent_likelihood: 3,
    inherent_impact: 3,
  });

  const { data: risks, isLoading } = useQuery({
    queryKey: ['risks'],
    queryFn: whiteTeamAPI.listRisks,
  });

  const createMutation = useMutation({
    mutationFn: whiteTeamAPI.createRisk,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risks'] });
      setShowCreateModal(false);
      setFormData({ title: '', description: '', category: 'operational', inherent_likelihood: 3, inherent_impact: 3 });
      toast.success('Risk created successfully');
    },
    onError: () => toast.error('Failed to create risk'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const categories = [
    { value: 'operational', label: 'Operational' },
    { value: 'strategic', label: 'Strategic' },
    { value: 'compliance', label: 'Compliance' },
    { value: 'financial', label: 'Financial' },
    { value: 'reputational', label: 'Reputational' },
    { value: 'cyber', label: 'Cyber' },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Risk Register</h2>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4" />
          Add Risk
        </button>
      </div>

      {/* Risk Matrix Overview */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-5">
        <h3 className="text-sm font-medium text-gray-400 mb-4">Risk Distribution</h3>
        <div className="grid grid-cols-4 gap-4">
          <div className="text-center p-3 bg-red-500/10 rounded-lg border border-red-500/20">
            <p className="text-2xl font-bold text-red-400">
              {risks?.filter(r => (r.inherent_risk_score || 0) >= 20).length || 0}
            </p>
            <p className="text-xs text-gray-400">Critical</p>
          </div>
          <div className="text-center p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
            <p className="text-2xl font-bold text-orange-400">
              {risks?.filter(r => (r.inherent_risk_score || 0) >= 15 && (r.inherent_risk_score || 0) < 20).length || 0}
            </p>
            <p className="text-xs text-gray-400">High</p>
          </div>
          <div className="text-center p-3 bg-yellow-500/10 rounded-lg border border-yellow-500/20">
            <p className="text-2xl font-bold text-yellow-400">
              {risks?.filter(r => (r.inherent_risk_score || 0) >= 9 && (r.inherent_risk_score || 0) < 15).length || 0}
            </p>
            <p className="text-xs text-gray-400">Medium</p>
          </div>
          <div className="text-center p-3 bg-green-500/10 rounded-lg border border-green-500/20">
            <p className="text-2xl font-bold text-green-400">
              {risks?.filter(r => (r.inherent_risk_score || 0) < 9).length || 0}
            </p>
            <p className="text-xs text-gray-400">Low</p>
          </div>
        </div>
      </div>

      {/* Risks Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-900/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Risk</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Category</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Inherent</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Residual</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Treatment</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {risks?.map((risk) => (
              <tr key={risk.id} className="hover:bg-gray-700/50">
                <td className="px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-white">{risk.title}</p>
                    <p className="text-xs text-gray-500">{risk.risk_id}</p>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">{risk.category}</span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={risk.status} />
                </td>
                <td className="px-4 py-3">
                  {risk.inherent_risk_score && <RiskScoreBadge score={risk.inherent_risk_score} />}
                </td>
                <td className="px-4 py-3">
                  {risk.residual_risk_score ? (
                    <RiskScoreBadge score={risk.residual_risk_score} />
                  ) : (
                    <span className="text-xs text-gray-500">Not assessed</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">
                    {risk.treatment_strategy || '-'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button className="p-1 text-gray-400 hover:text-white" title="View">
                      <Eye className="w-4 h-4" />
                    </button>
                    <button className="p-1 text-cyan-400 hover:text-cyan-300" title="Assess">
                      <Target className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {(!risks || risks.length === 0) && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No risks found. Add your first risk to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Risk Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Add Risk">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
            <select
              value={formData.category}
              onChange={(e) => setFormData({ ...formData, category: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              {categories.map((cat) => (
                <option key={cat.value} value={cat.value}>{cat.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white h-24"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Likelihood (1-5)
              </label>
              <input
                type="number"
                min={1}
                max={5}
                value={formData.inherent_likelihood}
                onChange={(e) => setFormData({ ...formData, inherent_likelihood: parseInt(e.target.value) })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Impact (1-5)
              </label>
              <input
                type="number"
                min={1}
                max={5}
                value={formData.inherent_impact}
                onChange={(e) => setFormData({ ...formData, inherent_impact: parseInt(e.target.value) })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              />
            </div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <p className="text-sm text-gray-400">
              Risk Score: <span className="text-white font-medium">
                {formData.inherent_likelihood * formData.inherent_impact}
              </span>
              {' - '}
              <span className={riskScoreColors(formData.inherent_likelihood * formData.inherent_impact).text}>
                {riskScoreColors(formData.inherent_likelihood * formData.inherent_impact).label}
              </span>
            </p>
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Add Risk'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ============================================================================
// Controls Tab
// ============================================================================

function ControlsTab() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: 'preventive',
    control_type: 'technical',
    domain: 'access_control',
  });

  const { data: controls, isLoading } = useQuery({
    queryKey: ['controls'],
    queryFn: whiteTeamAPI.listControls,
  });

  const createMutation = useMutation({
    mutationFn: whiteTeamAPI.createControl,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controls'] });
      setShowCreateModal(false);
      setFormData({ title: '', description: '', category: 'preventive', control_type: 'technical', domain: 'access_control' });
      toast.success('Control created successfully');
    },
    onError: () => toast.error('Failed to create control'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const categories = [
    { value: 'preventive', label: 'Preventive' },
    { value: 'detective', label: 'Detective' },
    { value: 'corrective', label: 'Corrective' },
    { value: 'compensating', label: 'Compensating' },
  ];

  const types = [
    { value: 'administrative', label: 'Administrative' },
    { value: 'technical', label: 'Technical' },
    { value: 'physical', label: 'Physical' },
  ];

  const domains = [
    { value: 'access_control', label: 'Access Control' },
    { value: 'encryption', label: 'Encryption' },
    { value: 'logging', label: 'Logging & Monitoring' },
    { value: 'network', label: 'Network Security' },
    { value: 'endpoint', label: 'Endpoint Security' },
    { value: 'identity', label: 'Identity Management' },
    { value: 'data_protection', label: 'Data Protection' },
    { value: 'incident_response', label: 'Incident Response' },
  ];

  const effectivenessColors: Record<string, { bg: string; text: string }> = {
    effective: { bg: 'bg-green-500/20', text: 'text-green-400' },
    partially_effective: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    ineffective: { bg: 'bg-red-500/20', text: 'text-red-400' },
    not_tested: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Control Framework</h2>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4" />
          Add Control
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 text-center">
          <p className="text-2xl font-bold text-white">{controls?.length || 0}</p>
          <p className="text-xs text-gray-400">Total Controls</p>
        </div>
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 text-center">
          <p className="text-2xl font-bold text-green-400">
            {controls?.filter(c => c.implementation_status === 'implemented').length || 0}
          </p>
          <p className="text-xs text-gray-400">Implemented</p>
        </div>
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 text-center">
          <p className="text-2xl font-bold text-cyan-400">
            {controls?.filter(c => c.effectiveness === 'effective').length || 0}
          </p>
          <p className="text-xs text-gray-400">Effective</p>
        </div>
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 text-center">
          <p className="text-2xl font-bold text-yellow-400">
            {controls?.filter(c => c.next_test_date && new Date(c.next_test_date) <= new Date()).length || 0}
          </p>
          <p className="text-xs text-gray-400">Due for Testing</p>
        </div>
      </div>

      {/* Controls Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-900/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Control</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Domain</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Implementation</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Effectiveness</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Last Tested</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {controls?.map((control) => (
              <tr key={control.id} className="hover:bg-gray-700/50">
                <td className="px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-white">{control.title}</p>
                    <p className="text-xs text-gray-500">{control.control_id}</p>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">
                    {control.domain.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">{control.type}</span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={control.implementation_status} />
                </td>
                <td className="px-4 py-3">
                  {control.effectiveness ? (
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${effectivenessColors[control.effectiveness]?.bg || ''} ${effectivenessColors[control.effectiveness]?.text || ''}`}>
                      {control.effectiveness.replace(/_/g, ' ')}
                    </span>
                  ) : (
                    <span className="text-xs text-gray-500">Not tested</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm text-gray-400">
                  {control.last_tested_at ? new Date(control.last_tested_at).toLocaleDateString() : 'Never'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button className="p-1 text-gray-400 hover:text-white" title="View">
                      <Eye className="w-4 h-4" />
                    </button>
                    <button className="p-1 text-cyan-400 hover:text-cyan-300" title="Record Test">
                      <FileCheck className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {(!controls || controls.length === 0) && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No controls found. Add your first control to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Control Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Add Control">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              required
            />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
              <select
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                {categories.map((cat) => (
                  <option key={cat.value} value={cat.value}>{cat.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
              <select
                value={formData.control_type}
                onChange={(e) => setFormData({ ...formData, control_type: e.target.value })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                {types.map((type) => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Domain</label>
              <select
                value={formData.domain}
                onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                {domains.map((dom) => (
                  <option key={dom.value} value={dom.value}>{dom.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white h-24"
              required
            />
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Add Control'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ============================================================================
// Audits Tab
// ============================================================================

function AuditsTab() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    title: '',
    audit_type: 'internal',
    scope: '',
  });

  const { data: audits, isLoading } = useQuery({
    queryKey: ['audits'],
    queryFn: whiteTeamAPI.listAudits,
  });

  const createMutation = useMutation({
    mutationFn: whiteTeamAPI.createAudit,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['audits'] });
      setShowCreateModal(false);
      setFormData({ title: '', audit_type: 'internal', scope: '' });
      toast.success('Audit created successfully');
    },
    onError: () => toast.error('Failed to create audit'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const auditTypes = [
    { value: 'internal', label: 'Internal Audit' },
    { value: 'external', label: 'External Audit' },
    { value: 'regulatory', label: 'Regulatory Audit' },
  ];

  const statusIcons: Record<string, React.ReactNode> = {
    planning: <Calendar className="w-4 h-4" />,
    fieldwork: <ClipboardCheck className="w-4 h-4" />,
    reporting: <FileText className="w-4 h-4" />,
    follow_up: <History className="w-4 h-4" />,
    closed: <CheckCircle className="w-4 h-4" />,
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Audit Management</h2>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4" />
          Create Audit
        </button>
      </div>

      {/* Audits Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {audits?.map((audit) => (
          <div key={audit.id} className="bg-gray-800 rounded-lg border border-gray-700 p-5">
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-sm font-medium text-white">{audit.title}</p>
                <p className="text-xs text-gray-500">{audit.audit_number}</p>
              </div>
              <StatusBadge status={audit.status} />
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2 text-gray-400">
                <Gavel className="w-4 h-4" />
                <span className="capitalize">{audit.audit_type}</span>
              </div>
              <div className="flex items-center gap-2 text-gray-400">
                <Target className="w-4 h-4" />
                <span className="truncate">{audit.scope}</span>
              </div>
              {audit.planned_start_date && (
                <div className="flex items-center gap-2 text-gray-400">
                  <Calendar className="w-4 h-4" />
                  <span>
                    {new Date(audit.planned_start_date).toLocaleDateString()} -
                    {audit.planned_end_date ? new Date(audit.planned_end_date).toLocaleDateString() : 'TBD'}
                  </span>
                </div>
              )}
            </div>
            <div className="mt-4 pt-3 border-t border-gray-700 flex justify-end gap-2">
              <button className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700">
                <Eye className="w-4 h-4" />
              </button>
              <button className="p-2 text-cyan-400 hover:text-cyan-300 rounded-lg hover:bg-gray-700">
                <Plus className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
        {(!audits || audits.length === 0) && (
          <div className="col-span-full text-center py-8 text-gray-500">
            No audits found. Create your first audit to get started.
          </div>
        )}
      </div>

      {/* Create Audit Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Create Audit">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Title</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
            <select
              value={formData.audit_type}
              onChange={(e) => setFormData({ ...formData, audit_type: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              {auditTypes.map((type) => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Scope</label>
            <textarea
              value={formData.scope}
              onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white h-24"
              placeholder="Describe the scope of this audit..."
              required
            />
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Create Audit'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ============================================================================
// Vendors Tab
// ============================================================================

function VendorsTab() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    category: 'standard',
    tier: 'tier3',
    data_access_level: 'none',
  });

  const { data: vendors, isLoading } = useQuery({
    queryKey: ['vendors'],
    queryFn: whiteTeamAPI.listVendors,
  });

  const createMutation = useMutation({
    mutationFn: whiteTeamAPI.createVendor,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendors'] });
      setShowCreateModal(false);
      setFormData({ name: '', category: 'standard', tier: 'tier3', data_access_level: 'none' });
      toast.success('Vendor created successfully');
    },
    onError: () => toast.error('Failed to create vendor'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  const categories = [
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'standard', label: 'Standard' },
  ];

  const tiers = [
    { value: 'tier1', label: 'Tier 1 (Critical)' },
    { value: 'tier2', label: 'Tier 2 (Important)' },
    { value: 'tier3', label: 'Tier 3 (Standard)' },
  ];

  const accessLevels = [
    { value: 'none', label: 'None' },
    { value: 'limited', label: 'Limited' },
    { value: 'confidential', label: 'Confidential' },
    { value: 'restricted', label: 'Restricted' },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Vendor Risk Management</h2>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700"
        >
          <Plus className="w-4 h-4" />
          Add Vendor
        </button>
      </div>

      {/* Vendors Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-900/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Vendor</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Tier</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Data Access</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Risk Score</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Certifications</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {vendors?.map((vendor) => (
              <tr key={vendor.id} className="hover:bg-gray-700/50">
                <td className="px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-white">{vendor.name}</p>
                    <p className="text-xs text-gray-500">{vendor.vendor_id}</p>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <TierBadge tier={vendor.tier} />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={vendor.status} />
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm text-gray-300 capitalize">
                    {vendor.data_access_level || 'None'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {vendor.residual_risk_score ? (
                    <RiskScoreBadge score={vendor.residual_risk_score} />
                  ) : (
                    <span className="text-xs text-gray-500">Not assessed</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1">
                    {vendor.soc2_report && (
                      <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">SOC 2</span>
                    )}
                    {vendor.iso_27001_certified && (
                      <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded">ISO 27001</span>
                    )}
                    {!vendor.soc2_report && !vendor.iso_27001_certified && (
                      <span className="text-xs text-gray-500">None</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <button className="p-1 text-gray-400 hover:text-white" title="View">
                      <Eye className="w-4 h-4" />
                    </button>
                    <button className="p-1 text-cyan-400 hover:text-cyan-300" title="Assess">
                      <Target className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {(!vendors || vendors.length === 0) && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No vendors found. Add your first vendor to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create Vendor Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)} title="Add Vendor">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Category</label>
              <select
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                {categories.map((cat) => (
                  <option key={cat.value} value={cat.value}>{cat.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Tier</label>
              <select
                value={formData.tier}
                onChange={(e) => setFormData({ ...formData, tier: e.target.value })}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                {tiers.map((tier) => (
                  <option key={tier.value} value={tier.value}>{tier.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Data Access Level</label>
            <select
              value={formData.data_access_level}
              onChange={(e) => setFormData({ ...formData, data_access_level: e.target.value })}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            >
              {accessLevels.map((level) => (
                <option key={level.value} value={level.value}>{level.label}</option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={() => setShowCreateModal(false)}
              className="px-4 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Add Vendor'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function WhiteTeamPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');

  const tabs = [
    { id: 'dashboard' as TabType, label: 'Dashboard', icon: BarChart3 },
    { id: 'policies' as TabType, label: 'Policies', icon: FileText },
    { id: 'risks' as TabType, label: 'Risks', icon: AlertTriangle },
    { id: 'controls' as TabType, label: 'Controls', icon: Shield },
    { id: 'audits' as TabType, label: 'Audits', icon: ClipboardCheck },
    { id: 'vendors' as TabType, label: 'Vendors', icon: Building2 },
  ];

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-gray-500/20">
            <Scale className="w-8 h-8 text-gray-300" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">White Team</h1>
            <p className="text-gray-400">Governance, Risk & Compliance</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-gray-700 pb-2 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-t-lg whitespace-nowrap transition-colors ${
                  activeTab === tab.id
                    ? 'bg-gray-800 text-white border-b-2 border-cyan-400'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'dashboard' && <DashboardTab onTabChange={setActiveTab} />}
          {activeTab === 'policies' && <PoliciesTab />}
          {activeTab === 'risks' && <RisksTab />}
          {activeTab === 'controls' && <ControlsTab />}
          {activeTab === 'audits' && <AuditsTab />}
          {activeTab === 'vendors' && <VendorsTab />}
        </div>
      </div>
    </Layout>
  );
}
