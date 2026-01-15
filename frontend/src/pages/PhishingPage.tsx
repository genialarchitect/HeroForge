import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Mail,
  Users,
  Target,
  FileText,
  Server,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Plus,
  Trash2,
  Eye,
  Edit,
  Send,
  MousePointer,
  Key,
  AlertTriangle,
  BarChart3,
  Clock,
  RefreshCw,
  Globe,
  Copy,
  ChevronRight,
  X,
  Upload,
  Code,
  Link,
  Shield,
  Lock,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import api from '../services/api';

// Types
interface CampaignSummary {
  id: string;
  name: string;
  status: 'draft' | 'scheduled' | 'running' | 'paused' | 'completed' | 'cancelled';
  total_targets: number;
  emails_sent: number;
  emails_opened: number;
  links_clicked: number;
  credentials_captured: number;
  reported_phish: number;
  launch_date?: string;
  created_at: string;
}

interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  from_name: string;
  from_email: string;
  created_at: string;
  is_system?: boolean;
}

interface LandingPage {
  id: string;
  name: string;
  capture_credentials: boolean;
  cloned_from?: string;
  created_at: string;
}

interface SmtpProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  from_address: string;
  created_at: string;
}

interface CampaignStats {
  total_targets: number;
  emails_sent: number;
  emails_failed: number;
  emails_opened: number;
  unique_opens: number;
  links_clicked: number;
  unique_clicks: number;
  credentials_captured: number;
  reported_phish: number;
  open_rate: number;
  click_rate: number;
  submit_rate: number;
  report_rate: number;
}

// Create/Update Request Types
interface CreateCampaignRequest {
  name: string;
  description?: string;
  email_template_id: string;
  landing_page_id?: string;
  smtp_profile_id: string;
  tracking_domain?: string;
  awareness_training?: boolean;
  training_url?: string;
  launch_date?: string;
  end_date?: string;
  targets: CreateTargetRequest[];
  customer_id?: string;
  engagement_id?: string;
}

interface CreateTargetRequest {
  email: string;
  first_name?: string;
  last_name?: string;
  position?: string;
  department?: string;
}

interface CreateEmailTemplateRequest {
  name: string;
  subject: string;
  html_body: string;
  text_body?: string;
  from_name: string;
  from_email: string;
  envelope_sender?: string;
}

interface CreateLandingPageRequest {
  name: string;
  html_content: string;
  capture_credentials: boolean;
  capture_fields: string[];
  redirect_url?: string;
  redirect_delay?: number;
}

interface CreateSmtpProfileRequest {
  name: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  use_tls?: boolean;
  use_starttls?: boolean;
  from_address: string;
  ignore_cert_errors?: boolean;
}

interface CloneWebsiteRequest {
  url: string;
  name: string;
  capture_credentials: boolean;
  capture_fields: string[];
  redirect_url?: string;
}

// API Functions
const phishingAPI = {
  // Campaigns
  listCampaigns: () => api.get<CampaignSummary[]>('/phishing/campaigns'),
  getCampaign: (id: string) => api.get(`/phishing/campaigns/${id}`),
  createCampaign: (data: CreateCampaignRequest) => api.post('/phishing/campaigns', data),
  updateCampaign: (id: string, data: Partial<CreateCampaignRequest>) => api.put(`/phishing/campaigns/${id}`, data),
  getCampaignStats: (id: string) => api.get<CampaignStats>(`/phishing/campaigns/${id}/stats`),
  launchCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/launch`),
  pauseCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/pause`),
  completeCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/complete`),
  deleteCampaign: (id: string) => api.delete(`/phishing/campaigns/${id}`),
  // Email Templates
  listTemplates: () => api.get<EmailTemplate[]>('/phishing/templates'),
  getTemplate: (id: string) => api.get<EmailTemplate & { html_body: string; text_body?: string }>(`/phishing/templates/${id}`),
  createTemplate: (data: CreateEmailTemplateRequest) => api.post('/phishing/templates', data),
  updateTemplate: (id: string, data: Partial<CreateEmailTemplateRequest>) => api.put(`/phishing/templates/${id}`, data),
  deleteTemplate: (id: string) => api.delete(`/phishing/templates/${id}`),
  // Landing Pages
  listLandingPages: () => api.get<LandingPage[]>('/phishing/landing-pages'),
  getLandingPage: (id: string) => api.get<LandingPage & { html_content: string; capture_fields: string[] }>(`/phishing/landing-pages/${id}`),
  createLandingPage: (data: CreateLandingPageRequest) => api.post('/phishing/landing-pages', data),
  updateLandingPage: (id: string, data: Partial<CreateLandingPageRequest>) => api.put(`/phishing/landing-pages/${id}`, data),
  deleteLandingPage: (id: string) => api.delete(`/phishing/landing-pages/${id}`),
  cloneWebsite: (data: CloneWebsiteRequest) => api.post('/phishing/landing-pages/clone', data),
  // SMTP Profiles
  listSmtpProfiles: () => api.get<SmtpProfile[]>('/phishing/smtp-profiles'),
  getSmtpProfile: (id: string) => api.get<SmtpProfile & { username?: string; use_tls?: boolean }>(`/phishing/smtp-profiles/${id}`),
  createSmtpProfile: (data: CreateSmtpProfileRequest) => api.post('/phishing/smtp-profiles', data),
  updateSmtpProfile: (id: string, data: Partial<CreateSmtpProfileRequest>) => api.put(`/phishing/smtp-profiles/${id}`, data),
  deleteSmtpProfile: (id: string) => api.delete(`/phishing/smtp-profiles/${id}`),
  testSmtpProfile: (id: string, toEmail: string) =>
    api.post(`/phishing/smtp-profiles/${id}/test`, { to_email: toEmail }),
};

// Status badge component
const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const colors: Record<string, string> = {
    draft: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
    scheduled: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    running: 'bg-green-500/20 text-green-400 border-green-500/30',
    paused: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    completed: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    cancelled: 'bg-red-500/20 text-red-400 border-red-500/30',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded border capitalize ${colors[status] || colors.draft}`}>
      {status}
    </span>
  );
};

// Stats card component
const StatsCard: React.FC<{
  label: string;
  value: number;
  icon: React.ReactNode;
  color: string;
  percentage?: number;
}> = ({ label, value, icon, color, percentage }) => (
  <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
        <p className="text-2xl font-bold text-slate-900 dark:text-white">{value}</p>
        {percentage !== undefined && (
          <p className="text-sm text-slate-500 dark:text-slate-400">{percentage.toFixed(1)}%</p>
        )}
      </div>
      <div className={`p-3 rounded-lg ${color}`}>{icon}</div>
    </div>
  </div>
);

// Campaign card component
const CampaignCard: React.FC<{
  campaign: CampaignSummary;
  onSelect: () => void;
  onAction: (action: string) => void;
}> = ({ campaign, onSelect, onAction }) => {
  const openRate = campaign.emails_sent > 0
    ? (campaign.emails_opened / campaign.emails_sent * 100)
    : 0;
  const clickRate = campaign.emails_sent > 0
    ? (campaign.links_clicked / campaign.emails_sent * 100)
    : 0;

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 cursor-pointer" onClick={onSelect}>
          <h3 className="font-semibold text-slate-900 dark:text-white">{campaign.name}</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Created {new Date(campaign.created_at).toLocaleDateString()}
          </p>
        </div>
        <StatusBadge status={campaign.status} />
      </div>

      {/* Progress bars */}
      <div className="space-y-2 mb-4">
        <div>
          <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
            <span>Sent: {campaign.emails_sent}/{campaign.total_targets}</span>
            <span>{campaign.total_targets > 0 ? (campaign.emails_sent / campaign.total_targets * 100).toFixed(0) : 0}%</span>
          </div>
          <div className="h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all"
              style={{ width: `${campaign.total_targets > 0 ? (campaign.emails_sent / campaign.total_targets * 100) : 0}%` }}
            />
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-2 text-center text-sm mb-4">
        <div>
          <p className="text-slate-500 dark:text-slate-400">Opened</p>
          <p className="font-semibold text-green-400">{campaign.emails_opened}</p>
          <p className="text-xs text-slate-500">{openRate.toFixed(1)}%</p>
        </div>
        <div>
          <p className="text-slate-500 dark:text-slate-400">Clicked</p>
          <p className="font-semibold text-yellow-400">{campaign.links_clicked}</p>
          <p className="text-xs text-slate-500">{clickRate.toFixed(1)}%</p>
        </div>
        <div>
          <p className="text-slate-500 dark:text-slate-400">Submitted</p>
          <p className="font-semibold text-red-400">{campaign.credentials_captured}</p>
        </div>
        <div>
          <p className="text-slate-500 dark:text-slate-400">Reported</p>
          <p className="font-semibold text-purple-400">{campaign.reported_phish}</p>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        {campaign.status === 'draft' && (
          <Button size="sm" onClick={() => onAction('launch')}>
            <Play className="h-4 w-4 mr-1" />
            Launch
          </Button>
        )}
        {campaign.status === 'running' && (
          <Button size="sm" variant="outline" onClick={() => onAction('pause')}>
            <Pause className="h-4 w-4 mr-1" />
            Pause
          </Button>
        )}
        {campaign.status === 'paused' && (
          <Button size="sm" onClick={() => onAction('resume')}>
            <Play className="h-4 w-4 mr-1" />
            Resume
          </Button>
        )}
        {(campaign.status === 'running' || campaign.status === 'paused') && (
          <Button size="sm" variant="outline" onClick={() => onAction('complete')}>
            <CheckCircle className="h-4 w-4 mr-1" />
            Complete
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={onSelect}>
          <Eye className="h-4 w-4" />
        </Button>
        <Button size="sm" variant="ghost" className="text-red-400" onClick={() => onAction('delete')}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
};

// ============================================================================
// MODAL COMPONENTS
// ============================================================================

// SMTP Profile Modal
const SmtpProfileModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  editId?: string;
  onSuccess: () => void;
}> = ({ isOpen, onClose, editId, onSuccess }) => {
  const [formData, setFormData] = useState<CreateSmtpProfileRequest>({
    name: '',
    host: '',
    port: 587,
    username: '',
    password: '',
    use_tls: false,
    use_starttls: true,
    from_address: '',
    ignore_cert_errors: false,
  });
  const [testEmail, setTestEmail] = useState('');
  const [testing, setTesting] = useState(false);

  // Load existing profile for editing
  const { data: existingProfile } = useQuery({
    queryKey: ['smtp-profile', editId],
    queryFn: () => phishingAPI.getSmtpProfile(editId!).then(r => r.data),
    enabled: !!editId && isOpen,
  });

  React.useEffect(() => {
    if (existingProfile) {
      setFormData({
        name: existingProfile.name,
        host: existingProfile.host,
        port: existingProfile.port,
        username: existingProfile.username || '',
        password: '', // Never pre-fill password
        use_tls: existingProfile.use_tls || false,
        use_starttls: true,
        from_address: existingProfile.from_address,
        ignore_cert_errors: false,
      });
    } else if (!editId) {
      setFormData({
        name: '',
        host: '',
        port: 587,
        username: '',
        password: '',
        use_tls: false,
        use_starttls: true,
        from_address: '',
        ignore_cert_errors: false,
      });
    }
  }, [existingProfile, editId, isOpen]);

  const createMutation = useMutation({
    mutationFn: (data: CreateSmtpProfileRequest) => phishingAPI.createSmtpProfile(data),
    onSuccess: () => {
      toast.success('SMTP profile created');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to create SMTP profile'),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<CreateSmtpProfileRequest>) => phishingAPI.updateSmtpProfile(editId!, data),
    onSuccess: () => {
      toast.success('SMTP profile updated');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to update SMTP profile'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.host || !formData.from_address) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (editId) {
      updateMutation.mutate(formData);
    } else {
      createMutation.mutate(formData);
    }
  };

  const handleTest = async () => {
    if (!editId || !testEmail) {
      toast.error('Save the profile first and enter a test email');
      return;
    }
    setTesting(true);
    try {
      await phishingAPI.testSmtpProfile(editId, testEmail);
      toast.success('Test email sent successfully');
    } catch {
      toast.error('Failed to send test email');
    } finally {
      setTesting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {editId ? 'Edit' : 'New'} SMTP Profile
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Profile Name *
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="e.g., Corporate SMTP"
            />
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="col-span-2">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                SMTP Host *
              </label>
              <input
                type="text"
                value={formData.host}
                onChange={(e) => setFormData({ ...formData, host: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="smtp.example.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Port *
              </label>
              <input
                type="number"
                value={formData.port}
                onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) || 587 })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              From Address *
            </label>
            <input
              type="email"
              value={formData.from_address}
              onChange={(e) => setFormData({ ...formData, from_address: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="noreply@example.com"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Username
              </label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Password
              </label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder={editId ? '(unchanged)' : ''}
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.use_tls}
                onChange={(e) => setFormData({ ...formData, use_tls: e.target.checked })}
                className="w-4 h-4 text-primary bg-light-bg dark:bg-dark-bg border-light-border dark:border-dark-border rounded focus:ring-primary"
              />
              <span className="text-sm text-slate-700 dark:text-slate-300">Use TLS</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.use_starttls}
                onChange={(e) => setFormData({ ...formData, use_starttls: e.target.checked })}
                className="w-4 h-4 text-primary bg-light-bg dark:bg-dark-bg border-light-border dark:border-dark-border rounded focus:ring-primary"
              />
              <span className="text-sm text-slate-700 dark:text-slate-300">Use STARTTLS</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.ignore_cert_errors}
                onChange={(e) => setFormData({ ...formData, ignore_cert_errors: e.target.checked })}
                className="w-4 h-4 text-primary bg-light-bg dark:bg-dark-bg border-light-border dark:border-dark-border rounded focus:ring-primary"
              />
              <span className="text-sm text-slate-700 dark:text-slate-300">Ignore Cert Errors</span>
            </label>
          </div>

          {editId && (
            <div className="border-t border-light-border dark:border-dark-border pt-4 mt-4">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Test Email
              </label>
              <div className="flex gap-2">
                <input
                  type="email"
                  value={testEmail}
                  onChange={(e) => setTestEmail(e.target.value)}
                  className="flex-1 px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="test@example.com"
                />
                <Button type="button" variant="outline" onClick={handleTest} disabled={testing}>
                  <Send className="h-4 w-4 mr-1" />
                  {testing ? 'Sending...' : 'Test'}
                </Button>
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-4 border-t border-light-border dark:border-dark-border">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
              {editId ? 'Update' : 'Create'} Profile
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Email Template Modal
const EmailTemplateModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  editId?: string;
  onSuccess: () => void;
}> = ({ isOpen, onClose, editId, onSuccess }) => {
  const [formData, setFormData] = useState<CreateEmailTemplateRequest>({
    name: '',
    subject: '',
    html_body: '',
    text_body: '',
    from_name: '',
    from_email: '',
    envelope_sender: '',
  });
  const [activeBodyTab, setActiveBodyTab] = useState<'html' | 'text' | 'preview'>('html');

  const { data: existingTemplate } = useQuery({
    queryKey: ['email-template', editId],
    queryFn: () => phishingAPI.getTemplate(editId!).then(r => r.data),
    enabled: !!editId && isOpen,
  });

  React.useEffect(() => {
    if (existingTemplate) {
      setFormData({
        name: existingTemplate.name,
        subject: existingTemplate.subject,
        html_body: existingTemplate.html_body || '',
        text_body: existingTemplate.text_body || '',
        from_name: existingTemplate.from_name,
        from_email: existingTemplate.from_email,
        envelope_sender: '',
      });
    } else if (!editId) {
      setFormData({
        name: '',
        subject: '',
        html_body: '',
        text_body: '',
        from_name: '',
        from_email: '',
        envelope_sender: '',
      });
    }
  }, [existingTemplate, editId, isOpen]);

  const createMutation = useMutation({
    mutationFn: (data: CreateEmailTemplateRequest) => phishingAPI.createTemplate(data),
    onSuccess: () => {
      toast.success('Email template created');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to create email template'),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<CreateEmailTemplateRequest>) => phishingAPI.updateTemplate(editId!, data),
    onSuccess: () => {
      toast.success('Email template updated');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to update email template'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.subject || !formData.html_body || !formData.from_name || !formData.from_email) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (editId) {
      updateMutation.mutate(formData);
    } else {
      createMutation.mutate(formData);
    }
  };

  const insertVariable = (variable: string) => {
    const textarea = document.getElementById('html-body') as HTMLTextAreaElement;
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const text = formData.html_body;
      const newText = text.substring(0, start) + `{{.${variable}}}` + text.substring(end);
      setFormData({ ...formData, html_body: newText });
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {editId ? 'Edit' : 'New'} Email Template
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Template Name *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Password Reset Template"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Subject Line *
              </label>
              <input
                type="text"
                value={formData.subject}
                onChange={(e) => setFormData({ ...formData, subject: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Action Required: Reset Your Password"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                From Name *
              </label>
              <input
                type="text"
                value={formData.from_name}
                onChange={(e) => setFormData({ ...formData, from_name: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="IT Support"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                From Email *
              </label>
              <input
                type="email"
                value={formData.from_email}
                onChange={(e) => setFormData({ ...formData, from_email: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="support@company.com"
              />
            </div>
          </div>

          {/* Variable insertion buttons */}
          <div className="flex flex-wrap gap-2">
            <span className="text-sm text-slate-500 dark:text-slate-400 self-center">Insert Variable:</span>
            {['FirstName', 'LastName', 'Email', 'Position', 'URL', 'TrackingURL'].map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => insertVariable(v)}
                className="px-2 py-1 text-xs font-mono bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded text-slate-600 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover"
              >
                {`{{.${v}}}`}
              </button>
            ))}
          </div>

          {/* Body tabs */}
          <div>
            <div className="flex gap-2 mb-2">
              {[
                { id: 'html', label: 'HTML', icon: <Code className="h-4 w-4" /> },
                { id: 'text', label: 'Text', icon: <FileText className="h-4 w-4" /> },
                { id: 'preview', label: 'Preview', icon: <Eye className="h-4 w-4" /> },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveBodyTab(tab.id as 'html' | 'text' | 'preview')}
                  className={`flex items-center gap-1 px-3 py-1.5 text-sm font-medium rounded ${
                    activeBodyTab === tab.id
                      ? 'bg-primary text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </div>

            {activeBodyTab === 'html' && (
              <textarea
                id="html-body"
                value={formData.html_body}
                onChange={(e) => setFormData({ ...formData, html_body: e.target.value })}
                className="w-full h-64 px-3 py-2 font-mono text-sm bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="<html><body>Your email content here...</body></html>"
              />
            )}

            {activeBodyTab === 'text' && (
              <textarea
                value={formData.text_body}
                onChange={(e) => setFormData({ ...formData, text_body: e.target.value })}
                className="w-full h-64 px-3 py-2 font-mono text-sm bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Plain text version of your email..."
              />
            )}

            {activeBodyTab === 'preview' && (
              <div className="w-full h-64 bg-white dark:bg-slate-800 border border-light-border dark:border-dark-border rounded-lg overflow-auto">
                <iframe
                  srcDoc={formData.html_body}
                  className="w-full h-full border-0"
                  title="Email Preview"
                  sandbox="allow-same-origin"
                />
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-light-border dark:border-dark-border">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
              {editId ? 'Update' : 'Create'} Template
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Landing Page Modal
const LandingPageModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  editId?: string;
  onSuccess: () => void;
}> = ({ isOpen, onClose, editId, onSuccess }) => {
  const [formData, setFormData] = useState<CreateLandingPageRequest>({
    name: '',
    html_content: '',
    capture_credentials: true,
    capture_fields: ['username', 'password'],
    redirect_url: '',
    redirect_delay: 3,
  });
  const [activeTab, setActiveTab] = useState<'html' | 'preview'>('html');

  const { data: existingPage } = useQuery({
    queryKey: ['landing-page', editId],
    queryFn: () => phishingAPI.getLandingPage(editId!).then(r => r.data),
    enabled: !!editId && isOpen,
  });

  React.useEffect(() => {
    if (existingPage) {
      setFormData({
        name: existingPage.name,
        html_content: existingPage.html_content || '',
        capture_credentials: existingPage.capture_credentials,
        capture_fields: existingPage.capture_fields || ['username', 'password'],
        redirect_url: '',
        redirect_delay: 3,
      });
    } else if (!editId) {
      setFormData({
        name: '',
        html_content: '',
        capture_credentials: true,
        capture_fields: ['username', 'password'],
        redirect_url: '',
        redirect_delay: 3,
      });
    }
  }, [existingPage, editId, isOpen]);

  const createMutation = useMutation({
    mutationFn: (data: CreateLandingPageRequest) => phishingAPI.createLandingPage(data),
    onSuccess: () => {
      toast.success('Landing page created');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to create landing page'),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<CreateLandingPageRequest>) => phishingAPI.updateLandingPage(editId!, data),
    onSuccess: () => {
      toast.success('Landing page updated');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to update landing page'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.html_content) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (editId) {
      updateMutation.mutate(formData);
    } else {
      createMutation.mutate(formData);
    }
  };

  const handleFieldToggle = (field: string) => {
    const fields = formData.capture_fields.includes(field)
      ? formData.capture_fields.filter(f => f !== field)
      : [...formData.capture_fields, field];
    setFormData({ ...formData, capture_fields: fields });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {editId ? 'Edit' : 'New'} Landing Page
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Page Name *
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Office 365 Login"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Redirect URL
              </label>
              <input
                type="url"
                value={formData.redirect_url}
                onChange={(e) => setFormData({ ...formData, redirect_url: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="https://real-site.com/login"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Redirect Delay (seconds)
              </label>
              <input
                type="number"
                value={formData.redirect_delay}
                onChange={(e) => setFormData({ ...formData, redirect_delay: parseInt(e.target.value) || 3 })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                min="0"
                max="30"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.capture_credentials}
                onChange={(e) => setFormData({ ...formData, capture_credentials: e.target.checked })}
                className="w-4 h-4 text-primary bg-light-bg dark:bg-dark-bg border-light-border dark:border-dark-border rounded focus:ring-primary"
              />
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Capture Credentials</span>
            </label>

            {formData.capture_credentials && (
              <div className="ml-6 flex flex-wrap gap-3">
                <span className="text-sm text-slate-500 dark:text-slate-400">Capture fields:</span>
                {['username', 'password', 'email', 'otp', 'credit_card'].map((field) => (
                  <label key={field} className="flex items-center gap-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.capture_fields.includes(field)}
                      onChange={() => handleFieldToggle(field)}
                      className="w-3 h-3 text-primary rounded focus:ring-primary"
                    />
                    <span className="text-sm text-slate-600 dark:text-slate-400 capitalize">{field}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* HTML Editor / Preview tabs */}
          <div>
            <div className="flex gap-2 mb-2">
              {[
                { id: 'html', label: 'HTML Editor', icon: <Code className="h-4 w-4" /> },
                { id: 'preview', label: 'Preview', icon: <Eye className="h-4 w-4" /> },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id as 'html' | 'preview')}
                  className={`flex items-center gap-1 px-3 py-1.5 text-sm font-medium rounded ${
                    activeTab === tab.id
                      ? 'bg-primary text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === 'html' && (
              <textarea
                value={formData.html_content}
                onChange={(e) => setFormData({ ...formData, html_content: e.target.value })}
                className="w-full h-80 px-3 py-2 font-mono text-sm bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="<html><body><form>...</form></body></html>"
              />
            )}

            {activeTab === 'preview' && (
              <div className="w-full h-80 bg-white dark:bg-slate-800 border border-light-border dark:border-dark-border rounded-lg overflow-auto">
                <iframe
                  srcDoc={formData.html_content}
                  className="w-full h-full border-0"
                  title="Landing Page Preview"
                  sandbox="allow-same-origin allow-forms"
                />
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-light-border dark:border-dark-border">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
              {editId ? 'Update' : 'Create'} Landing Page
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Clone Website Modal
const CloneWebsiteModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}> = ({ isOpen, onClose, onSuccess }) => {
  const [formData, setFormData] = useState<CloneWebsiteRequest>({
    url: '',
    name: '',
    capture_credentials: true,
    capture_fields: ['username', 'password'],
    redirect_url: '',
  });
  const [cloning, setCloning] = useState(false);

  const handleFieldToggle = (field: string) => {
    const fields = formData.capture_fields.includes(field)
      ? formData.capture_fields.filter(f => f !== field)
      : [...formData.capture_fields, field];
    setFormData({ ...formData, capture_fields: fields });
  };

  const handleClone = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.url || !formData.name) {
      toast.error('Please enter a URL and name');
      return;
    }
    setCloning(true);
    try {
      await phishingAPI.cloneWebsite(formData);
      toast.success('Website cloned successfully');
      onSuccess();
      onClose();
    } catch {
      toast.error('Failed to clone website');
    } finally {
      setCloning(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            Clone Website
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>
        <form onSubmit={handleClone} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Website URL *
            </label>
            <input
              type="url"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="https://login.example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Landing Page Name *
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="Example Corp Login"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Redirect URL (after capture)
            </label>
            <input
              type="url"
              value={formData.redirect_url}
              onChange={(e) => setFormData({ ...formData, redirect_url: e.target.value })}
              className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="https://real-site.com"
            />
          </div>

          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.capture_credentials}
                onChange={(e) => setFormData({ ...formData, capture_credentials: e.target.checked })}
                className="w-4 h-4 text-primary rounded focus:ring-primary"
              />
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Capture Credentials</span>
            </label>

            {formData.capture_credentials && (
              <div className="ml-6 flex flex-wrap gap-3">
                {['username', 'password', 'email', 'otp'].map((field) => (
                  <label key={field} className="flex items-center gap-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.capture_fields.includes(field)}
                      onChange={() => handleFieldToggle(field)}
                      className="w-3 h-3 text-primary rounded focus:ring-primary"
                    />
                    <span className="text-sm text-slate-600 dark:text-slate-400 capitalize">{field}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-light-border dark:border-dark-border">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={cloning}>
              <Globe className="h-4 w-4 mr-1" />
              {cloning ? 'Cloning...' : 'Clone Website'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Campaign Modal
const CampaignModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  editId?: string;
  onSuccess: () => void;
}> = ({ isOpen, onClose, editId, onSuccess }) => {
  const [formData, setFormData] = useState<CreateCampaignRequest>({
    name: '',
    description: '',
    email_template_id: '',
    landing_page_id: '',
    smtp_profile_id: '',
    tracking_domain: '',
    awareness_training: false,
    training_url: '',
    targets: [],
  });
  const [targetInput, setTargetInput] = useState('');
  const [bulkImport, setBulkImport] = useState(false);

  // Fetch available resources
  const { data: templates } = useQuery({
    queryKey: ['phishing-templates'],
    queryFn: () => phishingAPI.listTemplates().then(r => r.data),
    enabled: isOpen,
  });

  const { data: landingPages } = useQuery({
    queryKey: ['phishing-landing-pages'],
    queryFn: () => phishingAPI.listLandingPages().then(r => r.data),
    enabled: isOpen,
  });

  const { data: smtpProfiles } = useQuery({
    queryKey: ['phishing-smtp-profiles'],
    queryFn: () => phishingAPI.listSmtpProfiles().then(r => r.data),
    enabled: isOpen,
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateCampaignRequest) => phishingAPI.createCampaign(data),
    onSuccess: () => {
      toast.success('Campaign created');
      onSuccess();
      onClose();
    },
    onError: () => toast.error('Failed to create campaign'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.email_template_id || !formData.smtp_profile_id) {
      toast.error('Please fill in all required fields');
      return;
    }
    if (formData.targets.length === 0) {
      toast.error('Please add at least one target');
      return;
    }
    createMutation.mutate(formData);
  };

  const addTarget = () => {
    if (!targetInput.trim()) return;
    // Parse email,first,last,position,department format
    const parts = targetInput.split(',').map(p => p.trim());
    const target: CreateTargetRequest = {
      email: parts[0],
      first_name: parts[1] || undefined,
      last_name: parts[2] || undefined,
      position: parts[3] || undefined,
      department: parts[4] || undefined,
    };
    if (target.email && target.email.includes('@')) {
      setFormData({ ...formData, targets: [...formData.targets, target] });
      setTargetInput('');
    } else {
      toast.error('Invalid email address');
    }
  };

  const handleBulkImport = () => {
    const lines = targetInput.split('\n').filter(l => l.trim());
    const newTargets: CreateTargetRequest[] = [];
    for (const line of lines) {
      const parts = line.split(',').map(p => p.trim());
      if (parts[0] && parts[0].includes('@')) {
        newTargets.push({
          email: parts[0],
          first_name: parts[1] || undefined,
          last_name: parts[2] || undefined,
          position: parts[3] || undefined,
          department: parts[4] || undefined,
        });
      }
    }
    if (newTargets.length > 0) {
      setFormData({ ...formData, targets: [...formData.targets, ...newTargets] });
      setTargetInput('');
      toast.success(`Added ${newTargets.length} targets`);
    }
  };

  const removeTarget = (index: number) => {
    setFormData({ ...formData, targets: formData.targets.filter((_, i) => i !== index) });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {editId ? 'Edit' : 'New'} Campaign
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Campaign Name *
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Q1 Security Awareness"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Description
              </label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Monthly phishing simulation"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Email Template *
              </label>
              <select
                value={formData.email_template_id}
                onChange={(e) => setFormData({ ...formData, email_template_id: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">Select template...</option>
                {templates?.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Landing Page
              </label>
              <select
                value={formData.landing_page_id}
                onChange={(e) => setFormData({ ...formData, landing_page_id: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">None (tracking only)</option>
                {landingPages?.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                SMTP Profile *
              </label>
              <select
                value={formData.smtp_profile_id}
                onChange={(e) => setFormData({ ...formData, smtp_profile_id: e.target.value })}
                className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">Select SMTP profile...</option>
                {smtpProfiles?.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.awareness_training}
                onChange={(e) => setFormData({ ...formData, awareness_training: e.target.checked })}
                className="w-4 h-4 text-primary rounded focus:ring-primary"
              />
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Enable Awareness Training
              </span>
            </label>
            {formData.awareness_training && (
              <div className="ml-6">
                <input
                  type="url"
                  value={formData.training_url}
                  onChange={(e) => setFormData({ ...formData, training_url: e.target.value })}
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="https://training.example.com/phishing-awareness"
                />
              </div>
            )}
          </div>

          {/* Targets Section */}
          <div className="border-t border-light-border dark:border-dark-border pt-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">
                Targets ({formData.targets.length})
              </h3>
              <button
                type="button"
                onClick={() => setBulkImport(!bulkImport)}
                className="text-sm text-primary hover:underline"
              >
                {bulkImport ? 'Single Entry' : 'Bulk Import'}
              </button>
            </div>

            {bulkImport ? (
              <div className="space-y-2">
                <textarea
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="w-full h-32 px-3 py-2 font-mono text-sm bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="email,first_name,last_name,position,department&#10;john@example.com,John,Doe,Engineer,IT&#10;jane@example.com,Jane,Smith,Manager,HR"
                />
                <Button type="button" size="sm" onClick={handleBulkImport}>
                  <Upload className="h-4 w-4 mr-1" />
                  Import Targets
                </Button>
              </div>
            ) : (
              <div className="flex gap-2">
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTarget())}
                  className="flex-1 px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="email@example.com,First,Last,Position,Department"
                />
                <Button type="button" size="sm" onClick={addTarget}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            )}

            {formData.targets.length > 0 && (
              <div className="mt-3 max-h-40 overflow-y-auto border border-light-border dark:border-dark-border rounded-lg">
                <table className="w-full text-sm">
                  <thead className="bg-light-bg dark:bg-dark-bg sticky top-0">
                    <tr>
                      <th className="text-left px-2 py-1 text-slate-500">Email</th>
                      <th className="text-left px-2 py-1 text-slate-500">Name</th>
                      <th className="text-left px-2 py-1 text-slate-500">Position</th>
                      <th className="w-8"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {formData.targets.map((t, i) => (
                      <tr key={i} className="border-t border-light-border dark:border-dark-border">
                        <td className="px-2 py-1 text-slate-900 dark:text-white">{t.email}</td>
                        <td className="px-2 py-1 text-slate-600 dark:text-slate-300">
                          {[t.first_name, t.last_name].filter(Boolean).join(' ') || '-'}
                        </td>
                        <td className="px-2 py-1 text-slate-600 dark:text-slate-300">{t.position || '-'}</td>
                        <td className="px-2 py-1">
                          <button type="button" onClick={() => removeTarget(i)} className="text-red-400 hover:text-red-500">
                            <X className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t border-light-border dark:border-dark-border">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={createMutation.isPending}>
              {editId ? 'Update' : 'Create'} Campaign
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ============================================================================
// MAIN PAGE COMPONENT
// ============================================================================

// Main page component
const PhishingPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { hasEngagement } = useRequireEngagement();
  const [activeTab, setActiveTab] = useState<'campaigns' | 'templates' | 'pages' | 'smtp'>('campaigns');
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null);

  // Modal states
  const [showCampaignModal, setShowCampaignModal] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [showLandingPageModal, setShowLandingPageModal] = useState(false);
  const [showCloneModal, setShowCloneModal] = useState(false);
  const [showSmtpModal, setShowSmtpModal] = useState(false);
  const [editingId, setEditingId] = useState<string | undefined>();

  // Delete confirmation states
  const [deletingTemplate, setDeletingTemplate] = useState<string | null>(null);
  const [deletingPage, setDeletingPage] = useState<string | null>(null);
  const [deletingSmtp, setDeletingSmtp] = useState<string | null>(null);

  // Queries
  const { data: campaigns, isLoading: loadingCampaigns } = useQuery({
    queryKey: ['phishing-campaigns'],
    queryFn: () => phishingAPI.listCampaigns().then(r => r.data),
  });

  const { data: templates, isLoading: loadingTemplates } = useQuery({
    queryKey: ['phishing-templates'],
    queryFn: () => phishingAPI.listTemplates().then(r => r.data),
    enabled: activeTab === 'templates',
  });

  const { data: landingPages, isLoading: loadingPages } = useQuery({
    queryKey: ['phishing-landing-pages'],
    queryFn: () => phishingAPI.listLandingPages().then(r => r.data),
    enabled: activeTab === 'pages',
  });

  const { data: smtpProfiles, isLoading: loadingSmtp } = useQuery({
    queryKey: ['phishing-smtp-profiles'],
    queryFn: () => phishingAPI.listSmtpProfiles().then(r => r.data),
    enabled: activeTab === 'smtp',
  });

  const { data: campaignStats } = useQuery({
    queryKey: ['phishing-campaign-stats', selectedCampaign],
    queryFn: () => phishingAPI.getCampaignStats(selectedCampaign!).then(r => r.data),
    enabled: !!selectedCampaign,
  });

  // Mutations
  const launchMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.launchCampaign(id),
    onSuccess: () => {
      toast.success('Campaign launched successfully');
      queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
    },
    onError: () => toast.error('Failed to launch campaign'),
  });

  const pauseMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.pauseCampaign(id),
    onSuccess: () => {
      toast.success('Campaign paused');
      queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
    },
  });

  const completeMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.completeCampaign(id),
    onSuccess: () => {
      toast.success('Campaign completed');
      queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.deleteCampaign(id),
    onSuccess: () => {
      toast.success('Campaign deleted');
      queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] });
    },
  });

  const deleteTemplateMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.deleteTemplate(id),
    onSuccess: () => {
      toast.success('Template deleted');
      queryClient.invalidateQueries({ queryKey: ['phishing-templates'] });
      setDeletingTemplate(null);
    },
    onError: () => toast.error('Failed to delete template'),
  });

  const deleteLandingPageMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.deleteLandingPage(id),
    onSuccess: () => {
      toast.success('Landing page deleted');
      queryClient.invalidateQueries({ queryKey: ['phishing-landing-pages'] });
      setDeletingPage(null);
    },
    onError: () => toast.error('Failed to delete landing page'),
  });

  const deleteSmtpMutation = useMutation({
    mutationFn: (id: string) => phishingAPI.deleteSmtpProfile(id),
    onSuccess: () => {
      toast.success('SMTP profile deleted');
      queryClient.invalidateQueries({ queryKey: ['phishing-smtp-profiles'] });
      setDeletingSmtp(null);
    },
    onError: () => toast.error('Failed to delete SMTP profile'),
  });

  // Modal handlers
  const openCampaignModal = (id?: string) => {
    setEditingId(id);
    setShowCampaignModal(true);
  };

  const openTemplateModal = (id?: string) => {
    setEditingId(id);
    setShowTemplateModal(true);
  };

  const openLandingPageModal = (id?: string) => {
    setEditingId(id);
    setShowLandingPageModal(true);
  };

  const openSmtpModal = (id?: string) => {
    setEditingId(id);
    setShowSmtpModal(true);
  };

  // Copy template handler
  const handleCopyTemplate = async (templateId: string) => {
    try {
      // Fetch the original template
      const response = await phishingAPI.getTemplate(templateId);
      const original = response.data;

      // Create a copy with modified name
      await phishingAPI.createTemplate({
        name: `${original.name} (Copy)`,
        subject: original.subject,
        html_body: original.html_body || '',
        text_body: original.text_body,
        from_name: original.from_name,
        from_email: original.from_email,
      });

      toast.success('Template copied successfully');
      queryClient.invalidateQueries({ queryKey: ['phishing-templates'] });
    } catch {
      toast.error('Failed to copy template');
    }
  };

  const handleCampaignAction = (campaign: CampaignSummary, action: string) => {
    switch (action) {
      case 'launch':
        launchMutation.mutate(campaign.id);
        break;
      case 'pause':
        pauseMutation.mutate(campaign.id);
        break;
      case 'resume':
        launchMutation.mutate(campaign.id);
        break;
      case 'complete':
        completeMutation.mutate(campaign.id);
        break;
      case 'delete':
        if (confirm('Are you sure you want to delete this campaign?')) {
          deleteMutation.mutate(campaign.id);
        }
        break;
    }
  };

  // Calculate totals for campaigns
  const totalStats = campaigns?.reduce(
    (acc, c) => ({
      targets: acc.targets + c.total_targets,
      sent: acc.sent + c.emails_sent,
      opened: acc.opened + c.emails_opened,
      clicked: acc.clicked + c.links_clicked,
      credentials: acc.credentials + c.credentials_captured,
    }),
    { targets: 0, sent: 0, opened: 0, clicked: 0, credentials: 0 }
  );

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              Phishing Campaign Manager
            </h1>
            <p className="text-slate-500 dark:text-slate-400">
              Create and manage security awareness phishing simulations
            </p>
          </div>
          <Button disabled={!hasEngagement} onClick={() => openCampaignModal()}>
            <Plus className="h-4 w-4 mr-2" />
            New Campaign
          </Button>
        </div>

        <EngagementRequiredBanner toolName="Phishing Campaign Manager" />

        {/* Warning Banner */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-yellow-400">Authorization Required</p>
            <p className="text-sm text-slate-400">
              Phishing simulations must be conducted with proper authorization. Only use for
              security awareness training or authorized penetration testing engagements.
            </p>
          </div>
        </div>

        {/* Stats Overview */}
        {totalStats && (
          <div className="grid grid-cols-5 gap-4">
            <StatsCard
              label="Total Targets"
              value={totalStats.targets}
              icon={<Users className="h-5 w-5 text-blue-400" />}
              color="bg-blue-500/10"
            />
            <StatsCard
              label="Emails Sent"
              value={totalStats.sent}
              icon={<Send className="h-5 w-5 text-green-400" />}
              color="bg-green-500/10"
            />
            <StatsCard
              label="Emails Opened"
              value={totalStats.opened}
              icon={<Eye className="h-5 w-5 text-cyan-400" />}
              color="bg-cyan-500/10"
              percentage={totalStats.sent > 0 ? (totalStats.opened / totalStats.sent * 100) : 0}
            />
            <StatsCard
              label="Links Clicked"
              value={totalStats.clicked}
              icon={<MousePointer className="h-5 w-5 text-yellow-400" />}
              color="bg-yellow-500/10"
              percentage={totalStats.sent > 0 ? (totalStats.clicked / totalStats.sent * 100) : 0}
            />
            <StatsCard
              label="Credentials Captured"
              value={totalStats.credentials}
              icon={<Key className="h-5 w-5 text-red-400" />}
              color="bg-red-500/10"
              percentage={totalStats.sent > 0 ? (totalStats.credentials / totalStats.sent * 100) : 0}
            />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 border-b border-light-border dark:border-dark-border pb-2">
          {[
            { id: 'campaigns', label: 'Campaigns', icon: <Target className="h-4 w-4" /> },
            { id: 'templates', label: 'Email Templates', icon: <Mail className="h-4 w-4" /> },
            { id: 'pages', label: 'Landing Pages', icon: <Globe className="h-4 w-4" /> },
            { id: 'smtp', label: 'SMTP Profiles', icon: <Server className="h-4 w-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary text-white'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'campaigns' && (
          <div className="space-y-4">
            {loadingCampaigns ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : campaigns?.length === 0 ? (
              <div className="text-center py-12">
                <Target className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No campaigns yet
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Create your first phishing campaign to get started
                </p>
                <Button onClick={() => openCampaignModal()}>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Campaign
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {campaigns?.map((campaign) => (
                  <CampaignCard
                    key={campaign.id}
                    campaign={campaign}
                    onSelect={() => setSelectedCampaign(campaign.id)}
                    onAction={(action) => handleCampaignAction(campaign, action)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'templates' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <Button onClick={() => openTemplateModal()}>
                <Plus className="h-4 w-4 mr-2" />
                New Template
              </Button>
            </div>
            {loadingTemplates ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : templates?.length === 0 ? (
              <div className="text-center py-12">
                <Mail className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No email templates
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Create email templates to use in your campaigns
                </p>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Name</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Subject</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">From</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Created</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {templates?.map((template) => (
                      <tr key={template.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                        <td className="px-4 py-3 text-sm text-slate-900 dark:text-white font-medium">
                          <div className="flex items-center gap-2">
                            {template.name}
                            {template.is_system && (
                              <span className="px-2 py-0.5 text-xs font-medium rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                                System
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{template.subject}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{template.from_name} &lt;{template.from_email}&gt;</td>
                        <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">{new Date(template.created_at).toLocaleDateString()}</td>
                        <td className="px-4 py-3">
                          <div className="flex gap-2">
                            {!template.is_system && (
                              <Button size="sm" variant="ghost" onClick={() => openTemplateModal(template.id)} title="Edit"><Edit className="h-4 w-4" /></Button>
                            )}
                            <Button size="sm" variant="ghost" onClick={() => handleCopyTemplate(template.id)} title="Copy to create your own">{template.is_system ? <><Copy className="h-4 w-4 mr-1" /><span className="text-xs">Use</span></> : <Copy className="h-4 w-4" />}</Button>
                            {!template.is_system && (
                              <Button size="sm" variant="ghost" className="text-red-400" onClick={() => setDeletingTemplate(template.id)} title="Delete"><Trash2 className="h-4 w-4" /></Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'pages' && (
          <div className="space-y-4">
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowCloneModal(true)}>
                <Globe className="h-4 w-4 mr-2" />
                Clone Website
              </Button>
              <Button onClick={() => openLandingPageModal()}>
                <Plus className="h-4 w-4 mr-2" />
                New Landing Page
              </Button>
            </div>
            {loadingPages ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : landingPages?.length === 0 ? (
              <div className="text-center py-12">
                <Globe className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No landing pages
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Create landing pages for credential harvesting
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {landingPages?.map((page) => (
                  <div key={page.id} className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h3 className="font-medium text-slate-900 dark:text-white">{page.name}</h3>
                        {page.cloned_from && (
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Cloned from: {page.cloned_from}
                          </p>
                        )}
                      </div>
                      {page.capture_credentials && (
                        <span className="px-2 py-1 text-xs font-medium rounded bg-red-500/20 text-red-400 border border-red-500/30">
                          Credential Capture
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                      Created {new Date(page.created_at).toLocaleDateString()}
                    </p>
                    <div className="flex gap-2">
                      <Button size="sm" variant="ghost" onClick={() => openLandingPageModal(page.id)}><Eye className="h-4 w-4" /></Button>
                      <Button size="sm" variant="ghost" onClick={() => openLandingPageModal(page.id)}><Edit className="h-4 w-4" /></Button>
                      <Button size="sm" variant="ghost" className="text-red-400" onClick={() => setDeletingPage(page.id)}><Trash2 className="h-4 w-4" /></Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'smtp' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <Button onClick={() => openSmtpModal()}>
                <Plus className="h-4 w-4 mr-2" />
                New SMTP Profile
              </Button>
            </div>
            {loadingSmtp ? (
              <div className="flex justify-center py-12">
                <RefreshCw className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : smtpProfiles?.length === 0 ? (
              <div className="text-center py-12">
                <Server className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                  No SMTP profiles
                </h3>
                <p className="text-slate-500 dark:text-slate-400 mb-4">
                  Configure SMTP servers for sending phishing emails
                </p>
              </div>
            ) : (
              <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-light-bg dark:bg-dark-bg">
                    <tr>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Name</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Host</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Port</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">From Address</th>
                      <th className="text-left px-4 py-3 text-sm font-medium text-slate-500 dark:text-slate-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-light-border dark:divide-dark-border">
                    {smtpProfiles?.map((profile) => (
                      <tr key={profile.id} className="hover:bg-light-hover dark:hover:bg-dark-hover">
                        <td className="px-4 py-3 text-sm text-slate-900 dark:text-white font-medium">{profile.name}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{profile.host}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{profile.port}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{profile.from_address}</td>
                        <td className="px-4 py-3">
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" onClick={() => openSmtpModal(profile.id)}>
                              <Send className="h-4 w-4 mr-1" />
                              Test
                            </Button>
                            <Button size="sm" variant="ghost" onClick={() => openSmtpModal(profile.id)}><Edit className="h-4 w-4" /></Button>
                            <Button size="sm" variant="ghost" className="text-red-400" onClick={() => setDeletingSmtp(profile.id)}><Trash2 className="h-4 w-4" /></Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Modals */}
        <CampaignModal
          isOpen={showCampaignModal}
          onClose={() => { setShowCampaignModal(false); setEditingId(undefined); }}
          editId={editingId}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['phishing-campaigns'] })}
        />

        <EmailTemplateModal
          isOpen={showTemplateModal}
          onClose={() => { setShowTemplateModal(false); setEditingId(undefined); }}
          editId={editingId}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['phishing-templates'] })}
        />

        <LandingPageModal
          isOpen={showLandingPageModal}
          onClose={() => { setShowLandingPageModal(false); setEditingId(undefined); }}
          editId={editingId}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['phishing-landing-pages'] })}
        />

        <CloneWebsiteModal
          isOpen={showCloneModal}
          onClose={() => setShowCloneModal(false)}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['phishing-landing-pages'] })}
        />

        <SmtpProfileModal
          isOpen={showSmtpModal}
          onClose={() => { setShowSmtpModal(false); setEditingId(undefined); }}
          editId={editingId}
          onSuccess={() => queryClient.invalidateQueries({ queryKey: ['phishing-smtp-profiles'] })}
        />

        {/* Delete Confirmation Dialogs */}
        {deletingTemplate && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 max-w-md">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Delete Template</h3>
              <p className="text-slate-600 dark:text-slate-400 mb-4">
                Are you sure you want to delete this email template? This action cannot be undone.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setDeletingTemplate(null)}>Cancel</Button>
                <Button
                  className="bg-red-600 hover:bg-red-700"
                  onClick={() => deleteTemplateMutation.mutate(deletingTemplate)}
                  disabled={deleteTemplateMutation.isPending}
                >
                  {deleteTemplateMutation.isPending ? 'Deleting...' : 'Delete'}
                </Button>
              </div>
            </div>
          </div>
        )}

        {deletingPage && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 max-w-md">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Delete Landing Page</h3>
              <p className="text-slate-600 dark:text-slate-400 mb-4">
                Are you sure you want to delete this landing page? This action cannot be undone.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setDeletingPage(null)}>Cancel</Button>
                <Button
                  className="bg-red-600 hover:bg-red-700"
                  onClick={() => deleteLandingPageMutation.mutate(deletingPage)}
                  disabled={deleteLandingPageMutation.isPending}
                >
                  {deleteLandingPageMutation.isPending ? 'Deleting...' : 'Delete'}
                </Button>
              </div>
            </div>
          </div>
        )}

        {deletingSmtp && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg p-6 max-w-md">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Delete SMTP Profile</h3>
              <p className="text-slate-600 dark:text-slate-400 mb-4">
                Are you sure you want to delete this SMTP profile? This action cannot be undone.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setDeletingSmtp(null)}>Cancel</Button>
                <Button
                  className="bg-red-600 hover:bg-red-700"
                  onClick={() => deleteSmtpMutation.mutate(deletingSmtp)}
                  disabled={deleteSmtpMutation.isPending}
                >
                  {deleteSmtpMutation.isPending ? 'Deleting...' : 'Delete'}
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default PhishingPage;
