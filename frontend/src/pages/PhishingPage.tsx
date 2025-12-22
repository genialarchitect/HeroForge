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
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
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

// API Functions
const phishingAPI = {
  listCampaigns: () => api.get<CampaignSummary[]>('/phishing/campaigns'),
  getCampaign: (id: string) => api.get(`/phishing/campaigns/${id}`),
  getCampaignStats: (id: string) => api.get<CampaignStats>(`/phishing/campaigns/${id}/stats`),
  launchCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/launch`),
  pauseCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/pause`),
  completeCampaign: (id: string) => api.post(`/phishing/campaigns/${id}/complete`),
  deleteCampaign: (id: string) => api.delete(`/phishing/campaigns/${id}`),
  listTemplates: () => api.get<EmailTemplate[]>('/phishing/templates'),
  listLandingPages: () => api.get<LandingPage[]>('/phishing/landing-pages'),
  listSmtpProfiles: () => api.get<SmtpProfile[]>('/phishing/smtp-profiles'),
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

// Main page component
const PhishingPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'campaigns' | 'templates' | 'pages' | 'smtp'>('campaigns');
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null);

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
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            New Campaign
          </Button>
        </div>

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
                <Button>
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
              <Button>
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
                        <td className="px-4 py-3 text-sm text-slate-900 dark:text-white font-medium">{template.name}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{template.subject}</td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{template.from_name} &lt;{template.from_email}&gt;</td>
                        <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">{new Date(template.created_at).toLocaleDateString()}</td>
                        <td className="px-4 py-3">
                          <div className="flex gap-2">
                            <Button size="sm" variant="ghost"><Edit className="h-4 w-4" /></Button>
                            <Button size="sm" variant="ghost"><Copy className="h-4 w-4" /></Button>
                            <Button size="sm" variant="ghost" className="text-red-400"><Trash2 className="h-4 w-4" /></Button>
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
              <Button variant="outline">
                <Globe className="h-4 w-4 mr-2" />
                Clone Website
              </Button>
              <Button>
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
                      <Button size="sm" variant="ghost"><Eye className="h-4 w-4" /></Button>
                      <Button size="sm" variant="ghost"><Edit className="h-4 w-4" /></Button>
                      <Button size="sm" variant="ghost" className="text-red-400"><Trash2 className="h-4 w-4" /></Button>
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
              <Button>
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
                            <Button size="sm" variant="outline">
                              <Send className="h-4 w-4 mr-1" />
                              Test
                            </Button>
                            <Button size="sm" variant="ghost"><Edit className="h-4 w-4" /></Button>
                            <Button size="sm" variant="ghost" className="text-red-400"><Trash2 className="h-4 w-4" /></Button>
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
      </div>
    </Layout>
  );
};

export default PhishingPage;
