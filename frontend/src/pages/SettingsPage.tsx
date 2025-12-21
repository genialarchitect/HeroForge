import React, { useState } from 'react';
import Layout from '../components/layout/Layout';
import Profile from '../components/settings/Profile';
import Administration from '../components/settings/Administration';
import TargetGroups from '../components/settings/TargetGroups';
import ScheduledScans from '../components/settings/ScheduledScans';
import NotificationSettings from '../components/settings/NotificationSettings';
import ScanComparison from '../components/compare/ScanComparison';
import ScanTemplates from '../components/settings/ScanTemplates';
import FindingTemplates from '../components/settings/FindingTemplates';
import ExclusionsSettings from '../components/settings/ExclusionsSettings';
import MfaSettings from '../components/settings/MfaSettings';
import ApiKeys from '../components/settings/ApiKeys';
import JiraSettings from '../components/settings/JiraSettings';
import ServiceNowSettings from '../components/settings/ServiceNowSettings';
import SiemSettings from '../components/settings/SiemSettings';
import VpnSettings from '../components/settings/VpnSettings';
import AgentManagement from '../components/settings/AgentManagement';
import ScheduledReports from '../components/settings/ScheduledReports';
import WebhookSettings from '../components/settings/WebhookSettings';
import CiCdSettings from '../components/settings/CiCdSettings';
import SsoSettings from '../components/settings/SsoSettings';
import { Target, Clock, Bell, Settings, GitCompare, FileText, User, Shield, Lock, Key, ExternalLink, Database, Wifi, BookOpen, Ban, Mail, Webhook, Building2, Server, GitBranch, Users } from 'lucide-react';

type TabId = 'profile' | 'security' | 'api-keys' | 'administration' | 'sso' | 'target-groups' | 'exclusions' | 'scheduled-scans' | 'scheduled-reports' | 'templates' | 'finding-templates' | 'vpn' | 'agents' | 'notifications' | 'webhooks' | 'jira-integration' | 'servicenow-integration' | 'siem-integration' | 'cicd' | 'compare-scans';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
  component: React.ReactNode;
}

interface TabCategory {
  name: string;
  tabs: Tab[];
}

const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('profile');

  const categories: TabCategory[] = [
    {
      name: 'Account',
      tabs: [
        {
          id: 'profile',
          label: 'Profile',
          icon: <User className="h-4 w-4" />,
          component: <Profile />,
        },
        {
          id: 'security',
          label: 'Security',
          icon: <Lock className="h-4 w-4" />,
          component: <MfaSettings />,
        },
        {
          id: 'api-keys',
          label: 'API Keys',
          icon: <Key className="h-4 w-4" />,
          component: <ApiKeys />,
        },
      ],
    },
    {
      name: 'Administration',
      tabs: [
        {
          id: 'administration',
          label: 'Users',
          icon: <Shield className="h-4 w-4" />,
          component: <Administration />,
        },
        {
          id: 'sso',
          label: 'SSO',
          icon: <Users className="h-4 w-4" />,
          component: <SsoSettings />,
        },
      ],
    },
    {
      name: 'Scanning',
      tabs: [
        {
          id: 'target-groups',
          label: 'Target Groups',
          icon: <Target className="h-4 w-4" />,
          component: <TargetGroups />,
        },
        {
          id: 'exclusions',
          label: 'Exclusions',
          icon: <Ban className="h-4 w-4" />,
          component: <ExclusionsSettings />,
        },
        {
          id: 'scheduled-scans',
          label: 'Scheduled Scans',
          icon: <Clock className="h-4 w-4" />,
          component: <ScheduledScans />,
        },
        {
          id: 'scheduled-reports',
          label: 'Scheduled Reports',
          icon: <Mail className="h-4 w-4" />,
          component: <ScheduledReports />,
        },
        {
          id: 'templates',
          label: 'Scan Templates',
          icon: <FileText className="h-4 w-4" />,
          component: <ScanTemplates />,
        },
        {
          id: 'finding-templates',
          label: 'Finding Templates',
          icon: <BookOpen className="h-4 w-4" />,
          component: <FindingTemplates />,
        },
        {
          id: 'vpn',
          label: 'VPN',
          icon: <Wifi className="h-4 w-4" />,
          component: <VpnSettings />,
        },
        {
          id: 'agents',
          label: 'Agents',
          icon: <Server className="h-4 w-4" />,
          component: <AgentManagement />,
        },
        {
          id: 'compare-scans',
          label: 'Compare',
          icon: <GitCompare className="h-4 w-4" />,
          component: <ScanComparison />,
        },
      ],
    },
    {
      name: 'Integrations',
      tabs: [
        {
          id: 'notifications',
          label: 'Notifications',
          icon: <Bell className="h-4 w-4" />,
          component: <NotificationSettings />,
        },
        {
          id: 'webhooks',
          label: 'Webhooks',
          icon: <Webhook className="h-4 w-4" />,
          component: <WebhookSettings />,
        },
        {
          id: 'jira-integration',
          label: 'JIRA',
          icon: <ExternalLink className="h-4 w-4" />,
          component: <JiraSettings />,
        },
        {
          id: 'servicenow-integration',
          label: 'ServiceNow',
          icon: <Building2 className="h-4 w-4" />,
          component: <ServiceNowSettings />,
        },
        {
          id: 'siem-integration',
          label: 'SIEM',
          icon: <Database className="h-4 w-4" />,
          component: <SiemSettings />,
        },
        {
          id: 'cicd',
          label: 'CI/CD',
          icon: <GitBranch className="h-4 w-4" />,
          component: <CiCdSettings />,
        },
      ],
    },
  ];

  // Flatten tabs for easy lookup
  const allTabs = categories.flatMap(c => c.tabs);
  const activeTabData = allTabs.find((t) => t.id === activeTab);

  return (
    <Layout>
      <div className="space-y-6">
        {/* Page Header */}
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Settings className="h-6 w-6 text-primary" />
            <h1 className="text-2xl font-bold text-white">Settings</h1>
          </div>
          <p className="text-slate-400">
            Manage your account, scanning configuration, and integrations
          </p>
        </div>

        {/* Categorized Tabs */}
        <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
          <div className="flex flex-wrap gap-6">
            {categories.map((category) => (
              <div key={category.name} className="flex flex-col gap-2">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  {category.name}
                </span>
                <div className="flex gap-1">
                  {category.tabs.map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                        activeTab === tab.id
                          ? 'bg-primary text-white'
                          : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                      }`}
                    >
                      {tab.icon}
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div>{activeTabData?.component}</div>
      </div>
    </Layout>
  );
};

export default SettingsPage;
