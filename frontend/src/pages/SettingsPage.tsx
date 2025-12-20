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
import MfaSettings from '../components/settings/MfaSettings';
import ApiKeys from '../components/settings/ApiKeys';
import JiraSettings from '../components/settings/JiraSettings';
import SiemSettings from '../components/settings/SiemSettings';
import VpnSettings from '../components/settings/VpnSettings';
import { Target, Clock, Bell, Settings, GitCompare, FileText, User, Shield, Lock, Key, ExternalLink, Database, Wifi, BookOpen } from 'lucide-react';

type TabId = 'profile' | 'security' | 'api-keys' | 'administration' | 'target-groups' | 'scheduled-scans' | 'templates' | 'finding-templates' | 'vpn' | 'notifications' | 'jira-integration' | 'siem-integration' | 'compare-scans';

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
          id: 'scheduled-scans',
          label: 'Scheduled Scans',
          icon: <Clock className="h-4 w-4" />,
          component: <ScheduledScans />,
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
          id: 'jira-integration',
          label: 'JIRA',
          icon: <ExternalLink className="h-4 w-4" />,
          component: <JiraSettings />,
        },
        {
          id: 'siem-integration',
          label: 'SIEM',
          icon: <Database className="h-4 w-4" />,
          component: <SiemSettings />,
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
