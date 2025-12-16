import React, { useState } from 'react';
import Layout from '../components/layout/Layout';
import Profile from '../components/settings/Profile';
import Administration from '../components/settings/Administration';
import TargetGroups from '../components/settings/TargetGroups';
import ScheduledScans from '../components/settings/ScheduledScans';
import NotificationSettings from '../components/settings/NotificationSettings';
import ScanComparison from '../components/compare/ScanComparison';
import ScanTemplates from '../components/settings/ScanTemplates';
import MfaSettings from '../components/settings/MfaSettings';
import { Target, Clock, Bell, Settings, GitCompare, FileText, User, Shield, Lock } from 'lucide-react';

type TabId = 'profile' | 'security' | 'administration' | 'target-groups' | 'scheduled-scans' | 'templates' | 'notifications' | 'compare-scans';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
  component: React.ReactNode;
}

const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('profile');

  const tabs: Tab[] = [
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
      id: 'administration',
      label: 'Administration',
      icon: <Shield className="h-4 w-4" />,
      component: <Administration />,
    },
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
      id: 'notifications',
      label: 'Notifications',
      icon: <Bell className="h-4 w-4" />,
      component: <NotificationSettings />,
    },
    {
      id: 'compare-scans',
      label: 'Compare Scans',
      icon: <GitCompare className="h-4 w-4" />,
      component: <ScanComparison />,
    },
  ];

  const activeTabData = tabs.find((t) => t.id === activeTab);

  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <Settings className="h-6 w-6 text-primary" />
            <h1 className="text-2xl font-bold text-white">Settings</h1>
          </div>
          <p className="text-slate-400">
            Manage your profile, security, users, target groups, scheduled scans, templates, and notifications
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-dark-border pb-2">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-dark-surface text-primary border-b-2 border-primary'
                  : 'text-slate-400 hover:text-white hover:bg-dark-hover'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div>{activeTabData?.component}</div>
      </div>
    </Layout>
  );
};

export default SettingsPage;
