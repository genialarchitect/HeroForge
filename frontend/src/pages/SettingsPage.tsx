import React, { useState } from 'react';
import Layout from '../components/layout/Layout';
import TargetGroups from '../components/settings/TargetGroups';
import ScheduledScans from '../components/settings/ScheduledScans';
import NotificationSettings from '../components/settings/NotificationSettings';
import { Target, Clock, Bell, Settings } from 'lucide-react';

type TabId = 'target-groups' | 'scheduled-scans' | 'notifications';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ReactNode;
  component: React.ReactNode;
}

const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('target-groups');

  const tabs: Tab[] = [
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
      id: 'notifications',
      label: 'Notifications',
      icon: <Bell className="h-4 w-4" />,
      component: <NotificationSettings />,
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
            Manage target groups, scheduled scans, and notification preferences
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
