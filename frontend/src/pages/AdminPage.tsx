import React, { useState } from 'react';
import Layout from '../components/layout/Layout';
import UserManagement from '../components/admin/UserManagement';
import ScanManagement from '../components/admin/ScanManagement';
import AuditLogs from '../components/admin/AuditLogs';
import SystemSettings from '../components/admin/SystemSettings';
import { Shield, Users, Activity, Settings, FileText } from 'lucide-react';

type TabValue = 'users' | 'scans' | 'audit' | 'settings';

const AdminPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabValue>('users');

  const tabs = [
    { value: 'users' as TabValue, label: 'Users', icon: Users },
    { value: 'scans' as TabValue, label: 'Scans', icon: Activity },
    { value: 'audit' as TabValue, label: 'Audit Logs', icon: FileText },
    { value: 'settings' as TabValue, label: 'Settings', icon: Settings },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h2 className="text-3xl font-bold text-white">Admin Console</h2>
            <p className="text-slate-400">Manage users, scans, and system settings</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-dark-border">
          <div className="flex gap-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.value}
                  onClick={() => setActiveTab(tab.value)}
                  className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                    activeTab === tab.value
                      ? 'border-primary text-primary font-medium'
                      : 'border-transparent text-slate-400 hover:text-white hover:border-slate-600'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Tab Content */}
        <div className="animate-fadeIn">
          {activeTab === 'users' && <UserManagement />}
          {activeTab === 'scans' && <ScanManagement />}
          {activeTab === 'audit' && <AuditLogs />}
          {activeTab === 'settings' && <SystemSettings />}
        </div>
      </div>
    </Layout>
  );
};

export default AdminPage;
