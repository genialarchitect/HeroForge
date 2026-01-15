import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileCode,
  Shield,
  Settings,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle,
  Trash2,
  RefreshCw,
  ChevronRight,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { iacAPI } from '../services/api';
import type { IacScan } from '../types';
import IacScanForm from '../components/iac/IacScanForm';
import IacScanResults from '../components/iac/IacScanResults';
import IacRulesManager from '../components/iac/IacRulesManager';
import Button from '../components/ui/Button';
import { Layout } from '../components/layout/Layout';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';

type TabType = 'scans' | 'rules';

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case 'completed':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'failed':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'running':
      return <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />;
    default:
      return <Clock className="w-4 h-4 text-yellow-400" />;
  }
};

const getSeverityBadge = (count: number, severity: string, color: string) => {
  if (count === 0) return null;
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded ${color}`}>
      {count} {severity}
    </span>
  );
};

export default function IacSecurityPage() {
  const [activeTab, setActiveTab] = useState<TabType>('scans');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const { hasEngagement } = useRequireEngagement();

  // Fetch scans
  const {
    data: scans = [],
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['iac-scans'],
    queryFn: async () => {
      const response = await iacAPI.listScans();
      return response.data;
    },
  });

  // Delete scan mutation
  const handleDelete = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await iacAPI.deleteScan(scanId);
      toast.success('Scan deleted successfully');
      refetch();
    } catch (err) {
      toast.error('Failed to delete scan');
    }
  };

  const handleScanCreated = (scanId: string) => {
    refetch();
    setSelectedScanId(scanId);
  };

  // If viewing a specific scan
  if (selectedScanId) {
    return (
      <Layout>
        <IacScanResults
          scanId={selectedScanId}
          onBack={() => setSelectedScanId(null)}
        />
      </Layout>
    );
  }

  return (
    <Layout>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">IaC Security Scanning</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          Scan Terraform, CloudFormation, and Azure ARM templates for security issues
        </p>
      </div>

      <EngagementRequiredBanner toolName="IaC Security Scanning" className="mb-6" />

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-6 border-b border-gray-700">
        <button
          onClick={() => setActiveTab('scans')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'scans'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4" />
            <span>Scans</span>
          </div>
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`pb-3 px-1 border-b-2 transition-colors ${
            activeTab === 'rules'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4" />
            <span>Rules</span>
          </div>
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'scans' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Upload Form */}
          <div className="lg:col-span-1">
            <IacScanForm onScanCreated={handleScanCreated} />

            {/* Supported Platforms */}
            <div className="mt-6 bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h4 className="text-sm font-medium text-gray-400 mb-3">Supported Platforms</h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm text-gray-300">
                  <div className="w-2 h-2 rounded-full bg-purple-500" />
                  Terraform (.tf, .tf.json)
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-300">
                  <div className="w-2 h-2 rounded-full bg-orange-500" />
                  AWS CloudFormation (JSON/YAML)
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-300">
                  <div className="w-2 h-2 rounded-full bg-blue-500" />
                  Azure ARM Templates
                </div>
              </div>
            </div>
          </div>

          {/* Scan List */}
          <div className="lg:col-span-2">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
              <Button variant="outline" size="sm" onClick={() => refetch()}>
                <RefreshCw className="w-4 h-4 mr-2" />
                Refresh
              </Button>
            </div>

            {isLoading ? (
              <div className="flex items-center justify-center h-64 bg-gray-800 rounded-lg">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              </div>
            ) : scans.length === 0 ? (
              <div className="text-center py-12 bg-gray-800 rounded-lg border border-gray-700">
                <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">No Scans Yet</h3>
                <p className="text-gray-400">
                  Upload your first IaC files to start scanning for security issues.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {scans.map((scan) => (
                  <ScanCard
                    key={scan.id}
                    scan={scan}
                    onView={() => setSelectedScanId(scan.id)}
                    onDelete={() => handleDelete(scan.id)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <IacRulesManager />
      )}
    </Layout>
  );
}

function ScanCard({
  scan,
  onView,
  onDelete,
}: {
  scan: IacScan;
  onView: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            {getStatusIcon(scan.status)}
            <h4 className="font-medium text-white truncate">{scan.name}</h4>
          </div>
          <div className="flex items-center gap-3 mt-2 text-sm text-gray-400">
            <span>{scan.file_count} files</span>
            <span className="text-gray-600">|</span>
            <span>{scan.resource_count} resources</span>
            <span className="text-gray-600">|</span>
            <span>{new Date(scan.created_at).toLocaleString()}</span>
          </div>
          {scan.status === 'completed' && scan.finding_count > 0 && (
            <div className="flex items-center gap-2 mt-2">
              {getSeverityBadge(scan.critical_count, 'Critical', 'bg-red-500/20 text-red-400')}
              {getSeverityBadge(scan.high_count, 'High', 'bg-orange-500/20 text-orange-400')}
              {getSeverityBadge(scan.medium_count, 'Medium', 'bg-yellow-500/20 text-yellow-400')}
              {getSeverityBadge(scan.low_count, 'Low', 'bg-blue-500/20 text-blue-400')}
            </div>
          )}
          {scan.status === 'completed' && scan.finding_count === 0 && (
            <div className="flex items-center gap-2 mt-2 text-sm text-green-400">
              <CheckCircle className="w-4 h-4" />
              No security issues found
            </div>
          )}
          {scan.status === 'failed' && scan.error_message && (
            <div className="flex items-center gap-2 mt-2 text-sm text-red-400">
              <AlertTriangle className="w-4 h-4" />
              {scan.error_message.slice(0, 50)}...
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onView}
            className="p-2 text-gray-400 hover:text-cyan-400 transition-colors"
            title="View details"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
          <button
            onClick={onDelete}
            className="p-2 text-gray-400 hover:text-red-400 transition-colors"
            title="Delete scan"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
