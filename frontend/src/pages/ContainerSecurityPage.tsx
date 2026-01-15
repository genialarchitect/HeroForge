import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Layers,
  FileCode,
  Plus,
  List,
  AlertTriangle,
  CheckCircle,
  Clock,
  RefreshCw,
  Trash2,
  ChevronRight,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { Layout } from '../components/layout/Layout';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import {
  ContainerScanForm,
  ContainerScanResults,
  DockerfileAnalyzer,
  K8sManifestAnalyzer,
} from '../components/container';
import { containerAPI } from '../services/api';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import type { ContainerScan, CreateContainerScanRequest } from '../types';

type TabType = 'scans' | 'new-scan' | 'dockerfile' | 'k8s-manifest';

const statusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  running: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

export default function ContainerSecurityPage() {
  const [activeTab, setActiveTab] = useState<TabType>('scans');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { hasEngagement } = useRequireEngagement();

  // Fetch scans list
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['containerScans'],
    queryFn: () => containerAPI.listScans().then((res) => res.data),
  });

  // Fetch scan types
  const { data: scanTypes } = useQuery({
    queryKey: ['containerScanTypes'],
    queryFn: () => containerAPI.getScanTypes().then((res) => res.data),
  });

  // Create scan mutation
  const createScanMutation = useMutation({
    mutationFn: (data: CreateContainerScanRequest) => containerAPI.createScan(data).then((res) => res.data),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ['containerScans'] });
      toast.success('Scan started successfully');
      setSelectedScanId(scan.id);
      setActiveTab('scans');
    },
    onError: () => {
      toast.error('Failed to start scan');
    },
  });

  // Delete scan mutation
  const deleteScanMutation = useMutation({
    mutationFn: (id: string) => containerAPI.deleteScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['containerScans'] });
      toast.success('Scan deleted');
      if (selectedScanId) setSelectedScanId(null);
    },
    onError: () => {
      toast.error('Failed to delete scan');
    },
  });

  const scans = scansData?.scans || [];

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'scans', label: 'Scan History', icon: <List className="w-4 h-4" /> },
    { id: 'new-scan', label: 'New Scan', icon: <Plus className="w-4 h-4" /> },
    { id: 'dockerfile', label: 'Dockerfile Analyzer', icon: <FileCode className="w-4 h-4" /> },
    { id: 'k8s-manifest', label: 'K8s Manifest Analyzer', icon: <Layers className="w-4 h-4" /> },
  ];

  const getScanTypeDisplay = (scanType: string) => {
    const type = scanTypes?.find((t) => t.id === scanType);
    return type?.name || scanType.replace('_', ' ');
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Box className="w-8 h-8 text-cyan-400" />
              Container Security
            </h1>
            <p className="text-gray-400 mt-1">
              Scan Docker images, analyze Dockerfiles, and audit Kubernetes configurations
            </p>
          </div>
        </div>

        <EngagementRequiredBanner toolName="Container Security" className="mb-6" />

        {/* Tabs */}
        <div className="border-b border-gray-700">
          <nav className="flex gap-4">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  if (tab.id !== 'scans') setSelectedScanId(null);
                }}
                className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-500 text-cyan-400'
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
          {activeTab === 'scans' && !selectedScanId && (
            <div className="space-y-4">
              {scansLoading ? (
                <div className="flex items-center justify-center p-12">
                  <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
                </div>
              ) : scans.length === 0 ? (
                <div className="bg-gray-800 rounded-lg border border-gray-700 p-12 text-center">
                  <Box className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-gray-300 mb-2">No Container Scans Yet</h3>
                  <p className="text-gray-400 mb-6">
                    Start by creating a new container security scan or analyzing a Dockerfile
                  </p>
                  <Button onClick={() => setActiveTab('new-scan')} disabled={!hasEngagement}>
                    <Plus className="w-4 h-4 mr-2" />
                    Create New Scan
                  </Button>
                </div>
              ) : (
                <div className="bg-gray-800 rounded-lg border border-gray-700">
                  <div className="p-4 border-b border-gray-700 flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-white">
                      Container Scans ({scans.length})
                    </h2>
                    <Button size="sm" onClick={() => setActiveTab('new-scan')} disabled={!hasEngagement}>
                      <Plus className="w-4 h-4 mr-2" />
                      New Scan
                    </Button>
                  </div>
                  <div className="divide-y divide-gray-700">
                    {scans.map((scan) => (
                      <div
                        key={scan.id}
                        className="p-4 hover:bg-gray-700/50 transition-colors cursor-pointer"
                        onClick={() => setSelectedScanId(scan.id)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div>
                              <h3 className="font-medium text-gray-200">{scan.name}</h3>
                              <div className="flex items-center gap-3 mt-1 text-sm text-gray-400">
                                <span className="flex items-center gap-1">
                                  <Box className="w-4 h-4" />
                                  {getScanTypeDisplay(scan.scan_type)}
                                </span>
                                <span className="flex items-center gap-1">
                                  <Clock className="w-4 h-4" />
                                  {new Date(scan.created_at).toLocaleDateString()}
                                </span>
                                <span className="text-gray-500 truncate max-w-xs">
                                  {scan.target}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            {scan.status === 'completed' && (
                              <div className="flex items-center gap-3 text-sm">
                                {scan.critical_count > 0 && (
                                  <span className="text-red-400">
                                    {scan.critical_count} Critical
                                  </span>
                                )}
                                {scan.high_count > 0 && (
                                  <span className="text-orange-400">
                                    {scan.high_count} High
                                  </span>
                                )}
                                <span className="text-gray-400">
                                  {scan.finding_count} Total
                                </span>
                              </div>
                            )}
                            <Badge className={`${statusColors[scan.status]?.bg} ${statusColors[scan.status]?.text}`}>
                              {scan.status === 'running' && <RefreshCw className="w-3 h-3 mr-1 animate-spin" />}
                              {scan.status === 'completed' && <CheckCircle className="w-3 h-3 mr-1" />}
                              {scan.status === 'failed' && <AlertTriangle className="w-3 h-3 mr-1" />}
                              {scan.status}
                            </Badge>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteScanMutation.mutate(scan.id);
                              }}
                              className="text-gray-400 hover:text-red-400 transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                            <ChevronRight className="w-5 h-5 text-gray-400" />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'scans' && selectedScanId && (
            <div>
              <button
                onClick={() => setSelectedScanId(null)}
                className="flex items-center gap-2 text-gray-400 hover:text-gray-200 mb-4"
              >
                <ChevronRight className="w-4 h-4 rotate-180" />
                Back to Scan List
              </button>
              <ContainerScanResults
                scanId={selectedScanId}
                onDelete={() => {
                  setSelectedScanId(null);
                  queryClient.invalidateQueries({ queryKey: ['containerScans'] });
                }}
              />
            </div>
          )}

          {activeTab === 'new-scan' && (
            <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
              <h2 className="text-lg font-semibold text-white mb-6">Create New Container Scan</h2>
              <ContainerScanForm
                onSubmit={(data) => createScanMutation.mutate(data)}
                isLoading={createScanMutation.isPending}
                scanTypes={scanTypes}
                disabled={!hasEngagement}
              />
            </div>
          )}

          {activeTab === 'dockerfile' && <DockerfileAnalyzer />}

          {activeTab === 'k8s-manifest' && <K8sManifestAnalyzer />}
        </div>
      </div>
    </Layout>
  );
}
