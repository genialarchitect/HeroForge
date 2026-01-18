import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  Clock,
  CheckCircle,
  XCircle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Package,
  Layers,
  ExternalLink,
  Trash2,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { containerAPI } from '../../services/api';
import { Button } from '../ui/Button';
import { Badge } from '../ui/Badge';
import type {
  ContainerFinding,
  ContainerFindingSeverity,
  FindingStatus,
} from '../../types';

interface ContainerScanResultsProps {
  scanId: string;
  onDelete?: () => void;
}

const severityColors: Record<ContainerFindingSeverity, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500' },
};

const statusColors: Record<string, { bg: string; text: string }> = {
  pending: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  running: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  completed: { bg: 'bg-green-500/20', text: 'text-green-400' },
  failed: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

const findingStatusColors: Record<FindingStatus, { bg: string; text: string }> = {
  open: { bg: 'bg-red-500/20', text: 'text-red-400' },
  resolved: { bg: 'bg-green-500/20', text: 'text-green-400' },
  accepted: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  false_positive: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
};

export function ContainerScanResults({ scanId, onDelete }: ContainerScanResultsProps) {
  const [selectedFinding, setSelectedFinding] = useState<ContainerFinding | null>(null);
  const [expandedImages, setExpandedImages] = useState<Set<string>>(new Set());
  const [expandedResources, setExpandedResources] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<ContainerFindingSeverity | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const queryClient = useQueryClient();

  // Fetch scan details
  const { data: scanData, isLoading: scanLoading, refetch: refetchScan } = useQuery({
    queryKey: ['containerScan', scanId],
    queryFn: () => containerAPI.getScan(scanId).then((res) => res.data),
    refetchInterval: (query) => {
      const status = query.state.data?.scan?.status;
      return status === 'running' || status === 'pending' ? 3000 : false;
    },
  });

  // Fetch findings
  const { data: findings = [], isLoading: findingsLoading } = useQuery({
    queryKey: ['containerFindings', scanId, severityFilter, statusFilter],
    queryFn: () =>
      containerAPI
        .getFindings(scanId, {
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          status: statusFilter !== 'all' ? statusFilter : undefined,
        })
        .then((res) => res.data),
    enabled: scanData?.scan?.status === 'completed',
  });

  // Fetch images
  const { data: images = [] } = useQuery({
    queryKey: ['containerImages', scanId],
    queryFn: () => containerAPI.getImages(scanId).then((res) => res.data),
    enabled: scanData?.scan?.status === 'completed',
  });

  // Fetch K8s resources
  const { data: resources = [] } = useQuery({
    queryKey: ['containerResources', scanId],
    queryFn: () => containerAPI.getResources(scanId).then((res) => res.data),
    enabled: scanData?.scan?.status === 'completed',
  });

  // Update finding status mutation
  const updateFindingStatusMutation = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      containerAPI.updateFindingStatus(findingId, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['containerFindings', scanId] });
      queryClient.invalidateQueries({ queryKey: ['containerScan', scanId] });
      toast.success('Finding status updated');
    },
    onError: () => {
      toast.error('Failed to update finding status');
    },
  });

  // Delete scan mutation
  const deleteMutation = useMutation({
    mutationFn: () => containerAPI.deleteScan(scanId),
    onSuccess: () => {
      toast.success('Scan deleted');
      onDelete?.();
    },
    onError: () => {
      toast.error('Failed to delete scan');
    },
  });

  const scan = scanData?.scan;
  const summary = scanData?.summary;

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center p-12 text-gray-400">
        Scan not found
      </div>
    );
  }

  const toggleImage = (id: string) => {
    const newSet = new Set(expandedImages);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setExpandedImages(newSet);
  };

  const toggleResource = (id: string) => {
    const newSet = new Set(expandedResources);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setExpandedResources(newSet);
  };

  return (
    <div className="space-y-6">
      {/* Scan Header */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white mb-2">{scan.name}</h2>
            <div className="flex items-center gap-4 text-sm text-gray-400">
              <span className="flex items-center gap-1">
                <Box className="w-4 h-4" />
                {scan.scan_type.replace('_', ' ')}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="w-4 h-4" />
                {new Date(scan.created_at).toLocaleString()}
              </span>
            </div>
            <p className="text-gray-300 mt-2">{scan.target}</p>
          </div>
          <div className="flex items-center gap-3">
            <Badge className={`${statusColors[scan.status]?.bg} ${statusColors[scan.status]?.text}`}>
              {scan.status === 'running' && <RefreshCw className="w-3 h-3 mr-1 animate-spin" />}
              {scan.status === 'completed' && <CheckCircle className="w-3 h-3 mr-1" />}
              {scan.status === 'failed' && <XCircle className="w-3 h-3 mr-1" />}
              {scan.status}
            </Badge>
            <Button variant="ghost" size="sm" onClick={() => refetchScan()}>
              <RefreshCw className="w-4 h-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={() => deleteMutation.mutate()}>
              <Trash2 className="w-4 h-4 text-red-400" />
            </Button>
          </div>
        </div>

        {scan.error_message && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
            {scan.error_message}
          </div>
        )}
      </div>

      {/* Summary Cards */}
      {summary && scan.status === 'completed' && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-2xl font-bold text-white">{summary.total_findings}</div>
            <div className="text-sm text-gray-400">Total Findings</div>
          </div>
          <div className={`rounded-lg p-4 border ${severityColors.critical.border} ${severityColors.critical.bg}`}>
            <div className={`text-2xl font-bold ${severityColors.critical.text}`}>{summary.critical_count}</div>
            <div className="text-sm text-gray-400">Critical</div>
          </div>
          <div className={`rounded-lg p-4 border ${severityColors.high.border} ${severityColors.high.bg}`}>
            <div className={`text-2xl font-bold ${severityColors.high.text}`}>{summary.high_count}</div>
            <div className="text-sm text-gray-400">High</div>
          </div>
          <div className={`rounded-lg p-4 border ${severityColors.medium.border} ${severityColors.medium.bg}`}>
            <div className={`text-2xl font-bold ${severityColors.medium.text}`}>{summary.medium_count}</div>
            <div className="text-sm text-gray-400">Medium</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-2xl font-bold text-white">{summary.images_scanned}</div>
            <div className="text-sm text-gray-400">Images</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="text-2xl font-bold text-white">{summary.resources_scanned}</div>
            <div className="text-sm text-gray-400">K8s Resources</div>
          </div>
        </div>
      )}

      {/* Running State */}
      {(scan.status === 'running' || scan.status === 'pending') && (
        <div className="bg-gray-800 rounded-lg p-8 border border-gray-700 text-center">
          <RefreshCw className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-4" />
          <p className="text-gray-300">Scan in progress...</p>
          <p className="text-sm text-gray-400 mt-2">This page will automatically refresh when the scan completes.</p>
        </div>
      )}

      {/* Images Section */}
      {images.length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Package className="w-5 h-5 text-cyan-400" />
              Scanned Images ({images.length})
            </h3>
          </div>
          <div className="divide-y divide-gray-700">
            {images.map((image) => (
              <div key={image.id} className="p-4">
                <button
                  onClick={() => toggleImage(image.id)}
                  className="w-full flex items-center justify-between text-left"
                >
                  <div className="flex items-center gap-3">
                    {expandedImages.has(image.id) ? (
                      <ChevronDown className="w-4 h-4 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    )}
                    <span className="font-mono text-cyan-400">
                      {image.image_name}:{image.image_tag}
                    </span>
                  </div>
                  {image.registry && (
                    <span className="text-sm text-gray-400">{image.registry}</span>
                  )}
                </button>
                {expandedImages.has(image.id) && (
                  <div className="mt-3 ml-7 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    {image.os && (
                      <div>
                        <span className="text-gray-400">OS:</span>{' '}
                        <span className="text-gray-200">{image.os}</span>
                      </div>
                    )}
                    {image.architecture && (
                      <div>
                        <span className="text-gray-400">Arch:</span>{' '}
                        <span className="text-gray-200">{image.architecture}</span>
                      </div>
                    )}
                    {image.layer_count && (
                      <div>
                        <span className="text-gray-400">Layers:</span>{' '}
                        <span className="text-gray-200">{image.layer_count}</span>
                      </div>
                    )}
                    {image.size_bytes && (
                      <div>
                        <span className="text-gray-400">Size:</span>{' '}
                        <span className="text-gray-200">
                          {(image.size_bytes / 1024 / 1024).toFixed(1)} MB
                        </span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* K8s Resources Section */}
      {resources.length > 0 && (
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-purple-400" />
              Kubernetes Resources ({resources.length})
            </h3>
          </div>
          <div className="divide-y divide-gray-700">
            {resources.map((resource) => (
              <div key={resource.id} className="p-4">
                <button
                  onClick={() => toggleResource(resource.id)}
                  className="w-full flex items-center justify-between text-left"
                >
                  <div className="flex items-center gap-3">
                    {expandedResources.has(resource.id) ? (
                      <ChevronDown className="w-4 h-4 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    )}
                    <Badge className="bg-purple-500/20 text-purple-400">
                      {resource.resource_type}
                    </Badge>
                    <span className="text-gray-200">{resource.name}</span>
                  </div>
                  {resource.namespace && (
                    <span className="text-sm text-gray-400">ns: {resource.namespace}</span>
                  )}
                </button>
                {expandedResources.has(resource.id) && (
                  <div className="mt-3 ml-7 text-sm text-gray-400">
                    {resource.api_version && <div>API Version: {resource.api_version}</div>}
                    {resource.spec_summary && <div className="mt-1">{resource.spec_summary}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Section */}
      {scan.status === 'completed' && (
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                Security Findings ({findings.length})
              </h3>
              <div className="flex items-center gap-3">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value as ContainerFindingSeverity | 'all')}
                  className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-sm text-gray-200"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value as FindingStatus | 'all')}
                  className="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-sm text-gray-200"
                >
                  <option value="all">All Status</option>
                  <option value="open">Open</option>
                  <option value="resolved">Resolved</option>
                  <option value="accepted">Accepted</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
            </div>
          </div>

          {findingsLoading ? (
            <div className="p-8 text-center">
              <RefreshCw className="w-6 h-6 text-gray-400 animate-spin mx-auto" />
            </div>
          ) : findings.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              {severityFilter !== 'all' || statusFilter !== 'all'
                ? 'No findings match the current filters'
                : 'No security findings detected'}
            </div>
          ) : (
            <div className="divide-y divide-gray-700">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className={`p-4 cursor-pointer hover:bg-gray-700/50 transition-colors ${
                    selectedFinding?.id === finding.id ? 'bg-gray-700/50' : ''
                  }`}
                  onClick={() => setSelectedFinding(finding)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <div className={`mt-0.5 ${severityColors[finding.severity].text}`}>
                        {finding.severity === 'critical' && <AlertCircle className="w-5 h-5" />}
                        {finding.severity === 'high' && <AlertTriangle className="w-5 h-5" />}
                        {finding.severity === 'medium' && <AlertTriangle className="w-5 h-5" />}
                        {finding.severity === 'low' && <Info className="w-5 h-5" />}
                        {finding.severity === 'info' && <Info className="w-5 h-5" />}
                      </div>
                      <div>
                        <h4 className="font-medium text-gray-200">{finding.title}</h4>
                        <p className="text-sm text-gray-400 mt-1 line-clamp-2">{finding.description}</p>
                        <div className="flex flex-wrap items-center gap-2 mt-2">
                          <Badge className={`${severityColors[finding.severity].bg} ${severityColors[finding.severity].text}`}>
                            {finding.severity}
                          </Badge>
                          <Badge className="bg-gray-700 text-gray-300">
                            {finding.finding_type.replace('_', ' ')}
                          </Badge>
                          {finding.cve_id && (
                            <Badge className="bg-purple-500/20 text-purple-400">
                              {finding.cve_id}
                            </Badge>
                          )}
                          {finding.cvss_score && (
                            <Badge className="bg-gray-700 text-gray-300">
                              CVSS: {finding.cvss_score.toFixed(1)}
                            </Badge>
                          )}
                          {finding.package_name && (
                            <Badge className="bg-blue-500/20 text-blue-400">
                              {finding.package_name}
                              {finding.installed_version && ` @ ${finding.installed_version}`}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={`${findingStatusColors[finding.status].bg} ${findingStatusColors[finding.status].text}`}>
                        {finding.status.replace('_', ' ')}
                      </Badge>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto border border-gray-700">
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-xl font-semibold text-white">{selectedFinding.title}</h3>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge className={`${severityColors[selectedFinding.severity].bg} ${severityColors[selectedFinding.severity].text}`}>
                      {selectedFinding.severity}
                    </Badge>
                    {selectedFinding.cve_id && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
                      >
                        {selectedFinding.cve_id}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-400 hover:text-gray-200"
                >
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <h4 className="text-sm font-medium text-gray-400 mb-1">Description</h4>
                <p className="text-gray-200">{selectedFinding.description}</p>
              </div>

              {selectedFinding.package_name && (
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-1">Affected Package</h4>
                  <p className="text-gray-200">
                    {selectedFinding.package_name}
                    {selectedFinding.installed_version && ` (${selectedFinding.installed_version})`}
                  </p>
                </div>
              )}

              {selectedFinding.fixed_version && (
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-1">Fixed In</h4>
                  <p className="text-green-400">{selectedFinding.fixed_version}</p>
                </div>
              )}

              {selectedFinding.file_path && (
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-1">Location</h4>
                  <p className="font-mono text-gray-200">
                    {selectedFinding.file_path}
                    {selectedFinding.line_number && `:${selectedFinding.line_number}`}
                  </p>
                </div>
              )}

              {selectedFinding.remediation && (
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-1">Remediation</h4>
                  <p className="text-gray-200">{selectedFinding.remediation}</p>
                </div>
              )}

              <div>
                <h4 className="text-sm font-medium text-gray-400 mb-2">Update Status</h4>
                <div className="flex items-center gap-2">
                  {(['open', 'resolved', 'accepted', 'false_positive'] as FindingStatus[]).map((status) => (
                    <Button
                      key={status}
                      variant={selectedFinding.status === status ? 'primary' : 'ghost'}
                      size="sm"
                      onClick={() => {
                        updateFindingStatusMutation.mutate({
                          findingId: selectedFinding.id,
                          status,
                        });
                        setSelectedFinding({ ...selectedFinding, status });
                      }}
                    >
                      {status.replace('_', ' ')}
                    </Button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
