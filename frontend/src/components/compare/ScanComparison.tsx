import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { scanAPI, compareAPI } from '../../services/api';
import { ScanResult, ScanComparisonResponse, HostDiff, ServiceChangeType } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  GitCompare,
  ChevronDown,
  ChevronRight,
  Plus,
  Minus,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Server,
  Network,
  Shield,
  Activity,
} from 'lucide-react';

const ScanComparison: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [scanId1, setScanId1] = useState('');
  const [scanId2, setScanId2] = useState('');
  const [comparing, setComparing] = useState(false);
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoadingScans(true);
    try {
      const response = await scanAPI.getAll();
      // Filter only completed scans
      const completedScans = response.data.filter((s) => s.status === 'completed');
      setScans(completedScans);
    } catch (error) {
      toast.error('Failed to load scans');
      console.error(error);
    } finally {
      setLoadingScans(false);
    }
  };

  const handleCompare = async () => {
    if (!scanId1 || !scanId2) {
      toast.error('Please select two scans to compare');
      return;
    }

    if (scanId1 === scanId2) {
      toast.error('Please select two different scans');
      return;
    }

    setComparing(true);
    try {
      const response = await compareAPI.compare(scanId1, scanId2);
      setComparison(response.data);
      toast.success('Comparison completed');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to compare scans');
      console.error(error);
    } finally {
      setComparing(false);
    }
  };

  const toggleHost = (ip: string) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(ip)) {
      newExpanded.delete(ip);
    } else {
      newExpanded.add(ip);
    }
    setExpandedHosts(newExpanded);
  };

  const getServiceChangeIcon = (changeType: ServiceChangeType) => {
    switch (changeType) {
      case 'NewService':
        return <Plus className="h-3 w-3 text-green-400" />;
      case 'ServiceRemoved':
        return <Minus className="h-3 w-3 text-red-400" />;
      case 'ServiceChanged':
      case 'VersionChanged':
        return <RefreshCw className="h-3 w-3 text-yellow-400" />;
      default:
        return null;
    }
  };

  const getChangeTypeLabel = (changeType: ServiceChangeType): string => {
    switch (changeType) {
      case 'NewService':
        return 'New Service';
      case 'ServiceRemoved':
        return 'Service Removed';
      case 'ServiceChanged':
        return 'Service Changed';
      case 'VersionChanged':
        return 'Version Changed';
      default:
        return changeType;
    }
  };

  if (loadingScans) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header Card */}
      <Card>
        <div className="flex items-center gap-2 mb-4">
          <GitCompare className="h-5 w-5 text-primary" />
          <h3 className="text-xl font-semibold text-white">Compare Scans</h3>
        </div>
        <p className="text-sm text-slate-400 mb-6">
          Select two completed scans to compare their results and identify changes in hosts, ports,
          services, and vulnerabilities.
        </p>

        {/* Scan Selection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Baseline Scan (Older)
            </label>
            <select
              value={scanId1}
              onChange={(e) => setScanId1(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="">Select a scan...</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.name} - {new Date(scan.created_at).toLocaleString()}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Comparison Scan (Newer)
            </label>
            <select
              value={scanId2}
              onChange={(e) => setScanId2(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
            >
              <option value="">Select a scan...</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.name} - {new Date(scan.created_at).toLocaleString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex justify-end">
          <Button
            variant="primary"
            onClick={handleCompare}
            loading={comparing}
            disabled={!scanId1 || !scanId2 || scanId1 === scanId2}
          >
            <GitCompare className="h-4 w-4 mr-2" />
            Compare Scans
          </Button>
        </div>
      </Card>

      {/* Comparison Results */}
      {comparison && (
        <>
          {/* Summary Card */}
          <Card>
            <div className="flex items-center gap-2 mb-4">
              <Activity className="h-5 w-5 text-primary" />
              <h3 className="text-lg font-semibold text-white">Comparison Summary</h3>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
              {/* New Hosts */}
              <div className="bg-dark-bg rounded-lg p-3 border border-green-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <Plus className="h-4 w-4 text-green-400" />
                  <span className="text-xs text-slate-400">New Hosts</span>
                </div>
                <p className="text-2xl font-bold text-green-400">
                  {comparison.diff.summary.total_new_hosts}
                </p>
              </div>

              {/* Removed Hosts */}
              <div className="bg-dark-bg rounded-lg p-3 border border-red-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <Minus className="h-4 w-4 text-red-400" />
                  <span className="text-xs text-slate-400">Removed</span>
                </div>
                <p className="text-2xl font-bold text-red-400">
                  {comparison.diff.summary.total_removed_hosts}
                </p>
              </div>

              {/* Changed Hosts */}
              <div className="bg-dark-bg rounded-lg p-3 border border-yellow-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <RefreshCw className="h-4 w-4 text-yellow-400" />
                  <span className="text-xs text-slate-400">Changed</span>
                </div>
                <p className="text-2xl font-bold text-yellow-400">
                  {comparison.diff.summary.total_hosts_changed}
                </p>
              </div>

              {/* New Ports */}
              <div className="bg-dark-bg rounded-lg p-3 border border-green-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <Network className="h-4 w-4 text-green-400" />
                  <span className="text-xs text-slate-400">New Ports</span>
                </div>
                <p className="text-2xl font-bold text-green-400">
                  {comparison.diff.summary.total_new_ports}
                </p>
              </div>

              {/* Closed Ports */}
              <div className="bg-dark-bg rounded-lg p-3 border border-red-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <Network className="h-4 w-4 text-red-400" />
                  <span className="text-xs text-slate-400">Closed</span>
                </div>
                <p className="text-2xl font-bold text-red-400">
                  {comparison.diff.summary.total_closed_ports}
                </p>
              </div>

              {/* New Vulnerabilities */}
              <div className="bg-dark-bg rounded-lg p-3 border border-red-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span className="text-xs text-slate-400">New Vulns</span>
                </div>
                <p className="text-2xl font-bold text-red-400">
                  {comparison.diff.summary.total_new_vulnerabilities}
                </p>
              </div>

              {/* Resolved Vulnerabilities */}
              <div className="bg-dark-bg rounded-lg p-3 border border-green-500/30">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="text-xs text-slate-400">Resolved</span>
                </div>
                <p className="text-2xl font-bold text-green-400">
                  {comparison.diff.summary.total_resolved_vulnerabilities}
                </p>
              </div>
            </div>
          </Card>

          {/* New Hosts */}
          {comparison.diff.new_hosts.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Plus className="h-5 w-5 text-green-400" />
                <h3 className="text-lg font-semibold text-white">
                  New Hosts ({comparison.diff.new_hosts.length})
                </h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {comparison.diff.new_hosts.map((host) => (
                  <span
                    key={host}
                    className="px-3 py-1.5 bg-green-500/20 border border-green-500/30 rounded-lg text-green-400 font-mono text-sm"
                  >
                    {host}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {/* Removed Hosts */}
          {comparison.diff.removed_hosts.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Minus className="h-5 w-5 text-red-400" />
                <h3 className="text-lg font-semibold text-white">
                  Removed Hosts ({comparison.diff.removed_hosts.length})
                </h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {comparison.diff.removed_hosts.map((host) => (
                  <span
                    key={host}
                    className="px-3 py-1.5 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 font-mono text-sm"
                  >
                    {host}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {/* Host Changes */}
          {comparison.diff.host_changes.length > 0 && (
            <Card>
              <div className="flex items-center gap-2 mb-4">
                <Server className="h-5 w-5 text-yellow-400" />
                <h3 className="text-lg font-semibold text-white">
                  Host Changes ({comparison.diff.host_changes.length})
                </h3>
              </div>
              <div className="space-y-3">
                {comparison.diff.host_changes.map((hostDiff: HostDiff) => {
                  const isExpanded = expandedHosts.has(hostDiff.ip);
                  const hasChanges =
                    hostDiff.new_ports.length > 0 ||
                    hostDiff.closed_ports.length > 0 ||
                    hostDiff.new_vulnerabilities.length > 0 ||
                    hostDiff.resolved_vulnerabilities.length > 0 ||
                    hostDiff.service_changes.length > 0 ||
                    hostDiff.os_change !== null;

                  if (!hasChanges) return null;

                  return (
                    <div
                      key={hostDiff.ip}
                      className="bg-dark-bg rounded-lg border border-dark-border overflow-hidden"
                    >
                      {/* Host Header */}
                      <button
                        onClick={() => toggleHost(hostDiff.ip)}
                        className="w-full flex items-center justify-between p-4 hover:bg-dark-hover transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-slate-400" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-slate-400" />
                          )}
                          <Server className="h-4 w-4 text-primary" />
                          <span className="font-mono text-white">{hostDiff.ip}</span>
                          {hostDiff.hostname && (
                            <span className="text-sm text-slate-400">({hostDiff.hostname})</span>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          {hostDiff.new_ports.length > 0 && (
                            <span className="px-2 py-1 bg-green-500/20 border border-green-500/30 rounded text-xs text-green-400">
                              +{hostDiff.new_ports.length} ports
                            </span>
                          )}
                          {hostDiff.closed_ports.length > 0 && (
                            <span className="px-2 py-1 bg-red-500/20 border border-red-500/30 rounded text-xs text-red-400">
                              -{hostDiff.closed_ports.length} ports
                            </span>
                          )}
                          {hostDiff.new_vulnerabilities.length > 0 && (
                            <span className="px-2 py-1 bg-red-500/20 border border-red-500/30 rounded text-xs text-red-400">
                              +{hostDiff.new_vulnerabilities.length} vulns
                            </span>
                          )}
                          {hostDiff.resolved_vulnerabilities.length > 0 && (
                            <span className="px-2 py-1 bg-green-500/20 border border-green-500/30 rounded text-xs text-green-400">
                              -{hostDiff.resolved_vulnerabilities.length} vulns
                            </span>
                          )}
                        </div>
                      </button>

                      {/* Expanded Details */}
                      {isExpanded && (
                        <div className="border-t border-dark-border p-4 space-y-4">
                          {/* OS Change */}
                          {hostDiff.os_change && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2">
                                Operating System Change
                              </h5>
                              <div className="bg-dark-surface rounded p-3 space-y-1">
                                <div className="flex items-center gap-2">
                                  <Minus className="h-3 w-3 text-red-400" />
                                  <span className="text-sm text-red-400">
                                    {hostDiff.os_change.old_os} (
                                    {hostDiff.os_change.old_confidence}% confidence)
                                  </span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <Plus className="h-3 w-3 text-green-400" />
                                  <span className="text-sm text-green-400">
                                    {hostDiff.os_change.new_os} (
                                    {hostDiff.os_change.new_confidence}% confidence)
                                  </span>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* New Ports */}
                          {hostDiff.new_ports.length > 0 && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                                <Plus className="h-4 w-4 text-green-400" />
                                New Open Ports ({hostDiff.new_ports.length})
                              </h5>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {hostDiff.new_ports.map((port) => (
                                  <div
                                    key={port.port}
                                    className="bg-dark-surface rounded p-2 flex items-center justify-between"
                                  >
                                    <span className="font-mono text-sm text-green-400">
                                      {port.port}/{port.protocol}
                                    </span>
                                    {port.service && (
                                      <span className="text-xs text-slate-400">
                                        {port.service.name}
                                        {port.service.version && ` ${port.service.version}`}
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Closed Ports */}
                          {hostDiff.closed_ports.length > 0 && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                                <Minus className="h-4 w-4 text-red-400" />
                                Closed Ports ({hostDiff.closed_ports.length})
                              </h5>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {hostDiff.closed_ports.map((port) => (
                                  <div
                                    key={port.port}
                                    className="bg-dark-surface rounded p-2 flex items-center justify-between"
                                  >
                                    <span className="font-mono text-sm text-red-400">
                                      {port.port}/{port.protocol}
                                    </span>
                                    {port.service && (
                                      <span className="text-xs text-slate-400">
                                        {port.service.name}
                                        {port.service.version && ` ${port.service.version}`}
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Service Changes */}
                          {hostDiff.service_changes.length > 0 && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                                <RefreshCw className="h-4 w-4 text-yellow-400" />
                                Service Changes ({hostDiff.service_changes.length})
                              </h5>
                              <div className="space-y-2">
                                {hostDiff.service_changes.map((change, idx) => (
                                  <div
                                    key={idx}
                                    className="bg-dark-surface rounded p-3 space-y-1"
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="font-mono text-sm text-white">
                                        {change.port}/{change.protocol}
                                      </span>
                                      <div className="flex items-center gap-2">
                                        {getServiceChangeIcon(change.change_type)}
                                        <span className="text-xs text-yellow-400">
                                          {getChangeTypeLabel(change.change_type)}
                                        </span>
                                      </div>
                                    </div>
                                    {change.old_service && (
                                      <div className="flex items-center gap-2 text-sm">
                                        <Minus className="h-3 w-3 text-red-400" />
                                        <span className="text-red-400">
                                          {change.old_service}
                                          {change.old_version && ` ${change.old_version}`}
                                        </span>
                                      </div>
                                    )}
                                    {change.new_service && (
                                      <div className="flex items-center gap-2 text-sm">
                                        <Plus className="h-3 w-3 text-green-400" />
                                        <span className="text-green-400">
                                          {change.new_service}
                                          {change.new_version && ` ${change.new_version}`}
                                        </span>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* New Vulnerabilities */}
                          {hostDiff.new_vulnerabilities.length > 0 && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4 text-red-400" />
                                New Vulnerabilities ({hostDiff.new_vulnerabilities.length})
                              </h5>
                              <div className="space-y-2">
                                {hostDiff.new_vulnerabilities.map((vuln, idx) => (
                                  <div
                                    key={idx}
                                    className="bg-dark-surface rounded p-3 space-y-1"
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="text-sm font-medium text-white">
                                        {vuln.cve_id || vuln.title}
                                      </span>
                                      <Badge variant="severity" type={vuln.severity.toLowerCase() as any}>
                                        {vuln.severity}
                                      </Badge>
                                    </div>
                                    <p className="text-xs text-slate-400">{vuln.description}</p>
                                    {vuln.affected_service && (
                                      <span className="text-xs text-slate-500">
                                        Service: {vuln.affected_service}
                                      </span>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Resolved Vulnerabilities */}
                          {hostDiff.resolved_vulnerabilities.length > 0 && (
                            <div>
                              <h5 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                                <CheckCircle className="h-4 w-4 text-green-400" />
                                Resolved Vulnerabilities (
                                {hostDiff.resolved_vulnerabilities.length})
                              </h5>
                              <div className="space-y-2">
                                {hostDiff.resolved_vulnerabilities.map((vuln, idx) => (
                                  <div
                                    key={idx}
                                    className="bg-dark-surface rounded p-3 space-y-1 opacity-75"
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="text-sm font-medium text-green-400 line-through">
                                        {vuln.cve_id || vuln.title}
                                      </span>
                                      <Badge variant="severity" type={vuln.severity.toLowerCase() as any}>
                                        {vuln.severity}
                                      </Badge>
                                    </div>
                                    <p className="text-xs text-slate-500">{vuln.description}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {/* No Changes Message */}
          {comparison.diff.new_hosts.length === 0 &&
            comparison.diff.removed_hosts.length === 0 &&
            comparison.diff.host_changes.length === 0 && (
              <Card>
                <div className="text-center py-12">
                  <CheckCircle className="h-12 w-12 text-green-400 mx-auto mb-4" />
                  <p className="text-lg text-white font-medium mb-2">No Changes Detected</p>
                  <p className="text-sm text-slate-400">
                    The selected scans have identical results
                  </p>
                </div>
              </Card>
            )}
        </>
      )}

      {/* Empty State */}
      {!comparison && scans.length === 0 && (
        <Card>
          <div className="text-center py-12">
            <Shield className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No completed scans available</p>
            <p className="text-sm text-slate-500 mt-1">
              Complete at least two scans to use the comparison feature
            </p>
          </div>
        </Card>
      )}
    </div>
  );
};

export default ScanComparison;
