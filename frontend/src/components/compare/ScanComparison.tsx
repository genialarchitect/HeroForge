import React, { useEffect, useState, useMemo } from 'react';
import { toast } from 'react-toastify';
import { scanAPI, compareAPI } from '../../services/api';
import { ScanResult, ScanComparisonResponse, HostDiff, ServiceChangeType, toSeverityBadgeType } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
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
  Download,
  Filter,
  ArrowLeftRight,
  FileText,
} from 'lucide-react';

// Change type filter options
type ChangeFilter = 'all' | 'added' | 'removed' | 'changed';

const CHART_COLORS = {
  added: '#22c55e',    // green
  removed: '#ef4444',  // red
  changed: '#eab308',  // yellow
  newVulns: '#ef4444', // red for new vulns
  resolved: '#22c55e', // green for resolved
};

const ScanComparison: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [scanId1, setScanId1] = useState('');
  const [scanId2, setScanId2] = useState('');
  const [comparing, setComparing] = useState(false);
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [changeFilter, setChangeFilter] = useState<ChangeFilter>('all');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoadingScans(true);
    try {
      const response = await scanAPI.getAll();
      // Filter only completed scans and sort by date descending
      const completedScans = response.data
        .filter((s) => s.status === 'completed')
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
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
    setComparison(null);
    setExpandedHosts(new Set());
    try {
      const response = await compareAPI.compare(scanId1, scanId2);
      setComparison(response.data);
      toast.success('Comparison completed');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to compare scans');
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

  const expandAllHosts = () => {
    if (comparison) {
      const allIps = comparison.diff.host_changes.map((h) => h.ip);
      setExpandedHosts(new Set(allIps));
    }
  };

  const collapseAllHosts = () => {
    setExpandedHosts(new Set());
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

  // Filter host changes based on selected filter
  const filteredHostChanges = useMemo(() => {
    if (!comparison) return [];

    return comparison.diff.host_changes.filter((hostDiff) => {
      if (changeFilter === 'all') return true;
      if (changeFilter === 'added') {
        return hostDiff.new_ports.length > 0 || hostDiff.new_vulnerabilities.length > 0;
      }
      if (changeFilter === 'removed') {
        return hostDiff.closed_ports.length > 0 || hostDiff.resolved_vulnerabilities.length > 0;
      }
      if (changeFilter === 'changed') {
        return hostDiff.service_changes.length > 0 || hostDiff.os_change !== null;
      }
      return true;
    });
  }, [comparison, changeFilter]);

  // Chart data for summary
  const summaryChartData = useMemo(() => {
    if (!comparison) return [];
    const { summary } = comparison.diff;
    return [
      { name: 'New Hosts', value: summary.total_new_hosts, color: CHART_COLORS.added },
      { name: 'Removed Hosts', value: summary.total_removed_hosts, color: CHART_COLORS.removed },
      { name: 'Changed Hosts', value: summary.total_hosts_changed, color: CHART_COLORS.changed },
    ].filter((item) => item.value > 0);
  }, [comparison]);

  const portChartData = useMemo(() => {
    if (!comparison) return [];
    const { summary } = comparison.diff;
    return [
      { name: 'New Ports', value: summary.total_new_ports, fill: CHART_COLORS.added },
      { name: 'Closed Ports', value: summary.total_closed_ports, fill: CHART_COLORS.removed },
      { name: 'Service Changes', value: summary.total_service_changes, fill: CHART_COLORS.changed },
    ];
  }, [comparison]);

  const vulnChartData = useMemo(() => {
    if (!comparison) return [];
    const { summary } = comparison.diff;
    return [
      { name: 'New Vulnerabilities', value: summary.total_new_vulnerabilities, color: CHART_COLORS.newVulns },
      { name: 'Resolved', value: summary.total_resolved_vulnerabilities, color: CHART_COLORS.resolved },
    ].filter((item) => item.value > 0);
  }, [comparison]);

  // Export comparison report
  const handleExport = async (format: 'json' | 'csv' | 'markdown') => {
    if (!comparison) return;

    setExporting(true);
    try {
      let content: string;
      let filename: string;
      let mimeType: string;

      const { scan1, scan2, diff } = comparison;

      if (format === 'json') {
        content = JSON.stringify(comparison, null, 2);
        filename = `scan-comparison-${scan1.id.slice(0, 8)}-vs-${scan2.id.slice(0, 8)}.json`;
        mimeType = 'application/json';
      } else if (format === 'csv') {
        // Generate CSV content
        const rows: string[] = [];
        rows.push('Type,IP/Host,Port,Protocol,Details,Severity');

        // New hosts
        diff.new_hosts.forEach((host) => {
          rows.push(`New Host,${host},,,"New host discovered in scan 2",`);
        });

        // Removed hosts
        diff.removed_hosts.forEach((host) => {
          rows.push(`Removed Host,${host},,,"Host no longer present in scan 2",`);
        });

        // Host changes
        diff.host_changes.forEach((hostDiff) => {
          hostDiff.new_ports.forEach((port) => {
            rows.push(`New Port,${hostDiff.ip},${port.port},${port.protocol},"${port.service?.name || 'Unknown'}",`);
          });
          hostDiff.closed_ports.forEach((port) => {
            rows.push(`Closed Port,${hostDiff.ip},${port.port},${port.protocol},"${port.service?.name || 'Unknown'}",`);
          });
          hostDiff.new_vulnerabilities.forEach((vuln) => {
            rows.push(`New Vulnerability,${hostDiff.ip},,,"${vuln.title.replace(/"/g, '""')}",${vuln.severity}`);
          });
          hostDiff.resolved_vulnerabilities.forEach((vuln) => {
            rows.push(`Resolved Vulnerability,${hostDiff.ip},,,"${vuln.title.replace(/"/g, '""')}",${vuln.severity}`);
          });
          hostDiff.service_changes.forEach((change) => {
            const details = `${change.old_service || 'None'} -> ${change.new_service || 'None'}`;
            rows.push(`Service Change,${hostDiff.ip},${change.port},${change.protocol},"${details}",`);
          });
        });

        content = rows.join('\n');
        filename = `scan-comparison-${scan1.id.slice(0, 8)}-vs-${scan2.id.slice(0, 8)}.csv`;
        mimeType = 'text/csv';
      } else {
        // Generate Markdown content
        const lines: string[] = [];
        lines.push('# Scan Comparison Report');
        lines.push('');
        lines.push('## Scan Details');
        lines.push('');
        lines.push('| Scan | Name | Date |');
        lines.push('|------|------|------|');
        lines.push(`| Baseline (A) | ${scan1.name} | ${new Date(scan1.created_at).toLocaleString()} |`);
        lines.push(`| Comparison (B) | ${scan2.name} | ${new Date(scan2.created_at).toLocaleString()} |`);
        lines.push('');
        lines.push('## Summary');
        lines.push('');
        lines.push('| Metric | Count |');
        lines.push('|--------|-------|');
        lines.push(`| New Hosts | ${diff.summary.total_new_hosts} |`);
        lines.push(`| Removed Hosts | ${diff.summary.total_removed_hosts} |`);
        lines.push(`| Changed Hosts | ${diff.summary.total_hosts_changed} |`);
        lines.push(`| New Ports | ${diff.summary.total_new_ports} |`);
        lines.push(`| Closed Ports | ${diff.summary.total_closed_ports} |`);
        lines.push(`| New Vulnerabilities | ${diff.summary.total_new_vulnerabilities} |`);
        lines.push(`| Resolved Vulnerabilities | ${diff.summary.total_resolved_vulnerabilities} |`);
        lines.push(`| Service Changes | ${diff.summary.total_service_changes} |`);
        lines.push('');

        if (diff.new_hosts.length > 0) {
          lines.push('## New Hosts');
          lines.push('');
          diff.new_hosts.forEach((host) => {
            lines.push(`- ${host}`);
          });
          lines.push('');
        }

        if (diff.removed_hosts.length > 0) {
          lines.push('## Removed Hosts');
          lines.push('');
          diff.removed_hosts.forEach((host) => {
            lines.push(`- ${host}`);
          });
          lines.push('');
        }

        if (diff.host_changes.length > 0) {
          lines.push('## Host Changes');
          lines.push('');
          diff.host_changes.forEach((hostDiff) => {
            lines.push(`### ${hostDiff.ip}${hostDiff.hostname ? ` (${hostDiff.hostname})` : ''}`);
            lines.push('');

            if (hostDiff.new_ports.length > 0) {
              lines.push('**New Ports:**');
              hostDiff.new_ports.forEach((port) => {
                lines.push(`- ${port.port}/${port.protocol} - ${port.service?.name || 'Unknown'}`);
              });
              lines.push('');
            }

            if (hostDiff.closed_ports.length > 0) {
              lines.push('**Closed Ports:**');
              hostDiff.closed_ports.forEach((port) => {
                lines.push(`- ${port.port}/${port.protocol} - ${port.service?.name || 'Unknown'}`);
              });
              lines.push('');
            }

            if (hostDiff.new_vulnerabilities.length > 0) {
              lines.push('**New Vulnerabilities:**');
              hostDiff.new_vulnerabilities.forEach((vuln) => {
                lines.push(`- [${vuln.severity}] ${vuln.cve_id || vuln.title}`);
              });
              lines.push('');
            }

            if (hostDiff.resolved_vulnerabilities.length > 0) {
              lines.push('**Resolved Vulnerabilities:**');
              hostDiff.resolved_vulnerabilities.forEach((vuln) => {
                lines.push(`- [${vuln.severity}] ${vuln.cve_id || vuln.title}`);
              });
              lines.push('');
            }

            if (hostDiff.service_changes.length > 0) {
              lines.push('**Service Changes:**');
              hostDiff.service_changes.forEach((change) => {
                const oldVer = change.old_version ? ` ${change.old_version}` : '';
                const newVer = change.new_version ? ` ${change.new_version}` : '';
                lines.push(`- Port ${change.port}: ${change.old_service || 'None'}${oldVer} -> ${change.new_service || 'None'}${newVer}`);
              });
              lines.push('');
            }

            if (hostDiff.os_change) {
              lines.push('**OS Change:**');
              lines.push(`- ${hostDiff.os_change.old_os} (${hostDiff.os_change.old_confidence}%) -> ${hostDiff.os_change.new_os} (${hostDiff.os_change.new_confidence}%)`);
              lines.push('');
            }
          });
        }

        lines.push('---');
        lines.push(`*Generated on ${new Date().toLocaleString()}*`);

        content = lines.join('\n');
        filename = `scan-comparison-${scan1.id.slice(0, 8)}-vs-${scan2.id.slice(0, 8)}.md`;
        mimeType = 'text/markdown';
      }

      // Create and download the file
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast.success(`Comparison exported as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export error:', error);
      toast.error('Failed to export comparison');
    } finally {
      setExporting(false);
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
              Baseline Scan (A - Older)
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
              Comparison Scan (B - Newer)
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

        <div className="flex justify-between items-center">
          <div className="text-xs text-slate-500">
            <ArrowLeftRight className="inline h-3 w-3 mr-1" />
            Changes are shown relative to the baseline scan (A to B)
          </div>
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
          {/* Visual Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Host Changes Pie Chart */}
            <Card>
              <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" />
                Host Changes
              </h4>
              {summaryChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie
                      data={summaryChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={70}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {summaryChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                      labelStyle={{ color: '#f8fafc' }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: '12px' }}
                      formatter={(value) => <span className="text-slate-300">{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[180px] flex items-center justify-center text-slate-500 text-sm">
                  No host changes detected
                </div>
              )}
            </Card>

            {/* Port/Service Changes Bar Chart */}
            <Card>
              <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Network className="h-4 w-4 text-primary" />
                Port & Service Changes
              </h4>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={portChartData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <YAxis
                    dataKey="name"
                    type="category"
                    tick={{ fill: '#94a3b8', fontSize: 11 }}
                    width={100}
                  />
                  <RechartsTooltip
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                    labelStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Card>

            {/* Vulnerability Changes Pie Chart */}
            <Card>
              <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Vulnerability Changes
              </h4>
              {vulnChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie
                      data={vulnChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={70}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {vulnChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }}
                      labelStyle={{ color: '#f8fafc' }}
                    />
                    <Legend
                      wrapperStyle={{ fontSize: '12px' }}
                      formatter={(value) => <span className="text-slate-300">{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[180px] flex items-center justify-center text-slate-500 text-sm">
                  No vulnerability changes detected
                </div>
              )}
            </Card>
          </div>

          {/* Summary Card with Actions */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-white">Comparison Summary</h3>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <button
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-dark-bg border border-dark-border rounded-lg hover:border-primary transition-colors"
                    onClick={() => {
                      const dropdown = document.getElementById('export-dropdown');
                      if (dropdown) {
                        dropdown.classList.toggle('hidden');
                      }
                    }}
                    disabled={exporting}
                  >
                    {exporting ? (
                      <LoadingSpinner />
                    ) : (
                      <>
                        <Download className="h-4 w-4 text-slate-400" />
                        <span className="text-slate-300">Export</span>
                        <ChevronDown className="h-3 w-3 text-slate-400" />
                      </>
                    )}
                  </button>
                  <div
                    id="export-dropdown"
                    className="hidden absolute right-0 mt-1 w-40 bg-dark-surface border border-dark-border rounded-lg shadow-xl z-10"
                  >
                    <button
                      onClick={() => {
                        handleExport('json');
                        document.getElementById('export-dropdown')?.classList.add('hidden');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover transition-colors rounded-t-lg"
                    >
                      <FileText className="h-4 w-4" />
                      JSON
                    </button>
                    <button
                      onClick={() => {
                        handleExport('csv');
                        document.getElementById('export-dropdown')?.classList.add('hidden');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover transition-colors"
                    >
                      <FileText className="h-4 w-4" />
                      CSV
                    </button>
                    <button
                      onClick={() => {
                        handleExport('markdown');
                        document.getElementById('export-dropdown')?.classList.add('hidden');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover transition-colors rounded-b-lg"
                    >
                      <FileText className="h-4 w-4" />
                      Markdown
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Scan info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4 p-3 bg-dark-bg rounded-lg border border-dark-border">
              <div>
                <span className="text-xs text-slate-500">Baseline (A)</span>
                <p className="text-sm text-slate-300 font-medium">{comparison.scan1.name}</p>
                <p className="text-xs text-slate-500">{new Date(comparison.scan1.created_at).toLocaleString()}</p>
              </div>
              <div>
                <span className="text-xs text-slate-500">Comparison (B)</span>
                <p className="text-sm text-slate-300 font-medium">{comparison.scan2.name}</p>
                <p className="text-xs text-slate-500">{new Date(comparison.scan2.created_at).toLocaleString()}</p>
              </div>
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
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Server className="h-5 w-5 text-yellow-400" />
                  <h3 className="text-lg font-semibold text-white">
                    Host Changes ({filteredHostChanges.length}
                    {changeFilter !== 'all' && ` of ${comparison.diff.host_changes.length}`})
                  </h3>
                </div>
                <div className="flex items-center gap-3">
                  {/* Filter buttons */}
                  <div className="flex items-center gap-1 bg-dark-bg rounded-lg p-1 border border-dark-border">
                    <button
                      onClick={() => setChangeFilter('all')}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${
                        changeFilter === 'all'
                          ? 'bg-primary text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      All
                    </button>
                    <button
                      onClick={() => setChangeFilter('added')}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${
                        changeFilter === 'added'
                          ? 'bg-green-500 text-white'
                          : 'text-slate-400 hover:text-green-400'
                      }`}
                    >
                      <Plus className="h-3 w-3 inline mr-1" />
                      Added
                    </button>
                    <button
                      onClick={() => setChangeFilter('removed')}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${
                        changeFilter === 'removed'
                          ? 'bg-red-500 text-white'
                          : 'text-slate-400 hover:text-red-400'
                      }`}
                    >
                      <Minus className="h-3 w-3 inline mr-1" />
                      Removed
                    </button>
                    <button
                      onClick={() => setChangeFilter('changed')}
                      className={`px-3 py-1 text-xs rounded-md transition-colors ${
                        changeFilter === 'changed'
                          ? 'bg-yellow-500 text-white'
                          : 'text-slate-400 hover:text-yellow-400'
                      }`}
                    >
                      <RefreshCw className="h-3 w-3 inline mr-1" />
                      Changed
                    </button>
                  </div>
                  {/* Expand/Collapse buttons */}
                  <div className="flex items-center gap-1">
                    <button
                      onClick={expandAllHosts}
                      className="px-2 py-1 text-xs text-slate-400 hover:text-white transition-colors"
                      title="Expand all"
                    >
                      <ChevronDown className="h-4 w-4" />
                    </button>
                    <button
                      onClick={collapseAllHosts}
                      className="px-2 py-1 text-xs text-slate-400 hover:text-white transition-colors"
                      title="Collapse all"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>

              <div className="space-y-3 max-h-[600px] overflow-y-auto">
                {filteredHostChanges.map((hostDiff: HostDiff) => {
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
                          {hostDiff.service_changes.length > 0 && (
                            <span className="px-2 py-1 bg-yellow-500/20 border border-yellow-500/30 rounded text-xs text-yellow-400">
                              {hostDiff.service_changes.length} svc changes
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
                                      <Badge variant="severity" type={toSeverityBadgeType(vuln.severity)}>
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
                                      <Badge variant="severity" type={toSeverityBadgeType(vuln.severity)}>
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

              {filteredHostChanges.length === 0 && changeFilter !== 'all' && (
                <div className="text-center py-8">
                  <Filter className="h-8 w-8 text-slate-500 mx-auto mb-2" />
                  <p className="text-slate-400">No hosts match the current filter</p>
                  <button
                    onClick={() => setChangeFilter('all')}
                    className="mt-2 text-primary hover:underline text-sm"
                  >
                    Clear filter
                  </button>
                </div>
              )}
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

      {!comparison && scans.length >= 2 && (
        <Card>
          <div className="text-center py-12">
            <ArrowLeftRight className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">Select two scans above to compare</p>
            <p className="text-sm text-slate-500 mt-1">
              See what changed between scan runs
            </p>
          </div>
        </Card>
      )}
    </div>
  );
};

export default ScanComparison;
