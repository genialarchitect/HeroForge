import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import {
  privescAPI,
  PrivescScanSummary,
  PrivescResult,
  PrivescFinding,
  StartPrivescRequest,
} from '../services/api';
import {
  TrendingUp,
  Server,
  Play,
  Eye,
  Trash2,
  X,
  AlertTriangle,
  Shield,
  Key,
  Terminal,
  Network,
  ChevronDown,
  ChevronRight,
  Clock,
  CheckCircle,
  XCircle,
  Loader,
  ExternalLink,
  Copy,
  Info,
} from 'lucide-react';

// Scan form component
const ScanForm: React.FC<{
  onSubmit: (data: StartPrivescRequest) => void;
  isSubmitting: boolean;
}> = ({ onSubmit, isSubmitting }) => {
  const [osType, setOsType] = useState<'linux' | 'windows'>('linux');
  const [target, setTarget] = useState('');
  const [sshUsername, setSshUsername] = useState('');
  const [sshPassword, setSshPassword] = useState('');
  const [sshKeyPath, setSshKeyPath] = useState('');
  const [sshPort, setSshPort] = useState('22');
  const [winrmUsername, setWinrmUsername] = useState('');
  const [winrmPassword, setWinrmPassword] = useState('');
  const [winrmPort, setWinrmPort] = useState('5985');
  const [winrmHttps, setWinrmHttps] = useState(false);
  const [runPeas, setRunPeas] = useState(true);
  const [timeoutSecs, setTimeoutSecs] = useState('300');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) {
      toast.error('Target is required');
      return;
    }

    const data: StartPrivescRequest = {
      target,
      os_type: osType,
      run_peas: runPeas,
      timeout_secs: parseInt(timeoutSecs) || 300,
    };

    if (osType === 'linux') {
      if (sshUsername) data.ssh_username = sshUsername;
      if (sshPassword) data.ssh_password = sshPassword;
      if (sshKeyPath) data.ssh_key_path = sshKeyPath;
      if (sshPort) data.ssh_port = parseInt(sshPort) || 22;
    } else {
      if (winrmUsername) data.winrm_username = winrmUsername;
      if (winrmPassword) data.winrm_password = winrmPassword;
      if (winrmPort) data.winrm_port = parseInt(winrmPort) || 5985;
      data.winrm_https = winrmHttps;
    }

    onSubmit(data);
  };

  return (
    <form onSubmit={handleSubmit} className="bg-light-surface dark:bg-dark-surface rounded-lg p-6 border border-light-border dark:border-dark-border">
      <h3 className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">New Privilege Escalation Scan</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Target Host
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.100 or hostname"
            className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Operating System
          </label>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setOsType('linux')}
              className={`flex-1 py-2 px-4 rounded-lg border ${
                osType === 'linux'
                  ? 'bg-primary text-white border-primary'
                  : 'border-light-border dark:border-dark-border text-slate-700 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              Linux
            </button>
            <button
              type="button"
              onClick={() => setOsType('windows')}
              className={`flex-1 py-2 px-4 rounded-lg border ${
                osType === 'windows'
                  ? 'bg-primary text-white border-primary'
                  : 'border-light-border dark:border-dark-border text-slate-700 dark:text-slate-300 hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              Windows
            </button>
          </div>
        </div>
      </div>

      {osType === 'linux' ? (
        <div className="border border-light-border dark:border-dark-border rounded-lg p-4 mb-4">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">SSH Connection</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Username</label>
              <input
                type="text"
                value={sshUsername}
                onChange={(e) => setSshUsername(e.target.value)}
                placeholder="root"
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Port</label>
              <input
                type="number"
                value={sshPort}
                onChange={(e) => setSshPort(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Password</label>
              <input
                type="password"
                value={sshPassword}
                onChange={(e) => setSshPassword(e.target.value)}
                placeholder="Leave empty for key auth"
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">SSH Key Path</label>
              <input
                type="text"
                value={sshKeyPath}
                onChange={(e) => setSshKeyPath(e.target.value)}
                placeholder="/path/to/id_rsa"
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
          </div>
        </div>
      ) : (
        <div className="border border-light-border dark:border-dark-border rounded-lg p-4 mb-4">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">WinRM Connection</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Username</label>
              <input
                type="text"
                value={winrmUsername}
                onChange={(e) => setWinrmUsername(e.target.value)}
                placeholder="Administrator"
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Port</label>
              <input
                type="number"
                value={winrmPort}
                onChange={(e) => setWinrmPort(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Password</label>
              <input
                type="password"
                value={winrmPassword}
                onChange={(e) => setWinrmPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="winrm-https"
                checked={winrmHttps}
                onChange={(e) => setWinrmHttps(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="winrm-https" className="text-sm text-slate-700 dark:text-slate-300">
                Use HTTPS
              </label>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-4">
          <label className="flex items-center text-sm text-slate-700 dark:text-slate-300">
            <input
              type="checkbox"
              checked={runPeas}
              onChange={(e) => setRunPeas(e.target.checked)}
              className="mr-2"
            />
            Run {osType === 'linux' ? 'LinPEAS' : 'WinPEAS'}
          </label>
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-700 dark:text-slate-300">Timeout:</label>
            <input
              type="number"
              value={timeoutSecs}
              onChange={(e) => setTimeoutSecs(e.target.value)}
              className="w-20 px-2 py-1 rounded border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white text-sm"
            />
            <span className="text-sm text-slate-500 dark:text-slate-400">seconds</span>
          </div>
        </div>
        <Button type="submit" variant="primary" disabled={isSubmitting}>
          {isSubmitting ? (
            <>
              <Loader className="h-4 w-4 mr-2 animate-spin" />
              Starting...
            </>
          ) : (
            <>
              <Play className="h-4 w-4 mr-2" />
              Start Scan
            </>
          )}
        </Button>
      </div>
    </form>
  );
};

// Finding card component
const FindingCard: React.FC<{ finding: PrivescFinding }> = ({ finding }) => {
  const [expanded, setExpanded] = useState(false);

  const severityColors: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg overflow-hidden">
      <div
        className="p-4 cursor-pointer hover:bg-light-hover dark:hover:bg-dark-hover flex items-center justify-between"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-slate-500" />
          ) : (
            <ChevronRight className="h-4 w-4 text-slate-500" />
          )}
          <span className={`px-2 py-1 text-xs font-medium rounded border ${severityColors[finding.severity] || severityColors.info}`}>
            {finding.severity.toUpperCase()}
          </span>
          <span className="font-medium text-slate-900 dark:text-white">{finding.title}</span>
        </div>
        <div className="flex items-center gap-2">
          {finding.mitre_techniques.length > 0 && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {finding.mitre_techniques.join(', ')}
            </span>
          )}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-light-border dark:border-dark-border p-4 space-y-4">
          <div>
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Description</h4>
            <p className="text-sm text-slate-600 dark:text-slate-400">{finding.description}</p>
          </div>

          {finding.exploitation_steps.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Exploitation Steps</h4>
              <ol className="list-decimal list-inside space-y-1">
                {finding.exploitation_steps.map((step, idx) => (
                  <li key={idx} className="text-sm text-slate-600 dark:text-slate-400 flex items-start gap-2">
                    <span className="flex-1 font-mono bg-slate-100 dark:bg-slate-800 rounded px-2 py-1">
                      {step}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(step);
                      }}
                      className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {finding.references.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">References</h4>
              <ul className="space-y-1">
                {finding.references.map((ref, idx) => (
                  <li key={idx}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-primary hover:underline flex items-center gap-1"
                    >
                      {ref}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Scan detail view
const ScanDetail: React.FC<{
  scanId: string;
  onClose: () => void;
}> = ({ scanId, onClose }) => {
  const { data: scan, isLoading } = useQuery({
    queryKey: ['privesc-scan', scanId],
    queryFn: () => privescAPI.getScan(scanId).then((r) => r.data),
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 3000 : false),
  });

  if (isLoading) {
    return (
      <div className="bg-light-surface dark:bg-dark-surface rounded-lg p-6 border border-light-border dark:border-dark-border">
        <div className="flex justify-center items-center py-12">
          <Loader className="h-8 w-8 animate-spin text-primary" />
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="bg-light-surface dark:bg-dark-surface rounded-lg p-6 border border-light-border dark:border-dark-border">
        <p className="text-slate-500 dark:text-slate-400">Scan not found</p>
      </div>
    );
  }

  const stats = scan.statistics;

  return (
    <div className="bg-light-surface dark:bg-dark-surface rounded-lg border border-light-border dark:border-dark-border">
      <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
        <div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{scan.target}</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {scan.os_type.toUpperCase()} - Started {new Date(scan.started_at).toLocaleString()}
          </p>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* System Info */}
      {scan.system_info && scan.system_info.hostname && (
        <div className="p-4 border-b border-light-border dark:border-dark-border">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">System Information</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-slate-500 dark:text-slate-400">Hostname:</span>
              <span className="ml-2 text-slate-900 dark:text-white">{scan.system_info.hostname}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">OS:</span>
              <span className="ml-2 text-slate-900 dark:text-white">{scan.system_info.os_name}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">Kernel:</span>
              <span className="ml-2 text-slate-900 dark:text-white">{scan.system_info.kernel_version}</span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">User:</span>
              <span className="ml-2 text-slate-900 dark:text-white">{scan.system_info.current_user}</span>
            </div>
          </div>
        </div>
      )}

      {/* Statistics */}
      <div className="p-4 border-b border-light-border dark:border-dark-border">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="text-center p-3 bg-red-500/10 rounded-lg">
            <div className="text-2xl font-bold text-red-400">{stats.critical_findings}</div>
            <div className="text-xs text-red-400">Critical</div>
          </div>
          <div className="text-center p-3 bg-orange-500/10 rounded-lg">
            <div className="text-2xl font-bold text-orange-400">{stats.high_findings}</div>
            <div className="text-xs text-orange-400">High</div>
          </div>
          <div className="text-center p-3 bg-yellow-500/10 rounded-lg">
            <div className="text-2xl font-bold text-yellow-400">{stats.medium_findings}</div>
            <div className="text-xs text-yellow-400">Medium</div>
          </div>
          <div className="text-center p-3 bg-blue-500/10 rounded-lg">
            <div className="text-2xl font-bold text-blue-400">{stats.low_findings}</div>
            <div className="text-xs text-blue-400">Low</div>
          </div>
          <div className="text-center p-3 bg-slate-500/10 rounded-lg">
            <div className="text-2xl font-bold text-slate-400">{stats.info_findings}</div>
            <div className="text-xs text-slate-400">Info</div>
          </div>
          <div className="text-center p-3 bg-green-500/10 rounded-lg">
            <div className="text-2xl font-bold text-green-400">{stats.exploitable_count}</div>
            <div className="text-xs text-green-400">Exploitable</div>
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="p-4">
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-4">
          Findings ({scan.findings.length})
        </h4>
        {scan.findings.length === 0 ? (
          <p className="text-slate-500 dark:text-slate-400 text-center py-8">
            {scan.status === 'running' ? 'Scan in progress...' : 'No findings discovered'}
          </p>
        ) : (
          <div className="space-y-2">
            {scan.findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        )}
      </div>

      {/* Errors */}
      {scan.errors.length > 0 && (
        <div className="p-4 border-t border-light-border dark:border-dark-border">
          <h4 className="text-sm font-medium text-red-400 mb-2">Errors</h4>
          <ul className="space-y-1">
            {scan.errors.map((error, idx) => (
              <li key={idx} className="text-sm text-red-400">{error}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

// Main page component
const PrivescPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const { data: scansData, isLoading } = useQuery({
    queryKey: ['privesc-scans'],
    queryFn: () => privescAPI.listScans(50, 0).then((r) => r.data),
    refetchInterval: 5000,
  });

  const startMutation = useMutation({
    mutationFn: privescAPI.startScan,
    onSuccess: (response) => {
      toast.success('Privilege escalation scan started');
      queryClient.invalidateQueries({ queryKey: ['privesc-scans'] });
      setSelectedScanId(response.data.id);
    },
    onError: () => {
      toast.error('Failed to start scan');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: privescAPI.deleteScan,
    onSuccess: () => {
      toast.success('Scan deleted');
      queryClient.invalidateQueries({ queryKey: ['privesc-scans'] });
      if (selectedScanId) setSelectedScanId(null);
    },
    onError: () => {
      toast.error('Failed to delete scan');
    },
  });

  const scans = scansData?.scans || [];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'running':
        return <Loader className="h-4 w-4 text-primary animate-spin" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-400" />;
      default:
        return <Clock className="h-4 w-4 text-slate-400" />;
    }
  };

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <TrendingUp className="h-6 w-6 text-primary" />
              Privilege Escalation Scanner
            </h1>
            <p className="text-slate-500 dark:text-slate-400 mt-1">
              Automated privilege escalation enumeration with LinPEAS/WinPEAS integration
            </p>
          </div>
        </div>

        {/* Info banner */}
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-400 mt-0.5" />
          <div className="text-sm text-blue-400">
            <p className="font-medium">About Privilege Escalation Scanning</p>
            <p className="mt-1">
              This tool runs LinPEAS (Linux) or WinPEAS (Windows) on target systems to identify potential
              privilege escalation vectors. It checks for SUID binaries, sudo misconfigurations, kernel exploits,
              service weaknesses, and more. GTFOBins/LOLBAS references are included for exploitation guidance.
            </p>
          </div>
        </div>

        {/* Scan Form */}
        <ScanForm onSubmit={(data) => startMutation.mutate(data)} isSubmitting={startMutation.isPending} />

        {/* Scan Detail or List */}
        {selectedScanId ? (
          <ScanDetail scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
        ) : (
          <div className="bg-light-surface dark:bg-dark-surface rounded-lg border border-light-border dark:border-dark-border">
            <div className="p-4 border-b border-light-border dark:border-dark-border">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Recent Scans</h3>
            </div>

            {isLoading ? (
              <div className="flex justify-center items-center py-12">
                <Loader className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : scans.length === 0 ? (
              <div className="text-center py-12 text-slate-500 dark:text-slate-400">
                <TrendingUp className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No privilege escalation scans yet</p>
                <p className="text-sm mt-1">Start a scan to enumerate potential privilege escalation vectors</p>
              </div>
            ) : (
              <div className="divide-y divide-light-border dark:divide-dark-border">
                {scans.map((scan) => (
                  <div
                    key={scan.id}
                    className="p-4 hover:bg-light-hover dark:hover:bg-dark-hover flex items-center justify-between"
                  >
                    <div className="flex items-center gap-4">
                      {getStatusIcon(scan.status)}
                      <div>
                        <div className="font-medium text-slate-900 dark:text-white">{scan.target}</div>
                        <div className="text-sm text-slate-500 dark:text-slate-400">
                          {scan.os_type.toUpperCase()} - {new Date(scan.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {scan.status === 'completed' && (
                        <div className="flex items-center gap-2 text-sm">
                          {scan.critical_count > 0 && (
                            <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded">{scan.critical_count} Critical</span>
                          )}
                          {scan.high_count > 0 && (
                            <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded">{scan.high_count} High</span>
                          )}
                          <span className="text-slate-500">{scan.findings_count} findings</span>
                        </div>
                      )}
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedScanId(scan.id)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteMutation.mutate(scan.id)}
                        >
                          <Trash2 className="h-4 w-4 text-red-400" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
};

export default PrivescPage;
