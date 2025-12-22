import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Key,
  Play,
  Square,
  Trash2,
  Plus,
  Hash,
  FileText,
  Settings,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  Copy,
  Download,
  RefreshCw,
  Book,
  Zap,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import { crackingAPI } from '../services/api';
import type {
  CrackingJob,
  CrackedCredential,
  Wordlist,
  RuleFile,
  HashTypeInfo,
  CreateCrackingJobRequest,
  DetectHashResponse,
  CrackingStats,
} from '../types';

// Hash type presets for quick selection
const COMMON_HASH_TYPES: { mode: number; name: string; example: string }[] = [
  { mode: 1000, name: 'NTLM', example: '32 hex characters' },
  { mode: 0, name: 'MD5', example: '32 hex characters' },
  { mode: 100, name: 'SHA-1', example: '40 hex characters' },
  { mode: 1400, name: 'SHA-256', example: '64 hex characters' },
  { mode: 3200, name: 'bcrypt', example: '$2a$...' },
  { mode: 13100, name: 'Kerberos 5 TGS', example: '$krb5tgs$...' },
  { mode: 18200, name: 'Kerberos 5 AS-REP', example: '$krb5asrep$...' },
  { mode: 5600, name: 'NetNTLMv2', example: 'user::domain:...' },
  { mode: 3000, name: 'LM', example: '16 hex characters' },
  { mode: 1800, name: 'sha512crypt', example: '$6$...' },
];

export default function CrackingPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedJob, setSelectedJob] = useState<CrackingJob | null>(null);
  const [showResultsModal, setShowResultsModal] = useState(false);

  // Fetch jobs
  const { data: jobs = [], isLoading: jobsLoading, refetch: refetchJobs } = useQuery({
    queryKey: ['cracking-jobs'],
    queryFn: async () => {
      const response = await crackingAPI.listJobs();
      return response.data;
    },
    refetchInterval: 5000, // Poll every 5 seconds for running jobs
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['cracking-stats'],
    queryFn: async () => {
      const response = await crackingAPI.getStats();
      return response.data;
    },
  });

  // Fetch wordlists
  const { data: wordlists = [] } = useQuery({
    queryKey: ['cracking-wordlists'],
    queryFn: async () => {
      const response = await crackingAPI.listWordlists();
      return response.data;
    },
  });

  // Fetch rules
  const { data: rules = [] } = useQuery({
    queryKey: ['cracking-rules'],
    queryFn: async () => {
      const response = await crackingAPI.listRules();
      return response.data;
    },
  });

  // Fetch hash types
  const { data: hashTypes = [] } = useQuery({
    queryKey: ['cracking-hash-types'],
    queryFn: async () => {
      const response = await crackingAPI.listHashTypes();
      return response.data;
    },
  });

  // Create job mutation
  const createJobMutation = useMutation({
    mutationFn: (data: CreateCrackingJobRequest) => crackingAPI.createJob(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cracking-jobs'] });
      queryClient.invalidateQueries({ queryKey: ['cracking-stats'] });
      toast.success('Cracking job created');
      setShowCreateModal(false);
    },
    onError: (error: Error) => {
      toast.error(`Failed to create job: ${error.message}`);
    },
  });

  // Start job mutation
  const startJobMutation = useMutation({
    mutationFn: (id: string) => crackingAPI.startJob(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cracking-jobs'] });
      toast.success('Job started');
    },
    onError: (error: Error) => {
      toast.error(`Failed to start job: ${error.message}`);
    },
  });

  // Stop job mutation
  const stopJobMutation = useMutation({
    mutationFn: (id: string) => crackingAPI.stopJob(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cracking-jobs'] });
      toast.success('Job stopped');
    },
    onError: (error: Error) => {
      toast.error(`Failed to stop job: ${error.message}`);
    },
  });

  // Delete job mutation
  const deleteJobMutation = useMutation({
    mutationFn: (id: string) => crackingAPI.deleteJob(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cracking-jobs'] });
      queryClient.invalidateQueries({ queryKey: ['cracking-stats'] });
      toast.success('Job deleted');
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete job: ${error.message}`);
    },
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return <Clock className="w-4 h-4 text-gray-400" />;
      case 'running':
        return <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-400" />;
      case 'stopped':
        return <Square className="w-4 h-4 text-yellow-400" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'pending':
        return 'bg-gray-500/20 text-gray-300';
      case 'running':
        return 'bg-cyan-500/20 text-cyan-300';
      case 'completed':
        return 'bg-green-500/20 text-green-300';
      case 'failed':
        return 'bg-red-500/20 text-red-300';
      case 'stopped':
        return 'bg-yellow-500/20 text-yellow-300';
      default:
        return 'bg-gray-500/20 text-gray-300';
    }
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes) return 'N/A';
    const units = ['B', 'KB', 'MB', 'GB'];
    let unitIndex = 0;
    let size = bytes;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Key className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Password Cracking</h1>
              <p className="text-gray-400 text-sm">Crack password hashes using Hashcat or John the Ripper</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => refetchJobs()}
              className="p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-5 h-5 text-gray-300" />
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors"
            >
              <Plus className="w-5 h-5" />
              <span>New Job</span>
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Total Jobs</span>
                <Hash className="w-5 h-5 text-gray-500" />
              </div>
              <p className="text-2xl font-bold text-white mt-2">{stats.total_jobs}</p>
              <p className="text-xs text-gray-500 mt-1">{stats.running_jobs} running</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Total Hashes</span>
                <FileText className="w-5 h-5 text-gray-500" />
              </div>
              <p className="text-2xl font-bold text-white mt-2">{stats.total_hashes.toLocaleString()}</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Cracked</span>
                <CheckCircle className="w-5 h-5 text-green-500" />
              </div>
              <p className="text-2xl font-bold text-green-400 mt-2">{stats.total_cracked.toLocaleString()}</p>
              <p className="text-xs text-gray-500 mt-1">{stats.success_rate.toFixed(1)}% success rate</p>
            </div>
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Resources</span>
                <Book className="w-5 h-5 text-gray-500" />
              </div>
              <p className="text-2xl font-bold text-white mt-2">{stats.total_wordlists}</p>
              <p className="text-xs text-gray-500 mt-1">{stats.total_rules} rule files</p>
            </div>
          </div>
        )}

        {/* Jobs Table */}
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Cracking Jobs</h2>
          </div>
          <div className="overflow-x-auto">
            {jobsLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
              </div>
            ) : jobs.length === 0 ? (
              <div className="text-center p-8 text-gray-400">
                <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No cracking jobs yet</p>
                <p className="text-sm mt-1">Create a new job to start cracking hashes</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Hash Type</th>
                    <th className="px-4 py-3">Cracker</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Progress</th>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((job) => (
                    <tr
                      key={job.id}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                    >
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-white font-medium">{job.name}</p>
                          <p className="text-xs text-gray-500">{job.hashes_count} hashes</p>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-gray-300">{job.hash_type_name}</span>
                        <span className="text-xs text-gray-500 ml-1">({job.hash_type})</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          job.cracker_type === 'hashcat'
                            ? 'bg-purple-500/20 text-purple-300'
                            : 'bg-orange-500/20 text-orange-300'
                        }`}>
                          {job.cracker_type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center space-x-1 px-2 py-1 text-xs rounded-full ${getStatusBadgeClass(job.status)}`}>
                          {getStatusIcon(job.status)}
                          <span className="ml-1 capitalize">{job.status}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {job.status === 'running' && job.progress ? (
                          <div className="w-32">
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="text-gray-400">{job.progress.cracked}/{job.progress.total_hashes}</span>
                              <span className="text-cyan-400">{job.progress.speed}</span>
                            </div>
                            <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-cyan-500 transition-all"
                                style={{ width: `${job.progress.progress_percent || 0}%` }}
                              />
                            </div>
                          </div>
                        ) : job.status === 'completed' ? (
                          <span className="text-green-400">{job.cracked_count} cracked</span>
                        ) : (
                          <span className="text-gray-500">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-sm">
                        {new Date(job.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end space-x-2">
                          {job.status === 'pending' && (
                            <button
                              onClick={() => startJobMutation.mutate(job.id)}
                              className="p-1.5 text-green-400 hover:bg-green-500/20 rounded transition-colors"
                              title="Start job"
                            >
                              <Play className="w-4 h-4" />
                            </button>
                          )}
                          {job.status === 'running' && (
                            <button
                              onClick={() => stopJobMutation.mutate(job.id)}
                              className="p-1.5 text-yellow-400 hover:bg-yellow-500/20 rounded transition-colors"
                              title="Stop job"
                            >
                              <Square className="w-4 h-4" />
                            </button>
                          )}
                          {(job.status === 'completed' || job.cracked_count > 0) && (
                            <button
                              onClick={() => {
                                setSelectedJob(job);
                                setShowResultsModal(true);
                              }}
                              className="p-1.5 text-cyan-400 hover:bg-cyan-500/20 rounded transition-colors"
                              title="View results"
                            >
                              <FileText className="w-4 h-4" />
                            </button>
                          )}
                          <button
                            onClick={() => {
                              if (confirm('Delete this job?')) {
                                deleteJobMutation.mutate(job.id);
                              }
                            }}
                            className="p-1.5 text-red-400 hover:bg-red-500/20 rounded transition-colors"
                            title="Delete job"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Resources Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Wordlists */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white flex items-center">
                <Book className="w-5 h-5 mr-2 text-cyan-400" />
                Wordlists
              </h2>
              <span className="text-sm text-gray-400">{wordlists.length} available</span>
            </div>
            <div className="max-h-64 overflow-y-auto">
              {wordlists.length === 0 ? (
                <div className="p-4 text-center text-gray-400 text-sm">
                  No wordlists available
                </div>
              ) : (
                <div className="divide-y divide-gray-700/50">
                  {wordlists.map((wordlist) => (
                    <div key={wordlist.id} className="p-3 hover:bg-gray-700/30">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white text-sm font-medium">{wordlist.name}</p>
                          <p className="text-xs text-gray-500">
                            {wordlist.line_count?.toLocaleString() || '?'} words
                            {' • '}
                            {formatBytes(wordlist.size_bytes)}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {wordlist.is_builtin && (
                            <span className="text-xs text-gray-500 bg-gray-700 px-2 py-0.5 rounded">
                              Built-in
                            </span>
                          )}
                          {wordlist.category && (
                            <span className="text-xs text-cyan-400 bg-cyan-500/20 px-2 py-0.5 rounded">
                              {wordlist.category}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Rules */}
          <div className="bg-gray-800 rounded-lg border border-gray-700">
            <div className="p-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white flex items-center">
                <Settings className="w-5 h-5 mr-2 text-cyan-400" />
                Rule Files
              </h2>
              <span className="text-sm text-gray-400">{rules.length} available</span>
            </div>
            <div className="max-h-64 overflow-y-auto">
              {rules.length === 0 ? (
                <div className="p-4 text-center text-gray-400 text-sm">
                  No rule files available
                </div>
              ) : (
                <div className="divide-y divide-gray-700/50">
                  {rules.map((rule) => (
                    <div key={rule.id} className="p-3 hover:bg-gray-700/30">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-white text-sm font-medium">{rule.name}</p>
                          <p className="text-xs text-gray-500">
                            {rule.rule_count?.toLocaleString() || '?'} rules
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            rule.cracker_type === 'hashcat'
                              ? 'text-purple-300 bg-purple-500/20'
                              : 'text-orange-300 bg-orange-500/20'
                          }`}>
                            {rule.cracker_type}
                          </span>
                          {rule.is_builtin && (
                            <span className="text-xs text-gray-500 bg-gray-700 px-2 py-0.5 rounded">
                              Built-in
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Create Job Modal */}
        {showCreateModal && (
          <CreateJobModal
            hashTypes={hashTypes}
            wordlists={wordlists}
            rules={rules}
            onClose={() => setShowCreateModal(false)}
            onSubmit={(data) => createJobMutation.mutate(data)}
            isSubmitting={createJobMutation.isPending}
          />
        )}

        {/* Results Modal */}
        {showResultsModal && selectedJob && (
          <ResultsModal
            job={selectedJob}
            onClose={() => {
              setShowResultsModal(false);
              setSelectedJob(null);
            }}
          />
        )}
      </div>
    </Layout>
  );
}

// Create Job Modal Component
interface CreateJobModalProps {
  hashTypes: HashTypeInfo[];
  wordlists: Wordlist[];
  rules: RuleFile[];
  onClose: () => void;
  onSubmit: (data: CreateCrackingJobRequest) => void;
  isSubmitting: boolean;
}

function CreateJobModal({ hashTypes, wordlists, rules, onClose, onSubmit, isSubmitting }: CreateJobModalProps) {
  const [name, setName] = useState('');
  const [hashType, setHashType] = useState<number>(1000); // Default to NTLM
  const [crackerType, setCrackerType] = useState<'hashcat' | 'john'>('hashcat');
  const [hashesInput, setHashesInput] = useState('');
  const [selectedWordlists, setSelectedWordlists] = useState<string[]>([]);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [autoStart, setAutoStart] = useState(false);
  const [detectionResult, setDetectionResult] = useState<DetectHashResponse | null>(null);
  const [isDetecting, setIsDetecting] = useState(false);

  const handleDetectHashType = async () => {
    const hashes = hashesInput.split('\n').filter(h => h.trim());
    if (hashes.length === 0) {
      toast.error('Enter at least one hash to detect type');
      return;
    }

    setIsDetecting(true);
    try {
      const response = await crackingAPI.detectHashType({ hashes: hashes.slice(0, 5) });
      setDetectionResult(response.data);
      if (response.data.hash_type) {
        setHashType(response.data.hash_type);
        toast.success(`Detected: ${response.data.hash_type_name}`);
      } else {
        toast.warning('Could not auto-detect hash type');
      }
    } catch (error) {
      toast.error('Failed to detect hash type');
    } finally {
      setIsDetecting(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const hashes = hashesInput.split('\n')
      .map(line => line.trim())
      .filter(line => line)
      .map(line => {
        // Parse "username:hash" format
        const parts = line.split(':');
        if (parts.length >= 2) {
          return { hash: parts[parts.length - 1], username: parts[0] };
        }
        return { hash: line };
      });

    if (hashes.length === 0) {
      toast.error('Enter at least one hash');
      return;
    }

    onSubmit({
      name: name || `Cracking Job ${new Date().toLocaleDateString()}`,
      hash_type: hashType,
      cracker_type: crackerType,
      hashes,
      wordlist_ids: selectedWordlists.length > 0 ? selectedWordlists : undefined,
      rule_ids: selectedRules.length > 0 ? selectedRules : undefined,
      auto_start: autoStart,
    });
  };

  const filteredRules = rules.filter(r => r.cracker_type === crackerType);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-gray-800 rounded-lg border border-gray-700 w-full max-w-2xl max-h-[90vh] overflow-y-auto m-4">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center">
            <Key className="w-5 h-5 mr-2 text-cyan-400" />
            Create Cracking Job
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white"
          >
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {/* Job Name */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">Job Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Cracking Job"
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none"
            />
          </div>

          {/* Hash Input */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-sm text-gray-400">Hashes (one per line)</label>
              <button
                type="button"
                onClick={handleDetectHashType}
                disabled={isDetecting}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                {isDetecting ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <Zap className="w-3 h-3" />
                )}
                <span>Auto-detect type</span>
              </button>
            </div>
            <textarea
              value={hashesInput}
              onChange={(e) => setHashesInput(e.target.value)}
              placeholder="user:hash&#10;hash&#10;username:hash"
              rows={6}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none font-mono text-sm"
            />
            {detectionResult && (
              <p className="text-xs text-gray-400 mt-1">
                Detected: <span className="text-cyan-400">{detectionResult.hash_type_name || 'Unknown'}</span>
                {' '}({detectionResult.confidence} confidence)
              </p>
            )}
          </div>

          {/* Hash Type & Cracker */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Hash Type</label>
              <select
                value={hashType}
                onChange={(e) => setHashType(Number(e.target.value))}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none"
              >
                {COMMON_HASH_TYPES.map((ht) => (
                  <option key={ht.mode} value={ht.mode}>
                    {ht.name} ({ht.mode})
                  </option>
                ))}
                {hashTypes
                  .filter(ht => !COMMON_HASH_TYPES.some(c => c.mode === ht.mode))
                  .map((ht) => (
                    <option key={ht.mode} value={ht.mode}>
                      {ht.name} ({ht.mode})
                    </option>
                  ))}
              </select>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Cracker</label>
              <div className="flex space-x-2">
                <button
                  type="button"
                  onClick={() => setCrackerType('hashcat')}
                  className={`flex-1 py-2 px-3 rounded-lg border text-sm transition-colors ${
                    crackerType === 'hashcat'
                      ? 'bg-purple-600 border-purple-500 text-white'
                      : 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  Hashcat
                </button>
                <button
                  type="button"
                  onClick={() => setCrackerType('john')}
                  className={`flex-1 py-2 px-3 rounded-lg border text-sm transition-colors ${
                    crackerType === 'john'
                      ? 'bg-orange-600 border-orange-500 text-white'
                      : 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  John
                </button>
              </div>
            </div>
          </div>

          {/* Wordlists */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">Wordlists</label>
            <div className="max-h-32 overflow-y-auto bg-gray-700 border border-gray-600 rounded-lg p-2 space-y-1">
              {wordlists.map((wl) => (
                <label key={wl.id} className="flex items-center space-x-2 cursor-pointer p-1 hover:bg-gray-600 rounded">
                  <input
                    type="checkbox"
                    checked={selectedWordlists.includes(wl.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedWordlists([...selectedWordlists, wl.id]);
                      } else {
                        setSelectedWordlists(selectedWordlists.filter(id => id !== wl.id));
                      }
                    }}
                    className="rounded border-gray-500 bg-gray-600 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-gray-300">{wl.name}</span>
                  <span className="text-xs text-gray-500">({wl.line_count?.toLocaleString() || '?'} words)</span>
                </label>
              ))}
              {wordlists.length === 0 && (
                <p className="text-sm text-gray-500 text-center py-2">No wordlists available</p>
              )}
            </div>
          </div>

          {/* Rules */}
          <div>
            <label className="block text-sm text-gray-400 mb-1">Rules ({crackerType})</label>
            <div className="max-h-24 overflow-y-auto bg-gray-700 border border-gray-600 rounded-lg p-2 space-y-1">
              {filteredRules.map((rule) => (
                <label key={rule.id} className="flex items-center space-x-2 cursor-pointer p-1 hover:bg-gray-600 rounded">
                  <input
                    type="checkbox"
                    checked={selectedRules.includes(rule.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedRules([...selectedRules, rule.id]);
                      } else {
                        setSelectedRules(selectedRules.filter(id => id !== rule.id));
                      }
                    }}
                    className="rounded border-gray-500 bg-gray-600 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-gray-300">{rule.name}</span>
                  <span className="text-xs text-gray-500">({rule.rule_count?.toLocaleString() || '?'} rules)</span>
                </label>
              ))}
              {filteredRules.length === 0 && (
                <p className="text-sm text-gray-500 text-center py-2">No rules for {crackerType}</p>
              )}
            </div>
          </div>

          {/* Auto-start */}
          <div>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={autoStart}
                onChange={(e) => setAutoStart(e.target.checked)}
                className="rounded border-gray-500 bg-gray-600 text-cyan-500 focus:ring-cyan-500"
              />
              <span className="text-sm text-gray-300">Start job immediately after creation</span>
            </label>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-3 pt-4 border-t border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center space-x-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors disabled:opacity-50"
            >
              {isSubmitting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Plus className="w-4 h-4" />
              )}
              <span>Create Job</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// Results Modal Component
interface ResultsModalProps {
  job: CrackingJob;
  onClose: () => void;
}

function ResultsModal({ job, onClose }: ResultsModalProps) {
  const { data: credentials = [], isLoading } = useQuery({
    queryKey: ['cracking-results', job.id],
    queryFn: async () => {
      const response = await crackingAPI.getJobResults(job.id);
      return response.data;
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const exportResults = () => {
    const content = credentials
      .map(c => `${c.username || ''}:${c.plaintext}`)
      .join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${job.name.replace(/\s+/g, '_')}_cracked.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Exported cracked credentials');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-gray-800 rounded-lg border border-gray-700 w-full max-w-3xl max-h-[80vh] overflow-hidden m-4 flex flex-col">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">{job.name} - Results</h2>
            <p className="text-sm text-gray-400">
              {credentials.length} cracked out of {job.hashes_count} ({job.hash_type_name})
            </p>
          </div>
          <div className="flex items-center space-x-2">
            {credentials.length > 0 && (
              <button
                onClick={exportResults}
                className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
                title="Export results"
              >
                <Download className="w-5 h-5" />
              </button>
            )}
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
            </div>
          ) : credentials.length === 0 ? (
            <div className="text-center p-8 text-gray-400">
              <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No credentials cracked yet</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="sticky top-0 bg-gray-800">
                <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                  <th className="px-4 py-3">Username</th>
                  <th className="px-4 py-3">Password</th>
                  <th className="px-4 py-3">Hash</th>
                  <th className="px-4 py-3">Cracked At</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((cred) => (
                  <tr
                    key={cred.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30"
                  >
                    <td className="px-4 py-3 text-white font-mono text-sm">
                      {cred.username || '-'}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-green-400 font-mono text-sm bg-green-500/10 px-2 py-1 rounded">
                        {cred.plaintext}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 font-mono text-xs max-w-xs truncate" title={cred.hash}>
                      {cred.hash.length > 32 ? `${cred.hash.substring(0, 32)}...` : cred.hash}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm">
                      {new Date(cred.cracked_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => copyToClipboard(`${cred.username || ''}:${cred.plaintext}`)}
                        className="p-1.5 text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/20 rounded transition-colors"
                        title="Copy username:password"
                      >
                        <Copy className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
