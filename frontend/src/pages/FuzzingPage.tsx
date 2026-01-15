import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Zap,
  Plus,
  Trash2,
  Play,
  Pause,
  RefreshCw,
  AlertTriangle,
  Bug,
  Network,
  Globe,
  FileCode,
  Server,
  Binary,
  ChevronRight,
  Download,
  Copy,
  XCircle,
  Loader2,
  BarChart3,
  Target,
  Activity,
  Shield,
} from 'lucide-react';
import { fuzzingAPI } from '../services/api';
import Layout from '../components/layout/Layout';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';
import type {
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingStats,
  FuzzTargetType,
  FuzzerType,
  FuzzTargetConfig,
  FuzzerConfig,
  CrashType,
  Exploitability,
} from '../types';

// Stats Card Component
const StatsCard: React.FC<{ title: string; value: string | number; icon: React.ReactNode; color: string }> = ({
  title, value, icon, color
}) => (
  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-400 text-sm">{title}</p>
        <p className="text-2xl font-bold text-white mt-1">{value}</p>
      </div>
      <div className={`p-3 rounded-lg ${color}`}>
        {icon}
      </div>
    </div>
  </div>
);

// Target type icons
const getTargetIcon = (type: FuzzTargetType) => {
  switch (type) {
    case 'protocol': return <Network className="w-5 h-5" />;
    case 'http': return <Globe className="w-5 h-5" />;
    case 'file': return <FileCode className="w-5 h-5" />;
    case 'api': return <Server className="w-5 h-5" />;
    case 'binary': return <Binary className="w-5 h-5" />;
    default: return <Target className="w-5 h-5" />;
  }
};

// Status badge colors
const getStatusColor = (status: string) => {
  switch (status) {
    case 'running': return 'bg-green-500/20 text-green-400';
    case 'completed': return 'bg-blue-500/20 text-blue-400';
    case 'failed': return 'bg-red-500/20 text-red-400';
    case 'paused': return 'bg-yellow-500/20 text-yellow-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

// Exploitability badge colors
const getExploitabilityColor = (exp: Exploitability) => {
  switch (exp) {
    case 'high': return 'bg-red-500/20 text-red-400';
    case 'medium': return 'bg-orange-500/20 text-orange-400';
    case 'low': return 'bg-yellow-500/20 text-yellow-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

// Crash type badge colors
const getCrashTypeColor = (type: CrashType) => {
  switch (type) {
    case 'heap_overflow':
    case 'stack_overflow':
    case 'use_after_free':
    case 'double_free':
      return 'bg-red-500/20 text-red-400';
    case 'segfault':
    case 'null_deref':
      return 'bg-orange-500/20 text-orange-400';
    case 'assertion':
    case 'timeout':
      return 'bg-yellow-500/20 text-yellow-400';
    default:
      return 'bg-gray-500/20 text-gray-400';
  }
};

// Campaign Row Component
const CampaignRow: React.FC<{
  campaign: FuzzingCampaign;
  onSelect: () => void;
  onStart: () => void;
  onStop: () => void;
  onDelete: () => void;
}> = ({ campaign, onSelect, onStart, onStop, onDelete }) => (
  <tr
    className="border-b border-gray-700 hover:bg-gray-800/50 cursor-pointer transition-colors"
    onClick={onSelect}
  >
    <td className="px-4 py-3">
      <div className="flex items-center space-x-3">
        <div className="text-cyan-500">
          {getTargetIcon(campaign.target_type)}
        </div>
        <div>
          <p className="text-white font-medium">{campaign.name}</p>
          <p className="text-gray-500 text-xs">{campaign.target_type} / {campaign.fuzzer_type}</p>
        </div>
      </div>
    </td>
    <td className="px-4 py-3">
      <span className={`px-2 py-1 rounded text-xs ${getStatusColor(campaign.status)}`}>
        {campaign.status}
      </span>
    </td>
    <td className="px-4 py-3 text-gray-300">{campaign.iterations.toLocaleString()}</td>
    <td className="px-4 py-3">
      <div className="flex items-center space-x-1">
        <Bug className="w-4 h-4 text-red-400" />
        <span className="text-red-400 font-medium">{campaign.crashes_found}</span>
        <span className="text-gray-500">({campaign.unique_crashes} unique)</span>
      </div>
    </td>
    <td className="px-4 py-3">
      {campaign.coverage_percent !== null ? (
        <div className="flex items-center space-x-2">
          <div className="w-24 bg-gray-700 rounded-full h-2">
            <div
              className="bg-cyan-500 h-2 rounded-full"
              style={{ width: `${campaign.coverage_percent}%` }}
            />
          </div>
          <span className="text-gray-300 text-sm">{campaign.coverage_percent.toFixed(1)}%</span>
        </div>
      ) : (
        <span className="text-gray-500">-</span>
      )}
    </td>
    <td className="px-4 py-3">
      <div className="flex items-center space-x-2">
        {campaign.status === 'running' ? (
          <button
            onClick={(e) => { e.stopPropagation(); onStop(); }}
            className="p-1.5 text-yellow-400 hover:bg-yellow-500/20 rounded transition-colors"
            title="Pause Campaign"
          >
            <Pause className="w-4 h-4" />
          </button>
        ) : campaign.status !== 'completed' && (
          <button
            onClick={(e) => { e.stopPropagation(); onStart(); }}
            className="p-1.5 text-green-400 hover:bg-green-500/20 rounded transition-colors"
            title="Start Campaign"
          >
            <Play className="w-4 h-4" />
          </button>
        )}
        <button
          onClick={(e) => { e.stopPropagation(); onDelete(); }}
          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
          title="Delete Campaign"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </td>
  </tr>
);

// Create Campaign Modal
const CreateCampaignModal: React.FC<{
  onClose: () => void;
  onSubmit: (data: {
    name: string;
    description?: string;
    target_type: FuzzTargetType;
    fuzzer_type: FuzzerType;
    target_config: FuzzTargetConfig;
    fuzzer_config: FuzzerConfig;
  }) => void;
  isLoading: boolean;
}> = ({ onClose, onSubmit, isLoading }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetType, setTargetType] = useState<FuzzTargetType>('http');
  const [fuzzerType, setFuzzerType] = useState<FuzzerType>('mutation');

  // Target config fields
  const [url, setUrl] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [protocol, setProtocol] = useState<'tcp' | 'udp'>('tcp');
  const [filePath, setFilePath] = useState('');
  const [command, setCommand] = useState('');

  // Fuzzer config fields
  const [maxIterations, setMaxIterations] = useState('10000');
  const [timeoutMs, setTimeoutMs] = useState('5000');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const targetConfig: FuzzTargetConfig = {};
    if (targetType === 'http') {
      targetConfig.url = url;
    } else if (targetType === 'protocol') {
      targetConfig.host = host;
      targetConfig.port = parseInt(port);
      targetConfig.protocol = protocol;
    } else if (targetType === 'file') {
      targetConfig.file_path = filePath;
      targetConfig.command = command;
    }

    const fuzzerConfig: FuzzerConfig = {
      max_iterations: parseInt(maxIterations),
      timeout_ms: parseInt(timeoutMs),
      mutation_strategies: ['bit_flip', 'byte_flip', 'havoc'],
    };

    onSubmit({
      name,
      description: description || undefined,
      target_type: targetType,
      fuzzer_type: fuzzerType,
      target_config: targetConfig,
      fuzzer_config: fuzzerConfig,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white flex items-center">
            <Plus className="w-6 h-6 mr-2 text-cyan-500" />
            Create Fuzzing Campaign
          </h2>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-white">
            <XCircle className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {/* Basic Info */}
          <div>
            <label className="block text-gray-400 text-sm mb-1">Campaign Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
              placeholder="My Fuzzing Campaign"
              required
            />
          </div>

          <div>
            <label className="block text-gray-400 text-sm mb-1">Description (optional)</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
              placeholder="Describe the fuzzing campaign..."
              rows={2}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-400 text-sm mb-1">Target Type</label>
              <select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value as FuzzTargetType)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
              >
                <option value="http">HTTP/HTTPS</option>
                <option value="protocol">Network Protocol</option>
                <option value="file">File Format</option>
                <option value="api">API</option>
                <option value="binary">Binary</option>
              </select>
            </div>

            <div>
              <label className="block text-gray-400 text-sm mb-1">Fuzzer Type</label>
              <select
                value={fuzzerType}
                onChange={(e) => setFuzzerType(e.target.value as FuzzerType)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
              >
                <option value="mutation">Mutation-based</option>
                <option value="generation">Generation-based</option>
                <option value="grammar">Grammar-based</option>
                <option value="template">Template-based</option>
              </select>
            </div>
          </div>

          {/* Target-specific fields */}
          {targetType === 'http' && (
            <div>
              <label className="block text-gray-400 text-sm mb-1">Target URL</label>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                placeholder="https://example.com/api/endpoint"
                required
              />
            </div>
          )}

          {targetType === 'protocol' && (
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-gray-400 text-sm mb-1">Host</label>
                <input
                  type="text"
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                  placeholder="192.168.1.1"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-400 text-sm mb-1">Port</label>
                <input
                  type="number"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                  placeholder="8080"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-400 text-sm mb-1">Protocol</label>
                <select
                  value={protocol}
                  onChange={(e) => setProtocol(e.target.value as 'tcp' | 'udp')}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
            </div>
          )}

          {targetType === 'file' && (
            <div className="space-y-4">
              <div>
                <label className="block text-gray-400 text-sm mb-1">File Path</label>
                <input
                  type="text"
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                  placeholder="/path/to/input/file"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-400 text-sm mb-1">Command to Execute</label>
                <input
                  type="text"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                  placeholder="/usr/bin/myapp @@"
                  required
                />
                <p className="text-gray-500 text-xs mt-1">Use @@ as placeholder for input file</p>
              </div>
            </div>
          )}

          {/* Fuzzer Config */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-400 text-sm mb-1">Max Iterations</label>
              <input
                type="number"
                value={maxIterations}
                onChange={(e) => setMaxIterations(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                min="1"
              />
            </div>
            <div>
              <label className="block text-gray-400 text-sm mb-1">Timeout (ms)</label>
              <input
                type="number"
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                min="100"
              />
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center"
            >
              {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Create Campaign
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Campaign Detail Modal
const CampaignDetailModal: React.FC<{
  campaign: FuzzingCampaign;
  onClose: () => void;
}> = ({ campaign, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'crashes' | 'coverage' | 'seeds'>('overview');

  const { data: crashes, isLoading: crashesLoading } = useQuery({
    queryKey: ['fuzzing-crashes', campaign.id],
    queryFn: () => fuzzingAPI.listCrashes(campaign.id, { limit: 50 }).then(r => r.data),
    enabled: activeTab === 'crashes',
  });

  const { data: coverage } = useQuery({
    queryKey: ['fuzzing-coverage', campaign.id],
    queryFn: () => fuzzingAPI.getCoverage(campaign.id).then(r => r.data),
    enabled: activeTab === 'coverage',
  });

  const { data: seeds } = useQuery({
    queryKey: ['fuzzing-seeds', campaign.id],
    queryFn: () => fuzzingAPI.listSeeds(campaign.id).then(r => r.data),
    enabled: activeTab === 'seeds',
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-lg w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <div className="text-cyan-500">
              {getTargetIcon(campaign.target_type)}
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{campaign.name}</h2>
              <p className="text-gray-400 text-sm">{campaign.target_type} / {campaign.fuzzer_type}</p>
            </div>
            <span className={`px-2 py-1 rounded text-xs ${getStatusColor(campaign.status)}`}>
              {campaign.status}
            </span>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-white">
            <XCircle className="w-6 h-6" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700">
          {(['overview', 'crashes', 'coverage', 'seeds'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
              {tab === 'crashes' && campaign.crashes_found > 0 && (
                <span className="ml-2 px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                  {campaign.crashes_found}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Campaign Stats */}
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <BarChart3 className="w-5 h-5 mr-2 text-cyan-500" />
                  Campaign Statistics
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-gray-400 text-sm">Iterations</p>
                    <p className="text-2xl font-bold text-white">{campaign.iterations.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Crashes Found</p>
                    <p className="text-2xl font-bold text-red-400">{campaign.crashes_found}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Unique Crashes</p>
                    <p className="text-2xl font-bold text-orange-400">{campaign.unique_crashes}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Coverage</p>
                    <p className="text-2xl font-bold text-cyan-400">
                      {campaign.coverage_percent !== null ? `${campaign.coverage_percent.toFixed(1)}%` : '-'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Target Config */}
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Target className="w-5 h-5 mr-2 text-cyan-500" />
                  Target Configuration
                </h3>
                <div className="space-y-2">
                  {campaign.target_config.url && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">URL:</span>
                      <span className="text-white font-mono text-sm">{campaign.target_config.url}</span>
                    </div>
                  )}
                  {campaign.target_config.host && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Host:</span>
                      <span className="text-white font-mono">{campaign.target_config.host}:{campaign.target_config.port}</span>
                    </div>
                  )}
                  {campaign.target_config.protocol && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Protocol:</span>
                      <span className="text-white">{campaign.target_config.protocol.toUpperCase()}</span>
                    </div>
                  )}
                  {campaign.target_config.file_path && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">File:</span>
                      <span className="text-white font-mono text-sm">{campaign.target_config.file_path}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Fuzzer Config */}
              <div className="bg-gray-800 rounded-lg p-4 lg:col-span-2">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Zap className="w-5 h-5 mr-2 text-cyan-500" />
                  Fuzzer Configuration
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <p className="text-gray-400 text-sm">Max Iterations</p>
                    <p className="text-white">{campaign.fuzzer_config.max_iterations?.toLocaleString() || 'Unlimited'}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Timeout</p>
                    <p className="text-white">{campaign.fuzzer_config.timeout_ms || 5000}ms</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-gray-400 text-sm">Mutation Strategies</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {campaign.fuzzer_config.mutation_strategies?.map((s, i) => (
                        <span key={i} className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">
                          {s.replace('_', ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'crashes' && (
            <div>
              {crashesLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
                </div>
              ) : crashes && crashes.length > 0 ? (
                <div className="space-y-4">
                  {crashes.map((crash) => (
                    <div key={crash.id} className="bg-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <Bug className="w-5 h-5 text-red-400" />
                          <span className={`px-2 py-1 rounded text-xs ${getCrashTypeColor(crash.crash_type)}`}>
                            {crash.crash_type.replace('_', ' ')}
                          </span>
                          <span className={`px-2 py-1 rounded text-xs ${getExploitabilityColor(crash.exploitability)}`}>
                            {crash.exploitability} exploitability
                          </span>
                          {crash.is_unique && (
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">
                              Unique
                            </span>
                          )}
                        </div>
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => copyToClipboard(crash.crash_hash, 'Crash hash')}
                            className="p-1.5 text-gray-400 hover:text-white transition-colors"
                            title="Copy hash"
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => {
                              const blob = new Blob([atob(crash.input_data)], { type: 'application/octet-stream' });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `crash_${crash.crash_hash.substring(0, 8)}.bin`;
                              a.click();
                            }}
                            className="p-1.5 text-gray-400 hover:text-white transition-colors"
                            title="Download input"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      <div className="text-gray-500 text-xs font-mono mb-2">
                        Hash: {crash.crash_hash.substring(0, 32)}... | Iteration: {crash.iteration}
                      </div>

                      {crash.stack_trace && (
                        <div className="bg-gray-900 rounded p-2 mt-2">
                          <p className="text-gray-400 text-xs mb-1">Stack Trace:</p>
                          <pre className="text-gray-300 text-xs font-mono whitespace-pre-wrap overflow-x-auto">
                            {crash.stack_trace.split('\n').slice(0, 5).join('\n')}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <Bug className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No crashes found yet</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'coverage' && (
            <div>
              {coverage ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-gray-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-white mb-4">Coverage Overview</h3>
                    <div className="flex items-center justify-center mb-4">
                      <div className="relative w-32 h-32">
                        <svg className="transform -rotate-90 w-32 h-32">
                          <circle
                            cx="64"
                            cy="64"
                            r="56"
                            stroke="currentColor"
                            strokeWidth="12"
                            fill="none"
                            className="text-gray-700"
                          />
                          <circle
                            cx="64"
                            cy="64"
                            r="56"
                            stroke="currentColor"
                            strokeWidth="12"
                            fill="none"
                            strokeDasharray={`${coverage.coverage_percent * 3.51} 351`}
                            className="text-cyan-500"
                          />
                        </svg>
                        <span className="absolute inset-0 flex items-center justify-center text-2xl font-bold text-white">
                          {coverage.coverage_percent.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-6">
                    <h3 className="text-lg font-semibold text-white mb-4">Coverage Details</h3>
                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-gray-400">Edge Coverage</span>
                          <span className="text-white">{coverage.edge_coverage} / {coverage.total_edges}</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-cyan-500 h-2 rounded-full"
                            style={{ width: `${(coverage.edge_coverage / coverage.total_edges) * 100}%` }}
                          />
                        </div>
                      </div>
                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-gray-400">Block Coverage</span>
                          <span className="text-white">{coverage.block_coverage} / {coverage.total_blocks}</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-purple-500 h-2 rounded-full"
                            style={{ width: `${(coverage.block_coverage / coverage.total_blocks) * 100}%` }}
                          />
                        </div>
                      </div>
                      <div className="pt-2 border-t border-gray-700">
                        <p className="text-gray-400 text-sm">New Edges Found</p>
                        <p className="text-2xl font-bold text-green-400">{coverage.new_edges_found}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No coverage data available</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'seeds' && (
            <div>
              {seeds && seeds.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {seeds.map((seed) => (
                    <div key={seed.id} className="bg-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className={`px-2 py-1 rounded text-xs ${
                          seed.source === 'crash' ? 'bg-red-500/20 text-red-400' :
                          seed.source === 'corpus' ? 'bg-green-500/20 text-green-400' :
                          'bg-gray-500/20 text-gray-400'
                        }`}>
                          {seed.source}
                        </span>
                        {seed.coverage_contribution !== null && (
                          <span className="text-cyan-400 text-sm">
                            +{seed.coverage_contribution.toFixed(2)}% coverage
                          </span>
                        )}
                      </div>
                      <div className="bg-gray-900 rounded p-2 font-mono text-xs text-gray-300 break-all">
                        {seed.data.substring(0, 64)}...
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <FileCode className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No seeds in corpus</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Main Page Component
const FuzzingPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<FuzzingCampaign | null>(null);
  const { hasEngagement } = useRequireEngagement();

  // Fetch campaigns
  const { data: campaigns, isLoading: campaignsLoading, refetch } = useQuery({
    queryKey: ['fuzzing-campaigns'],
    queryFn: () => fuzzingAPI.listCampaigns({ limit: 100 }).then(r => r.data),
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['fuzzing-stats'],
    queryFn: () => fuzzingAPI.getStats().then(r => r.data),
  });

  // Create campaign mutation
  const createMutation = useMutation({
    mutationFn: fuzzingAPI.createCampaign,
    onSuccess: () => {
      toast.success('Fuzzing campaign created');
      queryClient.invalidateQueries({ queryKey: ['fuzzing-campaigns'] });
      queryClient.invalidateQueries({ queryKey: ['fuzzing-stats'] });
      setShowCreateModal(false);
    },
    onError: (error: Error) => {
      toast.error(`Failed to create campaign: ${error.message}`);
    },
  });

  // Start campaign mutation
  const startMutation = useMutation({
    mutationFn: (id: string) => fuzzingAPI.startCampaign(id),
    onSuccess: () => {
      toast.success('Campaign started');
      queryClient.invalidateQueries({ queryKey: ['fuzzing-campaigns'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to start campaign: ${error.message}`);
    },
  });

  // Stop campaign mutation
  const stopMutation = useMutation({
    mutationFn: (id: string) => fuzzingAPI.stopCampaign(id),
    onSuccess: () => {
      toast.success('Campaign stopped');
      queryClient.invalidateQueries({ queryKey: ['fuzzing-campaigns'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to stop campaign: ${error.message}`);
    },
  });

  // Delete campaign mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => fuzzingAPI.deleteCampaign(id),
    onSuccess: () => {
      toast.success('Campaign deleted');
      queryClient.invalidateQueries({ queryKey: ['fuzzing-campaigns'] });
      queryClient.invalidateQueries({ queryKey: ['fuzzing-stats'] });
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete campaign: ${error.message}`);
    },
  });

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center">
              <Zap className="w-8 h-8 mr-3 text-cyan-500" />
              Fuzzing Framework
            </h1>
            <p className="text-gray-400 mt-1">Automated vulnerability discovery through intelligent fuzzing</p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => refetch()}
              className="p-2 text-gray-400 hover:text-white transition-colors"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              disabled={!hasEngagement}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors flex items-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Plus className="w-5 h-5 mr-2" />
              New Campaign
            </button>
          </div>
        </div>

        <EngagementRequiredBanner toolName="Fuzzing Framework" className="mb-6" />

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatsCard
              title="Total Campaigns"
              value={stats.total_campaigns}
              icon={<Target className="w-6 h-6 text-white" />}
              color="bg-cyan-500/20"
            />
            <StatsCard
              title="Active Campaigns"
              value={stats.active_campaigns}
              icon={<Activity className="w-6 h-6 text-white" />}
              color="bg-green-500/20"
            />
            <StatsCard
              title="Total Crashes"
              value={stats.total_crashes}
              icon={<Bug className="w-6 h-6 text-white" />}
              color="bg-red-500/20"
            />
            <StatsCard
              title="Unique Crashes"
              value={stats.unique_crashes}
              icon={<AlertTriangle className="w-6 h-6 text-white" />}
              color="bg-orange-500/20"
            />
          </div>
        )}

        {/* Campaigns List */}
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Fuzzing Campaigns</h2>
          </div>

          {campaignsLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
            </div>
          ) : campaigns && campaigns.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                    <th className="px-4 py-3">Campaign</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Iterations</th>
                    <th className="px-4 py-3">Crashes</th>
                    <th className="px-4 py-3">Coverage</th>
                    <th className="px-4 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {campaigns.map((campaign) => (
                    <CampaignRow
                      key={campaign.id}
                      campaign={campaign}
                      onSelect={() => setSelectedCampaign(campaign)}
                      onStart={() => startMutation.mutate(campaign.id)}
                      onStop={() => stopMutation.mutate(campaign.id)}
                      onDelete={() => {
                        if (confirm('Are you sure you want to delete this campaign?')) {
                          deleteMutation.mutate(campaign.id);
                        }
                      }}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <Zap className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No fuzzing campaigns yet</p>
              <p className="text-sm mt-1">Create a campaign to start discovering vulnerabilities</p>
            </div>
          )}
        </div>

        {/* Create Modal */}
        {showCreateModal && (
          <CreateCampaignModal
            onClose={() => setShowCreateModal(false)}
            onSubmit={(data) => createMutation.mutate(data)}
            isLoading={createMutation.isPending}
          />
        )}

        {/* Detail Modal */}
        {selectedCampaign && (
          <CampaignDetailModal
            campaign={selectedCampaign}
            onClose={() => setSelectedCampaign(null)}
          />
        )}
      </div>
    </Layout>
  );
};

export default FuzzingPage;
