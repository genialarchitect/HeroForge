import React, { useState } from 'react';
import { X, Server, Copy, Check, AlertTriangle } from 'lucide-react';
import { toast } from 'react-toastify';
import { agentAPI } from '../../services/api';
import Button from '../ui/Button';
import type { RegisterAgentResponse } from '../../types';

interface RegisterAgentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const RegisterAgentModal: React.FC<RegisterAgentModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [step, setStep] = useState<'form' | 'success'>('form');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [networkZones, setNetworkZones] = useState('');
  const [maxConcurrentTasks, setMaxConcurrentTasks] = useState(5);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RegisterAgentResponse | null>(null);
  const [tokenCopied, setTokenCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      toast.error('Agent name is required');
      return;
    }

    setLoading(true);
    try {
      const zones = networkZones
        .split(',')
        .map((z) => z.trim())
        .filter((z) => z.length > 0);

      const response = await agentAPI.register({
        name: name.trim(),
        description: description.trim() || undefined,
        network_zones: zones.length > 0 ? zones : undefined,
        max_concurrent_tasks: maxConcurrentTasks,
      });

      setResult(response.data);
      setStep('success');
      onSuccess();
    } catch (error: unknown) {
      const err = error as { response?: { data?: { message?: string } } };
      toast.error(err.response?.data?.message || 'Failed to register agent');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyToken = async () => {
    if (result?.token) {
      await navigator.clipboard.writeText(result.token);
      setTokenCopied(true);
      toast.success('Token copied to clipboard');
      setTimeout(() => setTokenCopied(false), 2000);
    }
  };

  const handleClose = () => {
    setStep('form');
    setName('');
    setDescription('');
    setNetworkZones('');
    setMaxConcurrentTasks(5);
    setResult(null);
    setTokenCopied(false);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={handleClose} />

      <div className="relative bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-xl w-full max-w-lg mx-4">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg">
              <Server className="h-5 w-5 text-primary" />
            </div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
              {step === 'form' ? 'Register New Agent' : 'Agent Registered'}
            </h2>
          </div>
          <button
            onClick={handleClose}
            className="p-1 hover:bg-light-hover dark:hover:bg-dark-hover rounded"
          >
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>

        {step === 'form' ? (
          <form onSubmit={handleSubmit}>
            <div className="p-4 space-y-4">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Agent Name *
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., datacenter-scanner-01"
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                  required
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Optional description of this agent's purpose"
                  rows={2}
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary resize-none"
                />
              </div>

              {/* Network Zones */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Network Zones
                </label>
                <input
                  type="text"
                  value={networkZones}
                  onChange={(e) => setNetworkZones(e.target.value)}
                  placeholder="e.g., internal, dmz, production (comma-separated)"
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                />
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Define which network zones this agent can scan
                </p>
              </div>

              {/* Max Concurrent Tasks */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Max Concurrent Tasks
                </label>
                <input
                  type="number"
                  value={maxConcurrentTasks}
                  onChange={(e) => setMaxConcurrentTasks(parseInt(e.target.value) || 1)}
                  min={1}
                  max={20}
                  className="w-full px-3 py-2 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                />
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                  Maximum number of scan tasks this agent can run simultaneously
                </p>
              </div>
            </div>

            {/* Footer */}
            <div className="flex justify-end gap-3 p-4 border-t border-light-border dark:border-dark-border">
              <Button variant="secondary" onClick={handleClose} disabled={loading}>
                Cancel
              </Button>
              <Button type="submit" loading={loading}>
                Register Agent
              </Button>
            </div>
          </form>
        ) : (
          <div className="p-4 space-y-4">
            {/* Success message */}
            <div className="flex items-start gap-3 p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <Check className="h-5 w-5 text-green-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-green-700 dark:text-green-400">
                  Agent registered successfully!
                </p>
                <p className="text-sm text-green-600 dark:text-green-500 mt-1">
                  Your agent "{result?.name}" is ready to be configured.
                </p>
              </div>
            </div>

            {/* Token display */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                <span className="text-sm font-medium text-yellow-700 dark:text-yellow-400">
                  Save this token now - it won't be shown again!
                </span>
              </div>

              <div className="relative">
                <code className="block w-full p-3 bg-slate-100 dark:bg-slate-800 rounded-lg text-sm font-mono text-slate-900 dark:text-white break-all">
                  {result?.token}
                </code>
                <button
                  onClick={handleCopyToken}
                  className="absolute top-2 right-2 p-2 hover:bg-slate-200 dark:hover:bg-slate-700 rounded"
                  title="Copy token"
                >
                  {tokenCopied ? (
                    <Check className="h-4 w-4 text-green-500" />
                  ) : (
                    <Copy className="h-4 w-4 text-slate-500" />
                  )}
                </button>
              </div>
            </div>

            {/* Installation instructions */}
            <div className="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg">
              <h4 className="text-sm font-medium text-slate-900 dark:text-white mb-2">
                Configure the agent
              </h4>
              <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">
                Set the following environment variables on your agent:
              </p>
              <pre className="text-xs bg-slate-100 dark:bg-slate-800 p-2 rounded overflow-x-auto">
{`HEROFORGE_AGENT_TOKEN="${result?.token}"
HEROFORGE_SERVER_URL="https://heroforge.example.com"
HEROFORGE_AGENT_NAME="${result?.name}"`}
              </pre>
            </div>

            {/* Close button */}
            <div className="flex justify-end pt-2">
              <Button onClick={handleClose}>Done</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default RegisterAgentModal;
