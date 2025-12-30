import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { Copy, Plus, Trash2, Key, Shield, Settings2, GitBranch, CheckCircle2, XCircle, ExternalLink, Code2 } from 'lucide-react';
import Button from '../ui/Button';
import Input from '../ui/Input';
import Checkbox from '../ui/Checkbox';
import { cicdQualityGateAPI as cicdAPI } from '../../services/api';
import type { CiCdToken, CiCdTokenPermissions, QualityGate, CiCdRun, CiCdPlatform } from '../../types';

type Platform = CiCdPlatform | 'generic';

const CiCdSettings: React.FC = () => {
  // Tokens state
  const [tokens, setTokens] = useState<CiCdToken[]>([]);
  const [loadingTokens, setLoadingTokens] = useState(true);
  const [showNewToken, setShowNewToken] = useState(false);
  const [newTokenData, setNewTokenData] = useState({
    name: '',
    platform: 'github_actions' as Platform,
    permissions: {
      trigger_scans: true,
      view_results: true,
      download_reports: true,
      view_quality_gates: true,
    } as CiCdTokenPermissions,
    expires_in_days: 90 as number | null,
  });
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [creatingToken, setCreatingToken] = useState(false);

  // Quality gates state
  const [qualityGates, setQualityGates] = useState<QualityGate[]>([]);
  const [loadingGates, setLoadingGates] = useState(true);
  const [showNewGate, setShowNewGate] = useState(false);
  const [newGateData, setNewGateData] = useState({
    name: '',
    description: '',
    fail_on_critical: true,
    fail_on_high: true,
    max_critical: 0,
    max_high: 0,
    max_medium: 10,
    max_low: 50,
    is_default: false,
  });
  const [creatingGate, setCreatingGate] = useState(false);

  // Runs state
  const [runs, setRuns] = useState<CiCdRun[]>([]);
  const [loadingRuns, setLoadingRuns] = useState(true);

  // Active tab
  const [activeTab, setActiveTab] = useState<'tokens' | 'quality-gates' | 'runs' | 'examples'>('tokens');

  // Pipeline examples
  const [selectedPlatform, setSelectedPlatform] = useState<'github' | 'jenkins' | 'gitlab'>('github');
  const [pipelineExample, setPipelineExample] = useState('');
  const [loadingExample, setLoadingExample] = useState(false);

  // Load data on mount
  useEffect(() => {
    loadTokens();
    loadQualityGates();
    loadRuns();
  }, []);

  // Load pipeline example when platform changes
  useEffect(() => {
    if (activeTab === 'examples') {
      loadPipelineExample();
    }
  }, [selectedPlatform, activeTab]);

  const loadTokens = async () => {
    try {
      setLoadingTokens(true);
      const response = await cicdAPI.tokens.list();
      setTokens(response.data);
    } catch (error) {
      console.error('Failed to load tokens:', error);
      toast.error('Failed to load CI/CD tokens');
    } finally {
      setLoadingTokens(false);
    }
  };

  const loadQualityGates = async () => {
    try {
      setLoadingGates(true);
      const response = await cicdAPI.qualityGates.list();
      setQualityGates(response.data);
    } catch (error) {
      console.error('Failed to load quality gates:', error);
      toast.error('Failed to load quality gates');
    } finally {
      setLoadingGates(false);
    }
  };

  const loadRuns = async () => {
    try {
      setLoadingRuns(true);
      const response = await cicdAPI.runs.list(20);
      setRuns(response.data);
    } catch (error) {
      console.error('Failed to load runs:', error);
      toast.error('Failed to load CI/CD runs');
    } finally {
      setLoadingRuns(false);
    }
  };

  const loadPipelineExample = async () => {
    try {
      setLoadingExample(true);
      const response = await cicdAPI.examples.get(selectedPlatform);
      setPipelineExample(response.data.content);
    } catch (error) {
      console.error('Failed to load pipeline example:', error);
      toast.error('Failed to load pipeline example');
    } finally {
      setLoadingExample(false);
    }
  };

  const handleCreateToken = async () => {
    if (!newTokenData.name.trim()) {
      toast.error('Token name is required');
      return;
    }

    try {
      setCreatingToken(true);
      // Calculate expiration date if expires_in_days is set
      let expires_at: string | undefined;
      if (newTokenData.expires_in_days) {
        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + newTokenData.expires_in_days);
        expires_at = expirationDate.toISOString();
      }

      const response = await cicdAPI.tokens.create({
        name: newTokenData.name,
        platform: newTokenData.platform === 'generic' ? 'github_actions' : newTokenData.platform,
        permissions: newTokenData.permissions,
        expires_at,
      });
      setCreatedToken(response.data.token);
      await loadTokens();
      toast.success('CI/CD token created successfully');
    } catch (error) {
      console.error('Failed to create token:', error);
      toast.error('Failed to create token');
    } finally {
      setCreatingToken(false);
    }
  };

  const handleDeleteToken = async (tokenId: string) => {
    if (!confirm('Are you sure you want to revoke this token?')) return;

    try {
      await cicdAPI.tokens.delete(tokenId);
      await loadTokens();
      toast.success('Token revoked successfully');
    } catch (error) {
      console.error('Failed to delete token:', error);
      toast.error('Failed to revoke token');
    }
  };

  const handleCreateGate = async () => {
    if (!newGateData.name.trim()) {
      toast.error('Quality gate name is required');
      return;
    }

    try {
      setCreatingGate(true);
      await cicdAPI.qualityGates.create({
        name: newGateData.name,
        description: newGateData.description || undefined,
        fail_on_critical: newGateData.fail_on_critical,
        fail_on_high: newGateData.fail_on_high,
        max_critical: newGateData.max_critical,
        max_high: newGateData.max_high,
        max_medium: newGateData.max_medium,
        max_low: newGateData.max_low,
        is_default: newGateData.is_default,
      });
      await loadQualityGates();
      setShowNewGate(false);
      setNewGateData({
        name: '',
        description: '',
        fail_on_critical: true,
        fail_on_high: true,
        max_critical: 0,
        max_high: 0,
        max_medium: 10,
        max_low: 50,
        is_default: false,
      });
      toast.success('Quality gate created successfully');
    } catch (error) {
      console.error('Failed to create quality gate:', error);
      toast.error('Failed to create quality gate');
    } finally {
      setCreatingGate(false);
    }
  };

  const handleDeleteGate = async (gateId: string) => {
    if (!confirm('Are you sure you want to delete this quality gate?')) return;

    try {
      await cicdAPI.qualityGates.delete(gateId);
      await loadQualityGates();
      toast.success('Quality gate deleted');
    } catch (error) {
      console.error('Failed to delete quality gate:', error);
      toast.error('Failed to delete quality gate');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const getPlatformLabel = (platform: string) => {
    switch (platform) {
      case 'github_actions': return 'GitHub Actions';
      case 'jenkins': return 'Jenkins';
      case 'gitlab_ci': return 'GitLab CI';
      default: return 'Generic';
    }
  };

  return (
    <div className="space-y-6">
      {/* Tabs */}
      <div className="flex gap-2 border-b border-dark-border pb-2">
        <button
          onClick={() => setActiveTab('tokens')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-medium transition-colors ${
            activeTab === 'tokens'
              ? 'bg-primary text-white'
              : 'text-slate-400 hover:text-white hover:bg-dark-hover'
          }`}
        >
          <Key className="h-4 w-4" />
          API Tokens
        </button>
        <button
          onClick={() => setActiveTab('quality-gates')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-medium transition-colors ${
            activeTab === 'quality-gates'
              ? 'bg-primary text-white'
              : 'text-slate-400 hover:text-white hover:bg-dark-hover'
          }`}
        >
          <Shield className="h-4 w-4" />
          Quality Gates
        </button>
        <button
          onClick={() => setActiveTab('runs')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-medium transition-colors ${
            activeTab === 'runs'
              ? 'bg-primary text-white'
              : 'text-slate-400 hover:text-white hover:bg-dark-hover'
          }`}
        >
          <GitBranch className="h-4 w-4" />
          Recent Runs
        </button>
        <button
          onClick={() => setActiveTab('examples')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-medium transition-colors ${
            activeTab === 'examples'
              ? 'bg-primary text-white'
              : 'text-slate-400 hover:text-white hover:bg-dark-hover'
          }`}
        >
          <Code2 className="h-4 w-4" />
          Pipeline Examples
        </button>
      </div>

      {/* Tokens Tab */}
      {activeTab === 'tokens' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-white">CI/CD API Tokens</h3>
              <p className="text-sm text-slate-400">Create tokens for your CI/CD pipelines to trigger scans</p>
            </div>
            <Button onClick={() => { setShowNewToken(true); setCreatedToken(null); }}>
              <Plus className="h-4 w-4 mr-2" />
              New Token
            </Button>
          </div>

          {/* New Token Form */}
          {showNewToken && (
            <div className="bg-dark-surface border border-dark-border rounded-lg p-4 space-y-4">
              <h4 className="font-medium text-white">Create New Token</h4>

              {createdToken ? (
                <div className="space-y-4">
                  <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                    <p className="text-green-400 text-sm mb-2">Token created successfully! Copy it now - it won't be shown again.</p>
                    <div className="flex items-center gap-2">
                      <code className="bg-dark-bg px-3 py-2 rounded text-sm text-white flex-1 font-mono">
                        {createdToken}
                      </code>
                      <Button onClick={() => copyToClipboard(createdToken)} variant="outline" size="sm">
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <Button onClick={() => { setShowNewToken(false); setCreatedToken(null); }} variant="outline">
                    Done
                  </Button>
                </div>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <Input
                      label="Token Name"
                      value={newTokenData.name}
                      onChange={(e) => setNewTokenData({ ...newTokenData, name: e.target.value })}
                      placeholder="e.g., GitHub Actions Production"
                    />
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-1">Platform</label>
                      <select
                        value={newTokenData.platform}
                        onChange={(e) => setNewTokenData({ ...newTokenData, platform: e.target.value as Platform })}
                        className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white"
                      >
                        <option value="github_actions">GitHub Actions</option>
                        <option value="jenkins">Jenkins</option>
                        <option value="gitlab_ci">GitLab CI</option>
                        <option value="generic">Generic</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Permissions</label>
                    <div className="grid grid-cols-2 gap-2">
                      <Checkbox
                        checked={newTokenData.permissions.trigger_scans}
                        onChange={(checked) => setNewTokenData({
                          ...newTokenData,
                          permissions: { ...newTokenData.permissions, trigger_scans: checked }
                        })}
                        label="Trigger scans"
                      />
                      <Checkbox
                        checked={newTokenData.permissions.view_results}
                        onChange={(checked) => setNewTokenData({
                          ...newTokenData,
                          permissions: { ...newTokenData.permissions, view_results: checked }
                        })}
                        label="View results"
                      />
                      <Checkbox
                        checked={newTokenData.permissions.download_reports}
                        onChange={(checked) => setNewTokenData({
                          ...newTokenData,
                          permissions: { ...newTokenData.permissions, download_reports: checked }
                        })}
                        label="Download reports"
                      />
                      <Checkbox
                        checked={newTokenData.permissions.view_quality_gates}
                        onChange={(checked) => setNewTokenData({
                          ...newTokenData,
                          permissions: { ...newTokenData.permissions, view_quality_gates: checked }
                        })}
                        label="View quality gates"
                      />
                    </div>
                  </div>

                  <div className="w-1/2">
                    <label className="block text-sm font-medium text-slate-300 mb-1">Expiration (days)</label>
                    <Input
                      type="number"
                      value={newTokenData.expires_in_days?.toString() || ''}
                      onChange={(e) => setNewTokenData({
                        ...newTokenData,
                        expires_in_days: e.target.value ? parseInt(e.target.value) : null
                      })}
                      placeholder="Never expires if empty"
                    />
                  </div>

                  <div className="flex gap-2">
                    <Button onClick={handleCreateToken} loading={creatingToken}>
                      Create Token
                    </Button>
                    <Button onClick={() => setShowNewToken(false)} variant="outline">
                      Cancel
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Token List */}
          {loadingTokens ? (
            <div className="text-center py-8 text-slate-400">Loading tokens...</div>
          ) : tokens.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              No CI/CD tokens created yet. Create one to get started.
            </div>
          ) : (
            <div className="space-y-2">
              {tokens.map((token) => (
                <div
                  key={token.id}
                  className="bg-dark-surface border border-dark-border rounded-lg p-4 flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{token.name}</span>
                      <span className="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded">
                        {getPlatformLabel(token.platform)}
                      </span>
                    </div>
                    <div className="text-sm text-slate-400 mt-1">
                      <code className="bg-dark-bg px-2 py-0.5 rounded">{token.prefix}...</code>
                      <span className="mx-2">-</span>
                      Created {formatDate(token.created_at)}
                      {token.last_used_at && (
                        <span className="ml-2">- Last used {formatDate(token.last_used_at)}</span>
                      )}
                      {token.expires_at && (
                        <span className="ml-2">- Expires {formatDate(token.expires_at)}</span>
                      )}
                    </div>
                  </div>
                  <Button
                    onClick={() => handleDeleteToken(token.id)}
                    variant="outline"
                    size="sm"
                    className="text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Quality Gates Tab */}
      {activeTab === 'quality-gates' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-white">Quality Gates</h3>
              <p className="text-sm text-slate-400">Configure pass/fail thresholds for your CI/CD pipelines</p>
            </div>
            <Button onClick={() => setShowNewGate(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Quality Gate
            </Button>
          </div>

          {/* New Quality Gate Form */}
          {showNewGate && (
            <div className="bg-dark-surface border border-dark-border rounded-lg p-4 space-y-4">
              <h4 className="font-medium text-white">Create Quality Gate</h4>

              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="Name"
                  value={newGateData.name}
                  onChange={(e) => setNewGateData({ ...newGateData, name: e.target.value })}
                  placeholder="e.g., Production Standards"
                />
                <Input
                  label="Description"
                  value={newGateData.description}
                  onChange={(e) => setNewGateData({ ...newGateData, description: e.target.value })}
                  placeholder="Optional description"
                />
              </div>

              <div className="flex gap-4">
                <Checkbox
                  checked={newGateData.fail_on_critical}
                  onChange={(checked) => setNewGateData({ ...newGateData, fail_on_critical: checked })}
                  label="Fail on critical vulnerabilities"
                />
                <Checkbox
                  checked={newGateData.fail_on_high}
                  onChange={(checked) => setNewGateData({ ...newGateData, fail_on_high: checked })}
                  label="Fail on high vulnerabilities"
                />
              </div>

              <div className="grid grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Max Critical</label>
                  <Input
                    type="number"
                    value={newGateData.max_critical.toString()}
                    onChange={(e) => setNewGateData({
                      ...newGateData,
                      max_critical: parseInt(e.target.value) || 0
                    })}
                    placeholder="0"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Max High</label>
                  <Input
                    type="number"
                    value={newGateData.max_high.toString()}
                    onChange={(e) => setNewGateData({
                      ...newGateData,
                      max_high: parseInt(e.target.value) || 0
                    })}
                    placeholder="0"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Max Medium</label>
                  <Input
                    type="number"
                    value={newGateData.max_medium.toString()}
                    onChange={(e) => setNewGateData({
                      ...newGateData,
                      max_medium: parseInt(e.target.value) || 0
                    })}
                    placeholder="10"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-1">Max Low</label>
                  <Input
                    type="number"
                    value={newGateData.max_low.toString()}
                    onChange={(e) => setNewGateData({
                      ...newGateData,
                      max_low: parseInt(e.target.value) || 0
                    })}
                    placeholder="50"
                  />
                </div>
              </div>

              <div className="flex gap-4">
                <Checkbox
                  checked={newGateData.is_default}
                  onChange={(checked) => setNewGateData({ ...newGateData, is_default: checked })}
                  label="Set as default quality gate"
                />
              </div>

              <div className="flex gap-2">
                <Button onClick={handleCreateGate} loading={creatingGate}>
                  Create Quality Gate
                </Button>
                <Button onClick={() => setShowNewGate(false)} variant="outline">
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {/* Quality Gates List */}
          {loadingGates ? (
            <div className="text-center py-8 text-slate-400">Loading quality gates...</div>
          ) : qualityGates.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              No quality gates configured. The default gate will block any critical vulnerabilities.
            </div>
          ) : (
            <div className="space-y-2">
              {qualityGates.map((gate) => (
                <div
                  key={gate.id}
                  className="bg-dark-surface border border-dark-border rounded-lg p-4 flex items-center justify-between"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{gate.name}</span>
                      {gate.is_default && (
                        <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">Default</span>
                      )}
                      {!gate.user_id && (
                        <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">System</span>
                      )}
                    </div>
                    <div className="text-sm text-slate-400 mt-1">
                      {gate.fail_on_critical && 'Fail on Critical'}
                      {gate.fail_on_high && (gate.fail_on_critical ? ', High' : 'Fail on High')}
                      {` - Max: Critical=${gate.max_critical}, High=${gate.max_high}, Medium=${gate.max_medium}, Low=${gate.max_low}`}
                    </div>
                    {gate.description && (
                      <div className="text-sm text-slate-500 mt-1">{gate.description}</div>
                    )}
                  </div>
                  {gate.user_id && (
                    <Button
                      onClick={() => handleDeleteGate(gate.id)}
                      variant="outline"
                      size="sm"
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Runs Tab */}
      {activeTab === 'runs' && (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Recent CI/CD Runs</h3>
            <p className="text-sm text-slate-400">View recent scans triggered from CI/CD pipelines</p>
          </div>

          {loadingRuns ? (
            <div className="text-center py-8 text-slate-400">Loading runs...</div>
          ) : runs.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              No CI/CD runs yet. Trigger a scan from your pipeline to see results here.
            </div>
          ) : (
            <div className="space-y-2">
              {runs.map((run) => (
                <div
                  key={run.id}
                  className="bg-dark-surface border border-dark-border rounded-lg p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {run.quality_gate_passed === true ? (
                        <CheckCircle2 className="h-5 w-5 text-green-400" />
                      ) : run.quality_gate_passed === false ? (
                        <XCircle className="h-5 w-5 text-red-400" />
                      ) : (
                        <Settings2 className="h-5 w-5 text-slate-400 animate-spin" />
                      )}
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-white">
                            {run.scan_id ? `Scan ${run.scan_id.slice(0, 8)}...` : 'Pending Scan'}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            run.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                            run.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                            run.status === 'running' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-slate-500/20 text-slate-400'
                          }`}>
                            {run.status}
                          </span>
                        </div>
                        <div className="text-sm text-slate-400 mt-1">
                          {getPlatformLabel(run.platform)}
                          {run.branch && ` - ${run.branch}`}
                          {run.commit_sha && ` (${run.commit_sha.slice(0, 7)})`}
                          <span className="ml-2">- {formatDate(run.started_at)}</span>
                          {run.exit_code !== null && (
                            <span className="ml-2">Exit code: {run.exit_code}</span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {run.pipeline_url && (
                        <a
                          href={run.pipeline_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-slate-400 hover:text-white"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Examples Tab */}
      {activeTab === 'examples' && (
        <div className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Pipeline Configuration Examples</h3>
            <p className="text-sm text-slate-400">Copy these examples to integrate HeroForge with your CI/CD platform</p>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setSelectedPlatform('github')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedPlatform === 'github'
                  ? 'bg-primary text-white'
                  : 'bg-dark-surface text-slate-400 hover:text-white'
              }`}
            >
              GitHub Actions
            </button>
            <button
              onClick={() => setSelectedPlatform('jenkins')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedPlatform === 'jenkins'
                  ? 'bg-primary text-white'
                  : 'bg-dark-surface text-slate-400 hover:text-white'
              }`}
            >
              Jenkins
            </button>
            <button
              onClick={() => setSelectedPlatform('gitlab')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedPlatform === 'gitlab'
                  ? 'bg-primary text-white'
                  : 'bg-dark-surface text-slate-400 hover:text-white'
              }`}
            >
              GitLab CI
            </button>
          </div>

          <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">
                {selectedPlatform === 'github' && '.github/workflows/security-scan.yml'}
                {selectedPlatform === 'jenkins' && 'Jenkinsfile'}
                {selectedPlatform === 'gitlab' && '.gitlab-ci.yml'}
              </span>
              <Button onClick={() => copyToClipboard(pipelineExample)} variant="outline" size="sm">
                <Copy className="h-4 w-4 mr-1" />
                Copy
              </Button>
            </div>
            {loadingExample ? (
              <div className="text-center py-8 text-slate-400">Loading example...</div>
            ) : (
              <pre className="bg-dark-bg rounded-lg p-4 text-sm text-slate-300 overflow-x-auto max-h-[500px]">
                <code>{pipelineExample}</code>
              </pre>
            )}
          </div>

          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <h4 className="font-medium text-blue-400 mb-2">Setup Instructions</h4>
            <ol className="text-sm text-slate-300 space-y-2 list-decimal list-inside">
              <li>Create a CI/CD token in the "API Tokens" tab above</li>
              <li>Add the token as a secret in your CI/CD platform:
                <ul className="ml-6 mt-1 space-y-1">
                  <li>GitHub: Settings &gt; Secrets &gt; HEROFORGE_CI_TOKEN</li>
                  <li>Jenkins: Credentials &gt; Add &gt; heroforge-ci-token</li>
                  <li>GitLab: Settings &gt; CI/CD &gt; Variables &gt; HEROFORGE_CI_TOKEN</li>
                </ul>
              </li>
              <li>Copy the pipeline configuration above to your repository</li>
              <li>Update the target IP addresses in the configuration</li>
              <li>Configure a quality gate if needed (defaults will be used otherwise)</li>
            </ol>
          </div>
        </div>
      )}
    </div>
  );
};

export default CiCdSettings;
