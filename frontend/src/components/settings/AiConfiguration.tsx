import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { aiSettingsAPI } from '../../services/api';
import type {
  AiConfigurationResponse,
  UpdateAiConfigurationRequest,
  ProviderStatusResponse,
  AvailableModelsResponse,
  ModelInfo,
} from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import {
  Bot,
  Server,
  Key,
  RefreshCw,
  CheckCircle,
  XCircle,
  Zap,
  Save,
  TestTube,
  Settings2,
} from 'lucide-react';

const AiConfiguration: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [config, setConfig] = useState<AiConfigurationResponse | null>(null);
  const [providers, setProviders] = useState<ProviderStatusResponse[]>([]);
  const [models, setModels] = useState<AvailableModelsResponse | null>(null);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    responseTime?: number;
  } | null>(null);

  // Form state
  const [selectedProvider, setSelectedProvider] = useState<string>('anthropic');
  const [selectedModel, setSelectedModel] = useState<string>('');
  const [anthropicApiKey, setAnthropicApiKey] = useState<string>('');
  const [openaiApiKey, setOpenaiApiKey] = useState<string>('');
  const [ollamaBaseUrl, setOllamaBaseUrl] = useState<string>('');
  const [ollamaModel, setOllamaModel] = useState<string>('');
  const [fallbackProvider, setFallbackProvider] = useState<string>('');
  const [autoReports, setAutoReports] = useState<boolean>(false);
  const [autoRemediation, setAutoRemediation] = useState<boolean>(true);

  useEffect(() => {
    loadConfiguration();
  }, []);

  const loadConfiguration = async () => {
    setLoading(true);
    try {
      const [configRes, providersRes, modelsRes] = await Promise.all([
        aiSettingsAPI.getConfiguration(),
        aiSettingsAPI.getProviders(),
        aiSettingsAPI.getModels(),
      ]);

      setConfig(configRes.data);
      setProviders(providersRes.data);
      setModels(modelsRes.data);

      // Populate form with current config
      if (configRes.data) {
        setSelectedProvider(configRes.data.provider);
        setSelectedModel(configRes.data.model);
        setOllamaBaseUrl(configRes.data.ollama_base_url || '');
        setFallbackProvider(configRes.data.fallback_provider || '');
        setAutoReports(configRes.data.auto_reports);
        setAutoRemediation(configRes.data.auto_remediation);
      }
    } catch (error) {
      toast.error('Failed to load AI configuration');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setTestResult(null);

    try {
      const request: UpdateAiConfigurationRequest = {
        provider: selectedProvider,
        model: selectedModel || undefined,
        anthropic_api_key: anthropicApiKey || undefined,
        openai_api_key: openaiApiKey || undefined,
        ollama_base_url: ollamaBaseUrl || undefined,
        ollama_model: ollamaModel || undefined,
        fallback_provider: fallbackProvider || undefined,
        auto_reports: autoReports,
        auto_remediation: autoRemediation,
      };

      const response = await aiSettingsAPI.updateConfiguration(request);
      setConfig(response.data);
      toast.success('AI configuration saved successfully');

      // Clear sensitive fields after save
      setAnthropicApiKey('');
      setOpenaiApiKey('');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const response = await aiSettingsAPI.testConnection();
      setTestResult({
        success: response.data.success,
        message: response.data.message,
        responseTime: response.data.response_time_ms || undefined,
      });

      if (response.data.success) {
        toast.success('Connection test successful!');
      } else {
        toast.warning('Connection test failed');
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      setTestResult({
        success: false,
        message: axiosError.response?.data?.error || 'Connection test failed',
      });
      toast.error('Connection test failed');
    } finally {
      setTesting(false);
    }
  };

  const getModelsForProvider = (provider: string): ModelInfo[] => {
    if (!models) return [];
    switch (provider) {
      case 'anthropic':
        return models.anthropic;
      case 'ollama':
        return models.ollama;
      case 'openai':
        return models.openai;
      default:
        return [];
    }
  };

  const getProviderStatus = (providerName: string): ProviderStatusResponse | undefined => {
    return providers.find((p) => p.provider === providerName);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="w-6 h-6 text-cyan-400" />
          <h2 className="text-xl font-semibold text-white">AI Configuration</h2>
        </div>
        <Button
          variant="secondary"
          onClick={loadConfiguration}
          disabled={loading}
          className="flex items-center gap-2"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Provider Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {['anthropic', 'ollama', 'openai'].map((providerName) => {
          const status = getProviderStatus(providerName);
          const isSelected = selectedProvider === providerName;
          return (
            <Card
              key={providerName}
              className={`cursor-pointer transition-all ${
                isSelected
                  ? 'ring-2 ring-cyan-500 bg-gray-800/80'
                  : 'hover:bg-gray-800/60'
              }`}
              onClick={() => {
                setSelectedProvider(providerName);
                setSelectedModel('');
              }}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-cyan-400" />
                  <span className="font-medium text-white capitalize">{providerName}</span>
                </div>
                {status?.available ? (
                  <Badge variant="success" className="flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    Available
                  </Badge>
                ) : (
                  <Badge variant="danger" className="flex items-center gap-1">
                    <XCircle className="w-3 h-3" />
                    Not Configured
                  </Badge>
                )}
              </div>
              <div className="text-sm text-gray-400 space-y-1">
                <div>Model: {status?.model || 'Not set'}</div>
                <div className="flex items-center gap-2">
                  {status?.streaming && (
                    <Badge variant="primary" className="text-xs">
                      <Zap className="w-3 h-3 mr-1" />
                      Streaming
                    </Badge>
                  )}
                </div>
              </div>
              {isSelected && (
                <div className="mt-2 pt-2 border-t border-gray-700">
                  <span className="text-xs text-cyan-400">Selected</span>
                </div>
              )}
            </Card>
          );
        })}
      </div>

      {/* Configuration Form */}
      <Card>
        <div className="flex items-center gap-2 mb-4">
          <Settings2 className="w-5 h-5 text-cyan-400" />
          <h3 className="text-lg font-medium text-white">Provider Settings</h3>
        </div>

        <form onSubmit={handleSave} className="space-y-6">
          {/* Model Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Model
            </label>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
            >
              <option value="">Select a model</option>
              {getModelsForProvider(selectedProvider).map((model) => (
                <option key={model.id} value={model.id}>
                  {model.name} {model.description && `- ${model.description}`}
                </option>
              ))}
            </select>
          </div>

          {/* Provider-specific settings */}
          {selectedProvider === 'anthropic' && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                <Key className="w-4 h-4 inline mr-2" />
                Anthropic API Key
                {config?.has_anthropic_key && (
                  <Badge variant="success" className="ml-2 text-xs">
                    Configured
                  </Badge>
                )}
              </label>
              <Input
                type="password"
                value={anthropicApiKey}
                onChange={(e) => setAnthropicApiKey(e.target.value)}
                placeholder={config?.has_anthropic_key ? '••••••••••••••••' : 'sk-ant-...'}
                className="font-mono"
              />
              <p className="mt-1 text-xs text-gray-500">
                Leave blank to keep existing key. Get your key from{' '}
                <a
                  href="https://console.anthropic.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:underline"
                >
                  console.anthropic.com
                </a>
              </p>
            </div>
          )}

          {selectedProvider === 'openai' && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                <Key className="w-4 h-4 inline mr-2" />
                OpenAI API Key
                {config?.has_openai_key && (
                  <Badge variant="success" className="ml-2 text-xs">
                    Configured
                  </Badge>
                )}
              </label>
              <Input
                type="password"
                value={openaiApiKey}
                onChange={(e) => setOpenaiApiKey(e.target.value)}
                placeholder={config?.has_openai_key ? '••••••••••••••••' : 'sk-...'}
                className="font-mono"
              />
              <p className="mt-1 text-xs text-gray-500">
                Leave blank to keep existing key. Get your key from{' '}
                <a
                  href="https://platform.openai.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:underline"
                >
                  platform.openai.com
                </a>
              </p>
            </div>
          )}

          {selectedProvider === 'ollama' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  <Server className="w-4 h-4 inline mr-2" />
                  Ollama Base URL
                </label>
                <Input
                  type="url"
                  value={ollamaBaseUrl}
                  onChange={(e) => setOllamaBaseUrl(e.target.value)}
                  placeholder="http://localhost:11434"
                  className="font-mono"
                />
                <p className="mt-1 text-xs text-gray-500">
                  The URL where your Ollama server is running (default: http://localhost:11434)
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Custom Model Name (Optional)
                </label>
                <Input
                  type="text"
                  value={ollamaModel}
                  onChange={(e) => setOllamaModel(e.target.value)}
                  placeholder="llama3:8b"
                  className="font-mono"
                />
                <p className="mt-1 text-xs text-gray-500">
                  Override the model selection above with a custom Ollama model name
                </p>
              </div>
            </div>
          )}

          {/* Fallback Provider */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Fallback Provider (Optional)
            </label>
            <select
              value={fallbackProvider}
              onChange={(e) => setFallbackProvider(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
            >
              <option value="">None</option>
              {['anthropic', 'ollama', 'openai']
                .filter((p) => p !== selectedProvider)
                .map((p) => (
                  <option key={p} value={p}>
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                  </option>
                ))}
            </select>
            <p className="mt-1 text-xs text-gray-500">
              Used when primary provider is unavailable
            </p>
          </div>

          {/* Auto-features */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="autoReports"
                checked={autoReports}
                onChange={(e) => setAutoReports(e.target.checked)}
                className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-800"
              />
              <label htmlFor="autoReports" className="text-sm text-gray-300">
                Enable AI-generated executive reports
              </label>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="autoRemediation"
                checked={autoRemediation}
                onChange={(e) => setAutoRemediation(e.target.checked)}
                className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-800"
              />
              <label htmlFor="autoRemediation" className="text-sm text-gray-300">
                Enable AI-assisted remediation guidance
              </label>
            </div>
          </div>

          {/* Test Result */}
          {testResult && (
            <div
              className={`p-4 rounded-lg ${
                testResult.success ? 'bg-green-900/30 border border-green-700' : 'bg-red-900/30 border border-red-700'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                {testResult.success ? (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-red-400" />
                )}
                <span className={testResult.success ? 'text-green-400' : 'text-red-400'}>
                  {testResult.success ? 'Connection Successful' : 'Connection Failed'}
                </span>
              </div>
              <p className="text-sm text-gray-400">{testResult.message}</p>
              {testResult.responseTime && (
                <p className="text-xs text-gray-500 mt-1">
                  Response time: {testResult.responseTime}ms
                </p>
              )}
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center gap-3 pt-4 border-t border-gray-700">
            <Button
              type="submit"
              disabled={saving}
              className="flex items-center gap-2"
            >
              <Save className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
              {saving ? 'Saving...' : 'Save Configuration'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={handleTestConnection}
              disabled={testing}
              className="flex items-center gap-2"
            >
              <TestTube className={`w-4 h-4 ${testing ? 'animate-pulse' : ''}`} />
              {testing ? 'Testing...' : 'Test Connection'}
            </Button>
          </div>
        </form>
      </Card>

      {/* Current Configuration Info */}
      {config && (
        <Card>
          <h3 className="text-lg font-medium text-white mb-4">Current Configuration</h3>
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-gray-400">Active Provider</dt>
              <dd className="text-white font-medium capitalize">{config.provider}</dd>
            </div>
            <div>
              <dt className="text-gray-400">Active Model</dt>
              <dd className="text-white font-medium">{config.model}</dd>
            </div>
            <div>
              <dt className="text-gray-400">Anthropic Key</dt>
              <dd>
                {config.has_anthropic_key ? (
                  <Badge variant="success">Configured</Badge>
                ) : (
                  <Badge variant="warning">Not Set</Badge>
                )}
              </dd>
            </div>
            <div>
              <dt className="text-gray-400">OpenAI Key</dt>
              <dd>
                {config.has_openai_key ? (
                  <Badge variant="success">Configured</Badge>
                ) : (
                  <Badge variant="warning">Not Set</Badge>
                )}
              </dd>
            </div>
            {config.ollama_base_url && (
              <div className="col-span-2">
                <dt className="text-gray-400">Ollama URL</dt>
                <dd className="text-white font-mono text-xs">{config.ollama_base_url}</dd>
              </div>
            )}
            {config.updated_at && (
              <div className="col-span-2">
                <dt className="text-gray-400">Last Updated</dt>
                <dd className="text-white">{new Date(config.updated_at).toLocaleString()}</dd>
              </div>
            )}
          </dl>
        </Card>
      )}
    </div>
  );
};

export default AiConfiguration;
