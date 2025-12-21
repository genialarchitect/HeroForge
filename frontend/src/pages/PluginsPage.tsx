import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import PluginCard from '../components/plugins/PluginCard';
import InstallPluginModal from '../components/plugins/InstallPluginModal';
import PluginSettings from '../components/plugins/PluginSettings';
import { pluginsAPI } from '../services/pluginsApi';
import type { Plugin, PluginStats, PluginTypeInfo } from '../types/plugins';
import {
  Puzzle,
  Plus,
  Search,
  Filter,
  Scan,
  Shield,
  FileText,
  Plug,
  Power,
  PowerOff,
  AlertCircle,
  RefreshCw,
  Package,
} from 'lucide-react';

const PluginsPage: React.FC = () => {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [stats, setStats] = useState<PluginStats | null>(null);
  const [pluginTypes, setPluginTypes] = useState<PluginTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Modals
  const [showInstallModal, setShowInstallModal] = useState(false);
  const [settingsPlugin, setSettingsPlugin] = useState<Plugin | null>(null);

  const loadPlugins = useCallback(async () => {
    setLoading(true);
    try {
      const [pluginsRes, statsRes, typesRes] = await Promise.all([
        pluginsAPI.list({
          search: searchTerm || undefined,
          plugin_type: typeFilter || undefined,
          status: statusFilter || undefined,
        }),
        pluginsAPI.getStats(),
        pluginsAPI.getTypes(),
      ]);

      setPlugins(pluginsRes.data.plugins);
      setStats(statsRes.data);
      setPluginTypes(typesRes.data);
    } catch (error) {
      console.error('Failed to load plugins:', error);
      toast.error('Failed to load plugins');
    } finally {
      setLoading(false);
    }
  }, [searchTerm, typeFilter, statusFilter]);

  useEffect(() => {
    loadPlugins();
  }, [loadPlugins]);

  const handleEnable = async (id: string) => {
    setActionLoading(id);
    try {
      await pluginsAPI.enable(id);
      toast.success('Plugin enabled');
      await loadPlugins();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to enable plugin');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDisable = async (id: string) => {
    setActionLoading(id);
    try {
      await pluginsAPI.disable(id);
      toast.success('Plugin disabled');
      await loadPlugins();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to disable plugin');
    } finally {
      setActionLoading(null);
    }
  };

  const handleUninstall = async (id: string) => {
    const plugin = plugins.find((p) => p.id === id);
    if (!plugin) return;

    if (
      !window.confirm(
        `Are you sure you want to uninstall "${plugin.name}"? This action cannot be undone.`
      )
    ) {
      return;
    }

    setActionLoading(id);
    try {
      await pluginsAPI.uninstall(id);
      toast.success('Plugin uninstalled');
      await loadPlugins();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to uninstall plugin');
    } finally {
      setActionLoading(null);
    }
  };

  const handleSettings = (id: string) => {
    const plugin = plugins.find((p) => p.id === id);
    if (plugin) {
      setSettingsPlugin(plugin);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'scanner':
        return <Scan className="h-4 w-4" />;
      case 'detector':
        return <Shield className="h-4 w-4" />;
      case 'reporter':
        return <FileText className="h-4 w-4" />;
      case 'integration':
        return <Plug className="h-4 w-4" />;
      default:
        return <Puzzle className="h-4 w-4" />;
    }
  };

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
              <Puzzle className="h-7 w-7 text-primary" />
              Plugin Marketplace
            </h1>
            <p className="mt-1 text-slate-500 dark:text-slate-400">
              Manage installed plugins and extend HeroForge functionality
            </p>
          </div>
          <Button
            variant="primary"
            onClick={() => setShowInstallModal(true)}
            className="flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            Install Plugin
          </Button>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <div className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10 text-primary">
                  <Package className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.total}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Total Plugins</p>
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-green-500/10 text-green-500">
                  <Power className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.enabled}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Enabled</p>
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-slate-500/10 text-slate-500">
                  <PowerOff className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.disabled}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Disabled</p>
                </div>
              </div>
            </Card>

            <Card>
              <div className="p-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-500/10 text-red-500">
                  <AlertCircle className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">
                    {stats.error}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">Errors</p>
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* Filters */}
        <Card>
          <div className="p-4">
            <div className="flex flex-col md:flex-row gap-4">
              {/* Search */}
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  type="text"
                  placeholder="Search plugins..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>

              {/* Type Filter */}
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-slate-400" />
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                >
                  <option value="">All Types</option>
                  {pluginTypes.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Status Filter */}
              <div>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                >
                  <option value="">All Status</option>
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                  <option value="error">Error</option>
                </select>
              </div>

              {/* Refresh */}
              <Button
                variant="secondary"
                onClick={loadPlugins}
                disabled={loading}
                className="flex items-center gap-2"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
        </Card>

        {/* Plugin List */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        ) : plugins.length === 0 ? (
          <Card>
            <div className="p-12 text-center">
              <Puzzle className="h-16 w-16 mx-auto text-slate-400 mb-4" />
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">
                No Plugins Installed
              </h3>
              <p className="text-slate-500 dark:text-slate-400 mb-4">
                {searchTerm || typeFilter || statusFilter
                  ? 'No plugins match your filters.'
                  : 'Get started by installing your first plugin.'}
              </p>
              {!searchTerm && !typeFilter && !statusFilter && (
                <Button
                  variant="primary"
                  onClick={() => setShowInstallModal(true)}
                  className="flex items-center gap-2 mx-auto"
                >
                  <Plus className="h-4 w-4" />
                  Install Plugin
                </Button>
              )}
            </div>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {plugins.map((plugin) => (
              <PluginCard
                key={plugin.id}
                plugin={plugin}
                onEnable={handleEnable}
                onDisable={handleDisable}
                onUninstall={handleUninstall}
                onSettings={handleSettings}
                isLoading={actionLoading === plugin.id}
              />
            ))}
          </div>
        )}

        {/* Plugin Types Legend */}
        {pluginTypes.length > 0 && plugins.length > 0 && (
          <Card>
            <div className="p-4">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
                Plugin Types
              </h3>
              <div className="flex flex-wrap gap-4">
                {pluginTypes.map((type) => (
                  <div key={type.id} className="flex items-center gap-2 text-sm">
                    <div className="p-1.5 rounded bg-primary/10 text-primary">
                      {getTypeIcon(type.id)}
                    </div>
                    <div>
                      <span className="font-medium text-slate-900 dark:text-white">
                        {type.name}
                      </span>
                      <span className="text-slate-500 dark:text-slate-400 ml-1">
                        - {type.description}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        )}
      </div>

      {/* Install Modal */}
      <InstallPluginModal
        isOpen={showInstallModal}
        onClose={() => setShowInstallModal(false)}
        onInstalled={loadPlugins}
      />

      {/* Settings Modal */}
      {settingsPlugin && (
        <PluginSettings
          plugin={settingsPlugin}
          isOpen={!!settingsPlugin}
          onClose={() => setSettingsPlugin(null)}
          onUpdate={loadPlugins}
        />
      )}
    </Layout>
  );
};

export default PluginsPage;
