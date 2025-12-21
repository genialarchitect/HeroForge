import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { pluginsAPI } from '../../services/pluginsApi';
import type { Plugin, PluginPermissions } from '../../types/plugins';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import {
  X,
  Settings,
  Shield,
  Network,
  FolderOpen,
  Terminal,
  FileText,
  Server,
  Bug,
  Loader2,
  Save,
  Info,
  RefreshCw,
} from 'lucide-react';

interface PluginSettingsProps {
  plugin: Plugin;
  isOpen: boolean;
  onClose: () => void;
  onUpdate: () => void;
}

const PermissionIcon: React.FC<{ permission: string; granted: boolean }> = ({
  permission,
  granted,
}) => {
  const icons: Record<string, React.ReactNode> = {
    network: <Network className="h-4 w-4" />,
    filesystem: <FolderOpen className="h-4 w-4" />,
    environment: <Terminal className="h-4 w-4" />,
    subprocess: <Terminal className="h-4 w-4" />,
    scan_results: <FileText className="h-4 w-4" />,
    vulnerabilities: <Bug className="h-4 w-4" />,
    assets: <Server className="h-4 w-4" />,
    reports: <FileText className="h-4 w-4" />,
  };

  const labels: Record<string, string> = {
    network: 'Network Access',
    filesystem: 'Filesystem Access',
    environment: 'Environment Variables',
    subprocess: 'Spawn Processes',
    scan_results: 'Scan Results',
    vulnerabilities: 'Vulnerability Data',
    assets: 'Asset Inventory',
    reports: 'Report Generation',
  };

  return (
    <div
      className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
        granted
          ? 'bg-green-500/10 border-green-500/30 text-green-600'
          : 'bg-slate-500/10 border-slate-500/30 text-slate-400'
      }`}
    >
      {icons[permission] || <Shield className="h-4 w-4" />}
      <span className="text-sm">{labels[permission] || permission}</span>
      {granted && <Badge variant="success" size="sm">Granted</Badge>}
    </div>
  );
};

const PluginSettings: React.FC<PluginSettingsProps> = ({
  plugin,
  isOpen,
  onClose,
  onUpdate,
}) => {
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadSettings();
    }
  }, [isOpen, plugin.id]);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await pluginsAPI.getSettings(plugin.id);
      setSettings(response.data || {});
      setHasChanges(false);
    } catch (error) {
      console.error('Failed to load settings:', error);
      setSettings({});
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    setSaving(true);
    try {
      await pluginsAPI.updateSettings(plugin.id, settings);
      toast.success('Settings saved successfully');
      setHasChanges(false);
      onUpdate();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleResetSettings = async () => {
    if (!window.confirm('Are you sure you want to reset settings to defaults?')) return;

    setSaving(true);
    try {
      await pluginsAPI.deleteSettings(plugin.id);
      toast.success('Settings reset to defaults');
      await loadSettings();
      onUpdate();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to reset settings');
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key: string, value: unknown) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
    setHasChanges(true);
  };

  // Get permissions as array for display
  const getPermissionsArray = (permissions: PluginPermissions): Array<[string, boolean]> => {
    return Object.entries(permissions) as Array<[string, boolean]>;
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-light-surface dark:bg-dark-surface rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-light-border dark:border-dark-border">
        {/* Header */}
        <div className="sticky top-0 p-6 border-b border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface z-10">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Plugin Settings
              </h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                {plugin.name} v{plugin.version}
              </p>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-900 dark:hover:text-white"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Plugin Info */}
          <Card>
            <div className="p-4">
              <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                <Info className="h-4 w-4" />
                Plugin Information
              </h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-500 dark:text-slate-400">ID:</span>
                  <span className="ml-2 text-slate-900 dark:text-white font-mono text-xs">
                    {plugin.plugin_id}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Type:</span>
                  <Badge variant="primary" size="sm" className="ml-2">
                    {plugin.plugin_type}
                  </Badge>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Author:</span>
                  <span className="ml-2 text-slate-900 dark:text-white">{plugin.author}</span>
                </div>
                <div>
                  <span className="text-slate-500 dark:text-slate-400">Status:</span>
                  <Badge
                    variant={plugin.status === 'enabled' ? 'success' : 'secondary'}
                    size="sm"
                    className="ml-2"
                  >
                    {plugin.status}
                  </Badge>
                </div>
              </div>
              <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">
                {plugin.description}
              </p>
            </div>
          </Card>

          {/* Permissions */}
          <Card>
            <div className="p-4">
              <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Permissions
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {getPermissionsArray(plugin.permissions).map(([key, value]) => (
                  <PermissionIcon key={key} permission={key} granted={value} />
                ))}
              </div>
            </div>
          </Card>

          {/* User Settings */}
          <Card>
            <div className="p-4">
              <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                <Settings className="h-4 w-4" />
                Configuration
              </h3>

              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                </div>
              ) : Object.keys(settings).length === 0 ? (
                <div className="text-center py-8 text-slate-500 dark:text-slate-400">
                  <Settings className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No configurable settings for this plugin.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {Object.entries(settings).map(([key, value]) => (
                    <div key={key}>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        {key.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                      </label>
                      {typeof value === 'boolean' ? (
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={value}
                            onChange={(e) => updateSetting(key, e.target.checked)}
                            className="rounded border-light-border dark:border-dark-border text-primary focus:ring-primary"
                          />
                          <span className="text-sm text-slate-600 dark:text-slate-400">
                            {value ? 'Enabled' : 'Disabled'}
                          </span>
                        </div>
                      ) : typeof value === 'number' ? (
                        <input
                          type="number"
                          value={value}
                          onChange={(e) => updateSetting(key, parseInt(e.target.value, 10))}
                          className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                        />
                      ) : (
                        <input
                          type="text"
                          value={String(value)}
                          onChange={(e) => updateSetting(key, e.target.value)}
                          className="w-full px-3 py-2 rounded-lg border border-light-border dark:border-dark-border bg-light-bg dark:bg-dark-bg text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-primary"
                        />
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 p-6 border-t border-light-border dark:border-dark-border bg-light-surface dark:bg-dark-surface flex justify-between">
          <Button
            variant="ghost"
            onClick={handleResetSettings}
            disabled={saving || loading}
            className="flex items-center gap-2 text-slate-600 dark:text-slate-400"
          >
            <RefreshCw className="h-4 w-4" />
            Reset to Defaults
          </Button>

          <div className="flex gap-3">
            <Button variant="secondary" onClick={onClose} disabled={saving}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleSaveSettings}
              disabled={saving || loading || !hasChanges}
              className="flex items-center gap-2"
            >
              {saving && <Loader2 className="h-4 w-4 animate-spin" />}
              <Save className="h-4 w-4" />
              Save Settings
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PluginSettings;
