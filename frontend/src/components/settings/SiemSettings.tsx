import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { siemAPI, scanAPI } from '../../services/api';
import { SiemSettings as SiemSettingsType, CreateSiemSettingsRequest, UpdateSiemSettingsRequest, ScanResult } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Database, Plus, Edit2, Trash2, TestTube, Server, AlertCircle, CheckCircle, X, Upload, RefreshCw } from 'lucide-react';

const SiemSettings: React.FC = () => {
  const [settings, setSettings] = useState<SiemSettingsType[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingSettings, setEditingSettings] = useState<SiemSettingsType | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  // Manual export state
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    loadSettings();
    loadScans();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await siemAPI.getSettings();
      setSettings(response.data);
    } catch (error: any) {
      toast.error('Failed to load SIEM settings');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleTestConnection = async (id: string) => {
    setTesting(id);
    try {
      const response = await siemAPI.testConnection(id);
      if (response.data.success) {
        toast.success('Connection test successful!');
      } else {
        toast.error(`Connection test failed: ${response.data.message}`);
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Connection test failed');
    } finally {
      setTesting(null);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this SIEM integration?')) {
      return;
    }

    try {
      await siemAPI.deleteSettings(id);
      toast.success('SIEM integration deleted');
      loadSettings();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to delete SIEM integration');
    }
  };

  const loadScans = async () => {
    setLoadingScans(true);
    try {
      const response = await scanAPI.getAll();
      // Only show completed scans
      setScans(response.data.filter(scan => scan.status === 'completed'));
    } catch (error: any) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoadingScans(false);
    }
  };

  const handleExportScan = async () => {
    if (!selectedScanId) {
      toast.error('Please select a scan to export');
      return;
    }

    const enabledSettings = settings.filter(s => s.enabled);
    if (enabledSettings.length === 0) {
      toast.error('No enabled SIEM integrations found. Please enable at least one integration.');
      return;
    }

    setExporting(true);
    try {
      const response = await siemAPI.exportScan(selectedScanId);
      if (response.data.success) {
        toast.success(`Scan exported to ${response.data.exported_to} SIEM integration(s). ${response.data.events_count} events sent.`);
        if (response.data.errors && response.data.errors.length > 0) {
          response.data.errors.forEach((err: string) => toast.warning(err));
        }
      } else {
        toast.error('Export failed. Check SIEM configuration.');
      }
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to export scan to SIEM');
    } finally {
      setExporting(false);
    }
  };

  if (loading) {
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
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">SIEM Integrations</h3>
          </div>
          <Button variant="primary" onClick={() => setShowCreateModal(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Integration
          </Button>
        </div>

        {settings.length === 0 ? (
          <div className="text-center py-12">
            <Server className="h-12 w-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400 mb-4">No SIEM integrations configured</p>
            <Button variant="primary" onClick={() => setShowCreateModal(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Add Your First Integration
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            {settings.map((setting) => (
              <div key={setting.id} className="bg-dark-bg border border-dark-border rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="px-3 py-1 bg-primary/20 text-primary rounded-md text-sm font-medium uppercase">
                        {setting.siem_type}
                      </span>
                      {setting.enabled ? (
                        <span className="flex items-center gap-1 text-green-400 text-sm">
                          <CheckCircle className="h-4 w-4" />
                          Enabled
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-slate-500 text-sm">
                          <AlertCircle className="h-4 w-4" />
                          Disabled
                        </span>
                      )}
                    </div>

                    <div className="space-y-1 text-sm">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500">Endpoint:</span>
                        <span className="text-white font-mono">{setting.endpoint_url}</span>
                      </div>
                      {setting.protocol && (
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500">Protocol:</span>
                          <span className="text-white uppercase">{setting.protocol}</span>
                        </div>
                      )}
                      <div className="flex items-center gap-4 mt-2">
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={setting.export_on_scan_complete}
                            disabled
                            className="w-4 h-4 rounded border-dark-border bg-dark-surface text-primary"
                          />
                          <span className="text-slate-400">Export on scan complete</span>
                        </label>
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={setting.export_on_critical_vuln}
                            disabled
                            className="w-4 h-4 rounded border-dark-border bg-dark-surface text-primary"
                          />
                          <span className="text-slate-400">Export critical vulnerabilities</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleTestConnection(setting.id)}
                      disabled={testing === setting.id}
                    >
                      {testing === setting.id ? (
                        <LoadingSpinner />
                      ) : (
                        <TestTube className="h-4 w-4" />
                      )}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setEditingSettings(setting)}>
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleDelete(setting.id)}>
                      <Trash2 className="h-4 w-4 text-red-400" />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Manual Export Card */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Upload className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-semibold text-white">Manual Export</h3>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={loadScans}
            disabled={loadingScans}
          >
            {loadingScans ? (
              <LoadingSpinner />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
          </Button>
        </div>

        {settings.filter(s => s.enabled).length === 0 ? (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-amber-200">
              <p className="font-medium mb-1">No Enabled Integrations</p>
              <p>Enable at least one SIEM integration above before exporting scan results.</p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-slate-400">
              Manually export scan results to all enabled SIEM integrations.
            </p>
            <div className="flex gap-3">
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                className="flex-1 bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                disabled={loadingScans || exporting}
              >
                <option value="">Select a completed scan...</option>
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.name} - {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString()}
                  </option>
                ))}
              </select>
              <Button
                variant="primary"
                onClick={handleExportScan}
                disabled={!selectedScanId || exporting || loadingScans}
              >
                {exporting ? (
                  <>
                    <LoadingSpinner />
                    <span className="ml-2">Exporting...</span>
                  </>
                ) : (
                  <>
                    <Upload className="h-4 w-4 mr-2" />
                    Export to SIEM
                  </>
                )}
              </Button>
            </div>
            {scans.length === 0 && !loadingScans && (
              <p className="text-sm text-slate-500">No completed scans available for export.</p>
            )}
            <div className="text-xs text-slate-500 mt-2">
              Export will send data to: {settings.filter(s => s.enabled).map(s => s.siem_type.toUpperCase()).join(', ')}
            </div>
          </div>
        )}
      </Card>

      {/* Info Card */}
      <Card>
        <h4 className="text-sm font-medium text-slate-300 mb-3">About SIEM Integration</h4>
        <div className="space-y-2 text-sm text-slate-400">
          <p>
            SIEM (Security Information and Event Management) integration allows HeroForge to automatically
            export scan results and vulnerability findings to your security monitoring platform.
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li><strong>Syslog:</strong> RFC 5424 compliant syslog over TCP/UDP</li>
            <li><strong>Splunk:</strong> Splunk HTTP Event Collector (HEC)</li>
            <li><strong>Elasticsearch:</strong> Direct indexing via Bulk API</li>
          </ul>
        </div>
      </Card>

      {/* Create/Edit Modal */}
      {(showCreateModal || editingSettings) && (
        <SiemConfigModal
          settings={editingSettings}
          onClose={() => {
            setShowCreateModal(false);
            setEditingSettings(null);
          }}
          onSave={() => {
            setShowCreateModal(false);
            setEditingSettings(null);
            loadSettings();
          }}
        />
      )}
    </div>
  );
};

interface SiemConfigModalProps {
  settings?: SiemSettingsType | null;
  onClose: () => void;
  onSave: () => void;
}

const SiemConfigModal: React.FC<SiemConfigModalProps> = ({ settings, onClose, onSave }) => {
  const [formData, setFormData] = useState({
    siem_type: settings?.siem_type || 'syslog' as 'syslog' | 'splunk' | 'elasticsearch',
    endpoint_url: settings?.endpoint_url || '',
    api_key: settings?.api_key || '',
    protocol: settings?.protocol || 'tcp',
    enabled: settings?.enabled ?? true,
    export_on_scan_complete: settings?.export_on_scan_complete ?? false,
    export_on_critical_vuln: settings?.export_on_critical_vuln ?? true,
  });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.endpoint_url) {
      toast.error('Endpoint URL is required');
      return;
    }

    if (formData.siem_type === 'splunk' && !formData.api_key) {
      toast.error('API key is required for Splunk HEC');
      return;
    }

    setSaving(true);
    try {
      if (settings) {
        // Update existing
        const updateData: UpdateSiemSettingsRequest = {
          endpoint_url: formData.endpoint_url,
          enabled: formData.enabled,
          export_on_scan_complete: formData.export_on_scan_complete,
          export_on_critical_vuln: formData.export_on_critical_vuln,
        };
        if (formData.api_key) updateData.api_key = formData.api_key;
        if (formData.siem_type === 'syslog') updateData.protocol = formData.protocol;

        await siemAPI.updateSettings(settings.id, updateData);
        toast.success('SIEM integration updated');
      } else {
        // Create new
        const createData: CreateSiemSettingsRequest = {
          siem_type: formData.siem_type,
          endpoint_url: formData.endpoint_url,
          enabled: formData.enabled,
          export_on_scan_complete: formData.export_on_scan_complete,
          export_on_critical_vuln: formData.export_on_critical_vuln,
        };
        if (formData.api_key) createData.api_key = formData.api_key;
        if (formData.siem_type === 'syslog') createData.protocol = formData.protocol;

        await siemAPI.createSettings(createData);
        toast.success('SIEM integration created');
      }
      onSave();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save SIEM integration');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-dark-surface border border-dark-border rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-dark-border">
          <h3 className="text-xl font-semibold text-white">
            {settings ? 'Edit' : 'Add'} SIEM Integration
          </h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* SIEM Type */}
          {!settings && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                SIEM Type
              </label>
              <select
                value={formData.siem_type}
                onChange={(e) => setFormData({ ...formData, siem_type: e.target.value as any })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              >
                <option value="syslog">Syslog (RFC 5424)</option>
                <option value="splunk">Splunk HEC</option>
                <option value="elasticsearch">Elasticsearch</option>
              </select>
            </div>
          )}

          {/* Endpoint URL */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Endpoint URL
            </label>
            <input
              type="text"
              value={formData.endpoint_url}
              onChange={(e) => setFormData({ ...formData, endpoint_url: e.target.value })}
              className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              placeholder={
                formData.siem_type === 'syslog' ? '192.168.1.100:514' :
                formData.siem_type === 'splunk' ? 'https://splunk.example.com:8088' :
                'https://elasticsearch.example.com:9200'
              }
            />
          </div>

          {/* Protocol (Syslog only) */}
          {formData.siem_type === 'syslog' && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Protocol
              </label>
              <select
                value={formData.protocol}
                onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
          )}

          {/* API Key */}
          {(formData.siem_type === 'splunk' || formData.siem_type === 'elasticsearch') && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                {formData.siem_type === 'splunk' ? 'HEC Token' : 'API Key'} {formData.siem_type === 'splunk' && <span className="text-red-400">*</span>}
              </label>
              <input
                type="password"
                value={formData.api_key}
                onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                placeholder={settings ? '(leave blank to keep current)' : ''}
              />
            </div>
          )}

          {/* Options */}
          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.enabled}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                className="w-4 h-4 rounded border-dark-border bg-dark-surface text-primary focus:ring-primary"
              />
              <span className="text-white">Enable this integration</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.export_on_scan_complete}
                onChange={(e) => setFormData({ ...formData, export_on_scan_complete: e.target.checked })}
                className="w-4 h-4 rounded border-dark-border bg-dark-surface text-primary focus:ring-primary"
              />
              <span className="text-white">Auto-export when scans complete</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.export_on_critical_vuln}
                onChange={(e) => setFormData({ ...formData, export_on_critical_vuln: e.target.checked })}
                className="w-4 h-4 rounded border-dark-border bg-dark-surface text-primary focus:ring-primary"
              />
              <span className="text-white">Auto-export critical vulnerabilities immediately</span>
            </label>
          </div>

          {/* Buttons */}
          <div className="flex justify-end gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={saving}>
              {saving ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-2">Saving...</span>
                </>
              ) : (
                <span>{settings ? 'Update' : 'Create'} Integration</span>
              )}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default SiemSettings;
