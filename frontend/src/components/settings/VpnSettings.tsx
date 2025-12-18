import React, { useState, useEffect, useRef } from 'react';
import { toast } from 'react-toastify';
import { vpnAPI } from '../../services/api';
import type { VpnConfig, VpnStatus, VpnType } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import {
  Wifi,
  WifiOff,
  Upload,
  Trash2,
  Play,
  Square,
  CheckCircle,
  AlertTriangle,
  Shield,
  Edit2,
  Star,
  Clock,
} from 'lucide-react';

interface UploadForm {
  name: string;
  vpnType: VpnType;
  username: string;
  password: string;
}

const VpnSettings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [configs, setConfigs] = useState<VpnConfig[]>([]);
  const [status, setStatus] = useState<VpnStatus | null>(null);
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [uploadForm, setUploadForm] = useState<UploadForm>({
    name: '',
    vpnType: 'openvpn',
    username: '',
    password: '',
  });
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [configsRes, statusRes] = await Promise.all([
        vpnAPI.getConfigs(),
        vpnAPI.getStatus(),
      ]);
      setConfigs(configsRes.data);
      setStatus(statusRes.data);
    } catch (error: any) {
      console.error('Failed to load VPN data:', error);
      toast.error('Failed to load VPN settings');
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Detect VPN type from extension
    const ext = file.name.split('.').pop()?.toLowerCase();
    let vpnType: VpnType = 'openvpn';
    if (ext === 'conf') {
      vpnType = 'wireguard';
    }

    setSelectedFile(file);
    setUploadForm({
      ...uploadForm,
      name: file.name.replace(/\.(ovpn|conf)$/i, ''),
      vpnType,
    });
    setShowUploadForm(true);
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toast.error('Please select a VPN config file');
      return;
    }
    if (!uploadForm.name.trim()) {
      toast.error('Please enter a name for the VPN config');
      return;
    }

    setUploading(true);
    try {
      // Read file as base64
      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = (reader.result as string).split(',')[1];

        try {
          await vpnAPI.uploadConfig({
            name: uploadForm.name.trim(),
            vpn_type: uploadForm.vpnType,
            config_data: base64,
            filename: selectedFile.name,
            username: uploadForm.username || undefined,
            password: uploadForm.password || undefined,
            set_as_default: false,
          });

          toast.success('VPN config uploaded successfully');
          setShowUploadForm(false);
          setSelectedFile(null);
          setUploadForm({ name: '', vpnType: 'openvpn', username: '', password: '' });
          if (fileInputRef.current) {
            fileInputRef.current.value = '';
          }
          await loadData();
        } catch (error: any) {
          console.error('Failed to upload VPN config:', error);
          toast.error(error.response?.data?.error || 'Failed to upload VPN config');
        }
      };
      reader.readAsDataURL(selectedFile);
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this VPN config?')) {
      return;
    }

    try {
      await vpnAPI.deleteConfig(id);
      toast.success('VPN config deleted');
      await loadData();
    } catch (error: any) {
      console.error('Failed to delete VPN config:', error);
      toast.error(error.response?.data?.error || 'Failed to delete VPN config');
    }
  };

  const handleTest = async (id: string) => {
    setTesting(id);
    try {
      const result = await vpnAPI.testConfig(id);
      if (result.data.success) {
        toast.success(`Connection successful! IP: ${result.data.assigned_ip || 'N/A'}`);
      } else {
        toast.error(result.data.message || 'Connection test failed');
      }
    } catch (error: any) {
      console.error('Failed to test VPN config:', error);
      toast.error(error.response?.data?.error || 'Connection test failed');
    } finally {
      setTesting(null);
    }
  };

  const handleConnect = async (id: string) => {
    setConnecting(true);
    try {
      await vpnAPI.connect({ config_id: id, connection_mode: 'persistent' });
      toast.success('VPN connected');
      await loadData();
    } catch (error: any) {
      console.error('Failed to connect VPN:', error);
      toast.error(error.response?.data?.error || 'Failed to connect');
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      await vpnAPI.disconnect();
      toast.success('VPN disconnected');
      await loadData();
    } catch (error: any) {
      console.error('Failed to disconnect VPN:', error);
      toast.error(error.response?.data?.error || 'Failed to disconnect');
    } finally {
      setDisconnecting(false);
    }
  };

  const handleSetDefault = async (id: string) => {
    try {
      await vpnAPI.updateConfig(id, { is_default: true });
      toast.success('Default VPN config updated');
      await loadData();
    } catch (error: any) {
      console.error('Failed to set default:', error);
      toast.error(error.response?.data?.error || 'Failed to set default');
    }
  };

  const handleSaveEdit = async (id: string) => {
    if (!editName.trim()) {
      toast.error('Name cannot be empty');
      return;
    }

    try {
      await vpnAPI.updateConfig(id, { name: editName.trim() });
      toast.success('VPN config updated');
      setEditingId(null);
      await loadData();
    } catch (error: any) {
      console.error('Failed to update config:', error);
      toast.error(error.response?.data?.error || 'Failed to update');
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
    <div className="space-y-6">
      {/* Connection Status */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            {status?.connected ? (
              <Wifi className="h-6 w-6 text-green-500" />
            ) : (
              <WifiOff className="h-6 w-6 text-slate-400" />
            )}
            <div>
              <h3 className="text-lg font-semibold text-white">VPN Status</h3>
              <p className="text-sm text-slate-400">
                {status?.connected
                  ? `Connected to ${status.config_name}`
                  : 'Not connected'}
              </p>
            </div>
          </div>
          {status?.connected && (
            <Button
              onClick={handleDisconnect}
              disabled={disconnecting}
              variant="danger"
              className="flex items-center gap-2"
            >
              <Square className="h-4 w-4" />
              {disconnecting ? 'Disconnecting...' : 'Disconnect'}
            </Button>
          )}
        </div>

        {status?.connected && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-dark-hover rounded-lg">
            <div>
              <p className="text-xs text-slate-500 uppercase">Mode</p>
              <p className="text-sm text-white">
                {status.connection_mode === 'persistent' ? 'Persistent' : 'Per-Scan'}
              </p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase">Assigned IP</p>
              <p className="text-sm text-white font-mono">{status.assigned_ip || 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase">Interface</p>
              <p className="text-sm text-white font-mono">{status.interface_name || 'N/A'}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500 uppercase">Connected Since</p>
              <p className="text-sm text-white">
                {status.connected_since
                  ? new Date(status.connected_since).toLocaleString()
                  : 'N/A'}
              </p>
            </div>
          </div>
        )}
      </Card>

      {/* Upload New Config */}
      <Card>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-primary" />
            <h3 className="text-lg font-semibold text-white">VPN Configurations</h3>
          </div>
          <div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".ovpn,.conf"
              onChange={handleFileSelect}
              className="hidden"
            />
            <Button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-2"
            >
              <Upload className="h-4 w-4" />
              Upload Config
            </Button>
          </div>
        </div>

        {/* Upload Form */}
        {showUploadForm && (
          <div className="mb-6 p-4 bg-dark-hover rounded-lg border border-dark-border">
            <h4 className="text-md font-semibold text-white mb-4">
              Upload VPN Configuration
            </h4>
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-sm text-slate-400">
                <span>File:</span>
                <span className="text-white font-mono">{selectedFile?.name}</span>
                <span className="px-2 py-0.5 bg-primary/20 text-primary rounded text-xs uppercase">
                  {uploadForm.vpnType}
                </span>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Config Name <span className="text-red-500">*</span>
                </label>
                <Input
                  type="text"
                  placeholder="My VPN Connection"
                  value={uploadForm.name}
                  onChange={(e) => setUploadForm({ ...uploadForm, name: e.target.value })}
                />
              </div>

              {uploadForm.vpnType === 'openvpn' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Username (optional)
                    </label>
                    <Input
                      type="text"
                      placeholder="VPN username"
                      value={uploadForm.username}
                      onChange={(e) => setUploadForm({ ...uploadForm, username: e.target.value })}
                    />
                    <p className="mt-1 text-xs text-slate-500">
                      Required if your VPN requires authentication
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Password (optional)
                    </label>
                    <Input
                      type="password"
                      placeholder="VPN password"
                      value={uploadForm.password}
                      onChange={(e) => setUploadForm({ ...uploadForm, password: e.target.value })}
                    />
                  </div>
                </>
              )}

              <div className="flex gap-3">
                <Button onClick={handleUpload} disabled={uploading}>
                  {uploading ? 'Uploading...' : 'Upload'}
                </Button>
                <Button
                  onClick={() => {
                    setShowUploadForm(false);
                    setSelectedFile(null);
                    if (fileInputRef.current) {
                      fileInputRef.current.value = '';
                    }
                  }}
                  variant="secondary"
                >
                  Cancel
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Config List */}
        {configs.length === 0 ? (
          <div className="text-center py-8 text-slate-400">
            <WifiOff className="h-12 w-12 mx-auto mb-3 opacity-50" />
            <p>No VPN configurations yet</p>
            <p className="text-sm">Upload an OpenVPN (.ovpn) or WireGuard (.conf) file to get started</p>
          </div>
        ) : (
          <div className="space-y-3">
            {configs.map((config) => (
              <div
                key={config.id}
                className="p-4 bg-dark-hover rounded-lg border border-dark-border flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`p-2 rounded-lg ${
                      config.vpn_type === 'openvpn'
                        ? 'bg-orange-500/20 text-orange-400'
                        : 'bg-blue-500/20 text-blue-400'
                    }`}
                  >
                    <Shield className="h-5 w-5" />
                  </div>
                  <div>
                    {editingId === config.id ? (
                      <div className="flex items-center gap-2">
                        <Input
                          type="text"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                          className="w-48"
                          autoFocus
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSaveEdit(config.id);
                            if (e.key === 'Escape') setEditingId(null);
                          }}
                        />
                        <Button size="sm" onClick={() => handleSaveEdit(config.id)}>
                          Save
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => setEditingId(null)}
                        >
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="text-white font-medium">{config.name}</span>
                        {config.is_default && (
                          <Star className="h-4 w-4 text-yellow-400 fill-yellow-400" />
                        )}
                        <span className="px-2 py-0.5 bg-slate-700 text-slate-300 rounded text-xs uppercase">
                          {config.vpn_type}
                        </span>
                        {status?.connected && status.config_id === config.id && (
                          <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">
                            Connected
                          </span>
                        )}
                      </div>
                    )}
                    <div className="flex items-center gap-4 text-xs text-slate-500 mt-1">
                      {config.requires_credentials && (
                        <span className={config.has_credentials ? 'text-green-400' : 'text-yellow-400'}>
                          {config.has_credentials ? 'Credentials saved' : 'Credentials required'}
                        </span>
                      )}
                      {config.last_used_at && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          Last used: {new Date(config.last_used_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {editingId !== config.id && (
                    <>
                      {!config.is_default && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleSetDefault(config.id)}
                          title="Set as default"
                        >
                          <Star className="h-4 w-4" />
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditingId(config.id);
                          setEditName(config.name);
                        }}
                        title="Edit"
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleTest(config.id)}
                        disabled={testing === config.id}
                        title="Test connection"
                      >
                        {testing === config.id ? (
                          <LoadingSpinner size="sm" />
                        ) : (
                          <CheckCircle className="h-4 w-4" />
                        )}
                      </Button>
                      {!status?.connected || status.config_id !== config.id ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => handleConnect(config.id)}
                          disabled={connecting || status?.connected}
                          title="Connect"
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                      ) : null}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDelete(config.id)}
                        className="text-red-400 hover:text-red-300"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Help Section */}
      <Card>
        <h4 className="text-md font-semibold text-white mb-4">How to Use VPN Integration</h4>
        <div className="space-y-3 text-sm text-slate-400">
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">1</span>
            </div>
            <p>Upload your OpenVPN (.ovpn) or WireGuard (.conf) configuration file.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">2</span>
            </div>
            <p>
              If your VPN requires credentials, enter them during upload. They are stored
              encrypted.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">3</span>
            </div>
            <p>
              Test your connection to verify it works before using it for scans.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-primary/20 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-primary font-semibold text-xs">4</span>
            </div>
            <p>
              When creating a scan, select a VPN config to route the scan through that VPN.
              The VPN connects before the scan starts and disconnects when it completes.
            </p>
          </div>
        </div>

        <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-yellow-200">
              <p className="font-medium">Security Note</p>
              <p className="text-yellow-300/80 mt-1">
                VPN credentials are encrypted using AES-256-GCM. Config files containing
                dangerous options (scripts, hooks) are rejected. Only use VPN configurations
                from trusted sources.
              </p>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default VpnSettings;
