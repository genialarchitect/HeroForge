import React, { useState, useEffect } from 'react';
import {
  Wifi,
  Camera,
  Thermometer,
  Speaker,
  Lock,
  Unlock,
  AlertTriangle,
  RefreshCw,
  Search,
  Shield,
  Play,
  Eye,
  Key,
  Globe,
  Activity
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';

// Types
interface IotDevice {
  id: string;
  name?: string;
  device_type: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  ip_address?: string;
  mac_address?: string;
  hostname?: string;
  protocols: string[];
  open_ports: number[];
  default_creds_status: 'vulnerable' | 'changed' | 'unknown';
  risk_score: number;
  last_seen?: string;
}

interface IotScan {
  id: string;
  name: string;
  scan_type: string;
  target_range?: string;
  status: string;
  devices_found: number;
  vulnerabilities_found: number;
  started_at?: string;
  completed_at?: string;
}

interface DefaultCredential {
  device_type: string;
  vendor?: string;
  model?: string;
  protocol: string;
  username: string;
  password: string;
}

// Mock API
const iotAPI = {
  getDevices: async (): Promise<IotDevice[]> => {
    return [
      { id: '1', name: 'Front Door Camera', device_type: 'camera', vendor: 'Hikvision', model: 'DS-2CD2143G2-I', firmware_version: '5.7.1', ip_address: '192.168.1.100', mac_address: 'AA:BB:CC:DD:EE:01', protocols: ['rtsp', 'http'], open_ports: [80, 554, 8000], default_creds_status: 'vulnerable', risk_score: 85, last_seen: new Date().toISOString() },
      { id: '2', name: 'Living Room Thermostat', device_type: 'thermostat', vendor: 'Nest', model: 'Learning Thermostat', firmware_version: '6.2', ip_address: '192.168.1.101', mac_address: 'AA:BB:CC:DD:EE:02', protocols: ['http', 'mqtt'], open_ports: [80, 443], default_creds_status: 'changed', risk_score: 25, last_seen: new Date().toISOString() },
      { id: '3', name: 'Smart Speaker', device_type: 'speaker', vendor: 'Amazon', model: 'Echo Dot', ip_address: '192.168.1.102', mac_address: 'AA:BB:CC:DD:EE:03', protocols: ['http', 'mqtt'], open_ports: [443], default_creds_status: 'changed', risk_score: 20, last_seen: new Date().toISOString() },
      { id: '4', name: 'Smart Hub', device_type: 'hub', vendor: 'Samsung', model: 'SmartThings Hub', ip_address: '192.168.1.103', mac_address: 'AA:BB:CC:DD:EE:04', protocols: ['http', 'zigbee', 'zwave'], open_ports: [80, 443, 8080], default_creds_status: 'unknown', risk_score: 45, last_seen: new Date().toISOString() },
      { id: '5', name: 'IP Camera 2', device_type: 'camera', vendor: 'Dahua', model: 'IPC-HDW2431T', ip_address: '192.168.1.104', mac_address: 'AA:BB:CC:DD:EE:05', protocols: ['rtsp', 'http', 'onvif'], open_ports: [80, 554, 37777], default_creds_status: 'vulnerable', risk_score: 90, last_seen: new Date().toISOString() },
      { id: '6', name: 'Motion Sensor', device_type: 'sensor', vendor: 'Philips', model: 'Hue Motion', ip_address: '192.168.1.105', mac_address: 'AA:BB:CC:DD:EE:06', protocols: ['zigbee'], open_ports: [], default_creds_status: 'changed', risk_score: 15, last_seen: new Date().toISOString() },
    ];
  },
  getScans: async (): Promise<IotScan[]> => {
    return [
      { id: '1', name: 'Network Discovery', scan_type: 'discovery', target_range: '192.168.1.0/24', status: 'completed', devices_found: 12, vulnerabilities_found: 4, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      { id: '2', name: 'Credential Check', scan_type: 'credential', target_range: '192.168.1.0/24', status: 'running', devices_found: 6, vulnerabilities_found: 2, started_at: new Date().toISOString() },
    ];
  },
  searchCredentials: async (query: string): Promise<DefaultCredential[]> => {
    const allCreds: DefaultCredential[] = [
      { device_type: 'camera', vendor: 'Hikvision', protocol: 'http', username: 'admin', password: 'admin' },
      { device_type: 'camera', vendor: 'Hikvision', protocol: 'http', username: 'admin', password: '12345' },
      { device_type: 'camera', vendor: 'Dahua', protocol: 'http', username: 'admin', password: 'admin' },
      { device_type: 'camera', vendor: 'Axis', protocol: 'http', username: 'root', password: 'pass' },
      { device_type: 'router', vendor: 'TP-Link', protocol: 'http', username: 'admin', password: 'admin' },
      { device_type: 'router', vendor: 'Netgear', protocol: 'http', username: 'admin', password: 'password' },
      { device_type: 'thermostat', vendor: 'Generic', protocol: 'http', username: 'admin', password: '1234' },
      { device_type: 'hub', vendor: 'Generic', protocol: 'http', username: 'admin', password: 'admin' },
    ];
    return allCreds.filter(c =>
      c.device_type.toLowerCase().includes(query.toLowerCase()) ||
      c.vendor?.toLowerCase().includes(query.toLowerCase())
    );
  },
  startScan: async (scan: Partial<IotScan>): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 500));
  }
};

const IotSecurityPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'devices' | 'scans' | 'credentials'>('devices');
  const [devices, setDevices] = useState<IotDevice[]>([]);
  const [scans, setScans] = useState<IotScan[]>([]);
  const [credentials, setCredentials] = useState<DefaultCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [credSearchTerm, setCredSearchTerm] = useState('');
  const [selectedDevice, setSelectedDevice] = useState<IotDevice | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (activeTab === 'credentials' && credSearchTerm) {
      searchCredentials();
    }
  }, [credSearchTerm]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [devicesData, scansData] = await Promise.all([
        iotAPI.getDevices(),
        iotAPI.getScans()
      ]);
      setDevices(devicesData);
      setScans(scansData);
    } catch (error) {
      toast.error('Failed to load IoT data');
    } finally {
      setLoading(false);
    }
  };

  const searchCredentials = async () => {
    try {
      const results = await iotAPI.searchCredentials(credSearchTerm);
      setCredentials(results);
    } catch (error) {
      toast.error('Failed to search credentials');
    }
  };

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'camera': return <Camera className="h-5 w-5" />;
      case 'thermostat': return <Thermometer className="h-5 w-5" />;
      case 'speaker': return <Speaker className="h-5 w-5" />;
      case 'hub': return <Globe className="h-5 w-5" />;
      case 'sensor': return <Activity className="h-5 w-5" />;
      default: return <Wifi className="h-5 w-5" />;
    }
  };

  const getCredStatusIcon = (status: string) => {
    switch (status) {
      case 'vulnerable': return <Unlock className="h-5 w-5 text-red-400" />;
      case 'changed': return <Lock className="h-5 w-5 text-green-400" />;
      default: return <Key className="h-5 w-5 text-yellow-400" />;
    }
  };

  const getCredStatusText = (status: string) => {
    switch (status) {
      case 'vulnerable': return 'Default Credentials';
      case 'changed': return 'Secured';
      default: return 'Unknown';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const filteredDevices = devices.filter(device =>
    device.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.vendor?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.ip_address?.includes(searchTerm) ||
    device.device_type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const vulnerableDevices = devices.filter(d => d.default_creds_status === 'vulnerable');

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Wifi className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">IoT Security</h1>
              <p className="text-gray-400">Discover and assess IoT device security</p>
            </div>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500">
            <Play className="h-4 w-4" />
            Start IoT Scan
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-white">{devices.length}</div>
            <div className="text-gray-400 text-sm">IoT Devices</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-red-400">{vulnerableDevices.length}</div>
            <div className="text-gray-400 text-sm">Default Creds</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {devices.filter(d => d.risk_score >= 70).length}
            </div>
            <div className="text-gray-400 text-sm">High Risk</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-cyan-400">
              {new Set(devices.flatMap(d => d.protocols)).size}
            </div>
            <div className="text-gray-400 text-sm">Protocols</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-green-400">
              {devices.filter(d => d.default_creds_status === 'changed').length}
            </div>
            <div className="text-gray-400 text-sm">Secured</div>
          </div>
        </div>

        {/* Vulnerable Devices Alert */}
        {vulnerableDevices.length > 0 && (
          <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-6 w-6 text-red-400" />
              <div>
                <h3 className="text-red-400 font-medium">
                  {vulnerableDevices.length} device(s) using default credentials
                </h3>
                <p className="text-red-300/70 text-sm mt-1">
                  These devices are vulnerable to unauthorized access. Change their default passwords immediately.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-gray-700">
          {['devices', 'scans', 'credentials'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={`px-4 py-2 font-medium capitalize ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab === 'credentials' ? 'Default Credentials' : tab}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Devices Tab */}
            {activeTab === 'devices' && (
              <div>
                <div className="flex items-center gap-4 mb-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search devices..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                    />
                  </div>
                </div>

                <div className="grid gap-4">
                  {filteredDevices.map((device) => (
                    <div
                      key={device.id}
                      className="bg-gray-800 rounded-lg p-4 cursor-pointer hover:bg-gray-750"
                      onClick={() => setSelectedDevice(device)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="p-2 bg-gray-700 rounded-lg text-cyan-400">
                            {getDeviceIcon(device.device_type)}
                          </div>
                          <div>
                            <h3 className="text-white font-medium flex items-center gap-2">
                              {device.name || 'Unknown Device'}
                              {getCredStatusIcon(device.default_creds_status)}
                            </h3>
                            <div className="text-gray-400 text-sm">
                              {device.vendor} {device.model} • {device.ip_address}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-6">
                          <div className="flex gap-1">
                            {device.protocols.slice(0, 3).map((protocol) => (
                              <span
                                key={protocol}
                                className="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded"
                              >
                                {protocol.toUpperCase()}
                              </span>
                            ))}
                          </div>
                          <div className="text-right">
                            <div className={`text-lg font-bold ${getRiskColor(device.risk_score)}`}>
                              {device.risk_score}
                            </div>
                            <div className="text-gray-400 text-xs">Risk Score</div>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-4 mt-3 text-sm">
                        <span className={`px-2 py-1 rounded text-xs ${
                          device.default_creds_status === 'vulnerable' ? 'bg-red-600 text-white' :
                          device.default_creds_status === 'changed' ? 'bg-green-600 text-white' :
                          'bg-yellow-600 text-white'
                        }`}>
                          {getCredStatusText(device.default_creds_status)}
                        </span>
                        <span className="text-gray-400">
                          Ports: {device.open_ports.length > 0 ? device.open_ports.join(', ') : 'None'}
                        </span>
                        <span className="text-gray-400 capitalize">{device.device_type}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Scans Tab */}
            {activeTab === 'scans' && (
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="px-4 py-3 text-left text-gray-300">Name</th>
                      <th className="px-4 py-3 text-left text-gray-300">Type</th>
                      <th className="px-4 py-3 text-left text-gray-300">Target</th>
                      <th className="px-4 py-3 text-left text-gray-300">Status</th>
                      <th className="px-4 py-3 text-left text-gray-300">Results</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
                      <tr key={scan.id} className="border-t border-gray-700 hover:bg-gray-750">
                        <td className="px-4 py-3 text-white">{scan.name}</td>
                        <td className="px-4 py-3 text-gray-300 capitalize">{scan.scan_type}</td>
                        <td className="px-4 py-3">
                          <code className="text-gray-300 bg-gray-700 px-2 py-1 rounded text-sm">
                            {scan.target_range}
                          </code>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs ${
                            scan.status === 'completed' ? 'bg-green-600 text-white' :
                            scan.status === 'running' ? 'bg-cyan-600 text-white' :
                            'bg-gray-600 text-gray-300'
                          }`}>
                            {scan.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <span className="text-white">{scan.devices_found} devices</span>
                          {scan.vulnerabilities_found > 0 && (
                            <span className="text-red-400 ml-2">{scan.vulnerabilities_found} vulns</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Credentials Tab */}
            {activeTab === 'credentials' && (
              <div>
                <div className="flex items-center gap-4 mb-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search by device type or vendor..."
                      value={credSearchTerm}
                      onChange={(e) => setCredSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                    />
                  </div>
                </div>

                {credentials.length > 0 ? (
                  <div className="bg-gray-800 rounded-lg overflow-hidden">
                    <table className="w-full">
                      <thead className="bg-gray-700">
                        <tr>
                          <th className="px-4 py-3 text-left text-gray-300">Device Type</th>
                          <th className="px-4 py-3 text-left text-gray-300">Vendor</th>
                          <th className="px-4 py-3 text-left text-gray-300">Protocol</th>
                          <th className="px-4 py-3 text-left text-gray-300">Username</th>
                          <th className="px-4 py-3 text-left text-gray-300">Password</th>
                        </tr>
                      </thead>
                      <tbody>
                        {credentials.map((cred, idx) => (
                          <tr key={idx} className="border-t border-gray-700 hover:bg-gray-750">
                            <td className="px-4 py-3 text-white capitalize">{cred.device_type}</td>
                            <td className="px-4 py-3 text-gray-300">{cred.vendor || '-'}</td>
                            <td className="px-4 py-3 text-gray-300 uppercase">{cred.protocol}</td>
                            <td className="px-4 py-3">
                              <code className="text-cyan-400 bg-gray-700 px-2 py-1 rounded">{cred.username}</code>
                            </td>
                            <td className="px-4 py-3">
                              <code className="text-yellow-400 bg-gray-700 px-2 py-1 rounded">{cred.password}</code>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="bg-gray-800 rounded-lg p-8 text-center">
                    <Key className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                    <h3 className="text-white text-lg font-medium">Search Default Credentials</h3>
                    <p className="text-gray-400 mt-2">
                      Enter a device type or vendor name to search our database of known default credentials
                    </p>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Device Detail Modal */}
        {selectedDevice && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedDevice(null)}>
            <div className="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gray-700 rounded-lg text-cyan-400">
                    {getDeviceIcon(selectedDevice.device_type)}
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white">{selectedDevice.name || 'Unknown Device'}</h2>
                    <p className="text-gray-400">{selectedDevice.vendor} {selectedDevice.model}</p>
                  </div>
                </div>
                <button onClick={() => setSelectedDevice(null)} className="text-gray-400 hover:text-white text-2xl">
                  ×
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="text-gray-400 text-sm">IP Address</div>
                  <div className="text-white">{selectedDevice.ip_address}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">MAC Address</div>
                  <div className="text-white">{selectedDevice.mac_address}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Device Type</div>
                  <div className="text-white capitalize">{selectedDevice.device_type}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Firmware</div>
                  <div className="text-white">{selectedDevice.firmware_version || 'Unknown'}</div>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-gray-400 text-sm mb-2">Credential Status</div>
                <div className={`flex items-center gap-2 p-3 rounded ${
                  selectedDevice.default_creds_status === 'vulnerable' ? 'bg-red-900/30 border border-red-700' :
                  selectedDevice.default_creds_status === 'changed' ? 'bg-green-900/30 border border-green-700' :
                  'bg-yellow-900/30 border border-yellow-700'
                }`}>
                  {getCredStatusIcon(selectedDevice.default_creds_status)}
                  <span className={
                    selectedDevice.default_creds_status === 'vulnerable' ? 'text-red-400' :
                    selectedDevice.default_creds_status === 'changed' ? 'text-green-400' :
                    'text-yellow-400'
                  }>
                    {getCredStatusText(selectedDevice.default_creds_status)}
                  </span>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-gray-400 text-sm mb-2">Open Ports</div>
                <div className="flex flex-wrap gap-2">
                  {selectedDevice.open_ports.length > 0 ? (
                    selectedDevice.open_ports.map((port) => (
                      <span key={port} className="px-3 py-1 bg-gray-700 text-white rounded">
                        {port}
                      </span>
                    ))
                  ) : (
                    <span className="text-gray-500">No open ports detected</span>
                  )}
                </div>
              </div>

              <div>
                <div className="text-gray-400 text-sm mb-2">Protocols</div>
                <div className="flex flex-wrap gap-2">
                  {selectedDevice.protocols.map((p) => (
                    <span key={p} className="px-3 py-1 bg-cyan-600 text-white rounded">
                      {p.toUpperCase()}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default IotSecurityPage;
