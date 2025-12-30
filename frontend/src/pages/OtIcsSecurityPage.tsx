import React, { useState, useEffect } from 'react';
import {
  Factory,
  Cpu,
  Network,
  AlertTriangle,
  RefreshCw,
  Plus,
  Search,
  Shield,
  Layers,
  Activity,
  Settings,
  Eye,
  Play,
  MapPin
} from 'lucide-react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';

// Types
interface OtAsset {
  id: string;
  name: string;
  asset_type: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  ip_address?: string;
  protocols: string[];
  purdue_level: number;
  zone?: string;
  criticality: string;
  risk_score: number;
  vulnerabilities: string[];
  last_seen?: string;
}

interface OtProtocol {
  id: string;
  asset_id: string;
  protocol_type: string;
  port: number;
  security_issues: string[];
}

interface OtScan {
  id: string;
  name: string;
  scan_type: string;
  target_range: string;
  protocols_enabled: string[];
  status: string;
  assets_discovered: number;
  vulnerabilities_found: number;
  started_at?: string;
  completed_at?: string;
}

// Purdue Model levels
const PURDUE_LEVELS = [
  { level: 5, name: 'Enterprise Network', color: 'bg-blue-600' },
  { level: 4, name: 'Business Network', color: 'bg-blue-500' },
  { level: 3.5, name: 'DMZ', color: 'bg-purple-600' },
  { level: 3, name: 'Site Operations', color: 'bg-yellow-600' },
  { level: 2, name: 'Area Control', color: 'bg-orange-600' },
  { level: 1, name: 'Basic Control', color: 'bg-red-500' },
  { level: 0, name: 'Process', color: 'bg-red-700' },
];

// Mock API
const otAPI = {
  getAssets: async (): Promise<OtAsset[]> => {
    return [
      { id: '1', name: 'Siemens S7-1500 PLC', asset_type: 'plc', vendor: 'Siemens', model: 'S7-1500', firmware_version: '2.9.4', ip_address: '10.10.1.10', protocols: ['s7', 'modbus'], purdue_level: 1, zone: 'Production Line 1', criticality: 'critical', risk_score: 75, vulnerabilities: ['CVE-2023-28489'], last_seen: new Date().toISOString() },
      { id: '2', name: 'Allen-Bradley HMI', asset_type: 'hmi', vendor: 'Rockwell', model: 'PanelView Plus 7', firmware_version: '12.011', ip_address: '10.10.1.20', protocols: ['ethernetip', 'cip'], purdue_level: 2, zone: 'Production Line 1', criticality: 'high', risk_score: 45, vulnerabilities: [], last_seen: new Date().toISOString() },
      { id: '3', name: 'Schneider SCADA', asset_type: 'scada', vendor: 'Schneider Electric', model: 'ClearSCADA', ip_address: '10.10.2.10', protocols: ['dnp3', 'modbus'], purdue_level: 3, zone: 'Control Room', criticality: 'critical', risk_score: 60, vulnerabilities: ['CVE-2022-45789'], last_seen: new Date().toISOString() },
      { id: '4', name: 'Historian Server', asset_type: 'historian', vendor: 'OSIsoft', model: 'PI Server', ip_address: '10.10.3.10', protocols: ['pi-sdk'], purdue_level: 3, zone: 'Control Room', criticality: 'high', risk_score: 30, vulnerabilities: [], last_seen: new Date().toISOString() },
      { id: '5', name: 'RTU-001', asset_type: 'rtu', vendor: 'ABB', model: 'RTU560', firmware_version: '13.5.2', ip_address: '10.10.4.10', protocols: ['dnp3', 'iec104'], purdue_level: 1, zone: 'Remote Site 1', criticality: 'high', risk_score: 55, vulnerabilities: [], last_seen: new Date().toISOString() },
    ];
  },
  getScans: async (): Promise<OtScan[]> => {
    return [
      { id: '1', name: 'Weekly Discovery', scan_type: 'discovery', target_range: '10.10.0.0/16', protocols_enabled: ['modbus', 's7', 'dnp3'], status: 'completed', assets_discovered: 23, vulnerabilities_found: 5, started_at: new Date().toISOString(), completed_at: new Date().toISOString() },
      { id: '2', name: 'Protocol Analysis', scan_type: 'protocol', target_range: '10.10.1.0/24', protocols_enabled: ['modbus'], status: 'running', assets_discovered: 8, vulnerabilities_found: 2, started_at: new Date().toISOString() },
    ];
  },
  startScan: async (scan: Partial<OtScan>): Promise<void> => {
    await new Promise(resolve => setTimeout(resolve, 500));
  }
};

const OtIcsSecurityPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'assets' | 'purdue' | 'protocols' | 'scans'>('assets');
  const [assets, setAssets] = useState<OtAsset[]>([]);
  const [scans, setScans] = useState<OtScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAsset, setSelectedAsset] = useState<OtAsset | null>(null);
  const [showScanModal, setShowScanModal] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [assetsData, scansData] = await Promise.all([
        otAPI.getAssets(),
        otAPI.getScans()
      ]);
      setAssets(assetsData);
      setScans(scansData);
    } catch (error) {
      toast.error('Failed to load OT/ICS data');
    } finally {
      setLoading(false);
    }
  };

  const getAssetTypeIcon = (type: string) => {
    switch (type) {
      case 'plc': return <Cpu className="h-5 w-5" />;
      case 'hmi': return <Activity className="h-5 w-5" />;
      case 'scada': return <Network className="h-5 w-5" />;
      case 'rtu': return <Factory className="h-5 w-5" />;
      case 'historian': return <Layers className="h-5 w-5" />;
      default: return <Settings className="h-5 w-5" />;
    }
  };

  const getCriticalityColor = (criticality: string) => {
    switch (criticality) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-600';
      case 'medium': return 'bg-yellow-600';
      case 'low': return 'bg-green-600';
      default: return 'bg-gray-600';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getProtocolColor = (protocol: string) => {
    const colors: Record<string, string> = {
      modbus: 'bg-blue-600',
      s7: 'bg-purple-600',
      dnp3: 'bg-orange-600',
      ethernetip: 'bg-green-600',
      bacnet: 'bg-cyan-600',
      opcua: 'bg-yellow-600',
    };
    return colors[protocol.toLowerCase()] || 'bg-gray-600';
  };

  const filteredAssets = assets.filter(asset =>
    asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.vendor?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.ip_address?.includes(searchTerm)
  );

  const assetsByLevel = PURDUE_LEVELS.map(level => ({
    ...level,
    assets: assets.filter(a => a.purdue_level === level.level)
  }));

  return (
    <Layout>
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Factory className="h-8 w-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">OT/ICS Security</h1>
              <p className="text-gray-400">Industrial Control Systems monitoring and security</p>
            </div>
          </div>
          <button
            onClick={() => setShowScanModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-500"
          >
            <Play className="h-4 w-4" />
            Start OT Scan
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-white">{assets.length}</div>
            <div className="text-gray-400 text-sm">OT Assets</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-red-400">
              {assets.filter(a => a.criticality === 'critical').length}
            </div>
            <div className="text-gray-400 text-sm">Critical Assets</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {assets.reduce((sum, a) => sum + a.vulnerabilities.length, 0)}
            </div>
            <div className="text-gray-400 text-sm">Vulnerabilities</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-cyan-400">
              {new Set(assets.flatMap(a => a.protocols)).size}
            </div>
            <div className="text-gray-400 text-sm">Protocols</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="text-2xl font-bold text-white">
              {scans.filter(s => s.status === 'running').length}
            </div>
            <div className="text-gray-400 text-sm">Active Scans</div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-gray-700">
          {['assets', 'purdue', 'protocols', 'scans'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab as typeof activeTab)}
              className={`px-4 py-2 font-medium capitalize ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab === 'purdue' ? 'Purdue Model' : tab}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Assets Tab */}
            {activeTab === 'assets' && (
              <div>
                <div className="flex items-center gap-4 mb-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search assets..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white"
                    />
                  </div>
                </div>

                <div className="grid gap-4">
                  {filteredAssets.map((asset) => (
                    <div
                      key={asset.id}
                      className="bg-gray-800 rounded-lg p-4 cursor-pointer hover:bg-gray-750"
                      onClick={() => setSelectedAsset(asset)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="p-2 bg-gray-700 rounded-lg text-cyan-400">
                            {getAssetTypeIcon(asset.asset_type)}
                          </div>
                          <div>
                            <h3 className="text-white font-medium flex items-center gap-2">
                              {asset.name}
                              <span className={`px-2 py-0.5 text-xs rounded text-white ${getCriticalityColor(asset.criticality)}`}>
                                {asset.criticality}
                              </span>
                            </h3>
                            <div className="text-gray-400 text-sm">
                              {asset.vendor} {asset.model} • {asset.ip_address}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-6">
                          <div className="flex gap-1">
                            {asset.protocols.map((protocol) => (
                              <span
                                key={protocol}
                                className={`px-2 py-1 text-xs text-white rounded ${getProtocolColor(protocol)}`}
                              >
                                {protocol.toUpperCase()}
                              </span>
                            ))}
                          </div>
                          <div className="text-right">
                            <div className={`text-lg font-bold ${getRiskColor(asset.risk_score)}`}>
                              {asset.risk_score}
                            </div>
                            <div className="text-gray-400 text-xs">Risk Score</div>
                          </div>
                          {asset.vulnerabilities.length > 0 && (
                            <div className="flex items-center gap-1 text-red-400">
                              <AlertTriangle className="h-4 w-4" />
                              <span>{asset.vulnerabilities.length}</span>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-4 mt-3 text-sm text-gray-400">
                        <span className="flex items-center gap-1">
                          <Layers className="h-3 w-3" />
                          Level {asset.purdue_level}
                        </span>
                        <span className="flex items-center gap-1">
                          <MapPin className="h-3 w-3" />
                          {asset.zone || 'Unknown'}
                        </span>
                        {asset.firmware_version && (
                          <span>FW: {asset.firmware_version}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Purdue Model Tab */}
            {activeTab === 'purdue' && (
              <div className="space-y-4">
                {assetsByLevel.map((level) => (
                  <div key={level.level} className="bg-gray-800 rounded-lg overflow-hidden">
                    <div className={`${level.color} px-4 py-3 flex items-center justify-between`}>
                      <div className="flex items-center gap-3">
                        <span className="text-white font-bold">Level {level.level}</span>
                        <span className="text-white/80">{level.name}</span>
                      </div>
                      <span className="text-white/80">{level.assets.length} assets</span>
                    </div>
                    {level.assets.length > 0 && (
                      <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-4">
                        {level.assets.map((asset) => (
                          <div
                            key={asset.id}
                            className="bg-gray-700 rounded-lg p-3 cursor-pointer hover:bg-gray-600"
                            onClick={() => setSelectedAsset(asset)}
                          >
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-cyan-400">{getAssetTypeIcon(asset.asset_type)}</span>
                              <span className="text-white text-sm font-medium truncate">{asset.name}</span>
                            </div>
                            <div className="text-gray-400 text-xs">{asset.ip_address}</div>
                            <div className="flex gap-1 mt-2">
                              {asset.protocols.slice(0, 2).map((p) => (
                                <span key={p} className="text-xs text-gray-300 bg-gray-600 px-1 rounded">
                                  {p}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    {level.assets.length === 0 && (
                      <div className="p-4 text-gray-500 text-center text-sm">
                        No assets at this level
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Protocols Tab */}
            {activeTab === 'protocols' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {['Modbus', 'S7', 'DNP3', 'EtherNet/IP', 'BACnet', 'OPC-UA', 'IEC 61850', 'IEC 104'].map((protocol) => {
                  const protocolAssets = assets.filter(a =>
                    a.protocols.some(p => p.toLowerCase() === protocol.toLowerCase().replace('/', '').replace(' ', ''))
                  );
                  return (
                    <div key={protocol} className="bg-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-white font-medium">{protocol}</h3>
                        <span className="text-gray-400 text-sm">{protocolAssets.length} devices</span>
                      </div>
                      <div className="space-y-2">
                        {protocolAssets.slice(0, 3).map((asset) => (
                          <div key={asset.id} className="flex items-center justify-between text-sm">
                            <span className="text-gray-300">{asset.name}</span>
                            <span className="text-gray-500">{asset.ip_address}</span>
                          </div>
                        ))}
                        {protocolAssets.length > 3 && (
                          <div className="text-cyan-400 text-sm">
                            +{protocolAssets.length - 3} more
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
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
                      <th className="px-4 py-3 text-left text-gray-300">Protocols</th>
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
                          <div className="flex gap-1">
                            {scan.protocols_enabled.map((p) => (
                              <span key={p} className={`px-2 py-0.5 text-xs text-white rounded ${getProtocolColor(p)}`}>
                                {p}
                              </span>
                            ))}
                          </div>
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
                          <span className="text-white">{scan.assets_discovered} assets</span>
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
          </>
        )}

        {/* Asset Detail Modal */}
        {selectedAsset && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedAsset(null)}>
            <div className="bg-gray-800 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gray-700 rounded-lg text-cyan-400">
                    {getAssetTypeIcon(selectedAsset.asset_type)}
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white">{selectedAsset.name}</h2>
                    <p className="text-gray-400">{selectedAsset.vendor} {selectedAsset.model}</p>
                  </div>
                </div>
                <button onClick={() => setSelectedAsset(null)} className="text-gray-400 hover:text-white">
                  ×
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div className="text-gray-400 text-sm">IP Address</div>
                  <div className="text-white">{selectedAsset.ip_address}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Firmware</div>
                  <div className="text-white">{selectedAsset.firmware_version || 'Unknown'}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Purdue Level</div>
                  <div className="text-white">Level {selectedAsset.purdue_level}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Zone</div>
                  <div className="text-white">{selectedAsset.zone || 'Unknown'}</div>
                </div>
              </div>

              <div className="mb-4">
                <div className="text-gray-400 text-sm mb-2">Protocols</div>
                <div className="flex gap-2">
                  {selectedAsset.protocols.map((p) => (
                    <span key={p} className={`px-3 py-1 text-white rounded ${getProtocolColor(p)}`}>
                      {p.toUpperCase()}
                    </span>
                  ))}
                </div>
              </div>

              {selectedAsset.vulnerabilities.length > 0 && (
                <div>
                  <div className="text-gray-400 text-sm mb-2">Vulnerabilities</div>
                  <div className="space-y-2">
                    {selectedAsset.vulnerabilities.map((vuln) => (
                      <div key={vuln} className="flex items-center gap-2 bg-red-600/20 border border-red-600/40 rounded p-2">
                        <AlertTriangle className="h-4 w-4 text-red-400" />
                        <span className="text-red-400">{vuln}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default OtIcsSecurityPage;
