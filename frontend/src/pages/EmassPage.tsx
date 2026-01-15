import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Building2,
  Shield,
  RefreshCw,
  Link2,
  Settings,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  FileText,
  Upload,
  Download,
  Search,
  Filter,
  ChevronRight,
  ChevronDown,
  Calendar,
  Users,
  Target,
  ClipboardList,
  Eye,
  Edit2,
} from 'lucide-react';
import api from '../services/api';
import Layout from '../components/layout/Layout';
import AcasNavigation from '../components/navigation/AcasNavigation';

// Types
interface EmassSystem {
  system_id: number;
  system_name: string;
  acronym?: string;
  system_type: string;
  authorization_status: string;
  mission_criticality?: string;
  created_at?: string;
}

interface EmassControl {
  control_id: string;
  acronym: string;
  name: string;
  compliance_status: string;
  implementation_status: string;
  responsible_entities?: string;
  last_assessment_date?: string;
}

interface EmassPoam {
  poam_id: number;
  control_id: string;
  office_org: string;
  weakness_description: string;
  poc_name: string;
  status: string;
  scheduled_completion_date?: string;
  milestones?: EmassPoamMilestone[];
}

interface EmassPoamMilestone {
  milestone_id: number;
  description: string;
  scheduled_date: string;
  status: string;
}

interface EmassArtifact {
  artifact_id: number;
  filename: string;
  type: string;
  category: string;
  uploaded_at: string;
}

interface SyncStatus {
  last_sync: string;
  status: string;
  systems_synced: number;
  controls_synced: number;
  poams_synced: number;
}

// API functions
const emassAPI = {
  getConfig: () => api.get('/api/emass/config').then((r) => r.data),
  updateConfig: (data: any) => api.put('/api/emass/config', data).then((r) => r.data),
  testConnection: () => api.post('/api/emass/test').then((r) => r.data),
  listSystems: () => api.get<EmassSystem[]>('/api/emass/systems').then((r) => r.data),
  getSystem: (id: number) => api.get<EmassSystem>(`/api/emass/systems/${id}`).then((r) => r.data),
  listControls: (systemId: number) =>
    api.get<EmassControl[]>(`/api/emass/systems/${systemId}/controls`).then((r) => r.data),
  syncControls: (systemId: number) =>
    api.post(`/api/emass/systems/${systemId}/controls/sync`).then((r) => r.data),
  listPoams: (systemId: number) =>
    api.get<EmassPoam[]>(`/api/emass/systems/${systemId}/poams`).then((r) => r.data),
  createPoam: (systemId: number, data: any) =>
    api.post(`/api/emass/systems/${systemId}/poams`, data).then((r) => r.data),
  updatePoam: (systemId: number, poamId: number, data: any) =>
    api.put(`/api/emass/systems/${systemId}/poams/${poamId}`, data).then((r) => r.data),
  uploadArtifact: (systemId: number, data: FormData) =>
    api.post(`/api/emass/systems/${systemId}/artifacts`, data).then((r) => r.data),
  fullSync: (systemId: number) =>
    api.post(`/api/emass/systems/${systemId}/sync`).then((r) => r.data),
  getSyncStatus: () => api.get<SyncStatus>('/api/emass/sync-status').then((r) => r.data),
};

// Status badge
const StatusBadge: React.FC<{ status: string; type?: 'auth' | 'compliance' | 'poam' }> = ({ status, type }) => {
  const configs: Record<string, { bg: string; icon: React.ReactNode }> = {
    // Authorization status
    authorized: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    'authorized to operate': { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    conditional: { bg: 'bg-amber-900/50 text-amber-400', icon: <AlertTriangle className="w-3 h-3" /> },
    'not authorized': { bg: 'bg-red-900/50 text-red-400', icon: <XCircle className="w-3 h-3" /> },
    pending: { bg: 'bg-gray-700 text-gray-300', icon: <Clock className="w-3 h-3" /> },
    // Compliance status
    compliant: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    'non-compliant': { bg: 'bg-red-900/50 text-red-400', icon: <XCircle className="w-3 h-3" /> },
    'not applicable': { bg: 'bg-gray-600 text-gray-400', icon: null },
    // POA&M status
    open: { bg: 'bg-amber-900/50 text-amber-400', icon: <AlertTriangle className="w-3 h-3" /> },
    closed: { bg: 'bg-green-900/50 text-green-400', icon: <CheckCircle className="w-3 h-3" /> },
    delayed: { bg: 'bg-red-900/50 text-red-400', icon: <Clock className="w-3 h-3" /> },
  };
  const key = status.toLowerCase();
  const config = configs[key] || { bg: 'bg-gray-700', icon: null };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${config.bg}`}>
      {config.icon}
      {status}
    </span>
  );
};

// Config modal
const ConfigModal: React.FC<{ isOpen: boolean; onClose: () => void; onSuccess: () => void }> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [apiKey, setApiKey] = useState('');
  const [userUid, setUserUid] = useState('');
  const [certPath, setCertPath] = useState('');
  const [keyPath, setKeyPath] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await emassAPI.updateConfig({
        api_key: apiKey,
        user_uid: userUid,
        cert_path: certPath,
        key_path: keyPath,
      });
      toast.success('eMASS configuration saved');
      onSuccess();
      onClose();
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    try {
      await emassAPI.testConnection();
      toast.success('Connection successful!');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Connection failed');
    } finally {
      setTesting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg">
        <h2 className="text-xl font-semibold text-gray-100 mb-4">eMASS Configuration</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">User UID</label>
            <input
              type="text"
              value={userUid}
              onChange={(e) => setUserUid(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">PKI Certificate Path</label>
            <input
              type="text"
              value={certPath}
              onChange={(e) => setCertPath(e.target.value)}
              placeholder="/path/to/cert.pem"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">PKI Key Path</label>
            <input
              type="text"
              value={keyPath}
              onChange={(e) => setKeyPath(e.target.value)}
              placeholder="/path/to/key.pem"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex justify-between pt-4">
            <button
              onClick={handleTest}
              disabled={testing}
              className="px-4 py-2 bg-gray-600 text-gray-200 rounded hover:bg-gray-500 disabled:opacity-50"
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <div className="flex gap-2">
              <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-gray-200">
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// System detail panel
const SystemDetailPanel: React.FC<{
  system: EmassSystem | null;
  onClose: () => void;
}> = ({ system, onClose }) => {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'controls' | 'poams'>('controls');

  const { data: controls = [] } = useQuery({
    queryKey: ['emass-controls', system?.system_id],
    queryFn: () => (system ? emassAPI.listControls(system.system_id) : Promise.resolve([])),
    enabled: !!system,
  });

  const { data: poams = [] } = useQuery({
    queryKey: ['emass-poams', system?.system_id],
    queryFn: () => (system ? emassAPI.listPoams(system.system_id) : Promise.resolve([])),
    enabled: !!system && activeTab === 'poams',
  });

  const syncMutation = useMutation({
    mutationFn: () => system ? emassAPI.fullSync(system.system_id) : Promise.reject(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['emass-controls'] });
      queryClient.invalidateQueries({ queryKey: ['emass-poams'] });
      toast.success('Sync complete');
    },
    onError: () => toast.error('Sync failed'),
  });

  if (!system) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-[500px] bg-gray-800 border-l border-gray-700 shadow-xl z-40 overflow-y-auto">
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-100">{system.system_name}</h2>
            {system.acronym && <p className="text-sm text-gray-400">{system.acronym}</p>}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <div className="flex items-center gap-2 mt-2">
          <StatusBadge status={system.authorization_status} type="auth" />
          {system.mission_criticality && (
            <span className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
              {system.mission_criticality}
            </span>
          )}
        </div>
      </div>

      <div className="p-4">
        <button
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
          {syncMutation.isPending ? 'Syncing...' : 'Sync with eMASS'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-700 px-4">
        <button
          onClick={() => setActiveTab('controls')}
          className={`px-4 py-2 text-sm ${
            activeTab === 'controls'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Controls ({controls.length})
        </button>
        <button
          onClick={() => setActiveTab('poams')}
          className={`px-4 py-2 text-sm ${
            activeTab === 'poams'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          POA&Ms ({poams.length})
        </button>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        {activeTab === 'controls' && (
          <>
            {controls.length === 0 ? (
              <p className="text-center text-gray-400 py-8">No controls synced</p>
            ) : (
              controls.slice(0, 20).map((ctrl) => (
                <div key={ctrl.control_id} className="p-3 bg-gray-700 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-200 font-medium">{ctrl.acronym}</span>
                    <StatusBadge status={ctrl.compliance_status} type="compliance" />
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{ctrl.name}</p>
                </div>
              ))
            )}
          </>
        )}

        {activeTab === 'poams' && (
          <>
            {poams.length === 0 ? (
              <p className="text-center text-gray-400 py-8">No POA&Ms found</p>
            ) : (
              poams.map((poam) => (
                <div key={poam.poam_id} className="p-3 bg-gray-700 rounded">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-200 font-medium">POA&M #{poam.poam_id}</span>
                    <StatusBadge status={poam.status} type="poam" />
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{poam.control_id}</p>
                  <p className="text-sm text-gray-300 mt-2 line-clamp-2">{poam.weakness_description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <span>POC: {poam.poc_name}</span>
                    {poam.scheduled_completion_date && (
                      <span>Due: {new Date(poam.scheduled_completion_date).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </>
        )}
      </div>
    </div>
  );
};

// Main component
const EmassPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [showConfig, setShowConfig] = useState(false);
  const [selectedSystem, setSelectedSystem] = useState<EmassSystem | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const { data: systems = [], isLoading } = useQuery({
    queryKey: ['emass-systems'],
    queryFn: emassAPI.listSystems,
  });

  const { data: syncStatus } = useQuery({
    queryKey: ['emass-sync-status'],
    queryFn: emassAPI.getSyncStatus,
    refetchInterval: 60000,
  });

  const filteredSystems = systems.filter(
    (s) =>
      s.system_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.acronym?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <Layout>
    <div className="space-y-6">
      {/* ACAS Navigation */}
      <AcasNavigation />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Building2 className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-100">eMASS Integration</h1>
            <p className="text-sm text-gray-400">
              Enterprise Mission Assurance Support Service integration for RMF compliance
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowConfig(true)}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 text-gray-200 rounded hover:bg-gray-600"
        >
          <Settings className="w-4 h-4" />
          Configure
        </button>
      </div>

      {/* Sync Status Card */}
      {syncStatus && (
        <div className="bg-gray-800 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`p-2 rounded-full ${
              syncStatus.status === 'success' ? 'bg-green-900/50' : 'bg-amber-900/50'
            }`}>
              {syncStatus.status === 'success' ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-amber-400" />
              )}
            </div>
            <div>
              <p className="text-gray-200">Last Sync: {new Date(syncStatus.last_sync).toLocaleString()}</p>
              <p className="text-sm text-gray-400">
                {syncStatus.systems_synced} systems, {syncStatus.controls_synced} controls, {syncStatus.poams_synced} POA&Ms
              </p>
            </div>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 text-white rounded hover:bg-cyan-500">
            <RefreshCw className="w-4 h-4" />
            Full Sync
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-gray-100">{systems.length}</div>
          <div className="text-sm text-gray-400">Total Systems</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-green-400">
            {systems.filter((s) => s.authorization_status.toLowerCase().includes('authorized')).length}
          </div>
          <div className="text-sm text-gray-400">Authorized</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-amber-400">
            {systems.filter((s) => s.authorization_status.toLowerCase().includes('conditional')).length}
          </div>
          <div className="text-sm text-gray-400">Conditional</div>
        </div>
        <div className="bg-gray-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-red-400">
            {systems.filter((s) => s.authorization_status.toLowerCase().includes('not')).length}
          </div>
          <div className="text-sm text-gray-400">Not Authorized</div>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search systems..."
          className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded text-gray-200 focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* System List */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-400">Loading systems...</div>
      ) : filteredSystems.length === 0 ? (
        <div className="text-center py-12">
          <Building2 className="w-12 h-12 mx-auto mb-4 text-gray-600" />
          <p className="text-gray-400">No systems found</p>
          <p className="text-sm text-gray-500 mt-1">Configure eMASS connection and sync systems</p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-900">
              <tr>
                <th className="px-4 py-3 text-left text-sm text-gray-400">System</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Acronym</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Type</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Authorization</th>
                <th className="px-4 py-3 text-left text-sm text-gray-400">Criticality</th>
                <th className="px-4 py-3 text-right text-sm text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {filteredSystems.map((sys) => (
                <tr
                  key={sys.system_id}
                  className="hover:bg-gray-700/50 cursor-pointer"
                  onClick={() => setSelectedSystem(sys)}
                >
                  <td className="px-4 py-3 text-gray-200">{sys.system_name}</td>
                  <td className="px-4 py-3 text-gray-400">{sys.acronym || '-'}</td>
                  <td className="px-4 py-3 text-gray-400">{sys.system_type}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={sys.authorization_status} type="auth" />
                  </td>
                  <td className="px-4 py-3 text-gray-400">{sys.mission_criticality || '-'}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedSystem(sys);
                        }}
                        className="p-2 text-gray-400 hover:text-cyan-400 rounded"
                        title="View Details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Config Modal */}
      <ConfigModal
        isOpen={showConfig}
        onClose={() => setShowConfig(false)}
        onSuccess={() => queryClient.invalidateQueries({ queryKey: ['emass-systems'] })}
      />

      {/* System Detail Panel */}
      <SystemDetailPanel system={selectedSystem} onClose={() => setSelectedSystem(null)} />
    </div>
    </Layout>
  );
};

export default EmassPage;
