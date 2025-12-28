import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Database,
  Server,
  Globe,
  Users,
  FileText,
  Search,
  Plus,
  RefreshCw,
  Trash2,
  Edit,
  Eye,
  X,
  Check,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Shield,
  Target,
  Activity,
  Link2,
  Upload,
  Download,
  Play,
  Zap,
  Filter,
  Hash,
  MapPin,
  Briefcase,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Copy,
  BarChart3,
} from 'lucide-react';
import Layout from '../components/layout/Layout';
import {
  extendedThreatIntelAPI,
  MispServer,
  MispEvent,
  TaxiiServer,
  TaxiiCollection,
  StixBundle,
  StixObject,
  ThreatActorSummary,
  ThreatActorDetail,
  ThreatIntelStats,
} from '../services/api';

type TabType = 'dashboard' | 'misp' | 'taxii' | 'stix' | 'actors' | 'correlate';

// ============================================================================
// Main Component
// ============================================================================

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');

  const tabs = [
    { id: 'dashboard' as TabType, label: 'Dashboard', icon: BarChart3 },
    { id: 'misp' as TabType, label: 'MISP', icon: Database },
    { id: 'taxii' as TabType, label: 'TAXII', icon: Server },
    { id: 'stix' as TabType, label: 'STIX Objects', icon: FileText },
    { id: 'actors' as TabType, label: 'Threat Actors', icon: Users },
    { id: 'correlate' as TabType, label: 'IOC Correlation', icon: Zap },
  ];

  return (
    <Layout>
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="h-7 w-7 text-cyan-400" />
              Threat Intelligence
            </h1>
            <p className="text-gray-400 mt-1">
              Manage MISP, TAXII feeds, STIX objects, and threat actor intelligence
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex space-x-1 mb-6 bg-gray-800 rounded-lg p-1 w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'dashboard' && <DashboardTab />}
        {activeTab === 'misp' && <MispTab />}
        {activeTab === 'taxii' && <TaxiiTab />}
        {activeTab === 'stix' && <StixTab />}
        {activeTab === 'actors' && <ThreatActorsTab />}
        {activeTab === 'correlate' && <CorrelationTab />}
      </div>
    </Layout>
  );
}

// ============================================================================
// Dashboard Tab
// ============================================================================

function DashboardTab() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['threat-intel-stats'],
    queryFn: () => extendedThreatIntelAPI.getStats(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  const statCards = [
    { label: 'MISP Servers', value: stats?.data?.misp_servers || 0, icon: Database, color: 'cyan' },
    { label: 'MISP Events', value: stats?.data?.misp_events || 0, icon: FileText, color: 'blue' },
    { label: 'MISP Attributes', value: stats?.data?.misp_attributes || 0, icon: Hash, color: 'purple' },
    { label: 'TAXII Servers', value: stats?.data?.taxii_servers || 0, icon: Server, color: 'green' },
    { label: 'TAXII Collections', value: stats?.data?.taxii_collections || 0, icon: Globe, color: 'yellow' },
    { label: 'STIX Bundles', value: stats?.data?.stix_bundles || 0, icon: FileText, color: 'orange' },
    { label: 'STIX Objects', value: stats?.data?.stix_objects || 0, icon: Activity, color: 'red' },
    { label: 'Threat Actors', value: stats?.data?.threat_actors || 0, icon: Users, color: 'pink' },
    { label: 'Campaigns', value: stats?.data?.campaigns || 0, icon: Target, color: 'indigo' },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {statCards.map((card) => (
        <div key={card.label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <card.icon className={`h-5 w-5 text-${card.color}-400`} />
            <span className="text-2xl font-bold text-white">{card.value}</span>
          </div>
          <p className="text-sm text-gray-400">{card.label}</p>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// MISP Tab
// ============================================================================

function MispTab() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedServer, setSelectedServer] = useState<MispServer | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<MispEvent | null>(null);

  const { data: servers, isLoading: loadingServers } = useQuery({
    queryKey: ['misp-servers'],
    queryFn: () => extendedThreatIntelAPI.listMispServers(),
  });

  const { data: events, isLoading: loadingEvents } = useQuery({
    queryKey: ['misp-events'],
    queryFn: () => extendedThreatIntelAPI.listMispEvents({ limit: 50 }),
  });

  const addServerMutation = useMutation({
    mutationFn: (data: { name: string; url: string; api_key: string }) =>
      extendedThreatIntelAPI.addMispServer(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['misp-servers'] });
      setShowAddModal(false);
      toast.success('MISP server added successfully');
    },
    onError: () => toast.error('Failed to add MISP server'),
  });

  const deleteServerMutation = useMutation({
    mutationFn: (id: string) => extendedThreatIntelAPI.deleteMispServer(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['misp-servers'] });
      toast.success('MISP server deleted');
    },
    onError: () => toast.error('Failed to delete MISP server'),
  });

  const testServerMutation = useMutation({
    mutationFn: (id: string) => extendedThreatIntelAPI.testMispServer(id),
    onSuccess: (response) => {
      if (response.data.success) {
        toast.success('Connection successful');
      } else {
        toast.error(response.data.message || 'Connection failed');
      }
    },
    onError: () => toast.error('Connection test failed'),
  });

  const syncServerMutation = useMutation({
    mutationFn: (id: string) => extendedThreatIntelAPI.syncMispServer(id),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['misp-servers'] });
      queryClient.invalidateQueries({ queryKey: ['misp-events'] });
      if (response.data.success) {
        toast.success(`Synced ${response.data.events_synced || 0} events`);
      } else {
        toast.error(response.data.message || 'Sync failed');
      }
    },
    onError: () => toast.error('Sync failed'),
  });

  return (
    <div className="space-y-6">
      {/* Servers Section */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Database className="h-5 w-5 text-cyan-400" />
            MISP Servers
          </h2>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
          >
            <Plus className="h-4 w-4" />
            Add Server
          </button>
        </div>
        <div className="p-4">
          {loadingServers ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
          ) : !servers?.data?.length ? (
            <p className="text-gray-400 text-center py-8">No MISP servers configured</p>
          ) : (
            <div className="space-y-3">
              {servers.data.map((server) => (
                <div
                  key={server.id}
                  className="flex items-center justify-between p-3 bg-gray-900 rounded-lg"
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-3 h-3 rounded-full ${
                        server.enabled ? 'bg-green-400' : 'bg-gray-500'
                      }`}
                    />
                    <div>
                      <p className="text-white font-medium">{server.name}</p>
                      <p className="text-gray-400 text-sm">{server.url}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right text-sm">
                      <p className="text-gray-400">Events: {server.events_synced}</p>
                      {server.last_sync_at && (
                        <p className="text-gray-500 text-xs">
                          Last sync: {new Date(server.last_sync_at).toLocaleString()}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => testServerMutation.mutate(server.id)}
                        className="p-1.5 text-gray-400 hover:text-cyan-400"
                        title="Test Connection"
                      >
                        <Zap className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => syncServerMutation.mutate(server.id)}
                        className="p-1.5 text-gray-400 hover:text-green-400"
                        title="Sync Events"
                      >
                        <RefreshCw className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setSelectedServer(server)}
                        className="p-1.5 text-gray-400 hover:text-blue-400"
                        title="View Details"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteServerMutation.mutate(server.id)}
                        className="p-1.5 text-gray-400 hover:text-red-400"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Events Section */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-cyan-400" />
            Recent MISP Events
          </h2>
        </div>
        <div className="overflow-x-auto">
          {loadingEvents ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
          ) : !events?.data?.length ? (
            <p className="text-gray-400 text-center py-8">No events synced yet</p>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                  <th className="p-3">Event</th>
                  <th className="p-3">Organization</th>
                  <th className="p-3">Threat Level</th>
                  <th className="p-3">Attributes</th>
                  <th className="p-3">Date</th>
                  <th className="p-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {events.data.map((event) => (
                  <tr key={event.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                    <td className="p-3">
                      <div>
                        <p className="text-white font-medium truncate max-w-md">
                          {event.info}
                        </p>
                        <p className="text-gray-500 text-xs">{event.misp_uuid}</p>
                      </div>
                    </td>
                    <td className="p-3 text-gray-300">{event.org_name}</td>
                    <td className="p-3">
                      <ThreatLevelBadge level={event.threat_level} />
                    </td>
                    <td className="p-3 text-gray-300">{event.attribute_count}</td>
                    <td className="p-3 text-gray-400 text-sm">{event.date}</td>
                    <td className="p-3">
                      <button
                        onClick={() => setSelectedEvent(event)}
                        className="p-1.5 text-gray-400 hover:text-cyan-400"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Add Server Modal */}
      {showAddModal && (
        <AddMispServerModal
          onClose={() => setShowAddModal(false)}
          onSubmit={(data) => addServerMutation.mutate(data)}
          isLoading={addServerMutation.isPending}
        />
      )}

      {/* Event Detail Modal */}
      {selectedEvent && (
        <MispEventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}

function ThreatLevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    '1': 'bg-red-900 text-red-300',
    '2': 'bg-orange-900 text-orange-300',
    '3': 'bg-yellow-900 text-yellow-300',
    '4': 'bg-gray-700 text-gray-300',
  };
  const labels: Record<string, string> = {
    '1': 'High',
    '2': 'Medium',
    '3': 'Low',
    '4': 'Undefined',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${colors[level] || colors['4']}`}>
      {labels[level] || 'Unknown'}
    </span>
  );
}

function AddMispServerModal({
  onClose,
  onSubmit,
  isLoading,
}: {
  onClose: () => void;
  onSubmit: (data: { name: string; url: string; api_key: string }) => void;
  isLoading: boolean;
}) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [apiKey, setApiKey] = useState('');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-md border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Add MISP Server</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Server Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="My MISP Server"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">URL</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="https://misp.example.com"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="MISP API Key"
            />
          </div>
        </div>
        <div className="p-4 border-t border-gray-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-white"
          >
            Cancel
          </button>
          <button
            onClick={() => onSubmit({ name, url, api_key: apiKey })}
            disabled={isLoading || !name || !url || !apiKey}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
          >
            {isLoading ? 'Adding...' : 'Add Server'}
          </button>
        </div>
      </div>
    </div>
  );
}

function MispEventDetailModal({
  event,
  onClose,
}: {
  event: MispEvent;
  onClose: () => void;
}) {
  const { data: attributes } = useQuery({
    queryKey: ['misp-event-attributes', event.id],
    queryFn: () => extendedThreatIntelAPI.getMispEventAttributes(event.id),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-4xl max-h-[80vh] overflow-hidden border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">{event.info}</h3>
            <p className="text-gray-400 text-sm">{event.misp_uuid}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto max-h-[60vh]">
          <div className="grid grid-cols-2 gap-4 mb-6">
            <div>
              <p className="text-gray-400 text-sm">Organization</p>
              <p className="text-white">{event.org_name}</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Date</p>
              <p className="text-white">{event.date}</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Threat Level</p>
              <ThreatLevelBadge level={event.threat_level} />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Published</p>
              <p className="text-white">{event.published ? 'Yes' : 'No'}</p>
            </div>
          </div>

          {event.tags.length > 0 && (
            <div className="mb-6">
              <p className="text-gray-400 text-sm mb-2">Tags</p>
              <div className="flex flex-wrap gap-2">
                {event.tags.map((tag, i) => (
                  <span key={i} className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="text-gray-400 text-sm mb-2">Attributes ({event.attribute_count})</p>
            {attributes?.data?.length ? (
              <div className="space-y-2">
                {attributes.data.slice(0, 20).map((attr) => (
                  <div key={attr.id} className="flex items-center gap-3 p-2 bg-gray-900 rounded">
                    <span className="px-2 py-0.5 bg-cyan-900 text-cyan-300 rounded text-xs">
                      {attr.attr_type}
                    </span>
                    <span className="text-gray-300 font-mono text-sm truncate">
                      {attr.value}
                    </span>
                    {attr.to_ids && (
                      <span className="px-2 py-0.5 bg-red-900 text-red-300 rounded text-xs">
                        IDS
                      </span>
                    )}
                  </div>
                ))}
                {attributes.data.length > 20 && (
                  <p className="text-gray-500 text-sm text-center">
                    And {attributes.data.length - 20} more...
                  </p>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-center py-4">Loading attributes...</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// TAXII Tab
// ============================================================================

function TaxiiTab() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [expandedServer, setExpandedServer] = useState<string | null>(null);

  const { data: servers, isLoading } = useQuery({
    queryKey: ['taxii-servers'],
    queryFn: () => extendedThreatIntelAPI.listTaxiiServers(),
  });

  const addServerMutation = useMutation({
    mutationFn: (data: { name: string; url: string; username?: string; password?: string; version?: string }) =>
      extendedThreatIntelAPI.addTaxiiServer(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['taxii-servers'] });
      setShowAddModal(false);
      toast.success('TAXII server added successfully');
    },
    onError: () => toast.error('Failed to add TAXII server'),
  });

  const deleteServerMutation = useMutation({
    mutationFn: (id: string) => extendedThreatIntelAPI.deleteTaxiiServer(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['taxii-servers'] });
      toast.success('TAXII server deleted');
    },
    onError: () => toast.error('Failed to delete TAXII server'),
  });

  const discoverMutation = useMutation({
    mutationFn: (id: string) => extendedThreatIntelAPI.discoverTaxiiCollections(id),
    onSuccess: (response, id) => {
      queryClient.invalidateQueries({ queryKey: ['taxii-collections', id] });
      if (response.data.success) {
        toast.success(`Discovered ${response.data.collections_found || 0} collections`);
      } else {
        toast.error('Discovery failed');
      }
    },
    onError: () => toast.error('Discovery failed'),
  });

  return (
    <div className="space-y-6">
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-400" />
            TAXII Servers
          </h2>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
          >
            <Plus className="h-4 w-4" />
            Add Server
          </button>
        </div>
        <div className="p-4">
          {isLoading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
          ) : !servers?.data?.length ? (
            <p className="text-gray-400 text-center py-8">No TAXII servers configured</p>
          ) : (
            <div className="space-y-3">
              {servers.data.map((server) => (
                <TaxiiServerCard
                  key={server.id}
                  server={server}
                  expanded={expandedServer === server.id}
                  onToggle={() =>
                    setExpandedServer(expandedServer === server.id ? null : server.id)
                  }
                  onDiscover={() => discoverMutation.mutate(server.id)}
                  onDelete={() => deleteServerMutation.mutate(server.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {showAddModal && (
        <AddTaxiiServerModal
          onClose={() => setShowAddModal(false)}
          onSubmit={(data) => addServerMutation.mutate(data)}
          isLoading={addServerMutation.isPending}
        />
      )}
    </div>
  );
}

function TaxiiServerCard({
  server,
  expanded,
  onToggle,
  onDiscover,
  onDelete,
}: {
  server: TaxiiServer;
  expanded: boolean;
  onToggle: () => void;
  onDiscover: () => void;
  onDelete: () => void;
}) {
  const queryClient = useQueryClient();

  const { data: collections } = useQuery({
    queryKey: ['taxii-collections', server.id],
    queryFn: () => extendedThreatIntelAPI.listTaxiiCollections(server.id),
    enabled: expanded,
  });

  const pollMutation = useMutation({
    mutationFn: (collectionId: string) =>
      extendedThreatIntelAPI.pollTaxiiCollection(server.id, collectionId),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['taxii-collections', server.id] });
      if (response.data.success) {
        toast.success(`Retrieved ${response.data.objects_retrieved || 0} objects`);
      }
    },
    onError: () => toast.error('Poll failed'),
  });

  return (
    <div className="bg-gray-900 rounded-lg overflow-hidden">
      <div
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-800"
        onClick={onToggle}
      >
        <div className="flex items-center gap-4">
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-gray-400" />
          ) : (
            <ChevronRight className="h-4 w-4 text-gray-400" />
          )}
          <div
            className={`w-3 h-3 rounded-full ${
              server.enabled ? 'bg-green-400' : 'bg-gray-500'
            }`}
          />
          <div>
            <p className="text-white font-medium">{server.name}</p>
            <p className="text-gray-400 text-sm">{server.url}</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-gray-500 bg-gray-700 px-2 py-1 rounded">
            TAXII {server.version}
          </span>
          <p className="text-gray-400 text-sm">Objects: {server.objects_synced}</p>
          <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={onDiscover}
              className="p-1.5 text-gray-400 hover:text-cyan-400"
              title="Discover Collections"
            >
              <Search className="h-4 w-4" />
            </button>
            <button
              onClick={onDelete}
              className="p-1.5 text-gray-400 hover:text-red-400"
              title="Delete"
            >
              <Trash2 className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-700 p-3">
          <p className="text-sm text-gray-400 mb-3">Collections</p>
          {!collections?.data?.length ? (
            <p className="text-gray-500 text-sm">
              No collections found. Click discover to fetch.
            </p>
          ) : (
            <div className="space-y-2">
              {collections.data.map((collection) => (
                <div
                  key={collection.id}
                  className="flex items-center justify-between p-2 bg-gray-800 rounded"
                >
                  <div>
                    <p className="text-white text-sm">{collection.title}</p>
                    <p className="text-gray-500 text-xs">{collection.collection_id}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-gray-400 text-xs">
                      {collection.objects_count} objects
                    </span>
                    {collection.can_read && (
                      <button
                        onClick={() => pollMutation.mutate(collection.collection_id)}
                        className="p-1.5 text-gray-400 hover:text-green-400"
                        title="Poll Collection"
                      >
                        <Download className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AddTaxiiServerModal({
  onClose,
  onSubmit,
  isLoading,
}: {
  onClose: () => void;
  onSubmit: (data: { name: string; url: string; username?: string; password?: string; version?: string }) => void;
  isLoading: boolean;
}) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [version, setVersion] = useState('2.1');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-md border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Add TAXII Server</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Server Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="CIRCL TAXII"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">URL</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="https://limo.anomali.com/api/v1/taxii2"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Version</label>
            <select
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
            >
              <option value="2.1">TAXII 2.1</option>
              <option value="2.0">TAXII 2.0</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Username (optional)</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Password (optional)</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
            />
          </div>
        </div>
        <div className="p-4 border-t border-gray-700 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-white">
            Cancel
          </button>
          <button
            onClick={() =>
              onSubmit({
                name,
                url,
                username: username || undefined,
                password: password || undefined,
                version,
              })
            }
            disabled={isLoading || !name || !url}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
          >
            {isLoading ? 'Adding...' : 'Add Server'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// STIX Tab
// ============================================================================

function StixTab() {
  const queryClient = useQueryClient();
  const [showImportModal, setShowImportModal] = useState(false);
  const [selectedBundle, setSelectedBundle] = useState<StixBundle | null>(null);
  const [typeFilter, setTypeFilter] = useState('');

  const { data: bundles, isLoading } = useQuery({
    queryKey: ['stix-bundles'],
    queryFn: () => extendedThreatIntelAPI.listStixBundles({ limit: 50 }),
  });

  const { data: objects } = useQuery({
    queryKey: ['stix-objects', typeFilter],
    queryFn: () =>
      extendedThreatIntelAPI.listStixObjects({ type: typeFilter || undefined, limit: 100 }),
  });

  const stixTypes = [
    'indicator',
    'malware',
    'threat-actor',
    'attack-pattern',
    'campaign',
    'identity',
    'tool',
    'vulnerability',
  ];

  return (
    <div className="space-y-6">
      {/* Bundles */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <FileText className="h-5 w-5 text-cyan-400" />
            STIX Bundles
          </h2>
          <button
            onClick={() => setShowImportModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm"
          >
            <Upload className="h-4 w-4" />
            Import Bundle
          </button>
        </div>
        <div className="p-4">
          {isLoading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
          ) : !bundles?.data?.length ? (
            <p className="text-gray-400 text-center py-8">No STIX bundles imported</p>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {bundles.data.map((bundle) => (
                <div
                  key={bundle.id}
                  className="p-4 bg-gray-900 rounded-lg cursor-pointer hover:bg-gray-700"
                  onClick={() => setSelectedBundle(bundle)}
                >
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="text-white font-medium">{bundle.name}</h3>
                    <span className="text-xs text-gray-500">{bundle.spec_version}</span>
                  </div>
                  <p className="text-gray-400 text-sm">Source: {bundle.source}</p>
                  <p className="text-gray-400 text-sm">{bundle.objects_count} objects</p>
                  <p className="text-gray-500 text-xs mt-2">
                    {new Date(bundle.created_at).toLocaleDateString()}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Objects */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            STIX Objects
          </h2>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-1.5 text-white text-sm"
          >
            <option value="">All Types</option>
            {stixTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                <th className="p-3">Type</th>
                <th className="p-3">Name</th>
                <th className="p-3">STIX ID</th>
                <th className="p-3">Created</th>
              </tr>
            </thead>
            <tbody>
              {objects?.data?.map((obj) => (
                <tr key={obj.id} className="border-b border-gray-700 hover:bg-gray-700/50">
                  <td className="p-3">
                    <span className="px-2 py-1 bg-cyan-900 text-cyan-300 rounded text-xs">
                      {obj.stix_type}
                    </span>
                  </td>
                  <td className="p-3 text-white">{obj.name || '-'}</td>
                  <td className="p-3 text-gray-400 font-mono text-xs truncate max-w-xs">
                    {obj.stix_id}
                  </td>
                  <td className="p-3 text-gray-400 text-sm">
                    {new Date(obj.created).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showImportModal && (
        <ImportStixModal
          onClose={() => setShowImportModal(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['stix-bundles'] });
            queryClient.invalidateQueries({ queryKey: ['stix-objects'] });
          }}
        />
      )}

      {selectedBundle && (
        <StixBundleDetailModal
          bundle={selectedBundle}
          onClose={() => setSelectedBundle(null)}
        />
      )}
    </div>
  );
}

function ImportStixModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState('');
  const [content, setContent] = useState('');

  const importMutation = useMutation({
    mutationFn: (data: { name: string; content: string }) =>
      extendedThreatIntelAPI.importStixBundle(data),
    onSuccess: (response) => {
      if (response.data.success) {
        toast.success(`Imported ${response.data.objects_imported || 0} objects`);
        onSuccess();
        onClose();
      } else {
        toast.error('Import failed');
      }
    },
    onError: () => toast.error('Import failed'),
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-2xl border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Import STIX Bundle</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Bundle Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              placeholder="My STIX Bundle"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">STIX 2.1 JSON</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="w-full h-64 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm"
              placeholder='{"type": "bundle", "id": "bundle--...", "objects": [...]}'
            />
          </div>
        </div>
        <div className="p-4 border-t border-gray-700 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-white">
            Cancel
          </button>
          <button
            onClick={() => importMutation.mutate({ name, content })}
            disabled={importMutation.isPending || !name || !content}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
          >
            {importMutation.isPending ? 'Importing...' : 'Import'}
          </button>
        </div>
      </div>
    </div>
  );
}

function StixBundleDetailModal({
  bundle,
  onClose,
}: {
  bundle: StixBundle;
  onClose: () => void;
}) {
  const { data: objects } = useQuery({
    queryKey: ['stix-bundle-objects', bundle.id],
    queryFn: () => extendedThreatIntelAPI.getStixBundleObjects(bundle.id, { limit: 100 }),
  });

  const objectsByType = objects?.data?.reduce(
    (acc, obj) => {
      acc[obj.stix_type] = (acc[obj.stix_type] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-4xl max-h-[80vh] overflow-hidden border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">{bundle.name}</h3>
            <p className="text-gray-400 text-sm">
              {bundle.objects_count} objects | STIX {bundle.spec_version}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto max-h-[60vh]">
          {objectsByType && (
            <div className="mb-6">
              <p className="text-gray-400 text-sm mb-2">Object Types</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(objectsByType).map(([type, count]) => (
                  <span
                    key={type}
                    className="px-3 py-1 bg-gray-700 rounded-full text-sm text-gray-300"
                  >
                    {type}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="text-gray-400 text-sm mb-2">Objects</p>
            <div className="space-y-2">
              {objects?.data?.slice(0, 50).map((obj) => (
                <div key={obj.id} className="p-3 bg-gray-900 rounded-lg">
                  <div className="flex items-center justify-between mb-1">
                    <span className="px-2 py-0.5 bg-cyan-900 text-cyan-300 rounded text-xs">
                      {obj.stix_type}
                    </span>
                    <span className="text-gray-500 text-xs">{obj.stix_id}</span>
                  </div>
                  {obj.name && <p className="text-white">{obj.name}</p>}
                  {obj.description && (
                    <p className="text-gray-400 text-sm mt-1 line-clamp-2">
                      {obj.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Threat Actors Tab
// ============================================================================

function ThreatActorsTab() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    actor_type: '',
    motivation: '',
    active_only: false,
  });

  const { data: actors, isLoading } = useQuery({
    queryKey: ['threat-actors', filters, searchQuery],
    queryFn: () =>
      extendedThreatIntelAPI.listThreatActors({
        ...filters,
        name: searchQuery || undefined,
        limit: 50,
      }),
  });

  const { data: actorDetail } = useQuery({
    queryKey: ['threat-actor', selectedActor],
    queryFn: () => extendedThreatIntelAPI.getThreatActor(selectedActor!),
    enabled: !!selectedActor,
  });

  const motivations = ['espionage', 'financial', 'destruction', 'hacktivism', 'unknown'];
  const actorTypes = ['nation-state', 'crime-syndicate', 'hacktivist', 'insider', 'terrorist'];

  return (
    <div className="flex gap-6">
      {/* Actor List */}
      <div className="flex-1 bg-gray-800 rounded-lg border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center gap-4 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search threat actors..."
                className="w-full bg-gray-900 border border-gray-600 rounded-lg pl-10 pr-3 py-2 text-white"
              />
            </div>
          </div>
          <div className="flex items-center gap-4">
            <select
              value={filters.actor_type}
              onChange={(e) => setFilters({ ...filters, actor_type: e.target.value })}
              className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-1.5 text-white text-sm"
            >
              <option value="">All Types</option>
              {actorTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <select
              value={filters.motivation}
              onChange={(e) => setFilters({ ...filters, motivation: e.target.value })}
              className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-1.5 text-white text-sm"
            >
              <option value="">All Motivations</option>
              {motivations.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-sm text-gray-400">
              <input
                type="checkbox"
                checked={filters.active_only}
                onChange={(e) => setFilters({ ...filters, active_only: e.target.checked })}
                className="rounded border-gray-600"
              />
              Active only
            </label>
          </div>
        </div>
        <div className="overflow-y-auto max-h-[600px]">
          {isLoading ? (
            <div className="flex justify-center py-8">
              <RefreshCw className="h-6 w-6 text-cyan-400 animate-spin" />
            </div>
          ) : !actors?.data?.length ? (
            <p className="text-gray-400 text-center py-8">No threat actors found</p>
          ) : (
            <div className="divide-y divide-gray-700">
              {actors.data.map((actor) => (
                <div
                  key={actor.id}
                  className={`p-4 cursor-pointer hover:bg-gray-700/50 ${
                    selectedActor === actor.id ? 'bg-gray-700' : ''
                  }`}
                  onClick={() => setSelectedActor(actor.id)}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-white font-medium">{actor.name}</h3>
                        {actor.active && (
                          <span className="px-1.5 py-0.5 bg-green-900 text-green-300 rounded text-xs">
                            Active
                          </span>
                        )}
                      </div>
                      {actor.aliases.length > 0 && (
                        <p className="text-gray-500 text-sm">
                          AKA: {actor.aliases.slice(0, 3).join(', ')}
                        </p>
                      )}
                    </div>
                    <SophisticationBadge level={actor.sophistication} />
                  </div>
                  <div className="flex items-center gap-4 mt-2 text-sm">
                    <span className="text-gray-400">{actor.actor_type}</span>
                    {actor.country && (
                      <span className="flex items-center gap-1 text-gray-400">
                        <MapPin className="h-3 w-3" />
                        {actor.country}
                      </span>
                    )}
                    <span className="text-gray-400">{actor.motivation}</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {actor.target_sectors.slice(0, 4).map((sector, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300"
                      >
                        {sector}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Actor Detail */}
      {selectedActor && actorDetail?.data && (
        <div className="w-96 bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">{actorDetail.data.name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="px-2 py-0.5 bg-cyan-900 text-cyan-300 rounded text-xs">
                {actorDetail.data.actor_type}
              </span>
              {actorDetail.data.country && (
                <span className="flex items-center gap-1 text-gray-400 text-sm">
                  <MapPin className="h-3 w-3" />
                  {actorDetail.data.country}
                </span>
              )}
            </div>
          </div>
          <div className="p-4 space-y-4 overflow-y-auto max-h-[500px]">
            {actorDetail.data.description && (
              <div>
                <p className="text-gray-400 text-sm mb-1">Description</p>
                <p className="text-gray-300 text-sm">{actorDetail.data.description}</p>
              </div>
            )}

            <div>
              <p className="text-gray-400 text-sm mb-1">Motivation</p>
              <p className="text-white">{actorDetail.data.motivation}</p>
            </div>

            {actorDetail.data.aliases.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">Aliases</p>
                <div className="flex flex-wrap gap-1">
                  {actorDetail.data.aliases.map((alias, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300"
                    >
                      {alias}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-gray-400 text-sm mb-1">Sophistication</p>
                <SophisticationBadge level={actorDetail.data.sophistication} />
              </div>
              <div>
                <p className="text-gray-400 text-sm mb-1">Resource Level</p>
                <SophisticationBadge level={actorDetail.data.resource_level} />
              </div>
            </div>

            {actorDetail.data.first_seen && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm mb-1">First Seen</p>
                  <p className="text-white text-sm">{actorDetail.data.first_seen}</p>
                </div>
                {actorDetail.data.last_seen && (
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Last Seen</p>
                    <p className="text-white text-sm">{actorDetail.data.last_seen}</p>
                  </div>
                )}
              </div>
            )}

            {actorDetail.data.target_sectors.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">Target Sectors</p>
                <div className="flex flex-wrap gap-1">
                  {actorDetail.data.target_sectors.map((sector, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-red-900 text-red-300 rounded text-xs"
                    >
                      {sector}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {actorDetail.data.ttps.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">TTPs (MITRE ATT&CK)</p>
                <div className="flex flex-wrap gap-1">
                  {actorDetail.data.ttps.slice(0, 10).map((ttp, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-purple-900 text-purple-300 rounded text-xs font-mono"
                    >
                      {ttp}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {actorDetail.data.tools.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">Tools</p>
                <div className="flex flex-wrap gap-1">
                  {actorDetail.data.tools.map((tool, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-blue-900 text-blue-300 rounded text-xs"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {actorDetail.data.malware.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">Malware</p>
                <div className="flex flex-wrap gap-1">
                  {actorDetail.data.malware.map((m, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-orange-900 text-orange-300 rounded text-xs"
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {actorDetail.data.external_references.length > 0 && (
              <div>
                <p className="text-gray-400 text-sm mb-1">References</p>
                <div className="space-y-1">
                  {actorDetail.data.external_references.slice(0, 5).map((ref, i) => (
                    <a
                      key={i}
                      href={ref.url || '#'}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-cyan-400 text-sm hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {ref.source}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SophisticationBadge({ level }: { level: number }) {
  const colors = [
    'bg-gray-700 text-gray-300',
    'bg-green-900 text-green-300',
    'bg-yellow-900 text-yellow-300',
    'bg-orange-900 text-orange-300',
    'bg-red-900 text-red-300',
  ];
  const labels = ['Minimal', 'Low', 'Intermediate', 'Advanced', 'Expert'];
  const idx = Math.min(Math.max(0, level), 4);
  return (
    <span className={`px-2 py-0.5 rounded text-xs ${colors[idx]}`}>{labels[idx]}</span>
  );
}

// ============================================================================
// IOC Correlation Tab
// ============================================================================

function CorrelationTab() {
  const [mode, setMode] = useState<'manual' | 'scan'>('manual');
  const [iocs, setIocs] = useState<{ ioc_type: string; value: string }[]>([]);
  const [newIocType, setNewIocType] = useState('ip');
  const [newIocValue, setNewIocValue] = useState('');
  const [scanId, setScanId] = useState('');

  const correlateMutation = useMutation({
    mutationFn: (data: { iocs?: { ioc_type: string; value: string }[]; scan_id?: string }) =>
      extendedThreatIntelAPI.correlateIocs(data),
    onSuccess: () => {
      toast.success('Correlation complete');
    },
    onError: () => toast.error('Correlation failed'),
  });

  const addIoc = () => {
    if (newIocValue) {
      setIocs([...iocs, { ioc_type: newIocType, value: newIocValue }]);
      setNewIocValue('');
    }
  };

  const removeIoc = (index: number) => {
    setIocs(iocs.filter((_, i) => i !== index));
  };

  const runCorrelation = () => {
    if (mode === 'manual' && iocs.length > 0) {
      correlateMutation.mutate({ iocs });
    } else if (mode === 'scan' && scanId) {
      correlateMutation.mutate({ scan_id: scanId });
    }
  };

  const iocTypes = ['ip', 'domain', 'hash', 'url', 'email'];

  return (
    <div className="space-y-6">
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Zap className="h-5 w-5 text-cyan-400" />
          IOC Correlation
        </h2>

        <div className="flex gap-4 mb-6">
          <button
            onClick={() => setMode('manual')}
            className={`px-4 py-2 rounded-lg ${
              mode === 'manual'
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Manual IOCs
          </button>
          <button
            onClick={() => setMode('scan')}
            className={`px-4 py-2 rounded-lg ${
              mode === 'scan'
                ? 'bg-cyan-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            From Scan
          </button>
        </div>

        {mode === 'manual' ? (
          <div className="space-y-4">
            <div className="flex gap-3">
              <select
                value={newIocType}
                onChange={(e) => setNewIocType(e.target.value)}
                className="bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
              >
                {iocTypes.map((type) => (
                  <option key={type} value={type}>
                    {type.toUpperCase()}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={newIocValue}
                onChange={(e) => setNewIocValue(e.target.value)}
                placeholder="Enter IOC value..."
                className="flex-1 bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
                onKeyDown={(e) => e.key === 'Enter' && addIoc()}
              />
              <button
                onClick={addIoc}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>

            {iocs.length > 0 && (
              <div className="space-y-2">
                {iocs.map((ioc, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-2 bg-gray-900 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <span className="px-2 py-0.5 bg-cyan-900 text-cyan-300 rounded text-xs">
                        {ioc.ioc_type}
                      </span>
                      <span className="text-white font-mono text-sm">{ioc.value}</span>
                    </div>
                    <button
                      onClick={() => removeIoc(i)}
                      className="text-gray-400 hover:text-red-400"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div>
            <label className="block text-sm text-gray-400 mb-2">Scan ID</label>
            <input
              type="text"
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              placeholder="Enter scan ID to correlate IOCs from..."
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white"
            />
          </div>
        )}

        <button
          onClick={runCorrelation}
          disabled={
            correlateMutation.isPending ||
            (mode === 'manual' && iocs.length === 0) ||
            (mode === 'scan' && !scanId)
          }
          className="mt-6 flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50"
        >
          {correlateMutation.isPending ? (
            <>
              <RefreshCw className="h-4 w-4 animate-spin" />
              Correlating...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Run Correlation
            </>
          )}
        </button>
      </div>

      {/* Results */}
      {correlateMutation.data?.data && (
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
          <h3 className="text-lg font-semibold text-white mb-4">
            Results: {correlateMutation.data.data.correlations_found} correlations found
          </h3>

          {correlateMutation.data.data.correlations.length === 0 ? (
            <p className="text-gray-400">No correlations found in threat intelligence sources.</p>
          ) : (
            <div className="space-y-3">
              {correlateMutation.data.data.correlations.map((correlation, i) => (
                <div key={i} className="p-3 bg-gray-900 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <span className="px-2 py-0.5 bg-cyan-900 text-cyan-300 rounded text-xs">
                        {correlation.ioc_type}
                      </span>
                      <span className="text-white font-mono text-sm">{correlation.ioc_value}</span>
                    </div>
                    <span className="text-gray-400 text-sm">
                      Confidence: {(correlation.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">
                      Source: <span className="text-white">{correlation.source_type}</span>
                    </span>
                    <span className="text-gray-400">
                      Reference: <span className="text-white">{correlation.source_name}</span>
                    </span>
                    {correlation.threat_level && (
                      <ThreatLevelBadge level={correlation.threat_level} />
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
