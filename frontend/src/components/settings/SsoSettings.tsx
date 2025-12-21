import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { ssoAPI } from '../../services/api';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import Badge from '../ui/Badge';
import {
  Plus,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  Download,
  TestTube,
  Copy,
  KeyRound,
  Shield,
  Settings,
  ChevronDown,
  ChevronUp,
  Info
} from 'lucide-react';
import type {
  SsoProvider,
  SsoProviderPreset,
  SsoMetadata,
  CreateSsoProviderRequest,
  UpdateSsoProviderRequest,
  SsoProviderType,
  SsoProviderStatus,
  AttributeMapping,
  GroupMapping,
  SamlConfig,
  OidcConfig
} from '../../types';

const SsoSettings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  const [presets, setPresets] = useState<SsoProviderPreset[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<SsoProvider | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [providersRes, presetsRes] = await Promise.all([
        ssoAPI.admin.listProviders(),
        ssoAPI.admin.getPresets(),
      ]);
      setProviders(providersRes.data);
      setPresets(presetsRes.data);
    } catch (error) {
      console.error('Failed to load SSO data:', error);
      toast.error('Failed to load SSO providers');
    } finally {
      setLoading(false);
    }
  };

  const handleTestProvider = async (id: string) => {
    setTesting(id);
    try {
      const result = await ssoAPI.admin.testProvider(id);
      if (result.data.success) {
        toast.success(result.data.message);
      } else {
        toast.error(result.data.message);
      }
    } catch (error) {
      console.error('Test failed:', error);
      toast.error('Connection test failed');
    } finally {
      setTesting(null);
    }
  };

  const handleDeleteProvider = async (id: string) => {
    if (!confirm('Are you sure you want to delete this SSO provider?')) return;

    try {
      await ssoAPI.admin.deleteProvider(id);
      toast.success('SSO provider deleted');
      loadData();
    } catch (error) {
      console.error('Delete failed:', error);
      toast.error('Failed to delete provider');
    }
  };

  const handleToggleStatus = async (provider: SsoProvider) => {
    const newStatus: SsoProviderStatus = provider.status === 'active' ? 'disabled' : 'active';
    try {
      await ssoAPI.admin.updateProvider(provider.id, { status: newStatus });
      toast.success(`Provider ${newStatus === 'active' ? 'enabled' : 'disabled'}`);
      loadData();
    } catch (error) {
      console.error('Status toggle failed:', error);
      toast.error('Failed to update provider status');
    }
  };

  const getStatusBadge = (status: SsoProviderStatus) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-green-600">Active</Badge>;
      case 'disabled':
        return <Badge className="bg-gray-600">Disabled</Badge>;
      case 'incomplete':
        return <Badge className="bg-yellow-600">Incomplete</Badge>;
      case 'error':
        return <Badge className="bg-red-600">Error</Badge>;
      default:
        return <Badge className="bg-gray-600">{status}</Badge>;
    }
  };

  const getProviderIcon = (type: SsoProviderType) => {
    return type === 'saml' ? <Shield className="h-5 w-5" /> : <KeyRound className="h-5 w-5" />;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-semibold text-white">SSO Authentication</h2>
          <p className="text-gray-400 text-sm mt-1">
            Configure SAML 2.0 and OpenID Connect identity providers for enterprise single sign-on
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add Provider
        </Button>
      </div>

      {providers.length === 0 ? (
        <Card className="p-8 text-center">
          <KeyRound className="h-12 w-12 text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No SSO Providers Configured</h3>
          <p className="text-gray-400 mb-4">
            Add an identity provider to enable single sign-on for your users.
          </p>
          <Button onClick={() => setShowCreateModal(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Add Your First Provider
          </Button>
        </Card>
      ) : (
        <div className="space-y-4">
          {providers.map((provider) => (
            <ProviderCard
              key={provider.id}
              provider={provider}
              onEdit={() => {
                setSelectedProvider(provider);
                setShowEditModal(true);
              }}
              onDelete={() => handleDeleteProvider(provider.id)}
              onTest={() => handleTestProvider(provider.id)}
              onToggleStatus={() => handleToggleStatus(provider)}
              testing={testing === provider.id}
            />
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CreateProviderModal
          presets={presets}
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadData();
          }}
        />
      )}

      {/* Edit Modal */}
      {showEditModal && selectedProvider && (
        <EditProviderModal
          provider={selectedProvider}
          onClose={() => {
            setShowEditModal(false);
            setSelectedProvider(null);
          }}
          onSuccess={() => {
            setShowEditModal(false);
            setSelectedProvider(null);
            loadData();
          }}
        />
      )}
    </div>
  );
};

// ============================================================================
// Provider Card Component
// ============================================================================

interface ProviderCardProps {
  provider: SsoProvider;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
  onToggleStatus: () => void;
  testing: boolean;
}

const ProviderCard: React.FC<ProviderCardProps> = ({
  provider,
  onEdit,
  onDelete,
  onTest,
  onToggleStatus,
  testing,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [metadata, setMetadata] = useState<SsoMetadata | null>(null);
  const [loadingMetadata, setLoadingMetadata] = useState(false);

  const loadMetadata = async () => {
    if (metadata) return;
    setLoadingMetadata(true);
    try {
      const result = await ssoAPI.admin.getMetadata(provider.id);
      setMetadata(result.data);
    } catch (error) {
      console.error('Failed to load metadata:', error);
    } finally {
      setLoadingMetadata(false);
    }
  };

  const handleExpand = () => {
    if (!expanded) {
      loadMetadata();
    }
    setExpanded(!expanded);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const downloadMetadataXml = async () => {
    try {
      const response = await ssoAPI.admin.downloadMetadataXml(provider.id);
      const blob = new Blob([response.data], { type: 'application/xml' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sp-metadata-${provider.name}.xml`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download failed:', error);
      toast.error('Failed to download metadata');
    }
  };

  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-2 bg-gray-700 rounded-lg">
            {provider.provider_type === 'saml' ? (
              <Shield className="h-6 w-6 text-cyan-400" />
            ) : (
              <KeyRound className="h-6 w-6 text-cyan-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-medium text-white">{provider.display_name}</h3>
              <Badge className={provider.provider_type === 'saml' ? 'bg-purple-600' : 'bg-blue-600'}>
                {provider.provider_type.toUpperCase()}
              </Badge>
              {provider.status === 'active' ? (
                <Badge className="bg-green-600">Active</Badge>
              ) : (
                <Badge className="bg-gray-600">Disabled</Badge>
              )}
            </div>
            <p className="text-gray-400 text-sm">{provider.name}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={onTest}
            disabled={testing}
          >
            {testing ? <LoadingSpinner size="sm" /> : <TestTube className="h-4 w-4" />}
            <span className="ml-1">Test</span>
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={onToggleStatus}
          >
            {provider.status === 'active' ? (
              <XCircle className="h-4 w-4" />
            ) : (
              <CheckCircle className="h-4 w-4" />
            )}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={onEdit}
          >
            <Edit className="h-4 w-4" />
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={onDelete}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleExpand}
          >
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-gray-700">
          {loadingMetadata ? (
            <div className="flex justify-center py-4">
              <LoadingSpinner />
            </div>
          ) : metadata ? (
            <div className="space-y-4">
              <h4 className="text-sm font-medium text-gray-300">Service Provider Configuration</h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Entity ID</label>
                  <div className="flex items-center gap-2">
                    <code className="text-sm text-cyan-400 bg-gray-800 px-2 py-1 rounded flex-1 truncate">
                      {metadata.entity_id}
                    </code>
                    <Button size="sm" variant="secondary" onClick={() => copyToClipboard(metadata.entity_id)}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>

                {metadata.acs_url && (
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">ACS URL</label>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-cyan-400 bg-gray-800 px-2 py-1 rounded flex-1 truncate">
                        {metadata.acs_url}
                      </code>
                      <Button size="sm" variant="secondary" onClick={() => copyToClipboard(metadata.acs_url!)}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )}

                {metadata.redirect_uri && (
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Redirect URI</label>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-cyan-400 bg-gray-800 px-2 py-1 rounded flex-1 truncate">
                        {metadata.redirect_uri}
                      </code>
                      <Button size="sm" variant="secondary" onClick={() => copyToClipboard(metadata.redirect_uri!)}>
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>

              {provider.provider_type === 'saml' && (
                <Button variant="secondary" size="sm" onClick={downloadMetadataXml}>
                  <Download className="h-4 w-4 mr-2" />
                  Download SP Metadata XML
                </Button>
              )}

              <div className="text-xs text-gray-500 flex items-center gap-1">
                <Info className="h-3 w-3" />
                Configure your Identity Provider with the above values
              </div>
            </div>
          ) : (
            <p className="text-gray-400 text-sm">Failed to load metadata</p>
          )}
        </div>
      )}
    </Card>
  );
};

// ============================================================================
// Create Provider Modal
// ============================================================================

interface CreateProviderModalProps {
  presets: SsoProviderPreset[];
  onClose: () => void;
  onSuccess: () => void;
}

const CreateProviderModal: React.FC<CreateProviderModalProps> = ({ presets, onClose, onSuccess }) => {
  const [step, setStep] = useState<'preset' | 'configure'>('preset');
  const [selectedPreset, setSelectedPreset] = useState<SsoProviderPreset | null>(null);
  const [saving, setSaving] = useState(false);

  const [formData, setFormData] = useState({
    name: '',
    display_name: '',
    // SAML fields
    idp_entity_id: '',
    idp_sso_url: '',
    idp_slo_url: '',
    idp_certificate: '',
    // OIDC fields
    issuer_url: '',
    client_id: '',
    client_secret: '',
    scopes: 'openid email profile',
    // Common
    jit_provisioning: true,
    default_role: 'user',
  });

  const handlePresetSelect = (preset: SsoProviderPreset) => {
    setSelectedPreset(preset);
    setFormData(prev => ({
      ...prev,
      name: preset.name.toLowerCase().replace(/\s+/g, '_'),
      display_name: preset.name,
    }));
    setStep('configure');
  };

  const handleSubmit = async () => {
    if (!selectedPreset) return;

    setSaving(true);
    try {
      let config: SamlConfig | OidcConfig;

      if (selectedPreset.provider_type === 'saml') {
        config = {
          type: 'saml',
          idp_entity_id: formData.idp_entity_id,
          idp_sso_url: formData.idp_sso_url,
          idp_slo_url: formData.idp_slo_url || undefined,
          idp_certificate: formData.idp_certificate,
          sign_requests: true,
          require_signed_response: true,
          require_signed_assertion: true,
          encrypt_assertions: false,
          force_authn: false,
          allowed_clock_skew: 60,
        };
      } else {
        config = {
          type: 'oidc',
          issuer_url: formData.issuer_url,
          client_id: formData.client_id,
          client_secret: formData.client_secret,
          scopes: formData.scopes.split(/[,\s]+/).filter(Boolean),
          use_pkce: true,
          response_type: 'code',
        };
      }

      const request: CreateSsoProviderRequest = {
        name: formData.name,
        display_name: formData.display_name,
        provider_type: selectedPreset.provider_type,
        icon: selectedPreset.icon,
        config,
        attribute_mappings: selectedPreset.default_attribute_mappings,
        jit_provisioning: formData.jit_provisioning,
        default_role: formData.default_role,
      };

      await ssoAPI.admin.createProvider(request);
      toast.success('SSO provider created');
      onSuccess();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Create failed:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to create provider');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-white">Add SSO Provider</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <XCircle className="h-6 w-6" />
          </button>
        </div>

        {step === 'preset' ? (
          <>
            <p className="text-gray-400 mb-4">Select an identity provider:</p>
            <div className="grid grid-cols-2 gap-4">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => handlePresetSelect(preset)}
                  className="p-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-left transition-colors"
                >
                  <div className="flex items-center gap-3 mb-2">
                    {preset.provider_type === 'saml' ? (
                      <Shield className="h-6 w-6 text-purple-400" />
                    ) : (
                      <KeyRound className="h-6 w-6 text-blue-400" />
                    )}
                    <span className="font-medium text-white">{preset.name}</span>
                  </div>
                  <p className="text-sm text-gray-400">{preset.description}</p>
                  <Badge className={preset.provider_type === 'saml' ? 'bg-purple-600 mt-2' : 'bg-blue-600 mt-2'}>
                    {preset.provider_type.toUpperCase()}
                  </Badge>
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2 mb-4">
              <button
                onClick={() => setStep('preset')}
                className="text-cyan-400 hover:text-cyan-300"
              >
                Back
              </button>
              <span className="text-gray-500">/</span>
              <span className="text-white">{selectedPreset?.name}</span>
            </div>

            {selectedPreset?.setup_instructions && (
              <div className="bg-gray-700 p-4 rounded-lg mb-4 text-sm text-gray-300">
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <Info className="h-4 w-4" />
                  Setup Instructions
                </h4>
                <div className="prose prose-invert prose-sm max-w-none whitespace-pre-wrap">
                  {selectedPreset.setup_instructions}
                </div>
              </div>
            )}

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Internal Name</label>
                  <Input
                    value={formData.name}
                    onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="my_idp"
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Display Name</label>
                  <Input
                    value={formData.display_name}
                    onChange={(e) => setFormData(prev => ({ ...prev, display_name: e.target.value }))}
                    placeholder="My Identity Provider"
                  />
                </div>
              </div>

              {selectedPreset?.provider_type === 'saml' ? (
                <>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">IdP Entity ID</label>
                    <Input
                      value={formData.idp_entity_id}
                      onChange={(e) => setFormData(prev => ({ ...prev, idp_entity_id: e.target.value }))}
                      placeholder="https://idp.example.com/metadata"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">IdP SSO URL</label>
                    <Input
                      value={formData.idp_sso_url}
                      onChange={(e) => setFormData(prev => ({ ...prev, idp_sso_url: e.target.value }))}
                      placeholder="https://idp.example.com/sso/saml"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">IdP SLO URL (Optional)</label>
                    <Input
                      value={formData.idp_slo_url}
                      onChange={(e) => setFormData(prev => ({ ...prev, idp_slo_url: e.target.value }))}
                      placeholder="https://idp.example.com/slo/saml"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">IdP Certificate (PEM)</label>
                    <textarea
                      value={formData.idp_certificate}
                      onChange={(e) => setFormData(prev => ({ ...prev, idp_certificate: e.target.value }))}
                      className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
                      rows={5}
                      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    />
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Issuer URL</label>
                    <Input
                      value={formData.issuer_url}
                      onChange={(e) => setFormData(prev => ({ ...prev, issuer_url: e.target.value }))}
                      placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Client ID</label>
                    <Input
                      value={formData.client_id}
                      onChange={(e) => setFormData(prev => ({ ...prev, client_id: e.target.value }))}
                      placeholder="your-client-id"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Client Secret</label>
                    <Input
                      type="password"
                      value={formData.client_secret}
                      onChange={(e) => setFormData(prev => ({ ...prev, client_secret: e.target.value }))}
                      placeholder="your-client-secret"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Scopes</label>
                    <Input
                      value={formData.scopes}
                      onChange={(e) => setFormData(prev => ({ ...prev, scopes: e.target.value }))}
                      placeholder="openid email profile"
                    />
                  </div>
                </>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-300 mb-1">Default Role</label>
                  <select
                    value={formData.default_role}
                    onChange={(e) => setFormData(prev => ({ ...prev, default_role: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                    <option value="auditor">Auditor</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>
                <div className="flex items-center pt-6">
                  <label className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.jit_provisioning}
                      onChange={(e) => setFormData(prev => ({ ...prev, jit_provisioning: e.target.checked }))}
                      className="mr-2"
                    />
                    <span className="text-sm text-gray-300">Enable JIT User Provisioning</span>
                  </label>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={saving}>
                {saving ? <LoadingSpinner size="sm" /> : 'Create Provider'}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// Edit Provider Modal
// ============================================================================

interface EditProviderModalProps {
  provider: SsoProvider;
  onClose: () => void;
  onSuccess: () => void;
}

const EditProviderModal: React.FC<EditProviderModalProps> = ({ provider, onClose, onSuccess }) => {
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'general' | 'mappings'>('general');

  const [formData, setFormData] = useState({
    display_name: provider.display_name,
    jit_provisioning: provider.jit_provisioning,
    default_role: provider.default_role,
    update_on_login: provider.update_on_login,
  });

  const [attributeMappings, setAttributeMappings] = useState<AttributeMapping[]>(
    provider.attribute_mappings || []
  );

  const [groupMappings, setGroupMappings] = useState<GroupMapping[]>(
    provider.group_mappings || []
  );

  const handleSubmit = async () => {
    setSaving(true);
    try {
      const updates: UpdateSsoProviderRequest = {
        display_name: formData.display_name,
        jit_provisioning: formData.jit_provisioning,
        default_role: formData.default_role,
        update_on_login: formData.update_on_login,
        attribute_mappings: attributeMappings,
        group_mappings: groupMappings,
      };

      await ssoAPI.admin.updateProvider(provider.id, updates);
      toast.success('SSO provider updated');
      onSuccess();
    } catch (error) {
      console.error('Update failed:', error);
      toast.error('Failed to update provider');
    } finally {
      setSaving(false);
    }
  };

  const addAttributeMapping = () => {
    setAttributeMappings([...attributeMappings, { source: '', target: '', required: false }]);
  };

  const removeAttributeMapping = (index: number) => {
    setAttributeMappings(attributeMappings.filter((_, i) => i !== index));
  };

  const addGroupMapping = () => {
    setGroupMappings([...groupMappings, { group: '', role: 'user', priority: 0 }]);
  };

  const removeGroupMapping = (index: number) => {
    setGroupMappings(groupMappings.filter((_, i) => i !== index));
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-white">Edit {provider.display_name}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <XCircle className="h-6 w-6" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700 mb-4">
          <button
            onClick={() => setActiveTab('general')}
            className={`px-4 py-2 text-sm font-medium ${
              activeTab === 'general'
                ? 'text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            General
          </button>
          <button
            onClick={() => setActiveTab('mappings')}
            className={`px-4 py-2 text-sm font-medium ${
              activeTab === 'mappings'
                ? 'text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Attribute Mappings
          </button>
        </div>

        {activeTab === 'general' ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Display Name</label>
              <Input
                value={formData.display_name}
                onChange={(e) => setFormData(prev => ({ ...prev, display_name: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Default Role</label>
              <select
                value={formData.default_role}
                onChange={(e) => setFormData(prev => ({ ...prev, default_role: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="auditor">Auditor</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.jit_provisioning}
                  onChange={(e) => setFormData(prev => ({ ...prev, jit_provisioning: e.target.checked }))}
                  className="mr-2"
                />
                <span className="text-sm text-gray-300">Enable JIT User Provisioning</span>
              </label>
              <label className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.update_on_login}
                  onChange={(e) => setFormData(prev => ({ ...prev, update_on_login: e.target.checked }))}
                  className="mr-2"
                />
                <span className="text-sm text-gray-300">Update User Profile on Login</span>
              </label>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Attribute Mappings */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <h4 className="text-sm font-medium text-gray-300">Attribute Mappings</h4>
                <Button size="sm" variant="secondary" onClick={addAttributeMapping}>
                  <Plus className="h-3 w-3 mr-1" />
                  Add
                </Button>
              </div>
              <div className="space-y-2">
                {attributeMappings.map((mapping, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <Input
                      placeholder="IdP Attribute"
                      value={mapping.source}
                      onChange={(e) => {
                        const updated = [...attributeMappings];
                        updated[index].source = e.target.value;
                        setAttributeMappings(updated);
                      }}
                      className="flex-1"
                    />
                    <span className="text-gray-500">-&gt;</span>
                    <select
                      value={mapping.target}
                      onChange={(e) => {
                        const updated = [...attributeMappings];
                        updated[index].target = e.target.value;
                        setAttributeMappings(updated);
                      }}
                      className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white"
                    >
                      <option value="">Select field</option>
                      <option value="email">Email</option>
                      <option value="username">Username</option>
                      <option value="display_name">Display Name</option>
                      <option value="first_name">First Name</option>
                      <option value="last_name">Last Name</option>
                      <option value="groups">Groups</option>
                    </select>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => removeAttributeMapping(index)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>

            {/* Group Mappings */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <h4 className="text-sm font-medium text-gray-300">Group to Role Mappings</h4>
                <Button size="sm" variant="secondary" onClick={addGroupMapping}>
                  <Plus className="h-3 w-3 mr-1" />
                  Add
                </Button>
              </div>
              <div className="space-y-2">
                {groupMappings.map((mapping, index) => (
                  <div key={index} className="flex items-center gap-2">
                    <Input
                      placeholder="IdP Group"
                      value={mapping.group}
                      onChange={(e) => {
                        const updated = [...groupMappings];
                        updated[index].group = e.target.value;
                        setGroupMappings(updated);
                      }}
                      className="flex-1"
                    />
                    <span className="text-gray-500">-&gt;</span>
                    <select
                      value={mapping.role}
                      onChange={(e) => {
                        const updated = [...groupMappings];
                        updated[index].role = e.target.value;
                        setGroupMappings(updated);
                      }}
                      className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                      <option value="auditor">Auditor</option>
                      <option value="viewer">Viewer</option>
                    </select>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => removeGroupMapping(index)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        <div className="flex justify-end gap-3 mt-6">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={saving}>
            {saving ? <LoadingSpinner size="sm" /> : 'Save Changes'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default SsoSettings;
