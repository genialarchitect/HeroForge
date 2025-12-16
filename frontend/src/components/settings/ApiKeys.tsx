import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { apiKeyAPI } from '../../services/api';
import { ApiKey, CreateApiKeyResponse } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Key, Plus, Trash2, Copy, CheckCircle, Calendar, Clock } from 'lucide-react';

const ApiKeys: React.FC = () => {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [creating, setCreating] = useState(false);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<CreateApiKeyResponse | null>(null);

  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    setLoading(true);
    try {
      const response = await apiKeyAPI.getAll();
      setKeys(response.data);
    } catch (error: any) {
      toast.error('Failed to load API keys');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newKeyName.trim()) {
      toast.error('Please enter a name for the API key');
      return;
    }

    setCreating(true);
    try {
      const response = await apiKeyAPI.create({ name: newKeyName.trim() });
      setNewlyCreatedKey(response.data);
      setNewKeyName('');
      await loadKeys();
      toast.success('API key created successfully');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to create API key');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (keyId: string, keyName: string) => {
    if (!confirm(`Are you sure you want to revoke the API key "${keyName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await apiKeyAPI.delete(keyId);
      await loadKeys();
      toast.success('API key revoked successfully');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to revoke API key');
    }
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success('API key copied to clipboard');
  };

  const closeNewKeyModal = () => {
    setNewlyCreatedKey(null);
    setShowCreateModal(false);
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
            <Key className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">API Keys</h3>
          </div>
          <Button
            variant="primary"
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            Create API Key
          </Button>
        </div>

        <p className="text-sm text-slate-400 mb-6">
          API keys allow programmatic access to HeroForge. Keep your keys secure and never share them publicly.
        </p>

        {keys.length === 0 ? (
          <div className="text-center py-12">
            <Key className="h-12 w-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">No API keys yet</p>
            <p className="text-sm text-slate-500 mt-2">Create your first API key to get started</p>
          </div>
        ) : (
          <div className="space-y-3">
            {keys.map((key) => (
              <div
                key={key.id}
                className="flex items-center justify-between p-4 bg-dark-bg rounded-lg border border-dark-border hover:border-primary/30 transition-colors"
              >
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h4 className="font-medium text-white">{key.name}</h4>
                    <code className="px-2 py-1 bg-dark-surface rounded text-xs text-slate-400 font-mono">
                      {key.prefix}...
                    </code>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-slate-500">
                    <div className="flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      Created {new Date(key.created_at).toLocaleDateString()}
                    </div>
                    {key.last_used_at && (
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Last used {new Date(key.last_used_at).toLocaleDateString()}
                      </div>
                    )}
                    {!key.last_used_at && (
                      <span className="text-amber-500">Never used</span>
                    )}
                  </div>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleDelete(key.id, key.name)}
                  className="flex items-center gap-2"
                >
                  <Trash2 className="h-4 w-4" />
                  Revoke
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Create API Key Modal */}
      {showCreateModal && !newlyCreatedKey && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-dark-surface border border-dark-border rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-xl font-semibold text-white mb-4">Create API Key</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Key Name
                </label>
                <input
                  type="text"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  placeholder="e.g., Production Server, CI/CD Pipeline"
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  autoFocus
                />
                <p className="text-xs text-slate-500 mt-1">
                  Give your API key a descriptive name to remember where it's used
                </p>
              </div>

              <div className="flex gap-3 justify-end pt-4">
                <Button
                  variant="secondary"
                  onClick={() => {
                    setShowCreateModal(false);
                    setNewKeyName('');
                  }}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleCreate}
                  disabled={creating || !newKeyName.trim()}
                >
                  {creating ? (
                    <>
                      <LoadingSpinner />
                      <span className="ml-2">Creating...</span>
                    </>
                  ) : (
                    'Create Key'
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* New Key Created Modal */}
      {newlyCreatedKey && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-dark-surface border border-dark-border rounded-lg p-6 max-w-2xl w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-green-500/10 rounded-lg">
                <CheckCircle className="h-6 w-6 text-green-400" />
              </div>
              <h3 className="text-xl font-semibold text-white">API Key Created Successfully</h3>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 mb-4">
              <p className="text-sm text-amber-200 font-medium mb-2">
                Important: Save your API key now!
              </p>
              <p className="text-xs text-amber-300/70">
                This is the only time you'll see the full key. If you lose it, you'll need to create a new one.
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">API Key</label>
                <div className="flex gap-2">
                  <code className="flex-1 bg-dark-bg border border-dark-border rounded-lg px-4 py-3 text-white font-mono text-sm break-all">
                    {newlyCreatedKey.key}
                  </code>
                  <Button
                    variant="secondary"
                    onClick={() => handleCopyKey(newlyCreatedKey.key)}
                    className="flex items-center gap-2"
                  >
                    <Copy className="h-4 w-4" />
                    Copy
                  </Button>
                </div>
              </div>

              <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <h4 className="text-sm font-medium text-blue-200 mb-2">Using your API key</h4>
                <p className="text-xs text-blue-300/70 mb-3">
                  Include your API key in the X-API-Key header:
                </p>
                <code className="block bg-dark-bg border border-dark-border rounded px-3 py-2 text-xs text-slate-300 font-mono">
                  curl -H "X-API-Key: {newlyCreatedKey.key}" https://heroforge.example.com/api/scans
                </code>
              </div>

              <div className="flex justify-end pt-4">
                <Button variant="primary" onClick={closeNewKeyModal}>
                  Done
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiKeys;
