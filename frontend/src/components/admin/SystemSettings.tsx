import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { adminAPI } from '../../services/api';
import { SystemSetting } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Settings, Save, RotateCcw } from 'lucide-react';

const SystemSettings: React.FC = () => {
  const [settings, setSettings] = useState<SystemSetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<Record<string, boolean>>({});

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await adminAPI.getSettings();
      setSettings(response.data);
      // Initialize edited values
      const initialValues: Record<string, string> = {};
      response.data.forEach((setting) => {
        initialValues[setting.key] = setting.value;
      });
      setEditedValues(initialValues);
    } catch (error) {
      toast.error('Failed to load settings');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (key: string) => {
    setSaving({ ...saving, [key]: true });
    try {
      await adminAPI.updateSetting(key, editedValues[key]);
      toast.success(`Setting "${key}" updated successfully`);
      loadSettings();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update setting');
    } finally {
      setSaving({ ...saving, [key]: false });
    }
  };

  const handleReset = (key: string) => {
    const original = settings.find((s) => s.key === key);
    if (original) {
      setEditedValues({ ...editedValues, [key]: original.value });
    }
  };

  const hasChanges = (key: string) => {
    const original = settings.find((s) => s.key === key);
    return original && editedValues[key] !== original.value;
  };

  const getSettingIcon = (key: string) => {
    if (key.includes('scan')) return '🔍';
    if (key.includes('user')) return '👤';
    if (key.includes('retention')) return '🗓️';
    if (key.includes('registration')) return '📝';
    return '⚙️';
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
        <h3 className="text-xl font-semibold text-white mb-4">
          <Settings className="inline h-5 w-5 mr-2" />
          System Settings ({settings.length})
        </h3>

        <div className="space-y-4">
          {settings.map((setting) => (
            <div
              key={setting.key}
              className="bg-dark-bg border border-dark-border rounded-lg p-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  {/* Setting Header */}
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xl">{getSettingIcon(setting.key)}</span>
                    <div>
                      <h4 className="text-white font-medium">{setting.key}</h4>
                      {setting.description && (
                        <p className="text-sm text-slate-400">{setting.description}</p>
                      )}
                    </div>
                  </div>

                  {/* Value Input */}
                  <div className="mt-3">
                    {setting.key === 'allow_registration' ? (
                      // Boolean toggle
                      <div className="flex items-center gap-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={editedValues[setting.key] === 'true'}
                            onChange={(e) =>
                              setEditedValues({
                                ...editedValues,
                                [setting.key]: e.target.checked ? 'true' : 'false',
                              })
                            }
                            className="sr-only peer"
                          />
                          <div className="w-11 h-6 bg-dark-surface peer-focus:ring-2 peer-focus:ring-primary rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                        </label>
                        <span className="text-sm text-slate-400">
                          {editedValues[setting.key] === 'true' ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                    ) : (
                      // Text/Number input
                      <input
                        type={setting.key.includes('days') ? 'number' : 'text'}
                        value={editedValues[setting.key] || ''}
                        onChange={(e) =>
                          setEditedValues({ ...editedValues, [setting.key]: e.target.value })
                        }
                        className="w-full bg-dark-surface border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                      />
                    )}
                  </div>

                  {/* Metadata */}
                  <div className="mt-3 flex items-center gap-4 text-xs text-slate-500">
                    {setting.updated_by && (
                      <span>
                        Last updated by: <span className="font-mono">{setting.updated_by.substring(0, 8)}...</span>
                      </span>
                    )}
                    {setting.updated_at && (
                      <span>
                        {new Date(setting.updated_at).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex flex-col gap-2">
                  <Button
                    onClick={() => handleSave(setting.key)}
                    disabled={!hasChanges(setting.key) || saving[setting.key]}
                    variant="primary"
                    size="sm"
                  >
                    <Save className="h-4 w-4 mr-1" />
                    {saving[setting.key] ? 'Saving...' : 'Save'}
                  </Button>
                  {hasChanges(setting.key) && (
                    <Button
                      onClick={() => handleReset(setting.key)}
                      variant="secondary"
                      size="sm"
                    >
                      <RotateCcw className="h-4 w-4 mr-1" />
                      Reset
                    </Button>
                  )}
                </div>
              </div>
            </div>
          ))}

          {settings.length === 0 && (
            <div className="text-center py-8 text-slate-400">
              No system settings configured
            </div>
          )}
        </div>
      </Card>

      {/* Information */}
      <Card>
        <h3 className="text-lg font-semibold text-white mb-3">ℹ️ Information</h3>
        <div className="space-y-2 text-sm text-slate-400">
          <p>
            <strong className="text-white">max_scans_per_user:</strong> Maximum number of scans
            each user can create. Set to 0 for unlimited.
          </p>
          <p>
            <strong className="text-white">scan_retention_days:</strong> Automatically delete
            scans older than this many days. Set to 0 to disable auto-deletion.
          </p>
          <p>
            <strong className="text-white">allow_registration:</strong> Whether new users can
            register accounts. Disable this to restrict new registrations.
          </p>
        </div>
      </Card>
    </div>
  );
};

export default SystemSettings;
