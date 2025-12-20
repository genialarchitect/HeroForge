import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { serviceNowAPI, ServiceNowSettings as ServiceNowSettingsType, ServiceNowAssignmentGroup, ServiceNowCategory } from '../../services/api';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { CheckCircle, AlertTriangle, ExternalLink, Settings, Building2 } from 'lucide-react';

const ServiceNowSettings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [configured, setConfigured] = useState(false);

  const [settings, setSettings] = useState({
    instance_url: '',
    username: '',
    password: '',
    default_assignment_group: '',
    default_category: '',
    default_impact: 3,
    default_urgency: 3,
    enabled: true,
  });

  const [assignmentGroups, setAssignmentGroups] = useState<ServiceNowAssignmentGroup[]>([]);
  const [categories, setCategories] = useState<ServiceNowCategory[]>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [loadingCategories, setLoadingCategories] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await serviceNowAPI.getSettings();
      const data = response.data;
      setSettings({
        instance_url: data.instance_url || '',
        username: data.username || '',
        password: '', // Password is never returned from API
        default_assignment_group: data.default_assignment_group || '',
        default_category: data.default_category || '',
        default_impact: data.default_impact || 3,
        default_urgency: data.default_urgency || 3,
        enabled: data.enabled,
      });
      setConfigured(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        setConfigured(false);
      } else {
        console.error('Failed to load ServiceNow settings:', error);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!settings.instance_url || !settings.username || !settings.password) {
      toast.error('Please fill in all required fields');
      return;
    }

    if (!settings.instance_url.startsWith('https://')) {
      toast.error('Instance URL must start with https://');
      return;
    }

    setSaving(true);
    try {
      await serviceNowAPI.updateSettings({
        instance_url: settings.instance_url,
        username: settings.username,
        password: settings.password,
        default_assignment_group: settings.default_assignment_group || undefined,
        default_category: settings.default_category || undefined,
        default_impact: settings.default_impact,
        default_urgency: settings.default_urgency,
        enabled: settings.enabled,
      });
      toast.success('ServiceNow settings saved successfully');
      setConfigured(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to save ServiceNow settings:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to save ServiceNow settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    if (!configured) {
      toast.error('Please save your settings first');
      return;
    }

    setTesting(true);
    try {
      await serviceNowAPI.testConnection();
      toast.success('ServiceNow connection successful!');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('ServiceNow connection failed:', error);
      toast.error(axiosError.response?.data?.error || 'ServiceNow connection failed');
    } finally {
      setTesting(false);
    }
  };

  const handleLoadAssignmentGroups = async () => {
    if (!configured) {
      toast.error('Please save your settings first');
      return;
    }

    setLoadingGroups(true);
    try {
      const response = await serviceNowAPI.getAssignmentGroups();
      setAssignmentGroups(response.data);
      toast.success(`Loaded ${response.data.length} assignment groups`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to load assignment groups:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to load assignment groups');
    } finally {
      setLoadingGroups(false);
    }
  };

  const handleLoadCategories = async () => {
    if (!configured) {
      toast.error('Please save your settings first');
      return;
    }

    setLoadingCategories(true);
    try {
      const response = await serviceNowAPI.getCategories();
      setCategories(response.data);
      toast.success(`Loaded ${response.data.length} categories`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to load categories:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to load categories');
    } finally {
      setLoadingCategories(false);
    }
  };

  const impactOptions = [
    { value: 1, label: '1 - High' },
    { value: 2, label: '2 - Medium' },
    { value: 3, label: '3 - Low' },
  ];

  const urgencyOptions = [
    { value: 1, label: '1 - High' },
    { value: 2, label: '2 - Medium' },
    { value: 3, label: '3 - Low' },
  ];

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
      <Card>
        <div className="flex items-center gap-3 mb-6">
          <Building2 className="h-6 w-6 text-green-500" />
          <h3 className="text-lg font-semibold text-gray-100">ServiceNow Integration</h3>
        </div>

        <div className="space-y-4">
          {!configured && (
            <div className="bg-blue-900/30 border border-blue-700 rounded-lg p-4 flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-300">
                <p className="font-medium mb-1">ServiceNow Integration Not Configured</p>
                <p>Configure your ServiceNow instance to create incidents and change requests from vulnerabilities.</p>
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Instance URL <span className="text-red-500">*</span>
            </label>
            <Input
              type="url"
              placeholder="https://yourcompany.service-now.com"
              value={settings.instance_url}
              onChange={(e) => setSettings({ ...settings, instance_url: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">Your ServiceNow instance URL (e.g., https://company.service-now.com)</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Username <span className="text-red-500">*</span>
            </label>
            <Input
              type="text"
              placeholder="username"
              value={settings.username}
              onChange={(e) => setSettings({ ...settings, username: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">ServiceNow user with API access permissions</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Password <span className="text-red-500">*</span>
            </label>
            <Input
              type="password"
              placeholder={configured ? '********' : 'Enter password'}
              value={settings.password}
              onChange={(e) => setSettings({ ...settings, password: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">
              Password for the ServiceNow user. Consider using a{' '}
              <a
                href="https://docs.servicenow.com/bundle/tokyo-platform-security/page/administer/users/concept/c_OAuthApplications.html"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
              >
                OAuth token <ExternalLink className="h-3 w-3" />
              </a>
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Default Assignment Group
            </label>
            <div className="flex gap-2">
              <div className="flex-1">
                {assignmentGroups.length > 0 ? (
                  <select
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                    value={settings.default_assignment_group}
                    onChange={(e) => setSettings({ ...settings, default_assignment_group: e.target.value })}
                  >
                    <option value="">Select an assignment group</option>
                    {assignmentGroups.map((group) => (
                      <option key={group.sys_id} value={group.sys_id}>
                        {group.name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input
                    type="text"
                    placeholder="Group sys_id or name"
                    value={settings.default_assignment_group}
                    onChange={(e) => setSettings({ ...settings, default_assignment_group: e.target.value })}
                  />
                )}
              </div>
              <Button
                onClick={handleLoadAssignmentGroups}
                disabled={!configured || loadingGroups}
                variant="secondary"
              >
                {loadingGroups ? 'Loading...' : 'Load Groups'}
              </Button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Default Category
            </label>
            <div className="flex gap-2">
              <div className="flex-1">
                {categories.length > 0 ? (
                  <select
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                    value={settings.default_category}
                    onChange={(e) => setSettings({ ...settings, default_category: e.target.value })}
                  >
                    <option value="">Select a category</option>
                    {categories.map((cat) => (
                      <option key={cat.value} value={cat.value}>
                        {cat.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input
                    type="text"
                    placeholder="security"
                    value={settings.default_category}
                    onChange={(e) => setSettings({ ...settings, default_category: e.target.value })}
                  />
                )}
              </div>
              <Button
                onClick={handleLoadCategories}
                disabled={!configured || loadingCategories}
                variant="secondary"
              >
                {loadingCategories ? 'Loading...' : 'Load Categories'}
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Default Impact
              </label>
              <select
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                value={settings.default_impact}
                onChange={(e) => setSettings({ ...settings, default_impact: parseInt(e.target.value) })}
              >
                {impactOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-gray-500">Auto-calculated from severity when creating tickets</p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Default Urgency
              </label>
              <select
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                value={settings.default_urgency}
                onChange={(e) => setSettings({ ...settings, default_urgency: parseInt(e.target.value) })}
              >
                {urgencyOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-gray-500">Auto-calculated from severity when creating tickets</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="servicenow-enabled"
              checked={settings.enabled}
              onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
              className="h-4 w-4 text-cyan-500 focus:ring-cyan-500 border-gray-600 rounded bg-gray-700"
            />
            <label htmlFor="servicenow-enabled" className="text-sm font-medium text-gray-300">
              Enable ServiceNow integration
            </label>
          </div>

          <div className="flex gap-3 pt-4">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? 'Saving...' : 'Save Settings'}
            </Button>
            <Button onClick={handleTestConnection} disabled={!configured || testing} variant="secondary">
              {testing ? 'Testing...' : 'Test Connection'}
            </Button>
          </div>

          {configured && (
            <div className="bg-green-900/30 border border-green-700 rounded-lg p-4 flex items-start gap-3">
              <CheckCircle className="h-5 w-5 text-green-400 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-green-300">
                <p className="font-medium">ServiceNow Integration Configured</p>
                <p>You can now create incidents and change requests from vulnerabilities.</p>
              </div>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <h4 className="text-md font-semibold text-gray-100 mb-4">How to Use ServiceNow Integration</h4>
        <div className="space-y-3 text-sm text-gray-400">
          <div className="flex items-start gap-3">
            <div className="bg-cyan-900/50 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-cyan-400 font-semibold text-xs">1</span>
            </div>
            <p>Configure your ServiceNow instance settings above and test the connection.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-cyan-900/50 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-cyan-400 font-semibold text-xs">2</span>
            </div>
            <p>Navigate to any vulnerability in your scans.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-cyan-900/50 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-cyan-400 font-semibold text-xs">3</span>
            </div>
            <p>Use the ServiceNow dropdown to create an Incident or Change Request with vulnerability details.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-cyan-900/50 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-cyan-400 font-semibold text-xs">4</span>
            </div>
            <p>Tickets are linked to vulnerabilities and can be tracked in HeroForge.</p>
          </div>
        </div>
      </Card>

      <Card>
        <h4 className="text-md font-semibold text-gray-100 mb-4">ServiceNow Table API Reference</h4>
        <div className="text-sm text-gray-400 space-y-2">
          <p>HeroForge uses the ServiceNow Table API to create tickets:</p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li><code className="text-cyan-400">/api/now/table/incident</code> - Create incidents</li>
            <li><code className="text-cyan-400">/api/now/table/change_request</code> - Create change requests</li>
            <li><code className="text-cyan-400">/api/now/table/sys_user_group</code> - List assignment groups</li>
          </ul>
          <p className="mt-3">
            Ensure your ServiceNow user has the following roles: <code className="text-cyan-400">itil</code> or <code className="text-cyan-400">rest_api_explorer</code>.
          </p>
        </div>
      </Card>
    </div>
  );
};

export default ServiceNowSettings;
