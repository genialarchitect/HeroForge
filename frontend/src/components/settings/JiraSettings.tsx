import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { jiraAPI } from '../../services/api';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { CheckCircle, AlertTriangle, ExternalLink, Settings } from 'lucide-react';

interface JiraSettings {
  jira_url: string;
  username: string;
  api_token: string;
  project_key: string;
  issue_type: string;
  default_assignee?: string;
  enabled: boolean;
}

interface JiraProject {
  id: string;
  key: string;
  name: string;
}

interface JiraIssueType {
  id: string;
  name: string;
  description?: string;
}

const JiraSettings: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [configured, setConfigured] = useState(false);

  const [settings, setSettings] = useState<JiraSettings>({
    jira_url: '',
    username: '',
    api_token: '',
    project_key: '',
    issue_type: 'Task',
    default_assignee: '',
    enabled: true,
  });

  const [projects, setProjects] = useState<JiraProject[]>([]);
  const [issueTypes, setIssueTypes] = useState<JiraIssueType[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await jiraAPI.getSettings();
      setSettings(response.data);
      setConfigured(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        setConfigured(false);
      } else {
        console.error('Failed to load JIRA settings:', error);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!settings.jira_url || !settings.username || !settings.api_token || !settings.project_key) {
      toast.error('Please fill in all required fields');
      return;
    }

    setSaving(true);
    try {
      await jiraAPI.updateSettings(settings);
      toast.success('JIRA settings saved successfully');
      setConfigured(true);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to save JIRA settings:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to save JIRA settings');
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
      await jiraAPI.testConnection();
      toast.success('JIRA connection successful!');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('JIRA connection failed:', error);
      toast.error(axiosError.response?.data?.error || 'JIRA connection failed');
    } finally {
      setTesting(false);
    }
  };

  const handleLoadProjects = async () => {
    if (!configured) {
      toast.error('Please save your settings first');
      return;
    }

    setLoadingProjects(true);
    try {
      const response = await jiraAPI.listProjects();
      setProjects(response.data);
      toast.success(`Loaded ${response.data.length} projects`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to load projects:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to load projects');
    } finally {
      setLoadingProjects(false);
    }
  };

  const handleLoadIssueTypes = async () => {
    if (!configured || !settings.project_key) {
      toast.error('Please save your settings and select a project first');
      return;
    }

    setLoadingProjects(true);
    try {
      const response = await jiraAPI.listIssueTypes();
      setIssueTypes(response.data);
      toast.success(`Loaded ${response.data.length} issue types`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      console.error('Failed to load issue types:', error);
      toast.error(axiosError.response?.data?.error || 'Failed to load issue types');
    } finally {
      setLoadingProjects(false);
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
      <Card>
        <div className="flex items-center gap-3 mb-6">
          <Settings className="h-6 w-6 text-blue-500" />
          <h3 className="text-lg font-semibold text-gray-900">JIRA Integration</h3>
        </div>

        <div className="space-y-4">
          {!configured && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-1">JIRA Integration Not Configured</p>
                <p>Configure your JIRA instance to automatically create tickets from vulnerabilities.</p>
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              JIRA URL <span className="text-red-500">*</span>
            </label>
            <Input
              type="url"
              placeholder="https://your-domain.atlassian.net"
              value={settings.jira_url}
              onChange={(e) => setSettings({ ...settings, jira_url: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">Your JIRA instance URL (e.g., https://company.atlassian.net)</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Username/Email <span className="text-red-500">*</span>
            </label>
            <Input
              type="text"
              placeholder="user@example.com"
              value={settings.username}
              onChange={(e) => setSettings({ ...settings, username: e.target.value })}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              API Token <span className="text-red-500">*</span>
            </label>
            <Input
              type="password"
              placeholder="Your JIRA API token"
              value={settings.api_token}
              onChange={(e) => setSettings({ ...settings, api_token: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">
              Generate an API token at{' '}
              <a
                href="https://id.atlassian.com/manage-profile/security/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-700 inline-flex items-center gap-1"
              >
                Atlassian Account Settings <ExternalLink className="h-3 w-3" />
              </a>
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Project Key <span className="text-red-500">*</span>
            </label>
            <div className="flex gap-2">
              <div className="flex-1">
                {projects.length > 0 ? (
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={settings.project_key}
                    onChange={(e) => setSettings({ ...settings, project_key: e.target.value })}
                  >
                    <option value="">Select a project</option>
                    {projects.map((project) => (
                      <option key={project.key} value={project.key}>
                        {project.name} ({project.key})
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input
                    type="text"
                    placeholder="PROJECT"
                    value={settings.project_key}
                    onChange={(e) => setSettings({ ...settings, project_key: e.target.value })}
                  />
                )}
              </div>
              <Button
                onClick={handleLoadProjects}
                disabled={!configured || loadingProjects}
                variant="secondary"
              >
                {loadingProjects ? 'Loading...' : 'Load Projects'}
              </Button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Issue Type <span className="text-red-500">*</span>
            </label>
            <div className="flex gap-2">
              <div className="flex-1">
                {issueTypes.length > 0 ? (
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    value={settings.issue_type}
                    onChange={(e) => setSettings({ ...settings, issue_type: e.target.value })}
                  >
                    {issueTypes.map((type) => (
                      <option key={type.id} value={type.name}>
                        {type.name}
                      </option>
                    ))}
                  </select>
                ) : (
                  <Input
                    type="text"
                    placeholder="Task"
                    value={settings.issue_type}
                    onChange={(e) => setSettings({ ...settings, issue_type: e.target.value })}
                  />
                )}
              </div>
              <Button
                onClick={handleLoadIssueTypes}
                disabled={!configured || !settings.project_key || loadingProjects}
                variant="secondary"
              >
                {loadingProjects ? 'Loading...' : 'Load Types'}
              </Button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Default Assignee (optional)
            </label>
            <Input
              type="text"
              placeholder="username"
              value={settings.default_assignee || ''}
              onChange={(e) => setSettings({ ...settings, default_assignee: e.target.value })}
            />
            <p className="mt-1 text-xs text-gray-500">Leave empty for unassigned or enter a JIRA username</p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="jira-enabled"
              checked={settings.enabled}
              onChange={(e) => setSettings({ ...settings, enabled: e.target.checked })}
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="jira-enabled" className="text-sm font-medium text-gray-700">
              Enable JIRA integration
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
            <div className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-start gap-3">
              <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 flex-shrink-0" />
              <div className="text-sm text-green-800">
                <p className="font-medium">JIRA Integration Configured</p>
                <p>You can now create JIRA tickets from vulnerabilities.</p>
              </div>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <h4 className="text-md font-semibold text-gray-900 mb-4">How to Use JIRA Integration</h4>
        <div className="space-y-3 text-sm text-gray-600">
          <div className="flex items-start gap-3">
            <div className="bg-blue-100 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-700 font-semibold text-xs">1</span>
            </div>
            <p>Configure your JIRA instance settings above and test the connection.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-blue-100 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-700 font-semibold text-xs">2</span>
            </div>
            <p>Navigate to any vulnerability in your scans.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-blue-100 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-700 font-semibold text-xs">3</span>
            </div>
            <p>Click the "Create JIRA Ticket" button to automatically create an issue with vulnerability details.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="bg-blue-100 rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 mt-0.5">
              <span className="text-blue-700 font-semibold text-xs">4</span>
            </div>
            <p>The vulnerability will be linked to the JIRA ticket, and you can track it in your JIRA project.</p>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default JiraSettings;
