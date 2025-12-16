import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { notificationAPI } from '../../services/api';
import { NotificationSettings as NotificationSettingsType } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Bell, Mail, AlertTriangle, Save, CheckCircle, MessageSquare, Send } from 'lucide-react';

const NotificationSettings: React.FC = () => {
  const [settings, setSettings] = useState<NotificationSettingsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testingTeams, setTestingTeams] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [smtpConfigured, setSmtpConfigured] = useState<boolean | null>(null);
  const [formData, setFormData] = useState({
    email_on_scan_complete: false,
    email_on_critical_vuln: true,
    email_address: '',
    slack_webhook_url: '',
    teams_webhook_url: '',
  });

  useEffect(() => {
    loadSettings();
    checkSmtpStatus();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const response = await notificationAPI.getSettings();
      setSettings(response.data);
      setFormData({
        email_on_scan_complete: response.data.email_on_scan_complete,
        email_on_critical_vuln: response.data.email_on_critical_vuln,
        email_address: response.data.email_address || '',
        slack_webhook_url: response.data.slack_webhook_url || '',
        teams_webhook_url: response.data.teams_webhook_url || '',
      });
    } catch (error: any) {
      // 404 means no settings yet - use defaults
      if (error.response?.status !== 404) {
        toast.error('Failed to load notification settings');
        console.error(error);
      }
    } finally {
      setLoading(false);
    }
  };

  const checkSmtpStatus = async () => {
    try {
      const response = await notificationAPI.checkSmtpStatus();
      setSmtpConfigured(response.data.configured);
    } catch (error) {
      console.error('Failed to check SMTP status:', error);
      setSmtpConfigured(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if ((formData.email_on_scan_complete || formData.email_on_critical_vuln) && !formData.email_address) {
      toast.error('Email address is required when notifications are enabled');
      return;
    }

    setSaving(true);
    try {
      const response = await notificationAPI.updateSettings(formData);
      setSettings(response.data);
      toast.success('Notification settings saved');
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleTestSlack = async () => {
    if (!formData.slack_webhook_url) {
      toast.error('Please enter a Slack webhook URL first');
      return;
    }

    setTestingSlack(true);
    try {
      // Save first if there are unsaved changes
      if (formData.slack_webhook_url !== settings?.slack_webhook_url) {
        await notificationAPI.updateSettings({ slack_webhook_url: formData.slack_webhook_url });
      }

      const response = await notificationAPI.testSlack();
      toast.success(response.data.message);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to send test message');
    } finally {
      setTestingSlack(false);
    }
  };

  const handleTestTeams = async () => {
    if (!formData.teams_webhook_url) {
      toast.error('Please enter a Teams webhook URL first');
      return;
    }

    setTestingTeams(true);
    try {
      // Save first if there are unsaved changes
      if (formData.teams_webhook_url !== settings?.teams_webhook_url) {
        await notificationAPI.updateSettings({ teams_webhook_url: formData.teams_webhook_url });
      }

      const response = await notificationAPI.testTeams();
      toast.success(response.data.message);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to send test message');
    } finally {
      setTestingTeams(false);
    }
  };

  const handleTestEmail = async () => {
    if (!formData.email_address) {
      toast.error('Please enter an email address first');
      return;
    }

    if (!smtpConfigured) {
      toast.error('SMTP is not configured on the server. Contact your administrator.');
      return;
    }

    setTestingEmail(true);
    try {
      // Save first if there are unsaved changes
      if (formData.email_address !== settings?.email_address) {
        await notificationAPI.updateSettings({ email_address: formData.email_address });
      }

      const response = await notificationAPI.testEmail();
      toast.success(response.data.message);
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to send test email');
    } finally {
      setTestingEmail(false);
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
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-2 mb-6">
          <Bell className="h-5 w-5 text-primary" />
          <h3 className="text-xl font-semibold text-white">Notification Settings</h3>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Email Address */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Notification Email Address
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="email"
                  value={formData.email_address}
                  onChange={(e) => setFormData({ ...formData, email_address: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg pl-10 pr-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="your@email.com"
                />
              </div>
              <Button
                type="button"
                variant="secondary"
                onClick={handleTestEmail}
                disabled={!formData.email_address || testingEmail || !smtpConfigured}
                title={!smtpConfigured ? 'SMTP not configured on server' : 'Send test email'}
              >
                {testingEmail ? (
                  <>
                    <LoadingSpinner />
                    <span className="ml-2">Sending...</span>
                  </>
                ) : (
                  <>
                    <Send className="h-4 w-4 mr-2" />
                    Test
                  </>
                )}
              </Button>
            </div>
            <div className="flex items-center justify-between mt-1">
              <p className="text-xs text-slate-500">
                Email address where notifications will be sent
              </p>
              {smtpConfigured !== null && (
                <span className={`text-xs flex items-center gap-1 ${smtpConfigured ? 'text-green-400' : 'text-amber-400'}`}>
                  {smtpConfigured ? (
                    <>
                      <CheckCircle className="h-3 w-3" />
                      SMTP configured
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="h-3 w-3" />
                      SMTP not configured
                    </>
                  )}
                </span>
              )}
            </div>
          </div>

          {/* Notification Options */}
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-slate-300">Email Notifications</h4>

            {/* Scan Complete */}
            <label className="flex items-start gap-4 p-4 bg-dark-bg rounded-lg border border-dark-border cursor-pointer hover:border-primary/50 transition-colors">
              <input
                type="checkbox"
                checked={formData.email_on_scan_complete}
                onChange={(e) =>
                  setFormData({ ...formData, email_on_scan_complete: e.target.checked })
                }
                className="mt-1 w-4 h-4 rounded border-dark-border bg-dark-surface text-primary focus:ring-primary"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="font-medium text-white">Scan Completion</span>
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  Receive an email when any of your scans complete, including a summary of findings
                </p>
              </div>
            </label>

            {/* Critical Vulnerabilities */}
            <label className="flex items-start gap-4 p-4 bg-dark-bg rounded-lg border border-dark-border cursor-pointer hover:border-primary/50 transition-colors">
              <input
                type="checkbox"
                checked={formData.email_on_critical_vuln}
                onChange={(e) =>
                  setFormData({ ...formData, email_on_critical_vuln: e.target.checked })
                }
                className="mt-1 w-4 h-4 rounded border-dark-border bg-dark-surface text-primary focus:ring-primary"
              />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  <span className="font-medium text-white">Critical Vulnerabilities</span>
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  Get immediate alerts when critical or high severity vulnerabilities are discovered
                </p>
              </div>
            </label>
          </div>

          {/* Info Box - Show different message based on SMTP status */}
          {smtpConfigured === false ? (
            <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5" />
                <div>
                  <p className="text-sm text-amber-200">
                    SMTP is not configured on this server. Email notifications are disabled.
                  </p>
                  <p className="text-xs text-amber-300/70 mt-1">
                    Contact your administrator to configure SMTP settings (SMTP_HOST, SMTP_USER, etc.)
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg">
              <div className="flex items-start gap-3">
                <Mail className="h-5 w-5 text-blue-400 mt-0.5" />
                <div>
                  <p className="text-sm text-blue-200">
                    {smtpConfigured
                      ? 'Email notifications are ready. Use the Test button to verify delivery.'
                      : 'Checking SMTP configuration...'}
                  </p>
                  <p className="text-xs text-blue-300/70 mt-1">
                    Contact your administrator if you're not receiving emails.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Webhook Integrations */}
          <div className="space-y-4 pt-4 border-t border-dark-border">
            <h4 className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <MessageSquare className="h-4 w-4" />
              Webhook Integrations
            </h4>

            {/* Slack Webhook */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Slack Webhook URL
              </label>
              <div className="flex gap-2">
                <input
                  type="url"
                  value={formData.slack_webhook_url}
                  onChange={(e) => setFormData({ ...formData, slack_webhook_url: e.target.value })}
                  className="flex-1 bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
                />
                <Button
                  type="button"
                  variant="secondary"
                  onClick={handleTestSlack}
                  disabled={!formData.slack_webhook_url || testingSlack}
                >
                  {testingSlack ? (
                    <>
                      <LoadingSpinner />
                      <span className="ml-2">Testing...</span>
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4 mr-2" />
                      Test
                    </>
                  )}
                </Button>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Send scan notifications to a Slack channel. Create a webhook at{' '}
                <a
                  href="https://api.slack.com/messaging/webhooks"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  Slack Incoming Webhooks
                </a>
              </p>
            </div>

            {/* Teams Webhook */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Microsoft Teams Webhook URL
              </label>
              <div className="flex gap-2">
                <input
                  type="url"
                  value={formData.teams_webhook_url}
                  onChange={(e) => setFormData({ ...formData, teams_webhook_url: e.target.value })}
                  className="flex-1 bg-dark-bg border border-dark-border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="https://outlook.office.com/webhook/YOUR/WEBHOOK/URL"
                />
                <Button
                  type="button"
                  variant="secondary"
                  onClick={handleTestTeams}
                  disabled={!formData.teams_webhook_url || testingTeams}
                >
                  {testingTeams ? (
                    <>
                      <LoadingSpinner />
                      <span className="ml-2">Testing...</span>
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4 mr-2" />
                      Test
                    </>
                  )}
                </Button>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Send scan notifications to a Teams channel. Create a webhook in your Teams channel connectors.
              </p>
            </div>
          </div>

          {/* Submit Button */}
          <div className="flex justify-end">
            <Button type="submit" variant="primary" disabled={saving}>
              {saving ? (
                <>
                  <LoadingSpinner />
                  <span className="ml-2">Saving...</span>
                </>
              ) : (
                <>
                  <Save className="h-4 w-4 mr-2" />
                  Save Settings
                </>
              )}
            </Button>
          </div>
        </form>
      </Card>

      {/* Status Card */}
      {settings && (
        <Card>
          <h4 className="text-sm font-medium text-slate-300 mb-3">Current Status</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-slate-500">Scan Complete Emails:</span>
              <span className={`ml-2 ${settings.email_on_scan_complete ? 'text-green-400' : 'text-slate-400'}`}>
                {settings.email_on_scan_complete ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div>
              <span className="text-slate-500">Critical Vuln Alerts:</span>
              <span className={`ml-2 ${settings.email_on_critical_vuln ? 'text-green-400' : 'text-slate-400'}`}>
                {settings.email_on_critical_vuln ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div className="col-span-2">
              <span className="text-slate-500">Last Updated:</span>
              <span className="ml-2 text-slate-300">
                {new Date(settings.updated_at).toLocaleString()}
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

export default NotificationSettings;
