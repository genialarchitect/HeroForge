import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import {
  Webhook,
  Plus,
  Trash2,
  Edit2,
  TestTube2,
  History,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertCircle,
  Copy,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { webhooksAPI } from '../../services/api';
import type {
  Webhook as WebhookType,
  WebhookDelivery,
  WebhookEventTypeInfo,
  WebhookTestResponse,
  CreateWebhookRequest,
  UpdateWebhookRequest,
} from '../../types';

// Event type display names
const EVENT_DISPLAY_NAMES: Record<string, string> = {
  'scan.started': 'Scan Started',
  'scan.completed': 'Scan Completed',
  'scan.failed': 'Scan Failed',
  'vulnerability.found': 'Vulnerability Found',
  'vulnerability.critical': 'Critical Vulnerability',
  'vulnerability.resolved': 'Vulnerability Resolved',
  'asset.discovered': 'Asset Discovered',
  'compliance.violation': 'Compliance Violation',
};

export default function WebhookSettings() {
  const [webhooks, setWebhooks] = useState<WebhookType[]>([]);
  const [eventTypes, setEventTypes] = useState<WebhookEventTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookType | null>(null);
  const [showDeliveriesModal, setShowDeliveriesModal] = useState(false);
  const [selectedWebhookId, setSelectedWebhookId] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loadingDeliveries, setLoadingDeliveries] = useState(false);
  const [testingWebhook, setTestingWebhook] = useState<string | null>(null);
  const [expandedDelivery, setExpandedDelivery] = useState<string | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formSecret, setFormSecret] = useState('');
  const [formEvents, setFormEvents] = useState<string[]>([]);
  const [formHeaders, setFormHeaders] = useState<{ key: string; value: string }[]>([]);
  const [formIsActive, setFormIsActive] = useState(true);
  const [showSecret, setShowSecret] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadWebhooks();
    loadEventTypes();
  }, []);

  const loadWebhooks = async () => {
    try {
      const response = await webhooksAPI.list();
      setWebhooks(response.data);
    } catch (error) {
      console.error('Failed to load webhooks:', error);
      toast.error('Failed to load webhooks');
    } finally {
      setLoading(false);
    }
  };

  const loadEventTypes = async () => {
    try {
      const response = await webhooksAPI.getEventTypes();
      setEventTypes(response.data.event_types);
    } catch (error) {
      console.error('Failed to load event types:', error);
    }
  };

  const resetForm = () => {
    setFormName('');
    setFormUrl('');
    setFormSecret('');
    setFormEvents([]);
    setFormHeaders([]);
    setFormIsActive(true);
    setShowSecret(false);
    setEditingWebhook(null);
  };

  const openCreateForm = () => {
    resetForm();
    setShowForm(true);
  };

  const openEditForm = (webhook: WebhookType) => {
    setEditingWebhook(webhook);
    setFormName(webhook.name);
    setFormUrl(webhook.url);
    setFormSecret(''); // Don't prefill secret
    setFormEvents([...webhook.events]);
    setFormHeaders(
      webhook.headers
        ? Object.entries(webhook.headers).map(([key, value]) => ({ key, value }))
        : []
    );
    setFormIsActive(webhook.is_active);
    setShowForm(true);
  };

  const closeForm = () => {
    setShowForm(false);
    resetForm();
  };

  const handleGenerateSecret = async () => {
    try {
      const response = await webhooksAPI.generateSecret();
      setFormSecret(response.data.secret);
      setShowSecret(true);
      toast.success('Secret generated');
    } catch (error) {
      toast.error('Failed to generate secret');
    }
  };

  const handleCopySecret = () => {
    if (formSecret) {
      navigator.clipboard.writeText(formSecret);
      toast.success('Secret copied to clipboard');
    }
  };

  const handleAddHeader = () => {
    setFormHeaders([...formHeaders, { key: '', value: '' }]);
  };

  const handleRemoveHeader = (index: number) => {
    setFormHeaders(formHeaders.filter((_, i) => i !== index));
  };

  const handleHeaderChange = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...formHeaders];
    updated[index][field] = value;
    setFormHeaders(updated);
  };

  const toggleEvent = (eventId: string) => {
    if (formEvents.includes(eventId)) {
      setFormEvents(formEvents.filter((e) => e !== eventId));
    } else {
      setFormEvents([...formEvents, eventId]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formUrl.startsWith('http://') && !formUrl.startsWith('https://')) {
      toast.error('URL must start with http:// or https://');
      return;
    }

    if (formEvents.length === 0) {
      toast.error('Please select at least one event');
      return;
    }

    setSubmitting(true);

    try {
      const headers: Record<string, string> = {};
      formHeaders.forEach((h) => {
        if (h.key.trim() && h.value.trim()) {
          headers[h.key.trim()] = h.value.trim();
        }
      });

      if (editingWebhook) {
        // Update existing webhook
        const updateData: UpdateWebhookRequest = {
          name: formName,
          url: formUrl,
          events: formEvents as any,
          headers: Object.keys(headers).length > 0 ? headers : undefined,
          is_active: formIsActive,
        };
        if (formSecret) {
          updateData.secret = formSecret;
        }

        await webhooksAPI.update(editingWebhook.id, updateData);
        toast.success('Webhook updated');
      } else {
        // Create new webhook
        const createData: CreateWebhookRequest = {
          name: formName,
          url: formUrl,
          events: formEvents as any,
          headers: Object.keys(headers).length > 0 ? headers : undefined,
          is_active: formIsActive,
        };
        if (formSecret) {
          createData.secret = formSecret;
        }

        await webhooksAPI.create(createData);
        toast.success('Webhook created');
      }

      closeForm();
      loadWebhooks();
    } catch (error: any) {
      const message = error.response?.data?.error || 'Failed to save webhook';
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (webhookId: string, webhookName: string) => {
    if (!confirm(`Are you sure you want to delete the webhook "${webhookName}"?`)) {
      return;
    }

    try {
      await webhooksAPI.delete(webhookId);
      toast.success('Webhook deleted');
      loadWebhooks();
    } catch (error) {
      toast.error('Failed to delete webhook');
    }
  };

  const handleTest = async (webhookId: string) => {
    setTestingWebhook(webhookId);
    try {
      const response = await webhooksAPI.test(webhookId);
      const result = response.data;

      if (result.success) {
        toast.success(`Test successful (HTTP ${result.status_code})`);
      } else {
        toast.error(`Test failed: ${result.error || 'Unknown error'}`);
      }
    } catch (error: any) {
      const message = error.response?.data?.error || 'Failed to test webhook';
      toast.error(message);
    } finally {
      setTestingWebhook(null);
    }
  };

  const handleShowDeliveries = async (webhookId: string) => {
    setSelectedWebhookId(webhookId);
    setShowDeliveriesModal(true);
    setLoadingDeliveries(true);

    try {
      const response = await webhooksAPI.getDeliveries(webhookId, 50);
      setDeliveries(response.data);
    } catch (error) {
      toast.error('Failed to load delivery history');
      setDeliveries([]);
    } finally {
      setLoadingDeliveries(false);
    }
  };

  const getStatusIcon = (webhook: WebhookType) => {
    if (!webhook.is_active) {
      return <AlertCircle className="w-5 h-5 text-gray-500" />;
    }
    if (webhook.failure_count >= 5) {
      return <XCircle className="w-5 h-5 text-red-500" />;
    }
    if (webhook.last_status_code && webhook.last_status_code >= 200 && webhook.last_status_code < 300) {
      return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
    return <AlertCircle className="w-5 h-5 text-yellow-500" />;
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-100">Webhooks</h3>
          <p className="text-sm text-gray-400 mt-1">
            Send HTTP notifications to external systems when events occur
          </p>
        </div>
        <button
          onClick={openCreateForm}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Webhook
        </button>
      </div>

      {/* Webhooks List */}
      {webhooks.length === 0 ? (
        <div className="bg-gray-800/50 rounded-lg p-8 text-center">
          <Webhook className="w-12 h-12 mx-auto text-gray-500 mb-4" />
          <h4 className="text-lg font-medium text-gray-300">No webhooks configured</h4>
          <p className="text-sm text-gray-400 mt-2">
            Create a webhook to send notifications to external systems
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {webhooks.map((webhook) => (
            <div
              key={webhook.id}
              className="bg-gray-800/50 rounded-lg p-4 border border-gray-700"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  {getStatusIcon(webhook)}
                  <div>
                    <h4 className="font-medium text-gray-100">{webhook.name}</h4>
                    <p className="text-sm text-gray-400 mt-1 font-mono">{webhook.url}</p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {webhook.events.map((event) => (
                        <span
                          key={event}
                          className="px-2 py-0.5 text-xs bg-gray-700 text-gray-300 rounded"
                        >
                          {EVENT_DISPLAY_NAMES[event] || event}
                        </span>
                      ))}
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-sm text-gray-400">
                      <span>
                        Last triggered: {formatDate(webhook.last_triggered_at)}
                      </span>
                      {webhook.last_status_code && (
                        <span
                          className={
                            webhook.last_status_code >= 200 && webhook.last_status_code < 300
                              ? 'text-green-400'
                              : 'text-red-400'
                          }
                        >
                          HTTP {webhook.last_status_code}
                        </span>
                      )}
                      {webhook.failure_count > 0 && (
                        <span className="text-red-400">
                          {webhook.failure_count} failures
                        </span>
                      )}
                      {webhook.has_secret && (
                        <span className="text-cyan-400">Signed</span>
                      )}
                      {!webhook.is_active && (
                        <span className="text-gray-500">Disabled</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTest(webhook.id)}
                    disabled={testingWebhook === webhook.id}
                    className="p-2 text-gray-400 hover:text-cyan-400 transition-colors disabled:opacity-50"
                    title="Test webhook"
                  >
                    {testingWebhook === webhook.id ? (
                      <RefreshCw className="w-4 h-4 animate-spin" />
                    ) : (
                      <TestTube2 className="w-4 h-4" />
                    )}
                  </button>
                  <button
                    onClick={() => handleShowDeliveries(webhook.id)}
                    className="p-2 text-gray-400 hover:text-cyan-400 transition-colors"
                    title="View delivery history"
                  >
                    <History className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => openEditForm(webhook)}
                    className="p-2 text-gray-400 hover:text-cyan-400 transition-colors"
                    title="Edit webhook"
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(webhook.id, webhook.name)}
                    className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                    title="Delete webhook"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create/Edit Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-gray-100 mb-4">
              {editingWebhook ? 'Edit Webhook' : 'Create Webhook'}
            </h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Name
                </label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  placeholder="My Webhook"
                />
              </div>

              {/* URL */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  URL
                </label>
                <input
                  type="url"
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent font-mono text-sm"
                  placeholder="https://example.com/webhook"
                />
              </div>

              {/* Secret */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Secret Key (optional)
                </label>
                <p className="text-xs text-gray-400 mb-2">
                  If set, requests will include an X-Webhook-Signature header with HMAC-SHA256 signature
                </p>
                <div className="flex gap-2">
                  <div className="flex-1 relative">
                    <input
                      type={showSecret ? 'text' : 'password'}
                      value={formSecret}
                      onChange={(e) => setFormSecret(e.target.value)}
                      className="w-full px-3 py-2 pr-20 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 focus:ring-2 focus:ring-cyan-500 focus:border-transparent font-mono text-sm"
                      placeholder={editingWebhook?.has_secret ? '(unchanged)' : 'Enter or generate a secret'}
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                      <button
                        type="button"
                        onClick={() => setShowSecret(!showSecret)}
                        className="p-1 text-gray-400 hover:text-gray-200"
                      >
                        {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                      {formSecret && (
                        <button
                          type="button"
                          onClick={handleCopySecret}
                          className="p-1 text-gray-400 hover:text-gray-200"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={handleGenerateSecret}
                    className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg transition-colors"
                  >
                    Generate
                  </button>
                </div>
              </div>

              {/* Event Types */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Events
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {eventTypes.map((event) => (
                    <label
                      key={event.id}
                      className="flex items-start gap-2 p-3 bg-gray-700/50 rounded-lg cursor-pointer hover:bg-gray-700"
                    >
                      <input
                        type="checkbox"
                        checked={formEvents.includes(event.id)}
                        onChange={() => toggleEvent(event.id)}
                        className="mt-1 rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
                      />
                      <div>
                        <span className="text-sm font-medium text-gray-200">
                          {event.name}
                        </span>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {event.description}
                        </p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Custom Headers */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-gray-300">
                    Custom Headers (optional)
                  </label>
                  <button
                    type="button"
                    onClick={handleAddHeader}
                    className="text-sm text-cyan-400 hover:text-cyan-300"
                  >
                    + Add Header
                  </button>
                </div>
                {formHeaders.length > 0 && (
                  <div className="space-y-2">
                    {formHeaders.map((header, index) => (
                      <div key={index} className="flex gap-2">
                        <input
                          type="text"
                          value={header.key}
                          onChange={(e) => handleHeaderChange(index, 'key', e.target.value)}
                          placeholder="Header name"
                          className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 text-sm"
                        />
                        <input
                          type="text"
                          value={header.value}
                          onChange={(e) => handleHeaderChange(index, 'value', e.target.value)}
                          placeholder="Header value"
                          className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-100 text-sm"
                        />
                        <button
                          type="button"
                          onClick={() => handleRemoveHeader(index)}
                          className="p-2 text-gray-400 hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Active Toggle */}
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formIsActive}
                  onChange={(e) => setFormIsActive(e.target.checked)}
                  className="rounded border-gray-600 bg-gray-700 text-cyan-500 focus:ring-cyan-500"
                />
                <span className="text-sm text-gray-300">Enable webhook</span>
              </label>

              {/* Form Actions */}
              <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                <button
                  type="button"
                  onClick={closeForm}
                  className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  {submitting ? 'Saving...' : editingWebhook ? 'Save Changes' : 'Create Webhook'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delivery History Modal */}
      {showDeliveriesModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-100">
                Delivery History
              </h3>
              <button
                onClick={() => setShowDeliveriesModal(false)}
                className="text-gray-400 hover:text-white"
              >
                Close
              </button>
            </div>

            {loadingDeliveries ? (
              <div className="flex items-center justify-center py-12">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
              </div>
            ) : deliveries.length === 0 ? (
              <div className="text-center py-12 text-gray-400">
                No deliveries yet
              </div>
            ) : (
              <div className="space-y-3">
                {deliveries.map((delivery) => (
                  <div
                    key={delivery.id}
                    className="bg-gray-700/50 rounded-lg border border-gray-600"
                  >
                    <div
                      className="flex items-center justify-between p-4 cursor-pointer"
                      onClick={() =>
                        setExpandedDelivery(
                          expandedDelivery === delivery.id ? null : delivery.id
                        )
                      }
                    >
                      <div className="flex items-center gap-3">
                        {delivery.response_status &&
                        delivery.response_status >= 200 &&
                        delivery.response_status < 300 ? (
                          <CheckCircle className="w-5 h-5 text-green-500" />
                        ) : (
                          <XCircle className="w-5 h-5 text-red-500" />
                        )}
                        <div>
                          <span className="font-medium text-gray-200">
                            {EVENT_DISPLAY_NAMES[delivery.event_type] || delivery.event_type}
                          </span>
                          <span className="text-sm text-gray-400 ml-3">
                            {formatDate(delivery.delivered_at)}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {delivery.response_status && (
                          <span
                            className={
                              delivery.response_status >= 200 && delivery.response_status < 300
                                ? 'text-green-400'
                                : 'text-red-400'
                            }
                          >
                            HTTP {delivery.response_status}
                          </span>
                        )}
                        {delivery.error && (
                          <span className="text-red-400 text-sm">{delivery.error}</span>
                        )}
                        {expandedDelivery === delivery.id ? (
                          <ChevronUp className="w-4 h-4 text-gray-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-gray-400" />
                        )}
                      </div>
                    </div>
                    {expandedDelivery === delivery.id && (
                      <div className="px-4 pb-4 border-t border-gray-600 pt-4">
                        <div className="mb-3">
                          <h5 className="text-sm font-medium text-gray-400 mb-2">
                            Request Payload
                          </h5>
                          <pre className="bg-gray-900 p-3 rounded text-xs text-gray-300 overflow-x-auto">
                            {JSON.stringify(JSON.parse(delivery.payload || '{}'), null, 2)}
                          </pre>
                        </div>
                        {delivery.response_body && (
                          <div>
                            <h5 className="text-sm font-medium text-gray-400 mb-2">
                              Response Body
                            </h5>
                            <pre className="bg-gray-900 p-3 rounded text-xs text-gray-300 overflow-x-auto max-h-48">
                              {delivery.response_body}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
