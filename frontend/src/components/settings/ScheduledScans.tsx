import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { scheduledScanAPI, targetGroupAPI } from '../../services/api';
import { ScheduledScan, ScheduledScanConfig, TargetGroup } from '../../types';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';
import ConfirmationDialog from '../ui/ConfirmationDialog';
import { Clock, Plus, Edit2, Trash2, Play, Pause, Calendar, Save, X } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

type ScheduleType = 'daily' | 'weekly' | 'monthly';

interface FormData {
  name: string;
  description: string;
  schedule_type: ScheduleType;
  schedule_value: string;
  targets: string;
  port_range_start: number;
  port_range_end: number;
  threads: number;
  enable_os_detection: boolean;
  enable_service_detection: boolean;
  enable_vuln_scan: boolean;
  enable_enumeration: boolean;
}

const defaultFormData: FormData = {
  name: '',
  description: '',
  schedule_type: 'daily',
  schedule_value: '02:00',
  targets: '',
  port_range_start: 1,
  port_range_end: 1000,
  threads: 100,
  enable_os_detection: true,
  enable_service_detection: true,
  enable_vuln_scan: true,
  enable_enumeration: false,
};

const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

const ScheduledScans: React.FC = () => {
  const [scans, setScans] = useState<ScheduledScan[]>([]);
  const [targetGroups, setTargetGroups] = useState<TargetGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<FormData>(defaultFormData);
  const [selectedDay, setSelectedDay] = useState(0);
  const [selectedDayOfMonth, setSelectedDayOfMonth] = useState(1);
  const [deleteConfirm, setDeleteConfirm] = useState<ScheduledScan | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [scansRes, groupsRes] = await Promise.all([
        scheduledScanAPI.getAll(),
        targetGroupAPI.getAll(),
      ]);
      setScans(scansRes.data);
      setTargetGroups(groupsRes.data);
    } catch (error) {
      toast.error('Failed to load scheduled scans');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData(defaultFormData);
    setEditingId(null);
    setShowForm(false);
    setSelectedDay(0);
    setSelectedDayOfMonth(1);
  };

  const handleEdit = (scan: ScheduledScan) => {
    const config: ScheduledScanConfig = JSON.parse(scan.config);
    setFormData({
      name: scan.name,
      description: scan.description || '',
      schedule_type: scan.schedule_type as ScheduleType,
      schedule_value: scan.schedule_value,
      targets: config.targets.join('\n'),
      port_range_start: config.port_range[0],
      port_range_end: config.port_range[1],
      threads: config.threads,
      enable_os_detection: config.enable_os_detection,
      enable_service_detection: config.enable_service_detection,
      enable_vuln_scan: config.enable_vuln_scan,
      enable_enumeration: config.enable_enumeration,
    });

    // Parse schedule value for weekly/monthly
    if (scan.schedule_type === 'weekly') {
      const parts = scan.schedule_value.split(' ');
      if (parts.length >= 2) {
        setSelectedDay(parseInt(parts[1]) || 0);
      }
    } else if (scan.schedule_type === 'monthly') {
      const parts = scan.schedule_value.split(' ');
      if (parts.length >= 2) {
        setSelectedDayOfMonth(parseInt(parts[1]) || 1);
      }
    }

    setEditingId(scan.id);
    setShowForm(true);
  };

  const buildScheduleValue = (): string => {
    const time = formData.schedule_value.includes(':') ? formData.schedule_value : '02:00';
    switch (formData.schedule_type) {
      case 'daily':
        return time;
      case 'weekly':
        return `${time} ${selectedDay}`;
      case 'monthly':
        return `${time} ${selectedDayOfMonth}`;
      default:
        return time;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const targets = formData.targets
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    if (!formData.name.trim()) {
      toast.error('Name is required');
      return;
    }
    if (targets.length === 0) {
      toast.error('At least one target is required');
      return;
    }

    const config: ScheduledScanConfig = {
      targets,
      port_range: [formData.port_range_start, formData.port_range_end],
      threads: formData.threads,
      enable_os_detection: formData.enable_os_detection,
      enable_service_detection: formData.enable_service_detection,
      enable_vuln_scan: formData.enable_vuln_scan,
      enable_enumeration: formData.enable_enumeration,
    };

    const scheduleValue = buildScheduleValue();

    try {
      if (editingId) {
        await scheduledScanAPI.update(editingId, {
          name: formData.name,
          description: formData.description || undefined,
          config,
          schedule_type: formData.schedule_type,
          schedule_value: scheduleValue,
        });
        toast.success('Scheduled scan updated');
      } else {
        await scheduledScanAPI.create({
          name: formData.name,
          description: formData.description || undefined,
          config,
          schedule_type: formData.schedule_type,
          schedule_value: scheduleValue,
        });
        toast.success('Scheduled scan created');
      }
      resetForm();
      loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to save scheduled scan');
    }
  };

  const handleToggleActive = async (scan: ScheduledScan) => {
    try {
      await scheduledScanAPI.update(scan.id, { is_active: !scan.is_active });
      toast.success(`Scheduled scan ${scan.is_active ? 'paused' : 'activated'}`);
      loadData();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to update');
    }
  };

  const handleDelete = async () => {
    if (!deleteConfirm) return;

    setIsDeleting(true);
    try {
      await scheduledScanAPI.delete(deleteConfirm.id);
      toast.success(`Scheduled scan "${deleteConfirm.name}" deleted`);
      loadData();
      setDeleteConfirm(null);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to delete');
    } finally {
      setIsDeleting(false);
    }
  };

  const useTargetGroup = (group: TargetGroup) => {
    const targets = JSON.parse(group.targets || '[]');
    setFormData((prev) => ({
      ...prev,
      targets: targets.join('\n'),
    }));
  };

  const formatSchedule = (scan: ScheduledScan): string => {
    const parts = scan.schedule_value.split(' ');
    const time = parts[0];
    switch (scan.schedule_type) {
      case 'daily':
        return `Daily at ${time}`;
      case 'weekly':
        return `Every ${WEEKDAYS[parseInt(parts[1]) || 0]} at ${time}`;
      case 'monthly':
        return `Monthly on day ${parts[1] || 1} at ${time}`;
      default:
        return scan.schedule_value;
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
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-primary" />
            <h3 className="text-xl font-semibold text-white">Scheduled Scans</h3>
          </div>
          {!showForm && (
            <Button variant="primary" onClick={() => setShowForm(true)}>
              <Plus className="h-4 w-4 mr-2" />
              New Schedule
            </Button>
          )}
        </div>
      </Card>

      {showForm && (
        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-lg font-medium text-white">
                {editingId ? 'Edit Scheduled Scan' : 'Create Scheduled Scan'}
              </h4>
              <button type="button" onClick={resetForm} className="text-slate-400 hover:text-white">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Daily Network Scan"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">Description</label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                  placeholder="Optional description"
                />
              </div>
            </div>

            {/* Schedule Configuration */}
            <div className="p-4 bg-dark-bg rounded-lg border border-dark-border">
              <h5 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                <Calendar className="h-4 w-4" /> Schedule
              </h5>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Frequency</label>
                  <select
                    value={formData.schedule_type}
                    onChange={(e) =>
                      setFormData({ ...formData, schedule_type: e.target.value as ScheduleType })
                    }
                    className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                {formData.schedule_type === 'weekly' && (
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Day of Week</label>
                    <select
                      value={selectedDay}
                      onChange={(e) => setSelectedDay(parseInt(e.target.value))}
                      className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                    >
                      {WEEKDAYS.map((day, i) => (
                        <option key={day} value={i}>
                          {day}
                        </option>
                      ))}
                    </select>
                  </div>
                )}
                {formData.schedule_type === 'monthly' && (
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Day of Month</label>
                    <select
                      value={selectedDayOfMonth}
                      onChange={(e) => setSelectedDayOfMonth(parseInt(e.target.value))}
                      className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                    >
                      {Array.from({ length: 28 }, (_, i) => i + 1).map((day) => (
                        <option key={day} value={day}>
                          {day}
                        </option>
                      ))}
                    </select>
                  </div>
                )}
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Time (UTC)</label>
                  <input
                    type="time"
                    value={formData.schedule_value.split(' ')[0]}
                    onChange={(e) => setFormData({ ...formData, schedule_value: e.target.value })}
                    className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white"
                  />
                </div>
              </div>
            </div>

            {/* Targets */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-sm font-medium text-slate-300">
                  Targets (one per line)
                </label>
                {targetGroups.length > 0 && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">Use group:</span>
                    {targetGroups.slice(0, 3).map((g) => (
                      <button
                        key={g.id}
                        type="button"
                        onClick={() => useTargetGroup(g)}
                        className="px-2 py-0.5 text-xs rounded border border-dark-border text-slate-400 hover:text-white hover:border-primary"
                        style={{ borderLeftColor: g.color, borderLeftWidth: 3 }}
                      >
                        {g.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <textarea
                value={formData.targets}
                onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-primary focus:border-transparent font-mono text-sm"
                rows={4}
                placeholder="192.168.1.0/24&#10;10.0.0.1"
              />
            </div>

            {/* Scan Options */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Port Start</label>
                <input
                  type="number"
                  value={formData.port_range_start}
                  onChange={(e) =>
                    setFormData({ ...formData, port_range_start: parseInt(e.target.value) || 1 })
                  }
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white"
                  min={1}
                  max={65535}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Port End</label>
                <input
                  type="number"
                  value={formData.port_range_end}
                  onChange={(e) =>
                    setFormData({ ...formData, port_range_end: parseInt(e.target.value) || 1000 })
                  }
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white"
                  min={1}
                  max={65535}
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Threads</label>
                <input
                  type="number"
                  value={formData.threads}
                  onChange={(e) =>
                    setFormData({ ...formData, threads: parseInt(e.target.value) || 100 })
                  }
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-3 py-2 text-white"
                  min={1}
                  max={1000}
                />
              </div>
            </div>

            {/* Feature Toggles */}
            <div className="flex flex-wrap gap-4">
              {[
                { key: 'enable_os_detection', label: 'OS Detection' },
                { key: 'enable_service_detection', label: 'Service Detection' },
                { key: 'enable_vuln_scan', label: 'Vulnerability Scan' },
                { key: 'enable_enumeration', label: 'Enumeration' },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData[key as keyof FormData] as boolean}
                    onChange={(e) => setFormData({ ...formData, [key]: e.target.checked })}
                    className="w-4 h-4 rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-slate-300">{label}</span>
                </label>
              ))}
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="secondary" onClick={resetForm}>
                Cancel
              </Button>
              <Button type="submit" variant="primary">
                <Save className="h-4 w-4 mr-2" />
                {editingId ? 'Update' : 'Create'}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {scans.length === 0 && !showForm ? (
        <Card>
          <div className="text-center py-12">
            <Clock className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">No scheduled scans</p>
            <p className="text-sm text-slate-500 mt-1">
              Create automated recurring scans
            </p>
          </div>
        </Card>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => {
            const config: ScheduledScanConfig = JSON.parse(scan.config);
            return (
              <Card key={scan.id}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-2 rounded-lg ${
                        scan.is_active ? 'bg-green-500/20' : 'bg-slate-500/20'
                      }`}
                    >
                      <Clock
                        className={`h-5 w-5 ${
                          scan.is_active ? 'text-green-400' : 'text-slate-400'
                        }`}
                      />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="font-medium text-white">{scan.name}</h4>
                        <Badge
                          variant="status"
                          type={scan.is_active ? 'completed' : 'pending'}
                        >
                          {scan.is_active ? 'Active' : 'Paused'}
                        </Badge>
                      </div>
                      <p className="text-sm text-slate-400">{formatSchedule(scan)}</p>
                      <p className="text-xs text-slate-500 mt-1">
                        {config.targets.length} target{config.targets.length !== 1 ? 's' : ''} |
                        Ports {config.port_range[0]}-{config.port_range[1]} |
                        {scan.run_count} runs
                        {scan.last_run_at && (
                          <> | Last run {formatDistanceToNow(new Date(scan.last_run_at))} ago</>
                        )}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleToggleActive(scan)}
                      className={`p-2 rounded transition-colors ${
                        scan.is_active
                          ? 'text-yellow-400 hover:bg-yellow-500/20'
                          : 'text-green-400 hover:bg-green-500/20'
                      }`}
                      title={scan.is_active ? 'Pause' : 'Activate'}
                    >
                      {scan.is_active ? (
                        <Pause className="h-4 w-4" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                    </button>
                    <button
                      onClick={() => handleEdit(scan)}
                      className="p-2 text-slate-400 hover:text-primary transition-colors"
                    >
                      <Edit2 className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(scan)}
                      className="p-2 text-slate-400 hover:text-red-400 transition-colors"
                      aria-label={`Delete scheduled scan ${scan.name}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Delete Scheduled Scan Confirmation Dialog */}
      <ConfirmationDialog
        isOpen={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        onConfirm={handleDelete}
        title="Delete Scheduled Scan"
        message={`Are you sure you want to delete the scheduled scan "${deleteConfirm?.name}"? Future automated scans will no longer run.`}
        confirmLabel="Delete Schedule"
        variant="warning"
        loading={isDeleting}
      />
    </div>
  );
};

export default ScheduledScans;
