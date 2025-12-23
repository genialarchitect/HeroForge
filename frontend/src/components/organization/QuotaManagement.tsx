import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { quotasAPI } from '../../services/api';
import type { UpdateQuotasRequest } from '../../types';

interface QuotaManagementProps {
  orgId: string;
  isOwner: boolean;
}

interface QuotaFieldProps {
  label: string;
  value: number;
  onChange: (value: number) => void;
  disabled?: boolean;
  description?: string;
}

function QuotaField({ label, value, onChange, disabled, description }: QuotaFieldProps) {
  return (
    <div className="mb-4">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
      </label>
      <input
        type="number"
        min="0"
        value={value}
        onChange={(e) => onChange(parseInt(e.target.value, 10) || 0)}
        disabled={disabled}
        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md
          bg-white dark:bg-gray-700 text-gray-900 dark:text-white
          focus:ring-2 focus:ring-blue-500 focus:border-blue-500
          disabled:bg-gray-100 dark:disabled:bg-gray-800 disabled:cursor-not-allowed"
      />
      {description && (
        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{description}</p>
      )}
    </div>
  );
}

export function QuotaManagement({ orgId, isOwner }: QuotaManagementProps) {
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState<UpdateQuotasRequest>({
    max_users: 10,
    max_scans_per_day: 50,
    max_concurrent_scans: 5,
    max_assets: 1000,
    max_reports_per_month: 100,
    max_storage_mb: 5120,
    max_api_requests_per_hour: 1000,
    max_scheduled_scans: 20,
    max_teams: 10,
  });

  const { data, isLoading, error } = useQuery({
    queryKey: ['quotas', orgId],
    queryFn: () => quotasAPI.getQuotas(orgId),
    enabled: !!orgId,
  });

  // Update form data when query data is loaded
  useEffect(() => {
    if (data?.data) {
      setFormData({
        max_users: data.data.max_users ?? 10,
        max_scans_per_day: data.data.max_scans_per_day ?? 50,
        max_concurrent_scans: data.data.max_concurrent_scans ?? 5,
        max_assets: data.data.max_assets ?? 1000,
        max_reports_per_month: data.data.max_reports_per_month ?? 100,
        max_storage_mb: data.data.max_storage_mb ?? 5120,
        max_api_requests_per_hour: data.data.max_api_requests_per_hour ?? 1000,
        max_scheduled_scans: data.data.max_scheduled_scans ?? 20,
        max_teams: data.data.max_teams ?? 10,
      });
    }
  }, [data]);

  const updateMutation = useMutation({
    mutationFn: (updateData: UpdateQuotasRequest) => quotasAPI.updateQuotas(orgId, updateData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quotas', orgId] });
      queryClient.invalidateQueries({ queryKey: ['quotaUsage', orgId] });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateMutation.mutate(formData);
  };

  const updateField = (field: keyof UpdateQuotasRequest, value: number) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
          Quota Settings
        </h3>
        <div className="animate-pulse space-y-4">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i}>
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-2" />
              <div className="h-10 bg-gray-200 dark:bg-gray-700 rounded" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
          Quota Settings
        </h3>
        <p className="text-red-500">Failed to load quota settings</p>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        Quota Settings
      </h3>

      {!isOwner && (
        <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
          <p className="text-sm text-yellow-700 dark:text-yellow-300">
            Only organization owners can modify quota settings.
          </p>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <QuotaField
            label="Max Users"
            value={formData.max_users ?? 10}
            onChange={(v) => updateField('max_users', v)}
            disabled={!isOwner}
            description="Maximum members in the organization"
          />
          <QuotaField
            label="Daily Scan Limit"
            value={formData.max_scans_per_day ?? 50}
            onChange={(v) => updateField('max_scans_per_day', v)}
            disabled={!isOwner}
            description="Maximum scans per day"
          />
          <QuotaField
            label="Concurrent Scans"
            value={formData.max_concurrent_scans ?? 5}
            onChange={(v) => updateField('max_concurrent_scans', v)}
            disabled={!isOwner}
            description="Maximum simultaneous running scans"
          />
          <QuotaField
            label="Monthly Report Limit"
            value={formData.max_reports_per_month ?? 100}
            onChange={(v) => updateField('max_reports_per_month', v)}
            disabled={!isOwner}
            description="Maximum reports per month"
          />
          <QuotaField
            label="Max Assets"
            value={formData.max_assets ?? 1000}
            onChange={(v) => updateField('max_assets', v)}
            disabled={!isOwner}
            description="Maximum tracked assets"
          />
          <QuotaField
            label="Storage (MB)"
            value={formData.max_storage_mb ?? 5120}
            onChange={(v) => updateField('max_storage_mb', v)}
            disabled={!isOwner}
            description="Maximum storage in megabytes"
          />
          <QuotaField
            label="API Requests/Hour"
            value={formData.max_api_requests_per_hour ?? 1000}
            onChange={(v) => updateField('max_api_requests_per_hour', v)}
            disabled={!isOwner}
            description="Maximum API requests per hour"
          />
          <QuotaField
            label="Scheduled Scans"
            value={formData.max_scheduled_scans ?? 20}
            onChange={(v) => updateField('max_scheduled_scans', v)}
            disabled={!isOwner}
            description="Maximum scheduled scan configurations"
          />
          <QuotaField
            label="Max Teams"
            value={formData.max_teams ?? 10}
            onChange={(v) => updateField('max_teams', v)}
            disabled={!isOwner}
            description="Maximum teams in the organization"
          />
        </div>

        {isOwner && (
          <div className="mt-6 flex justify-end">
            <button
              type="submit"
              disabled={updateMutation.isPending}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700
                focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
                disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {updateMutation.isPending ? 'Saving...' : 'Save Quota Settings'}
            </button>
          </div>
        )}

        {updateMutation.isSuccess && (
          <div className="mt-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-md">
            <p className="text-sm text-green-700 dark:text-green-300">
              Quota settings saved successfully.
            </p>
          </div>
        )}

        {updateMutation.isError && (
          <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
            <p className="text-sm text-red-700 dark:text-red-300">
              Failed to save quota settings. Please try again.
            </p>
          </div>
        )}
      </form>
    </div>
  );
}

export default QuotaManagement;
