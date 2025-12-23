import { useQuery } from '@tanstack/react-query';
import { quotasAPI } from '../../services/api';
import type { QuotaUsage } from '../../types';

interface QuotaUsageCardProps {
  orgId: string;
}

const quotaLabels: Record<string, string> = {
  scans_per_day: 'Daily Scans',
  concurrent_scans: 'Concurrent Scans',
  reports_per_month: 'Monthly Reports',
  api_requests_per_hour: 'API Requests/Hour',
  storage_mb: 'Storage (MB)',
  users: 'Users',
  assets: 'Assets',
  scheduled_scans: 'Scheduled Scans',
  teams: 'Teams',
  departments: 'Departments',
  custom_roles: 'Custom Roles',
};

function getUsageColor(percentage: number): string {
  if (percentage >= 90) return 'bg-red-500';
  if (percentage >= 75) return 'bg-yellow-500';
  return 'bg-green-500';
}

function QuotaProgressBar({ usage }: { usage: QuotaUsage }) {
  const percentage = usage.max_value > 0 ? (usage.current_value / usage.max_value) * 100 : 0;
  const colorClass = getUsageColor(percentage);
  const label = quotaLabels[usage.quota_type] || usage.quota_type;

  return (
    <div className="mb-4">
      <div className="flex justify-between mb-1">
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          {label}
        </span>
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {usage.current_value} / {usage.max_value}
        </span>
      </div>
      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
        <div
          className={`${colorClass} h-2.5 rounded-full transition-all duration-300`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
      {percentage >= 90 && (
        <p className="text-xs text-red-500 mt-1">
          Warning: Approaching quota limit
        </p>
      )}
    </div>
  );
}

export function QuotaUsageCard({ orgId }: QuotaUsageCardProps) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['quotaUsage', orgId],
    queryFn: () => quotasAPI.getUsage(orgId),
    enabled: !!orgId,
    refetchInterval: 60000, // Refresh every minute
  });

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
          Quota Usage
        </h3>
        <div className="animate-pulse space-y-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i}>
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-2" />
              <div className="h-2.5 bg-gray-200 dark:bg-gray-700 rounded" />
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
          Quota Usage
        </h3>
        <p className="text-red-500">Failed to load quota usage</p>
      </div>
    );
  }

  const usages = data?.data?.usages || [];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
        Quota Usage
      </h3>
      {usages.length === 0 ? (
        <p className="text-gray-500 dark:text-gray-400">
          No quota limits configured
        </p>
      ) : (
        usages.map((usage) => (
          <QuotaProgressBar key={usage.quota_type} usage={usage} />
        ))
      )}
    </div>
  );
}

export default QuotaUsageCard;
