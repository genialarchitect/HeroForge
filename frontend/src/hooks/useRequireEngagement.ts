import { useEngagementStore } from '../store/engagementStore';

interface UseRequireEngagementReturn {
  /** Whether an engagement is currently selected */
  hasEngagement: boolean;
  /** Active customer ID if selected */
  customerId: string | null;
  /** Active engagement ID if selected */
  engagementId: string | null;
  /** Customer name for display */
  customerName: string | null;
  /** Engagement name for display */
  engagementName: string | null;
  /** Check if scan can proceed */
  canStartScan: boolean;
  /** Get context for API calls */
  getEngagementContext: () => { customer_id: string; engagement_id: string } | null;
}

/**
 * Hook for red-team pages that require an active engagement before allowing scans.
 *
 * Usage:
 * ```tsx
 * const { hasEngagement, canStartScan, getEngagementContext } = useRequireEngagement();
 *
 * // In your scan handler:
 * const handleStartScan = () => {
 *   if (!canStartScan) return;
 *   const context = getEngagementContext();
 *   // Include context.customer_id and context.engagement_id in API call
 * };
 *
 * // In your JSX, show EngagementRequiredBanner if !hasEngagement
 * ```
 */
export function useRequireEngagement(): UseRequireEngagementReturn {
  const { activeCustomer, activeEngagement, hasActiveEngagement } = useEngagementStore();

  const hasEngagement = hasActiveEngagement();

  return {
    hasEngagement,
    customerId: activeCustomer?.id ?? null,
    engagementId: activeEngagement?.id ?? null,
    customerName: activeCustomer?.name ?? null,
    engagementName: activeEngagement?.name ?? null,
    canStartScan: hasEngagement,
    getEngagementContext: () => {
      if (activeCustomer && activeEngagement) {
        return {
          customer_id: activeCustomer.id,
          engagement_id: activeEngagement.id,
        };
      }
      return null;
    },
  };
}
