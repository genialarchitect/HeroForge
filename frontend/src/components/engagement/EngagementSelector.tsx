import React, { useEffect, useState } from 'react';
import { Building2, Briefcase, AlertCircle, ChevronDown, RefreshCw } from 'lucide-react';
import { useEngagementStore } from '../../store/engagementStore';
import { crmAPI } from '../../services/api';
import type { Customer, Engagement } from '../../types/crm';

interface EngagementSelectorProps {
  /** Show in compact mode for toolbars */
  compact?: boolean;
  /** Custom class name */
  className?: string;
  /** Called when engagement context changes */
  onChange?: (customer: Customer | null, engagement: Engagement | null) => void;
  /** Filter engagements by status */
  engagementStatusFilter?: string[];
}

export const EngagementSelector: React.FC<EngagementSelectorProps> = ({
  compact = false,
  className = '',
  onChange,
  engagementStatusFilter = ['in_progress', 'planning'],
}) => {
  const {
    activeCustomer,
    activeEngagement,
    customers,
    engagements,
    isLoading,
    setActiveCustomer,
    setActiveEngagement,
    setCustomers,
    setEngagements,
    setLoading,
  } = useEngagementStore();

  const [loadError, setLoadError] = useState<string | null>(null);

  // Load customers on mount
  useEffect(() => {
    loadCustomers();
  }, []);

  // Load engagements when customer changes
  useEffect(() => {
    if (activeCustomer) {
      loadEngagements(activeCustomer.id);
    }
  }, [activeCustomer?.id]);

  // Notify parent of changes
  useEffect(() => {
    onChange?.(activeCustomer, activeEngagement);
  }, [activeCustomer, activeEngagement, onChange]);

  const loadCustomers = async () => {
    try {
      setLoading(true);
      setLoadError(null);
      const response = await crmAPI.customers.getAll('active');
      setCustomers(response.data);
    } catch (error) {
      console.error('Failed to load customers:', error);
      setLoadError('Failed to load customers');
    } finally {
      setLoading(false);
    }
  };

  const loadEngagements = async (customerId: string) => {
    try {
      setLoading(true);
      setLoadError(null);
      const response = await crmAPI.engagements.getByCustomer(customerId);
      // Filter by status if specified
      const filtered = engagementStatusFilter.length > 0
        ? response.data.filter(e => engagementStatusFilter.includes(e.status))
        : response.data;
      setEngagements(filtered);
    } catch (error) {
      console.error('Failed to load engagements:', error);
      setLoadError('Failed to load engagements');
    } finally {
      setLoading(false);
    }
  };

  const handleCustomerChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const customerId = e.target.value;
    if (customerId) {
      const customer = customers.find(c => c.id === customerId);
      setActiveCustomer(customer || null);
    } else {
      setActiveCustomer(null);
    }
  };

  const handleEngagementChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const engagementId = e.target.value;
    if (engagementId) {
      const engagement = engagements.find(eng => eng.id === engagementId);
      setActiveEngagement(engagement || null);
    } else {
      setActiveEngagement(null);
    }
  };

  const selectClassName = compact
    ? 'px-2 py-1 text-sm bg-gray-800 border border-gray-700 rounded text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent'
    : 'w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent';

  if (compact) {
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className="flex items-center gap-1">
          <Building2 className="w-4 h-4 text-gray-400" />
          <select
            value={activeCustomer?.id || ''}
            onChange={handleCustomerChange}
            disabled={isLoading}
            className={selectClassName}
          >
            <option value="">Select Customer</option>
            {customers.map(customer => (
              <option key={customer.id} value={customer.id}>
                {customer.name}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-1">
          <Briefcase className="w-4 h-4 text-gray-400" />
          <select
            value={activeEngagement?.id || ''}
            onChange={handleEngagementChange}
            disabled={isLoading || !activeCustomer}
            className={selectClassName}
          >
            <option value="">Select Engagement</option>
            {engagements.map(engagement => (
              <option key={engagement.id} value={engagement.id}>
                {engagement.name}
              </option>
            ))}
          </select>
        </div>

        {isLoading && (
          <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
        )}
      </div>
    );
  }

  return (
    <div className={`bg-gray-800 border border-gray-700 rounded-lg p-4 ${className}`}>
      <div className="flex items-center gap-2 mb-3">
        <Briefcase className="w-5 h-5 text-cyan-400" />
        <h3 className="text-sm font-medium text-white">Active Engagement</h3>
        {isLoading && (
          <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin ml-auto" />
        )}
      </div>

      {loadError && (
        <div className="flex items-center gap-2 text-red-400 text-sm mb-3">
          <AlertCircle className="w-4 h-4" />
          <span>{loadError}</span>
          <button
            onClick={loadCustomers}
            className="text-cyan-400 hover:text-cyan-300 underline ml-2"
          >
            Retry
          </button>
        </div>
      )}

      <div className="space-y-3">
        {/* Customer Selection */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Customer</label>
          <div className="relative">
            <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <select
              value={activeCustomer?.id || ''}
              onChange={handleCustomerChange}
              disabled={isLoading}
              className={`${selectClassName} pl-9 pr-8 appearance-none cursor-pointer`}
            >
              <option value="">Select a customer...</option>
              {customers.map(customer => (
                <option key={customer.id} value={customer.id}>
                  {customer.name}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          </div>
        </div>

        {/* Engagement Selection */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Engagement</label>
          <div className="relative">
            <Briefcase className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <select
              value={activeEngagement?.id || ''}
              onChange={handleEngagementChange}
              disabled={isLoading || !activeCustomer}
              className={`${selectClassName} pl-9 pr-8 appearance-none cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <option value="">
                {!activeCustomer
                  ? 'Select a customer first...'
                  : engagements.length === 0
                    ? 'No active engagements'
                    : 'Select an engagement...'}
              </option>
              {engagements.map(engagement => (
                <option key={engagement.id} value={engagement.id}>
                  {engagement.name} ({engagement.engagement_type})
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          </div>
        </div>

        {/* Active Engagement Info */}
        {activeEngagement && (
          <div className="mt-3 p-2 bg-gray-900/50 rounded border border-gray-700">
            <div className="flex items-center justify-between text-xs">
              <span className="text-gray-400">Scope:</span>
              <span className="text-white truncate max-w-[200px]" title={activeEngagement.scope || 'Not defined'}>
                {activeEngagement.scope || 'Not defined'}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs mt-1">
              <span className="text-gray-400">Type:</span>
              <span className="text-cyan-400 capitalize">
                {activeEngagement.engagement_type.replace('_', ' ')}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs mt-1">
              <span className="text-gray-400">Status:</span>
              <span className={`capitalize ${
                activeEngagement.status === 'in_progress' ? 'text-green-400' :
                activeEngagement.status === 'planning' ? 'text-yellow-400' :
                'text-gray-400'
              }`}>
                {activeEngagement.status.replace('_', ' ')}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EngagementSelector;
