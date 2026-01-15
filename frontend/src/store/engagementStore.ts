import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Customer, Engagement } from '../types/crm';

interface EngagementState {
  // Active context for red-team operations
  activeCustomer: Customer | null;
  activeEngagement: Engagement | null;

  // Cached lists for quick selection
  customers: Customer[];
  engagements: Engagement[]; // Engagements for active customer

  // Loading states
  isLoading: boolean;

  // Actions
  setActiveCustomer: (customer: Customer | null) => void;
  setActiveEngagement: (engagement: Engagement | null) => void;
  setCustomers: (customers: Customer[]) => void;
  setEngagements: (engagements: Engagement[]) => void;
  setLoading: (loading: boolean) => void;
  clearEngagementContext: () => void;

  // Helpers
  hasActiveEngagement: () => boolean;
  getActiveContext: () => { customerId: string; engagementId: string } | null;
}

export const useEngagementStore = create<EngagementState>()(
  persist(
    (set, get) => ({
      activeCustomer: null,
      activeEngagement: null,
      customers: [],
      engagements: [],
      isLoading: false,

      setActiveCustomer: (customer) => {
        set({
          activeCustomer: customer,
          // Clear engagement when customer changes
          activeEngagement: null,
          engagements: []
        });
      },

      setActiveEngagement: (engagement) => {
        set({ activeEngagement: engagement });
      },

      setCustomers: (customers) => {
        set({ customers });
        // If active customer is not in the list, clear it
        const activeCustomer = get().activeCustomer;
        if (activeCustomer && !customers.find(c => c.id === activeCustomer.id)) {
          set({ activeCustomer: null, activeEngagement: null });
        }
      },

      setEngagements: (engagements) => {
        set({ engagements });
        // If active engagement is not in the list, clear it
        const activeEngagement = get().activeEngagement;
        if (activeEngagement && !engagements.find(e => e.id === activeEngagement.id)) {
          set({ activeEngagement: null });
        }
      },

      setLoading: (isLoading) => set({ isLoading }),

      clearEngagementContext: () => {
        set({
          activeCustomer: null,
          activeEngagement: null,
          engagements: [],
        });
      },

      // Helper methods
      hasActiveEngagement: () => {
        const state = get();
        return state.activeCustomer !== null && state.activeEngagement !== null;
      },

      getActiveContext: () => {
        const state = get();
        if (state.activeCustomer && state.activeEngagement) {
          return {
            customerId: state.activeCustomer.id,
            engagementId: state.activeEngagement.id,
          };
        }
        return null;
      },
    }),
    {
      name: 'engagement-storage',
      partialize: (state) => ({
        // Persist IDs only - we'll reload full data on app start
        activeCustomerId: state.activeCustomer?.id,
        activeEngagementId: state.activeEngagement?.id,
      }),
    }
  )
);
