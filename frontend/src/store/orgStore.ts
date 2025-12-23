import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { OrganizationSummary, OrgRole } from '../types';

interface OrgState {
  // Current organization context
  currentOrg: OrganizationSummary | null;
  currentOrgId: string | null;

  // All organizations the user belongs to
  organizations: OrganizationSummary[];

  // Loading state
  isLoading: boolean;

  // Actions
  setCurrentOrg: (org: OrganizationSummary | null) => void;
  setCurrentOrgId: (orgId: string | null) => void;
  setOrganizations: (orgs: OrganizationSummary[]) => void;
  setLoading: (loading: boolean) => void;
  clearOrgState: () => void;

  // Helper methods
  isOrgOwner: () => boolean;
  isOrgAdmin: () => boolean;
  isOrgMember: () => boolean;
  getCurrentOrgRole: () => OrgRole | null;
  getOrgById: (orgId: string) => OrganizationSummary | undefined;
  hasMultipleOrgs: () => boolean;
}

export const useOrgStore = create<OrgState>()(
  persist(
    (set, get) => ({
      currentOrg: null,
      currentOrgId: null,
      organizations: [],
      isLoading: false,

      setCurrentOrg: (org) => {
        set({
          currentOrg: org,
          currentOrgId: org?.id ?? null
        });
      },

      setCurrentOrgId: (orgId) => {
        const orgs = get().organizations;
        const org = orgs.find(o => o.id === orgId) ?? null;
        set({
          currentOrgId: orgId,
          currentOrg: org
        });
      },

      setOrganizations: (orgs) => {
        set({ organizations: orgs });
        // If current org is not set but orgs exist, set the first one
        const currentOrg = get().currentOrg;
        if (!currentOrg && orgs.length > 0) {
          set({
            currentOrg: orgs[0],
            currentOrgId: orgs[0].id
          });
        }
        // If current org is set but not in the new list, clear it
        if (currentOrg && !orgs.find(o => o.id === currentOrg.id)) {
          if (orgs.length > 0) {
            set({
              currentOrg: orgs[0],
              currentOrgId: orgs[0].id
            });
          } else {
            set({ currentOrg: null, currentOrgId: null });
          }
        }
      },

      setLoading: (isLoading) => set({ isLoading }),

      clearOrgState: () => {
        set({
          currentOrg: null,
          currentOrgId: null,
          organizations: [],
          isLoading: false,
        });
      },

      // Helper methods
      isOrgOwner: () => get().currentOrg?.role === 'owner',

      isOrgAdmin: () => {
        const role = get().currentOrg?.role;
        return role === 'owner' || role === 'admin';
      },

      isOrgMember: () => get().currentOrg?.role === 'member',

      getCurrentOrgRole: () => get().currentOrg?.role ?? null,

      getOrgById: (orgId) => get().organizations.find(o => o.id === orgId),

      hasMultipleOrgs: () => get().organizations.length > 1,
    }),
    {
      name: 'org-storage',
      partialize: (state) => ({
        currentOrgId: state.currentOrgId,
        // Don't persist full org data, just the ID - we'll reload on app start
      }),
    }
  )
);
