import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, UserRole, TeamRole, isTeamRole } from '../types';

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
  login: (user: User, token: string) => void;
  logout: () => void;
  setLoading: (loading: boolean) => void;

  // Role helper methods
  isAdmin: () => boolean;
  hasRole: (role: UserRole) => boolean;
  canManageUsers: () => boolean;
  canManageScans: () => boolean;
  canViewAuditLogs: () => boolean;
  canManageSettings: () => boolean;

  // Team role helper methods
  getTeamRoles: () => TeamRole[];
  getPrimaryTeam: () => TeamRole | null;
  hasTeamRole: (team: TeamRole) => boolean;
  hasAnyTeamRole: (teams: TeamRole[]) => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      setUser: (user) => set({ user, isAuthenticated: !!user }),

      setToken: (token) => {
        set({ token });
        if (token) {
          localStorage.setItem('token', token);
        } else {
          localStorage.removeItem('token');
        }
      },

      login: (user, token) => {
        set({
          user,
          token,
          isAuthenticated: true,
          isLoading: false,
        });
        localStorage.setItem('token', token);
      },

      logout: () => {
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
        });
        localStorage.removeItem('token');
      },

      setLoading: (isLoading) => set({ isLoading }),

      // Role helper methods
      isAdmin: () => get().user?.roles?.includes('admin') ?? false,

      hasRole: (role) => get().user?.roles?.includes(role) ?? false,

      canManageUsers: () => get().user?.roles?.includes('admin') ?? false,

      canManageScans: () =>
        get().user?.roles?.some(r => ['admin', 'auditor'].includes(r)) ?? false,

      canViewAuditLogs: () =>
        get().user?.roles?.some(r => ['admin', 'auditor'].includes(r)) ?? false,

      canManageSettings: () => get().user?.roles?.includes('admin') ?? false,

      // Team role helper methods
      getTeamRoles: () => {
        const roles = get().user?.roles ?? [];
        return roles.filter(isTeamRole) as TeamRole[];
      },

      getPrimaryTeam: () => {
        const teamRoles = get().getTeamRoles();
        return teamRoles.length > 0 ? teamRoles[0] : null;
      },

      hasTeamRole: (team) => get().user?.roles?.includes(team) ?? false,

      hasAnyTeamRole: (teams) => {
        const userRoles = get().user?.roles ?? [];
        return teams.some(team => userRoles.includes(team));
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        token: state.token,
        user: state.user,
      }),
    }
  )
);
