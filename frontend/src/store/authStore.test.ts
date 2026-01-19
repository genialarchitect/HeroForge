import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from './authStore';

describe('AuthStore', () => {
  beforeEach(() => {
    // Reset store state
    useAuthStore.setState({
      token: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
    });
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const state = useAuthStore.getState();
      expect(state.isAuthenticated).toBe(false);
      expect(state.token).toBeNull();
      expect(state.user).toBeNull();
      expect(state.isLoading).toBe(false);
    });
  });

  describe('setToken', () => {
    it('should set token', () => {
      const store = useAuthStore.getState();
      store.setToken('test-token-123');

      const newState = useAuthStore.getState();
      expect(newState.token).toBe('test-token-123');
    });

    it('should remove token when set to null', () => {
      const store = useAuthStore.getState();
      store.setToken('test-token');
      store.setToken(null);

      expect(useAuthStore.getState().token).toBeNull();
    });
  });

  describe('setUser', () => {
    it('should set user data and authenticate', () => {
      const user = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@heroforge.io',
        roles: ['user'],
      };

      const store = useAuthStore.getState();
      store.setUser(user);

      const newState = useAuthStore.getState();
      expect(newState.user).toEqual(user);
      expect(newState.isAuthenticated).toBe(true);
    });

    it('should clear authentication when user is null', () => {
      const store = useAuthStore.getState();
      store.setUser({ id: '1', username: 'test', email: 'test@test.com', roles: [] });
      store.setUser(null);

      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });
  });

  describe('login', () => {
    it('should set user, token, and authentication state', () => {
      const user = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@heroforge.io',
        roles: ['user'],
      };

      const store = useAuthStore.getState();
      store.login(user, 'auth-token-123');

      const newState = useAuthStore.getState();
      expect(newState.user).toEqual(user);
      expect(newState.token).toBe('auth-token-123');
      expect(newState.isAuthenticated).toBe(true);
      expect(newState.isLoading).toBe(false);
    });
  });

  describe('logout', () => {
    it('should clear all auth state on logout', () => {
      // First set up authenticated state
      const store = useAuthStore.getState();
      store.login(
        {
          id: 'user-123',
          username: 'testuser',
          email: 'test@heroforge.io',
          roles: ['user'],
        },
        'test-token'
      );

      // Then logout
      store.logout();

      const newState = useAuthStore.getState();
      expect(newState.token).toBeNull();
      expect(newState.user).toBeNull();
      expect(newState.isAuthenticated).toBe(false);
    });
  });

  describe('Role Checks', () => {
    it('isAdmin should return true for admin users', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'admin-123',
        username: 'admin',
        email: 'admin@heroforge.io',
        roles: ['admin', 'user'],
      });

      expect(store.isAdmin()).toBe(true);
    });

    it('isAdmin should return false for non-admin users', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'user-123',
        username: 'user',
        email: 'user@heroforge.io',
        roles: ['user'],
      });

      expect(store.isAdmin()).toBe(false);
    });

    it('hasRole should check specific roles in roles array', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'user-123',
        username: 'analyst',
        email: 'analyst@heroforge.io',
        roles: ['analyst', 'user'],
      });

      expect(store.hasRole('analyst')).toBe(true);
      expect(store.hasRole('user')).toBe(true);
      expect(store.hasRole('admin')).toBe(false);
    });

    it('canManageUsers should return true for admins', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'admin-123',
        username: 'admin',
        email: 'admin@heroforge.io',
        roles: ['admin'],
      });

      expect(store.canManageUsers()).toBe(true);
    });

    it('canViewAuditLogs should return true for admins and auditors', () => {
      const store = useAuthStore.getState();

      // Test admin
      store.setUser({
        id: 'admin-123',
        username: 'admin',
        email: 'admin@heroforge.io',
        roles: ['admin'],
      });
      expect(store.canViewAuditLogs()).toBe(true);

      // Test auditor
      store.setUser({
        id: 'auditor-123',
        username: 'auditor',
        email: 'auditor@heroforge.io',
        roles: ['auditor'],
      });
      expect(store.canViewAuditLogs()).toBe(true);

      // Test regular user
      store.setUser({
        id: 'user-123',
        username: 'user',
        email: 'user@heroforge.io',
        roles: ['user'],
      });
      expect(store.canViewAuditLogs()).toBe(false);
    });
  });

  describe('Team Role Checks', () => {
    it('hasTeamRole should check for team roles', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'user-123',
        username: 'pentester',
        email: 'pentester@heroforge.io',
        roles: ['red_team', 'user'],
      });

      expect(store.hasTeamRole('red_team')).toBe(true);
      expect(store.hasTeamRole('blue_team')).toBe(false);
    });

    it('hasAnyTeamRole should check for any of multiple team roles', () => {
      const store = useAuthStore.getState();
      store.setUser({
        id: 'user-123',
        username: 'pentester',
        email: 'pentester@heroforge.io',
        roles: ['red_team', 'user'],
      });

      expect(store.hasAnyTeamRole(['red_team', 'blue_team'])).toBe(true);
      expect(store.hasAnyTeamRole(['blue_team', 'green_team'])).toBe(false);
    });
  });

  describe('Loading State', () => {
    it('should track loading state', () => {
      const store = useAuthStore.getState();
      store.setLoading(true);
      expect(useAuthStore.getState().isLoading).toBe(true);

      store.setLoading(false);
      expect(useAuthStore.getState().isLoading).toBe(false);
    });
  });
});
