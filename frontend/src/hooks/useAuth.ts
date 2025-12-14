import { useCallback, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { authAPI } from '../services/api';
import { toast } from 'react-toastify';

export const useAuth = () => {
  const {
    user,
    token,
    isAuthenticated,
    isLoading,
    login: setLogin,
    logout: setLogout,
    setLoading,
    setUser,
  } = useAuthStore();

  // Check authentication status on mount
  useEffect(() => {
    const checkAuth = async () => {
      const storedToken = localStorage.getItem('token');
      if (storedToken && !user) {
        setLoading(true);
        try {
          const response = await authAPI.me();
          setUser(response.data);
        } catch (error) {
          console.error('Failed to verify token:', error);
          setLogout();
        } finally {
          setLoading(false);
        }
      }
    };

    checkAuth();
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      setLoading(true);
      try {
        const response = await authAPI.login({ username, password });
        const { token, user } = response.data;
        setLogin(user, token);
        toast.success('Login successful!');
        return true;
      } catch (error: any) {
        const message = error.response?.data?.error || 'Login failed. Please check your credentials.';
        toast.error(message);
        return false;
      } finally {
        setLoading(false);
      }
    },
    [setLogin, setLoading]
  );

  const logout = useCallback(() => {
    setLogout();
    toast.info('Logged out successfully');
  }, [setLogout]);

  return {
    user,
    token,
    isAuthenticated,
    isLoading,
    login,
    logout,
  };
};
