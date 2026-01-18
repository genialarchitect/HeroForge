import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import Button from '../ui/Button';
import Input from '../ui/Input';
import { User, Lock, Shield, Key } from 'lucide-react';
import { toast } from 'react-toastify';
import { authAPI, mfaAPI, ssoAPI } from '../../services/api';
import { useAuthStore } from '../../store/authStore';
import { SsoProviderForLogin } from '../../types';
import SsoProviderButton from './SsoProviderButton';

interface LoginFormProps {
  onSwitchToRegister?: () => void;
}

const LoginForm: React.FC<LoginFormProps> = ({ onSwitchToRegister }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const { isLoading } = useAuth();
  const [loading, setLoading] = useState(false);
  const [ssoProviders, setSsoProviders] = useState<SsoProviderForLogin[]>([]);
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoRedirecting, setSsoRedirecting] = useState<string | null>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login: setLogin } = useAuthStore();

  // Fetch SSO providers on mount
  useEffect(() => {
    const fetchSsoProviders = async () => {
      try {
        const response = await ssoAPI.getProvidersForLogin();
        setSsoProviders(response.data);
      } catch (error) {
        // Silently fail - SSO might not be configured
        console.debug('SSO providers not available:', error);
      }
    };
    fetchSsoProviders();
  }, []);

  const handleSsoCallback = useCallback(async (token: string) => {
    try {
      setSsoLoading(true);
      // Temporarily set the token in localStorage so the API can use it
      localStorage.setItem('token', token);

      // Validate the token by fetching user info
      const response = await authAPI.me();
      const user = response.data;

      // Store the token and user info in auth store
      setLogin(user, token);
      toast.success('SSO login successful!');

      // Clear the URL params and navigate
      window.history.replaceState({}, document.title, window.location.pathname);
      navigate('/dashboard');
    } catch (error: unknown) {
      // Remove the invalid token
      localStorage.removeItem('token');
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'SSO login failed. Please try again.');
      // Clear the URL params
      window.history.replaceState({}, document.title, window.location.pathname);
    } finally {
      setSsoLoading(false);
    }
  }, [navigate, setLogin]);

  // Handle SSO callback tokens
  useEffect(() => {
    const token = searchParams.get('token');
    const error = searchParams.get('sso_error');

    if (error) {
      toast.error(decodeURIComponent(error));
      // Clear the URL params
      window.history.replaceState({}, document.title, window.location.pathname);
      return;
    }

    if (token) {
      // SSO login successful - validate the token and log in
      handleSsoCallback(token);
    }
  }, [searchParams, handleSsoCallback]);

  const handleSsoLogin = async (provider: SsoProviderForLogin) => {
    try {
      setSsoRedirecting(provider.id);
      const response = await ssoAPI.initiateLogin(provider.id);
      // Redirect to the SSO provider
      window.location.href = response.data.redirect_url;
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || `Failed to initiate ${provider.display_name} login`);
      setSsoRedirecting(null);
    }
  };

  const handleInitialLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || !password) {
      toast.error('Please enter both username and password');
      return;
    }

    setLoading(true);
    try {
      const response = await authAPI.login({ username, password });
      const data = response.data;

      // Check if MFA is required
      if (data.mfa_required && data.mfa_token) {
        setMfaRequired(true);
        setMfaToken(data.mfa_token);
        toast.info('Please enter your two-factor authentication code');
      } else {
        // No MFA required, proceed with login
        setLogin(data.user, data.token);
        toast.success('Login successful!');
        navigate('/dashboard');
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      const message = axiosError.response?.data?.error || 'Login failed. Please check your credentials.';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const handleMfaVerify = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!mfaCode || (useRecoveryCode ? mfaCode.length === 0 : mfaCode.length !== 6)) {
      toast.error(useRecoveryCode ? 'Please enter a recovery code' : 'Please enter a valid 6-digit code');
      return;
    }

    setLoading(true);
    try {
      const response = await mfaAPI.verify({
        mfa_token: mfaToken,
        ...(useRecoveryCode ? { recovery_code: mfaCode } : { totp_code: mfaCode }),
      });

      const { token, user } = response.data;
      setLogin(user, token);
      toast.success('Login successful!');
      navigate('/dashboard');
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Invalid authentication code');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToLogin = () => {
    setMfaRequired(false);
    setMfaToken('');
    setMfaCode('');
    setUseRecoveryCode(false);
  };

  if (mfaRequired) {
    return (
      <div className="space-y-4 w-full max-w-md">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-primary/20 rounded-lg mb-3">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Two-Factor Authentication</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {useRecoveryCode
              ? 'Enter one of your recovery codes'
              : 'Enter the 6-digit code from your authenticator app'}
          </p>
        </div>

        <form onSubmit={handleMfaVerify} className="space-y-4">
          <Input
            type="text"
            placeholder={useRecoveryCode ? 'Recovery Code' : '000000'}
            value={mfaCode}
            onChange={(e) => {
              if (useRecoveryCode) {
                setMfaCode(e.target.value);
              } else {
                setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6));
              }
            }}
            icon={useRecoveryCode ? <Key className="h-5 w-5" /> : <Shield className="h-5 w-5" />}
            className={useRecoveryCode ? '' : 'text-center tracking-widest font-mono'}
            maxLength={useRecoveryCode ? undefined : 6}
            required
            autoFocus
            autoComplete="one-time-code"
          />

          <div className="flex items-center justify-center">
            <button
              type="button"
              onClick={() => {
                setUseRecoveryCode(!useRecoveryCode);
                setMfaCode('');
              }}
              className="text-sm text-primary hover:text-primary-dark transition-colors"
            >
              {useRecoveryCode ? 'Use authenticator code instead' : 'Use recovery code instead'}
            </button>
          </div>

          <div className="flex gap-2">
            <Button
              type="button"
              variant="secondary"
              size="lg"
              onClick={handleBackToLogin}
              className="flex-1"
            >
              Back
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={loading}
              disabled={loading}
              className="flex-1"
            >
              Verify
            </Button>
          </div>
        </form>
      </div>
    );
  }

  // Show loading state while processing SSO callback
  if (ssoLoading) {
    return (
      <div className="space-y-4 w-full max-w-md text-center">
        <div className="inline-flex items-center justify-center w-12 h-12 bg-primary/20 rounded-lg mb-3">
          <svg className="animate-spin h-6 w-6 text-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Completing SSO Login</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Please wait while we verify your credentials...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 w-full max-w-md">
      {/* SSO Providers */}
      {ssoProviders.length > 0 && (
        <div className="space-y-3">
          {ssoProviders.map((provider) => (
            <SsoProviderButton
              key={provider.id}
              provider={provider}
              onClick={handleSsoLogin}
              loading={ssoRedirecting === provider.id}
              disabled={ssoRedirecting !== null && ssoRedirecting !== provider.id}
            />
          ))}
        </div>
      )}

      {/* Divider - only show if we have SSO providers */}
      {ssoProviders.length > 0 && (
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300 dark:border-gray-600"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-3 bg-light-surface dark:bg-dark-surface text-slate-500 dark:text-slate-400">
              or sign in with credentials
            </span>
          </div>
        </div>
      )}

      {/* Username/Password Form */}
      <form
        onSubmit={handleInitialLogin}
        className="space-y-4"
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !loading && !isLoading && ssoRedirecting === null) {
            e.preventDefault();
            handleInitialLogin(e as unknown as React.FormEvent);
          }
        }}
      >
        <Input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          icon={<User className="h-5 w-5" />}
          required
          autoComplete="username"
        />
        <Input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          icon={<Lock className="h-5 w-5" />}
          required
          autoComplete="current-password"
        />
        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={loading || isLoading}
          disabled={loading || isLoading || ssoRedirecting !== null}
          className="w-full"
        >
          Sign In
        </Button>
      </form>

      {/* Switch to Register */}
      {onSwitchToRegister && (
        <div className="text-center mt-4">
          <span className="text-slate-500 dark:text-slate-400">Don't have an account? </span>
          <button
            type="button"
            onClick={onSwitchToRegister}
            className="text-primary hover:text-primary-dark font-medium transition-colors"
          >
            Create Account
          </button>
        </div>
      )}
    </div>
  );
};

export default LoginForm;
