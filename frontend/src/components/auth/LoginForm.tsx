import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import Button from '../ui/Button';
import Input from '../ui/Input';
import { User, Lock, Shield, Key } from 'lucide-react';
import { toast } from 'react-toastify';
import { authAPI, mfaAPI } from '../../services/api';
import { useAuthStore } from '../../store/authStore';

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const { isLoading } = useAuth();
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login: setLogin } = useAuthStore();

  const handleInitialLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || !password) {
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

  return (
    <form onSubmit={handleInitialLogin} className="space-y-4 w-full max-w-md">
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
        disabled={loading || isLoading}
        className="w-full"
      >
        Sign In
      </Button>
    </form>
  );
};

export default LoginForm;
