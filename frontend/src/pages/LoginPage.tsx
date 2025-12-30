import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import LoginForm from '../components/auth/LoginForm';
import RegisterForm from '../components/auth/RegisterForm';
import { Shield } from 'lucide-react';

type AuthMode = 'login' | 'register';

const LoginPage: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<AuthMode>('login');

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 via-slate-50 to-white dark:from-dark-bg dark:via-slate-900 dark:to-slate-800 p-4">
      <div className="w-full max-w-md">
        {/* Logo and Title */}
        <div className="text-center mb-8 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary rounded-lg mb-4">
            <Shield className="h-10 w-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-slate-900 dark:text-white mb-2">
            HeroForge
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-lg">
            Network Triage & Reconnaissance
          </p>
        </div>

        {/* Auth Card */}
        <div className="bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-2xl p-8 animate-fadeIn">
          <h2 className="text-2xl font-semibold text-slate-900 dark:text-white mb-6 text-center">
            {mode === 'login' ? 'Sign In' : 'Create Account'}
          </h2>

          {mode === 'login' ? (
            <LoginForm onSwitchToRegister={() => setMode('register')} />
          ) : (
            <RegisterForm onSwitchToLogin={() => setMode('login')} />
          )}
        </div>

        {/* Footer */}
        <div className="text-center mt-6 text-slate-500 dark:text-slate-400 text-sm space-y-2">
          <p>Authorized personnel only</p>
          <div className="flex items-center justify-center gap-4">
            <Link to="/legal/terms" className="hover:text-primary transition-colors">Terms</Link>
            <span className="text-slate-300 dark:text-slate-600">|</span>
            <Link to="/legal/privacy" className="hover:text-primary transition-colors">Privacy</Link>
            <span className="text-slate-300 dark:text-slate-600">|</span>
            <Link to="/legal/acceptable-use" className="hover:text-primary transition-colors">Acceptable Use</Link>
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            &copy; {new Date().getFullYear()} Genial Architect
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
