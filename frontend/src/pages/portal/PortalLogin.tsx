import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { portalAuthAPI } from '../../services/portalApi';
import { Shield } from 'lucide-react';

export function PortalLogin() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (portalAuthAPI.isAuthenticated()) {
      navigate('/portal/dashboard');
    }
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await portalAuthAPI.login({ email, password });
      navigate('/portal/dashboard');
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      setError(error.response?.data?.error || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="w-12 h-12 bg-primary rounded-xl flex items-center justify-center">
            <Shield className="w-7 h-7 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-bold text-slate-900 dark:text-white">
          Customer Portal
        </h2>
        <p className="mt-2 text-center text-sm text-slate-500 dark:text-slate-400">
          Sign in to access your security dashboard
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-light-surface dark:bg-dark-surface py-8 px-4 shadow-lg rounded-lg sm:px-10 border border-light-border dark:border-dark-border">
          <form className="space-y-6" onSubmit={handleSubmit}>
            {error && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 p-4 rounded-lg text-sm">
                {error}
              </div>
            )}

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                Email address
              </label>
              <div className="mt-1">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="appearance-none block w-full px-4 py-3 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary transition-colors"
                  placeholder="you@company.com"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                Password
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="appearance-none block w-full px-4 py-3 bg-light-bg dark:bg-dark-bg border border-light-border dark:border-dark-border rounded-lg text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary transition-colors"
                  placeholder="Enter your password"
                />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="text-sm">
                <Link
                  to="/portal/forgot-password"
                  className="font-medium text-primary hover:text-primary-dark transition-colors"
                >
                  Forgot your password?
                </Link>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? (
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  'Sign in'
                )}
              </button>
            </div>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-light-border dark:border-dark-border" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-light-surface dark:bg-dark-surface text-slate-500 dark:text-slate-400">
                  Need help?
                </span>
              </div>
            </div>

            <div className="mt-4 text-center">
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Contact your HeroForge account manager for portal access.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-8 text-center space-y-2">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            &copy; 2025 Genial Architect Cybersecurity Research Associates. All rights reserved.
          </p>
          <div className="flex items-center justify-center gap-4 text-xs">
            <Link to="/legal/terms" className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300">Terms</Link>
            <span className="text-slate-400 dark:text-slate-500">|</span>
            <Link to="/legal/privacy" className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300">Privacy</Link>
            <span className="text-slate-400 dark:text-slate-500">|</span>
            <Link to="/legal/acceptable-use" className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300">Acceptable Use</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
export default PortalLogin;
