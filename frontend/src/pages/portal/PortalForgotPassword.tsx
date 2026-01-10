import { useState } from 'react';
import { Link } from 'react-router-dom';
import { portalAuthAPI } from '../../services/portalApi';
import { Shield, ArrowLeft, CheckCircle } from 'lucide-react';

export default function PortalForgotPassword() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await portalAuthAPI.forgotPassword(email);
      setSubmitted(true);
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      setError(error.response?.data?.error || 'Failed to process request. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (submitted) {
    return (
      <div className="min-h-screen bg-light-bg dark:bg-dark-bg flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-light-surface dark:bg-dark-surface py-8 px-4 shadow-lg rounded-lg sm:px-10 border border-light-border dark:border-dark-border text-center">
            <div className="flex justify-center mb-4">
              <div className="w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
            </div>
            <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-2">Check your email</h2>
            <p className="text-slate-500 dark:text-slate-400 mb-6">
              If an account exists for <strong className="text-slate-700 dark:text-slate-300">{email}</strong>, you will receive a password reset link shortly.
            </p>
            <Link
              to="/portal/login"
              className="inline-flex items-center gap-2 text-primary hover:text-primary-dark transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Return to login
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="w-12 h-12 bg-primary rounded-xl flex items-center justify-center">
            <Shield className="w-7 h-7 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-bold text-slate-900 dark:text-white">
          Reset Password
        </h2>
        <p className="mt-2 text-center text-sm text-slate-500 dark:text-slate-400">
          Enter your email to receive a reset link
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
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? (
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  'Send Reset Link'
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 text-center">
            <Link
              to="/portal/login"
              className="inline-flex items-center gap-2 text-sm text-primary hover:text-primary-dark transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to login
            </Link>
          </div>
        </div>

        <p className="mt-8 text-center text-xs text-slate-500 dark:text-slate-400">
          &copy; 2025 Genial Architect Cybersecurity Research Associates. All rights reserved.
        </p>
      </div>
    </div>
  );
}
