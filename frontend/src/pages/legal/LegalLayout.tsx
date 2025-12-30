import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowLeft } from 'lucide-react';

interface LegalLayoutProps {
  title: string;
  lastUpdated: string;
  children: React.ReactNode;
}

const LegalLayout: React.FC<LegalLayoutProps> = ({ title, lastUpdated, children }) => {
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-2 text-gray-600 dark:text-gray-300 hover:text-primary transition-colors">
              <ArrowLeft className="w-5 h-5" />
              <span>Back to HeroForge</span>
            </Link>
            <Link to="/" className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-primary" />
              <span className="text-xl font-bold text-gray-900 dark:text-white">HeroForge</span>
            </Link>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <article className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-8">
          <header className="mb-8 pb-6 border-b border-gray-200 dark:border-gray-700">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">{title}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">Last Updated: {lastUpdated}</p>
          </header>

          <div className="prose prose-gray dark:prose-invert max-w-none
            prose-headings:text-gray-900 dark:prose-headings:text-white
            prose-p:text-gray-600 dark:prose-p:text-gray-300
            prose-li:text-gray-600 dark:prose-li:text-gray-300
            prose-strong:text-gray-900 dark:prose-strong:text-white
            prose-a:text-primary hover:prose-a:text-cyan-400
            prose-table:text-sm
            prose-th:bg-gray-100 dark:prose-th:bg-gray-700
            prose-th:text-gray-900 dark:prose-th:text-white
            prose-td:text-gray-600 dark:prose-td:text-gray-300
          ">
            {children}
          </div>
        </article>

        {/* Legal Navigation */}
        <nav className="mt-8 p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
          <h2 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 uppercase tracking-wider">Legal Documents</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Link to="/legal/terms" className="text-sm text-gray-600 dark:text-gray-300 hover:text-primary transition-colors">
              Terms of Service
            </Link>
            <Link to="/legal/privacy" className="text-sm text-gray-600 dark:text-gray-300 hover:text-primary transition-colors">
              Privacy Policy
            </Link>
            <Link to="/legal/acceptable-use" className="text-sm text-gray-600 dark:text-gray-300 hover:text-primary transition-colors">
              Acceptable Use Policy
            </Link>
            <Link to="/legal/cookies" className="text-sm text-gray-600 dark:text-gray-300 hover:text-primary transition-colors">
              Cookie Policy
            </Link>
          </div>
        </nav>
      </main>

      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                &copy; {new Date().getFullYear()} Genial Architect. All rights reserved.
              </span>
            </div>
            <div className="flex items-center gap-6 text-sm">
              <a href="mailto:legal@heroforge.security" className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors">
                legal@heroforge.security
              </a>
              <a href="mailto:support@heroforge.security" className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors">
                support@heroforge.security
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LegalLayout;
