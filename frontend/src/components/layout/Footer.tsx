import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          {/* Logo and Copyright */}
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <span className="text-sm text-gray-600 dark:text-gray-400">
              &copy; 2026 Genial Architect Cybersecurity Research Associates. All rights reserved.
            </span>
          </div>

          {/* Legal Links */}
          <nav className="flex items-center gap-6 text-sm">
            <Link
              to="/legal/terms"
              className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors"
            >
              Terms
            </Link>
            <Link
              to="/legal/privacy"
              className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors"
            >
              Privacy
            </Link>
            <Link
              to="/legal/acceptable-use"
              className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors"
            >
              Acceptable Use
            </Link>
            <Link
              to="/legal/cookies"
              className="text-gray-500 dark:text-gray-400 hover:text-primary transition-colors"
            >
              Cookies
            </Link>
          </nav>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
