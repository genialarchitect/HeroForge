import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../store/authStore';
import Button from '../ui/Button';
import ThemeToggle from '../ui/ThemeToggle';
import { Shield, LogOut, User, LayoutDashboard, Users, Settings, Server, Globe, Network, ShieldCheck, ClipboardCheck, Building2, BookOpenCheck, BarChart3, Zap, GitCompare, GitBranch, Box, FileCode } from 'lucide-react';

const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const location = useLocation();

  return (
    <header className="bg-light-surface dark:bg-dark-surface border-b border-light-border dark:border-dark-border shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-10 h-10 bg-primary rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900 dark:text-white">HeroForge</h1>
                <p className="text-xs text-slate-500 dark:text-slate-400">Network Triage Dashboard</p>
              </div>
            </div>

            {/* Navigation */}
            {user && (
              <nav className="flex items-center space-x-1">
                <Link
                  to="/crm"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/crm')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Building2 className="h-4 w-4" />
                  CRM
                </Link>
                <Link
                  to="/dashboard"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/dashboard')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <LayoutDashboard className="h-4 w-4" />
                  Scans
                </Link>
                <Link
                  to="/compare"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname === '/compare'
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <GitCompare className="h-4 w-4" />
                  Compare
                </Link>
                <Link
                  to="/assets"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/assets')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Server className="h-4 w-4" />
                  Assets
                </Link>
                <Link
                  to="/webapp-scan"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/webapp-scan')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Globe className="h-4 w-4" />
                  Web Scan
                </Link>
                <Link
                  to="/dns-tools"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/dns-tools')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Network className="h-4 w-4" />
                  DNS Tools
                </Link>
                <Link
                  to="/api-security"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/api-security')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Zap className="h-4 w-4" />
                  API Sec
                </Link>
                <Link
                  to="/container-security"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/container-security')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Box className="h-4 w-4" />
                  Containers
                </Link>
                <Link
                  to="/iac-security"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/iac-security')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <FileCode className="h-4 w-4" />
                  IaC
                </Link>
                <Link
                  to="/compliance"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname === '/compliance'
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <ShieldCheck className="h-4 w-4" />
                  Compliance
                </Link>
                <Link
                  to="/manual-assessments"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/manual-assessments')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <ClipboardCheck className="h-4 w-4" />
                  Assessments
                </Link>
                <Link
                  to="/methodology"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/methodology')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <BookOpenCheck className="h-4 w-4" />
                  Methodology
                </Link>
                <Link
                  to="/executive-dashboard"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname === '/executive-dashboard'
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <BarChart3 className="h-4 w-4" />
                  Executive
                </Link>
                <Link
                  to="/workflows"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/workflows')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <GitBranch className="h-4 w-4" />
                  Workflows
                </Link>
                <Link
                  to="/settings"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/settings')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Settings className="h-4 w-4" />
                  Settings
                </Link>
                {isAdmin() && (
                  <Link
                    to="/admin"
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                      location.pathname.startsWith('/admin')
                        ? 'bg-primary/10 text-primary font-medium'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                    }`}
                  >
                    <Users className="h-4 w-4" />
                    Admin Console
                  </Link>
                )}
              </nav>
            )}
          </div>

          {/* User Info, Theme Toggle, and Logout */}
          <div className="flex items-center space-x-4">
            {user && (
              <div className="flex items-center space-x-3 text-sm">
                <div className="flex items-center space-x-2">
                  <User className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                  <span className="text-slate-700 dark:text-slate-300">{user.username}</span>
                </div>
                {user.roles && user.roles.length > 0 && (
                  <div className="flex gap-1">
                    {user.roles.map((role) => (
                      <span
                        key={role}
                        className="inline-flex items-center px-2 py-1 text-xs font-medium rounded border bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-500/30 capitalize"
                      >
                        {role}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
            <ThemeToggle />
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
            >
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
