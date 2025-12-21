import React, { useState, useRef, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../store/authStore';
import Button from '../ui/Button';
import ThemeToggle from '../ui/ThemeToggle';
import {
  Shield,
  LogOut,
  User,
  LayoutDashboard,
  Users,
  Settings,
  Server,
  Globe,
  Network,
  ShieldCheck,
  ClipboardCheck,
  Building2,
  BookOpenCheck,
  BarChart3,
  Zap,
  GitCompare,
  GitBranch,
  Box,
  FileCode,
  ChevronDown,
  Search,
  FileText,
  Puzzle,
  Radio,
  Activity,
  Crosshair,
  Share2,
} from 'lucide-react';

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  matchPaths?: string[];
}

interface DropdownMenuProps {
  label: string;
  icon: React.ReactNode;
  items: NavItem[];
  isActive: boolean;
}

const DropdownMenu: React.FC<DropdownMenuProps> = ({ label, icon, items, isActive }) => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isItemActive = (item: NavItem) => {
    if (item.matchPaths) {
      return item.matchPaths.some(path => location.pathname.startsWith(path));
    }
    return location.pathname === item.to || location.pathname.startsWith(item.to);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors ${
          isActive
            ? 'bg-primary/10 text-primary font-medium'
            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
        }`}
      >
        {icon}
        {label}
        <ChevronDown className={`h-3 w-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute left-0 mt-1 w-48 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg py-1 z-50">
          {items.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => setIsOpen(false)}
              className={`flex items-center gap-2 px-3 py-2 text-sm transition-colors ${
                isItemActive(item)
                  ? 'bg-primary/10 text-primary font-medium'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
              }`}
            >
              {item.icon}
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};

const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const location = useLocation();

  // Define navigation categories
  const scanningItems: NavItem[] = [
    { to: '/dashboard', icon: <LayoutDashboard className="h-4 w-4" />, label: 'Scans' },
    { to: '/compare', icon: <GitCompare className="h-4 w-4" />, label: 'Compare' },
    { to: '/assets', icon: <Server className="h-4 w-4" />, label: 'Assets' },
    { to: '/agents', icon: <Radio className="h-4 w-4" />, label: 'Agents' },
    { to: '/agents/mesh', icon: <Share2 className="h-4 w-4" />, label: 'Mesh Network' },
    { to: '/webapp-scan', icon: <Globe className="h-4 w-4" />, label: 'Web Scan' },
    { to: '/dns-tools', icon: <Network className="h-4 w-4" />, label: 'DNS Tools' },
    { to: '/api-security', icon: <Zap className="h-4 w-4" />, label: 'API Security' },
    { to: '/container-security', icon: <Box className="h-4 w-4" />, label: 'Containers' },
    { to: '/iac-security', icon: <FileCode className="h-4 w-4" />, label: 'IaC Security' },
    { to: '/attack-simulation', icon: <Crosshair className="h-4 w-4" />, label: 'BAS' },
  ];

  const complianceItems: NavItem[] = [
    { to: '/compliance', icon: <ShieldCheck className="h-4 w-4" />, label: 'Compliance' },
    { to: '/evidence', icon: <FileText className="h-4 w-4" />, label: 'Evidence' },
    { to: '/manual-assessments', icon: <ClipboardCheck className="h-4 w-4" />, label: 'Assessments' },
    { to: '/methodology', icon: <BookOpenCheck className="h-4 w-4" />, label: 'Methodology' },
  ];

  const reportsItems: NavItem[] = [
    { to: '/executive-dashboard', icon: <BarChart3 className="h-4 w-4" />, label: 'Executive Dashboard' },
    { to: '/workflows', icon: <GitBranch className="h-4 w-4" />, label: 'Workflows' },
    { to: '/remediation', icon: <FileText className="h-4 w-4" />, label: 'Remediation' },
  ];

  // Check if any item in a category is active
  const isScanningActive = scanningItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isComplianceActive = complianceItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );
  const isReportsActive = reportsItems.some(
    item => location.pathname === item.to || location.pathname.startsWith(item.to)
  );

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
                {/* CRM - Standalone */}
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

                {/* Scanning Dropdown */}
                <DropdownMenu
                  label="Scanning"
                  icon={<Search className="h-4 w-4" />}
                  items={scanningItems}
                  isActive={isScanningActive}
                />

                {/* Compliance Dropdown */}
                <DropdownMenu
                  label="Compliance"
                  icon={<ShieldCheck className="h-4 w-4" />}
                  items={complianceItems}
                  isActive={isComplianceActive}
                />

                {/* Reports Dropdown */}
                <DropdownMenu
                  label="Reports"
                  icon={<BarChart3 className="h-4 w-4" />}
                  items={reportsItems}
                  isActive={isReportsActive}
                />

                {/* SIEM - Standalone */}
                <Link
                  to="/siem"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/siem')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Activity className="h-4 w-4" />
                  SIEM
                </Link>

                {/* Settings - Standalone */}
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

                {/* Plugins - Standalone */}
                <Link
                  to="/plugins"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/plugins')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                  }`}
                >
                  <Puzzle className="h-4 w-4" />
                  Plugins
                </Link>

                {/* Admin - Standalone (conditional) */}
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
                    Admin
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
