import { useState, useEffect, ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { portalAuthAPI } from '../../services/portalApi';
import type { PortalUserInfo } from '../../types';
import {
  Home,
  Folder,
  ShieldAlert,
  FileText,
  User,
  LogOut,
  Menu,
  X,
  Shield,
} from 'lucide-react';

interface PortalLayoutProps {
  children: ReactNode;
}

const navigation = [
  { name: 'Dashboard', href: '/portal/dashboard', icon: Home },
  { name: 'Engagements', href: '/portal/engagements', icon: Folder },
  { name: 'Vulnerabilities', href: '/portal/vulnerabilities', icon: ShieldAlert },
  { name: 'Reports', href: '/portal/reports', icon: FileText },
  { name: 'Profile', href: '/portal/profile', icon: User },
];

export function PortalLayout({ children }: PortalLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [user, setUser] = useState<PortalUserInfo | null>(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const storedUser = portalAuthAPI.getStoredUser();
    if (storedUser) {
      setUser(storedUser);
    } else if (!portalAuthAPI.isAuthenticated()) {
      navigate('/portal/login');
    }
  }, [navigate]);

  const handleLogout = () => {
    portalAuthAPI.logout();
    navigate('/portal/login');
  };

  const isActive = (href: string) => {
    return location.pathname === href ||
      (href !== '/portal/dashboard' && location.pathname.startsWith(href));
  };

  return (
    <div className="min-h-screen bg-light-bg dark:bg-dark-bg transition-colors">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed top-0 left-0 h-full z-50
          bg-light-surface dark:bg-dark-surface
          border-r border-light-border dark:border-dark-border
          transition-transform duration-300 ease-in-out
          w-64 flex flex-col
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
          lg:translate-x-0
        `}
      >
        {/* Sidebar Header */}
        <div className="flex items-center justify-between p-4 border-b border-light-border dark:border-dark-border">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 bg-primary rounded-lg">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="font-bold text-slate-900 dark:text-white">Customer Portal</span>
          </div>
          <button
            className="lg:hidden p-1.5 rounded-lg hover:bg-light-hover dark:hover:bg-dark-hover"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-5 w-5 text-slate-600 dark:text-slate-400" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {navigation.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.href);
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={() => setSidebarOpen(false)}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-colors text-sm ${
                  active
                    ? 'bg-primary/10 text-primary font-medium'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Icon className="h-4 w-4 flex-shrink-0" />
                <span>{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* User Info & Logout */}
        <div className="p-4 border-t border-light-border dark:border-dark-border">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
              <User className="h-4 w-4 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                {user?.email}
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                {user?.customer_name}
              </p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-slate-600 dark:text-slate-400 hover:bg-light-hover dark:hover:bg-dark-hover hover:text-slate-900 dark:hover:text-white rounded-lg transition-colors"
          >
            <LogOut className="h-4 w-4" />
            <span>Sign out</span>
          </button>
        </div>
      </aside>

      {/* Main content area */}
      <div className="lg:ml-64 flex flex-col min-h-screen transition-all duration-300">
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-light-surface dark:bg-dark-surface border-b border-light-border dark:border-dark-border">
          <div className="flex items-center justify-between h-16 px-4 sm:px-6 lg:px-8">
            <button
              type="button"
              className="lg:hidden p-2 rounded-lg hover:bg-light-hover dark:hover:bg-dark-hover"
              onClick={() => setSidebarOpen(true)}
            >
              <Menu className="h-5 w-5 text-slate-600 dark:text-slate-400" />
            </button>
            <div className="flex-1" />
            <div className="flex items-center text-sm text-slate-500 dark:text-slate-400">
              Welcome, <span className="ml-1 font-medium text-slate-900 dark:text-white">{user?.customer_name}</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 px-4 sm:px-6 lg:px-8 py-6 w-full max-w-7xl mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
