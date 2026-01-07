import React from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useUIStore } from '../../store/uiStore';
import { useIsMobile } from '../../hooks/useMediaQuery';
import Button from '../ui/Button';
import ThemeToggle from '../ui/ThemeToggle';
import { OrgSwitcher } from '../organization';
import {
  Shield,
  LogOut,
  User,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';

const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const { sidebarCollapsed, toggleSidebar, setSidebarOpen } = useUIStore();
  const isMobile = useIsMobile();

  const handleToggle = () => {
    if (isMobile) {
      setSidebarOpen(true);
    } else {
      toggleSidebar();
    }
  };

  return (
    <header className="bg-light-surface dark:bg-dark-surface border-b border-light-border dark:border-dark-border shadow-sm sticky top-0 z-30">
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Left: Toggle + Logo */}
          <div className="flex items-center space-x-4">
            {user && (
              <button
                onClick={handleToggle}
                className="p-2 rounded-lg hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
                aria-label={isMobile ? 'Open menu' : sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              >
                {isMobile ? (
                  <Menu className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                ) : sidebarCollapsed ? (
                  <PanelLeftOpen className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                ) : (
                  <PanelLeftClose className="h-5 w-5 text-slate-600 dark:text-slate-400" />
                )}
              </button>
            )}

            {/* Logo - hidden on desktop since it's in sidebar */}
            {(!user || isMobile) && (
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-9 h-9 bg-primary rounded-lg">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <div>
                  <h1 className="text-lg font-bold text-slate-900 dark:text-white">HeroForge</h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400 hidden sm:block">
                    Network Triage Dashboard
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Right: User controls */}
          <div className="flex items-center space-x-3">
            {user && (
              <>
                {/* Organization Switcher */}
                <div className="hidden sm:block">
                  <OrgSwitcher />
                </div>

                {/* User Info */}
                <div className="hidden md:flex items-center space-x-2 text-sm">
                  <div className="flex items-center space-x-2">
                    <User className="h-4 w-4 text-slate-500 dark:text-slate-400" />
                    <span className="text-slate-700 dark:text-slate-300">{user.username}</span>
                  </div>
                  {user.roles && user.roles.length > 0 && (
                    <div className="flex gap-1">
                      {user.roles.slice(0, 2).map((role) => (
                        <span
                          key={role}
                          className="inline-flex items-center px-1.5 py-0.5 text-xs font-medium rounded border bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-500/30 capitalize"
                        >
                          {role}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}

            <ThemeToggle />

            {user && (
              <Button
                variant="ghost"
                size="sm"
                onClick={logout}
                className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline ml-2">Logout</span>
              </Button>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
