import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../store/authStore';
import Button from '../ui/Button';
import { Shield, LogOut, User, LayoutDashboard, Users, Settings, Server, Globe, Network, ShieldCheck } from 'lucide-react';

const Header: React.FC = () => {
  const { user, logout } = useAuth();
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const location = useLocation();

  return (
    <header className="bg-dark-surface border-b border-dark-border shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-10 h-10 bg-primary rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">HeroForge</h1>
                <p className="text-xs text-slate-400">Network Triage Dashboard</p>
              </div>
            </div>

            {/* Navigation */}
            {user && (
              <nav className="flex items-center space-x-1">
                <Link
                  to="/dashboard"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/dashboard')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                  }`}
                >
                  <LayoutDashboard className="h-4 w-4" />
                  Dashboard
                </Link>
                <Link
                  to="/assets"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/assets')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
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
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
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
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                  }`}
                >
                  <Network className="h-4 w-4" />
                  DNS Tools
                </Link>
                <Link
                  to="/compliance"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/compliance')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                  }`}
                >
                  <ShieldCheck className="h-4 w-4" />
                  Compliance
                </Link>
                <Link
                  to="/settings"
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                    location.pathname.startsWith('/settings')
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-slate-400 hover:text-white hover:bg-dark-hover'
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
                        : 'text-slate-400 hover:text-white hover:bg-dark-hover'
                    }`}
                  >
                    <Users className="h-4 w-4" />
                    Admin Console
                  </Link>
                )}
              </nav>
            )}
          </div>

          {/* User Info and Logout */}
          <div className="flex items-center space-x-4">
            {user && (
              <div className="flex items-center space-x-3 text-sm">
                <div className="flex items-center space-x-2">
                  <User className="h-5 w-5 text-slate-400" />
                  <span className="text-slate-300">{user.username}</span>
                </div>
                {user.roles && user.roles.length > 0 && (
                  <div className="flex gap-1">
                    {user.roles.map((role) => (
                      <span
                        key={role}
                        className="inline-flex items-center px-2 py-1 text-xs font-medium rounded border bg-slate-500/20 text-slate-300 border-slate-500/30 capitalize"
                      >
                        {role}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={logout}
              className="text-slate-400 hover:text-white"
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
