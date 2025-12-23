import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2, ChevronDown, Check, Plus, Settings } from 'lucide-react';
import { useOrgStore } from '../../store/orgStore';
import { organizationAPI } from '../../services/api';
import { useQuery } from '@tanstack/react-query';
import type { OrganizationSummary } from '../../types';

const OrgSwitcher: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const {
    currentOrg,
    organizations,
    setCurrentOrg,
    setOrganizations,
  } = useOrgStore();

  // Fetch organizations on mount
  const { isLoading } = useQuery({
    queryKey: ['organizations'],
    queryFn: async () => {
      const response = await organizationAPI.list();
      setOrganizations(response.data);
      return response.data;
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelectOrg = (org: OrganizationSummary) => {
    setCurrentOrg(org);
    setIsOpen(false);
  };

  const handleCreateOrg = () => {
    setIsOpen(false);
    navigate('/organization/new');
  };

  const handleManageOrg = () => {
    setIsOpen(false);
    if (currentOrg) {
      navigate(`/organization/${currentOrg.id}`);
    }
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'owner':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'admin':
        return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  // Don't show if user has no organizations
  if (!isLoading && organizations.length === 0) {
    return (
      <button
        onClick={handleCreateOrg}
        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
      >
        <Plus className="h-4 w-4" />
        Create Organization
      </button>
    );
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        disabled={isLoading}
        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover transition-colors border border-light-border dark:border-dark-border"
      >
        <Building2 className="h-4 w-4" />
        <span className="max-w-[120px] truncate">
          {isLoading ? 'Loading...' : (currentOrg?.name || 'Select Organization')}
        </span>
        <ChevronDown className={`h-3 w-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute left-0 mt-1 w-64 bg-light-surface dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-lg shadow-lg z-50 overflow-hidden">
          {/* Organizations List */}
          <div className="max-h-64 overflow-y-auto py-1">
            {organizations.map((org) => (
              <button
                key={org.id}
                onClick={() => handleSelectOrg(org)}
                className={`w-full flex items-center justify-between px-3 py-2 text-sm transition-colors ${
                  currentOrg?.id === org.id
                    ? 'bg-primary/10 text-primary'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover'
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Building2 className="h-4 w-4 flex-shrink-0" />
                  <span className="truncate">{org.name}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`text-xs px-1.5 py-0.5 rounded border ${getRoleBadgeColor(org.role)}`}>
                    {org.role}
                  </span>
                  {currentOrg?.id === org.id && (
                    <Check className="h-4 w-4 text-primary" />
                  )}
                </div>
              </button>
            ))}
          </div>

          {/* Divider */}
          <div className="border-t border-light-border dark:border-dark-border" />

          {/* Actions */}
          <div className="py-1">
            {currentOrg && (
              <button
                onClick={handleManageOrg}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
              >
                <Settings className="h-4 w-4" />
                Manage Organization
              </button>
            )}
            <button
              onClick={handleCreateOrg}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
            >
              <Plus className="h-4 w-4" />
              Create Organization
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrgSwitcher;
