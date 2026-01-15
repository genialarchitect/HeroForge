import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Building2, Monitor, FileCheck } from 'lucide-react';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

const acasNavItems: NavItem[] = [
  {
    to: '/scap',
    label: 'SCAP Scanner',
    icon: Shield,
    description: 'SCAP compliance scanning',
  },
  {
    to: '/emass',
    label: 'eMASS',
    icon: Building2,
    description: 'eMASS integration',
  },
  {
    to: '/windows-audit',
    label: 'Windows Audit',
    icon: Monitor,
    description: 'Windows STIG auditing',
  },
  {
    to: '/audit-files',
    label: 'Audit Files',
    icon: FileCheck,
    description: 'CKL/ARF file management',
  },
];

const AcasNavigation: React.FC = () => {
  const location = useLocation();

  return (
    <div className="mb-6">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
          ACAS / RMF Tools
        </span>
      </div>
      <div className="flex gap-2 flex-wrap">
        {acasNavItems.map((item) => {
          const isActive = location.pathname === item.to;
          const Icon = item.icon;
          return (
            <Link
              key={item.to}
              to={item.to}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-cyan-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-gray-100'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span className="text-sm font-medium">{item.label}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
};

export default AcasNavigation;
