import React from 'react';
import { Sparkles, X, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import Button from './Button';

interface UpgradePromptProps {
  isOpen: boolean;
  onClose: () => void;
  quotaType: string;
  current: number;
  limit: number;
}

const UpgradePrompt: React.FC<UpgradePromptProps> = ({
  isOpen,
  onClose,
  quotaType,
  current,
  limit,
}) => {
  const navigate = useNavigate();

  if (!isOpen) return null;

  const getQuotaLabel = (type: string): string => {
    switch (type) {
      case 'scans_per_day':
        return 'daily scans';
      case 'assets':
        return 'assets';
      case 'reports_per_month':
        return 'monthly reports';
      case 'users':
        return 'team members';
      default:
        return type.replace(/_/g, ' ');
    }
  };

  const handleUpgrade = () => {
    onClose();
    navigate('/pricing');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-dark-surface border border-dark-border rounded-xl shadow-2xl max-w-md w-full mx-4 overflow-hidden">
        {/* Header with gradient */}
        <div className="relative bg-gradient-to-br from-indigo-600/20 via-purple-600/20 to-pink-600/20 px-6 py-8 text-center">
          <button
            onClick={onClose}
            className="absolute top-4 right-4 p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>

          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 mb-4">
            <Sparkles className="h-8 w-8 text-white" />
          </div>

          <h2 className="text-2xl font-bold text-white mb-2">
            Unlock More Scans
          </h2>
          <p className="text-slate-300">
            You've reached your {getQuotaLabel(quotaType)} limit
          </p>
        </div>

        {/* Content */}
        <div className="px-6 py-6">
          {/* Usage indicator */}
          <div className="mb-6 p-4 bg-dark-bg rounded-lg">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-slate-400">Current usage</span>
              <span className="text-white font-medium">
                {current} / {limit} {getQuotaLabel(quotaType)}
              </span>
            </div>
            <div className="w-full h-2 bg-dark-border rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full transition-all"
                style={{ width: '100%' }}
              />
            </div>
          </div>

          {/* Benefits */}
          <div className="space-y-3 mb-6">
            <p className="text-sm font-medium text-slate-300">
              Upgrade to unlock:
            </p>
            <ul className="space-y-2">
              <li className="flex items-center gap-2 text-sm text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                Unlimited scans per day
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                Advanced vulnerability scanning
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                Priority support
              </li>
              <li className="flex items-center gap-2 text-sm text-slate-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                Custom branding and reports
              </li>
            </ul>
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <Button
              variant="secondary"
              onClick={onClose}
              className="flex-1"
            >
              Maybe Later
            </Button>
            <Button
              variant="primary"
              onClick={handleUpgrade}
              className="flex-1 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500"
            >
              View Plans
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default UpgradePrompt;
