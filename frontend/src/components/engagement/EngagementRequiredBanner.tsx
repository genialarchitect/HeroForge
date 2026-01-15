import React from 'react';
import { AlertTriangle, Briefcase, ArrowRight } from 'lucide-react';
import { useEngagementStore } from '../../store/engagementStore';
import { EngagementSelector } from './EngagementSelector';

interface EngagementRequiredBannerProps {
  /** Name of the tool/feature requiring engagement */
  toolName?: string;
  /** Show inline selector in banner */
  showInlineSelector?: boolean;
  /** Custom message to display */
  message?: string;
  /** Additional CSS classes */
  className?: string;
}

/**
 * Banner component shown when a red-team tool requires an engagement to be selected.
 * Shows a warning and optionally an inline engagement selector.
 */
export const EngagementRequiredBanner: React.FC<EngagementRequiredBannerProps> = ({
  toolName = 'this tool',
  showInlineSelector = true,
  message,
  className = '',
}) => {
  const { activeCustomer, activeEngagement } = useEngagementStore();

  // Don't show if engagement is selected
  if (activeCustomer && activeEngagement) {
    return null;
  }

  const defaultMessage = `Select a customer and engagement before using ${toolName}. All scan results will be associated with the selected engagement.`;

  return (
    <div className={`bg-yellow-900/20 border border-yellow-600/30 rounded-lg p-4 ${className}`}>
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0">
          <AlertTriangle className="w-6 h-6 text-yellow-500" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-yellow-400 mb-1">
            Engagement Required
          </h3>
          <p className="text-sm text-yellow-200/80 mb-4">
            {message || defaultMessage}
          </p>

          {showInlineSelector && (
            <div className="flex flex-col lg:flex-row gap-4">
              <EngagementSelector className="lg:max-w-md" />

              {activeCustomer && !activeEngagement && (
                <div className="flex items-center text-sm text-yellow-200/60">
                  <ArrowRight className="w-4 h-4 mr-2" />
                  Now select an engagement to continue
                </div>
              )}
            </div>
          )}

          {!showInlineSelector && (
            <div className="flex items-center gap-2 text-sm text-yellow-200/80">
              <Briefcase className="w-4 h-4" />
              <span>Use the engagement selector in the sidebar or header to set your active engagement.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default EngagementRequiredBanner;
