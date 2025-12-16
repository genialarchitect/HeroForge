import React, { useState } from 'react';
import { Download, Trash2, X } from 'lucide-react';
import Button from './Button';

export interface BulkAction {
  id: string;
  label: string;
  icon?: React.ReactNode;
  variant?: 'primary' | 'danger' | 'secondary';
  requiresConfirmation?: boolean;
  confirmationMessage?: string;
}

interface BulkActionBarProps {
  selectedCount: number;
  onClear: () => void;
  actions: BulkAction[];
  onAction: (actionId: string) => void;
  isProcessing?: boolean;
}

const BulkActionBar: React.FC<BulkActionBarProps> = ({
  selectedCount,
  onClear,
  actions,
  onAction,
  isProcessing = false,
}) => {
  const [showConfirmation, setShowConfirmation] = useState<string | null>(null);

  if (selectedCount === 0) {
    return null;
  }

  const handleActionClick = (action: BulkAction) => {
    if (action.requiresConfirmation) {
      setShowConfirmation(action.id);
    } else {
      onAction(action.id);
    }
  };

  const handleConfirm = () => {
    if (showConfirmation) {
      onAction(showConfirmation);
      setShowConfirmation(null);
    }
  };

  const getActionIcon = (action: BulkAction) => {
    if (action.icon) return action.icon;

    switch (action.id) {
      case 'delete':
        return <Trash2 className="h-4 w-4" />;
      case 'export':
        return <Download className="h-4 w-4" />;
      default:
        return null;
    }
  };

  const confirmingAction = actions.find((a) => a.id === showConfirmation);

  return (
    <>
      <div className="fixed bottom-6 left-1/2 transform -translate-x-1/2 z-50 animate-slide-up">
        <div className="bg-dark-card border border-dark-border rounded-lg shadow-2xl px-6 py-4 min-w-[400px]">
          <div className="flex items-center justify-between space-x-4">
            <div className="flex items-center space-x-3">
              <div className="bg-primary/10 text-primary rounded-full w-8 h-8 flex items-center justify-center font-semibold text-sm">
                {selectedCount}
              </div>
              <span className="text-white font-medium">
                {selectedCount} item{selectedCount !== 1 ? 's' : ''} selected
              </span>
            </div>

            <div className="flex items-center space-x-2">
              {actions.map((action) => (
                <Button
                  key={action.id}
                  variant={action.variant || 'secondary'}
                  onClick={() => handleActionClick(action)}
                  disabled={isProcessing}
                  className="flex items-center space-x-2"
                >
                  {getActionIcon(action)}
                  <span>{action.label}</span>
                </Button>
              ))}

              <button
                onClick={onClear}
                disabled={isProcessing}
                className="text-slate-400 hover:text-white transition-colors p-2 rounded-lg hover:bg-dark-bg disabled:opacity-50"
                title="Clear selection"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {showConfirmation && confirmingAction && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60]">
          <div className="bg-dark-card border border-dark-border rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-xl font-semibold text-white mb-4">Confirm Action</h3>
            <p className="text-slate-300 mb-6">
              {confirmingAction.confirmationMessage ||
                `Are you sure you want to ${confirmingAction.label.toLowerCase()} ${selectedCount} item${
                  selectedCount !== 1 ? 's' : ''
                }?`}
            </p>
            <div className="flex justify-end space-x-3">
              <Button
                variant="secondary"
                onClick={() => setShowConfirmation(null)}
                disabled={isProcessing}
              >
                Cancel
              </Button>
              <Button
                variant={confirmingAction.variant || 'primary'}
                onClick={handleConfirm}
                disabled={isProcessing}
              >
                Confirm
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default BulkActionBar;
