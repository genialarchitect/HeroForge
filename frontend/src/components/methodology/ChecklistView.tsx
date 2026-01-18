import React, { useState, useMemo } from 'react';
import type {
  ChecklistWithItems,
  ChecklistItemWithTemplate,
  ChecklistItemStatus,
  ScannerMapping,
  ExploitItemRequest,
} from '../../types';
import { methodologyAPI } from '../../services/api';
import { toast } from 'react-toastify';
import ProgressBar from './ProgressBar';
import ItemCard from './ItemCard';
import ExploitTargetModal from './ExploitTargetModal';
import {
  CheckCircle2,
  XCircle,
  Circle,
  Clock,
  Ban,
  Filter,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

interface ChecklistViewProps {
  checklist: ChecklistWithItems;
  onUpdate: (checklist: ChecklistWithItems) => void;
}

type StatusFilter = ChecklistItemStatus | 'all';

const ChecklistView: React.FC<ChecklistViewProps> = ({ checklist, onUpdate }) => {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    new Set(
      // Start with all categories expanded
      [...new Set(checklist.items.map((item) => item.category))]
    )
  );
  const [isUpdating, setIsUpdating] = useState<string | null>(null);

  // Exploit modal state
  const [exploitModalOpen, setExploitModalOpen] = useState(false);
  const [exploitingItem, setExploitingItem] = useState<ChecklistItemWithTemplate | null>(null);
  const [scannerMapping, setScannerMapping] = useState<ScannerMapping | null>(null);
  const [isExploiting, setIsExploiting] = useState(false);

  // Group items by category
  const itemsByCategory = useMemo(() => {
    const grouped: Record<string, ChecklistItemWithTemplate[]> = {};
    for (const item of checklist.items) {
      if (!grouped[item.category]) {
        grouped[item.category] = [];
      }
      grouped[item.category].push(item);
    }
    return grouped;
  }, [checklist.items]);

  // Filter items by status
  const filteredItemsByCategory = useMemo(() => {
    if (statusFilter === 'all') return itemsByCategory;

    const filtered: Record<string, ChecklistItemWithTemplate[]> = {};
    for (const [category, items] of Object.entries(itemsByCategory)) {
      const categoryItems = items.filter((item) => item.status === statusFilter);
      if (categoryItems.length > 0) {
        filtered[category] = categoryItems;
      }
    }
    return filtered;
  }, [itemsByCategory, statusFilter]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = checklist.items.length;
    const counts = {
      not_started: 0,
      in_progress: 0,
      pass: 0,
      fail: 0,
      na: 0,
    };
    for (const item of checklist.items) {
      counts[item.status]++;
    }
    return { total, ...counts };
  }, [checklist.items]);

  const handleItemUpdate = async (
    item: ChecklistItemWithTemplate,
    status: ChecklistItemStatus,
    notes?: string
  ) => {
    setIsUpdating(item.id);
    try {
      await methodologyAPI.updateItem(checklist.checklist.id, item.template_item_id, {
        status,
        notes,
      });

      // Refresh the checklist
      const response = await methodologyAPI.getChecklist(checklist.checklist.id);
      onUpdate(response.data);
      toast.success('Item updated');
    } catch (error) {
      console.error('Failed to update item:', error);
      toast.error('Failed to update item');
    } finally {
      setIsUpdating(null);
    }
  };

  // Handle exploit button click - fetch scanner info and open modal
  const handleExploitClick = async (item: ChecklistItemWithTemplate) => {
    const itemCode = item.template_item_code;
    if (!itemCode) {
      toast.error('No item code available for this test');
      return;
    }

    try {
      const response = await methodologyAPI.getScannerInfo(itemCode);
      setScannerMapping(response.data);
      setExploitingItem(item);
      setExploitModalOpen(true);
    } catch (error) {
      console.error('Failed to get scanner info:', error);
      toast.error('No automated scanner available for this item');
    }
  };

  // Handle exploit submission
  const handleExploitSubmit = async (request: ExploitItemRequest) => {
    if (!exploitingItem) return;

    setIsExploiting(true);
    try {
      const response = await methodologyAPI.exploitItem(
        checklist.checklist.id,
        exploitingItem.template_item_id,
        request
      );

      toast.success(`${response.data.summary}`);

      // Refresh the checklist to get updated item status
      const updated = await methodologyAPI.getChecklist(checklist.checklist.id);
      onUpdate(updated.data);
      setExploitModalOpen(false);
      setExploitingItem(null);
      setScannerMapping(null);
    } catch (error: unknown) {
      console.error('Exploit test failed:', error);
      const errorMessage =
        error instanceof Error && 'response' in error
          ? (error as { response?: { data?: { error?: string } } }).response?.data?.error
          : 'Exploit test failed';
      toast.error(errorMessage || 'Exploit test failed');
    } finally {
      setIsExploiting(false);
    }
  };

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const getCategoryProgress = (items: ChecklistItemWithTemplate[]) => {
    const completed = items.filter((i) =>
      ['pass', 'fail', 'na'].includes(i.status)
    ).length;
    return (completed / items.length) * 100;
  };

  const getStatusCount = (items: ChecklistItemWithTemplate[], status: ChecklistItemStatus) => {
    return items.filter((i) => i.status === status).length;
  };

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="bg-dark-surface rounded-lg border border-dark-border p-4">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{stats.total}</div>
            <div className="text-xs text-slate-400">Total Items</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-400">{stats.pass}</div>
            <div className="text-xs text-slate-400">Passed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">{stats.fail}</div>
            <div className="text-xs text-slate-400">Failed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.in_progress}</div>
            <div className="text-xs text-slate-400">In Progress</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-slate-400">{stats.na}</div>
            <div className="text-xs text-slate-400">N/A</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-slate-500">{stats.not_started}</div>
            <div className="text-xs text-slate-400">Not Started</div>
          </div>
        </div>

        <div className="mt-4">
          <ProgressBar progress={checklist.checklist.progress_percent} size="lg" showLabel />
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="h-4 w-4 text-slate-400" />
        <span className="text-sm text-slate-400 mr-2">Filter:</span>
        {[
          { value: 'all', label: 'All', icon: Circle, color: 'text-slate-400' },
          { value: 'not_started', label: 'Not Started', icon: Circle, color: 'text-slate-500' },
          { value: 'in_progress', label: 'In Progress', icon: Clock, color: 'text-yellow-400' },
          { value: 'pass', label: 'Pass', icon: CheckCircle2, color: 'text-green-400' },
          { value: 'fail', label: 'Fail', icon: XCircle, color: 'text-red-400' },
          { value: 'na', label: 'N/A', icon: Ban, color: 'text-slate-400' },
        ].map((filter) => (
          <button
            key={filter.value}
            onClick={() => setStatusFilter(filter.value as StatusFilter)}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              statusFilter === filter.value
                ? 'bg-primary/20 text-primary'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
          >
            <filter.icon className={`h-3.5 w-3.5 ${filter.color}`} />
            {filter.label}
          </button>
        ))}
      </div>

      {/* Categories and Items */}
      <div className="space-y-4">
        {Object.entries(filteredItemsByCategory).map(([category, items]) => (
          <div
            key={category}
            className="bg-dark-surface rounded-lg border border-dark-border overflow-hidden"
          >
            {/* Category Header */}
            <button
              onClick={() => toggleCategory(category)}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-dark-hover transition-colors"
            >
              <div className="flex items-center gap-3">
                {expandedCategories.has(category) ? (
                  <ChevronDown className="h-5 w-5 text-slate-400" />
                ) : (
                  <ChevronRight className="h-5 w-5 text-slate-400" />
                )}
                <span className="font-medium text-white">{category}</span>
                <span className="text-sm text-slate-400">
                  ({items.length} items)
                </span>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-green-400">
                    {getStatusCount(items, 'pass')} pass
                  </span>
                  <span className="text-red-400">
                    {getStatusCount(items, 'fail')} fail
                  </span>
                </div>
                <div className="w-32">
                  <ProgressBar progress={getCategoryProgress(items)} size="sm" />
                </div>
              </div>
            </button>

            {/* Items */}
            {expandedCategories.has(category) && (
              <div className="border-t border-dark-border divide-y divide-dark-border">
                {items.map((item) => (
                  <ItemCard
                    key={item.id}
                    item={item}
                    isUpdating={isUpdating === item.id}
                    onStatusChange={(status) => handleItemUpdate(item, status)}
                    onNotesChange={(notes) =>
                      handleItemUpdate(item, item.status, notes)
                    }
                    onExploit={handleExploitClick}
                    canExploit={!!item.template_item_code}
                  />
                ))}
              </div>
            )}
          </div>
        ))}

        {Object.keys(filteredItemsByCategory).length === 0 && (
          <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center">
            <Filter className="h-12 w-12 text-slate-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Items Found</h3>
            <p className="text-slate-400">
              No items match the current filter. Try selecting a different status filter.
            </p>
          </div>
        )}
      </div>

      {/* Exploit Target Modal */}
      <ExploitTargetModal
        isOpen={exploitModalOpen}
        onClose={() => {
          setExploitModalOpen(false);
          setExploitingItem(null);
          setScannerMapping(null);
        }}
        onSubmit={handleExploitSubmit}
        itemCode={exploitingItem?.template_item_code || ''}
        itemTitle={exploitingItem?.title || ''}
        scannerMapping={scannerMapping}
        isLoading={isExploiting}
      />
    </div>
  );
};

export default ChecklistView;
