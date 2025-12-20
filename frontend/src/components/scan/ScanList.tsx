import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { useScanStore } from '../../store/scanStore';
import { scanAPI, scanTagAPI } from '../../services/api';
import ScanCard from './ScanCard';
import Card from '../ui/Card';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Search, Filter, Tag, Plus, X, Copy } from 'lucide-react';
import type { ScanTag, ScanWithTags } from '../../types';

interface ScanListProps {
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
}

const ScanList: React.FC<ScanListProps> = ({ selectedIds, onSelectionChange }) => {
  const { scans, activeScan, setScans, setActiveScan } = useScanStore();
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [tagFilter, setTagFilter] = useState<string>('all');
  const [allTags, setAllTags] = useState<ScanTag[]>([]);
  const [scanTagsMap, setScanTagsMap] = useState<Record<string, ScanTag[]>>({});
  const [showTagManager, setShowTagManager] = useState(false);
  const [newTagName, setNewTagName] = useState('');
  const [newTagColor, setNewTagColor] = useState('#06b6d4');
  const [duplicatingId, setDuplicatingId] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
    loadTags();
  }, []);

  const loadScans = async () => {
    try {
      const response = await scanAPI.getAllWithTags();
      const scansData = response.data as ScanWithTags[];
      setScans(scansData.map((s) => ({ ...s, tags: undefined })));
      // Build tags map
      const tagsMap: Record<string, ScanTag[]> = {};
      scansData.forEach((scan) => {
        tagsMap[scan.id] = scan.tags || [];
      });
      setScanTagsMap(tagsMap);
    } catch (error) {
      // Fall back to regular scan list
      try {
        const response = await scanAPI.getAll();
        setScans(response.data);
      } catch {
        toast.error('Failed to load scans');
      }
    } finally {
      setLoading(false);
    }
  };

  const loadTags = async () => {
    try {
      const response = await scanTagAPI.getAll();
      setAllTags(response.data);
    } catch (error) {
      console.error('Failed to load tags:', error);
    }
  };

  const handleCreateTag = async () => {
    if (!newTagName.trim()) return;
    try {
      const response = await scanTagAPI.create({
        name: newTagName.trim(),
        color: newTagColor,
      });
      setAllTags([...allTags, response.data]);
      setNewTagName('');
      toast.success('Tag created successfully');
    } catch (error) {
      toast.error('Failed to create tag');
    }
  };

  const handleDeleteTag = async (tagId: string) => {
    try {
      await scanTagAPI.delete(tagId);
      setAllTags(allTags.filter((t) => t.id !== tagId));
      if (tagFilter === tagId) {
        setTagFilter('all');
      }
      toast.success('Tag deleted');
    } catch (error) {
      toast.error('Failed to delete tag');
    }
  };

  const handleDuplicateScan = async (e: React.MouseEvent, scanId: string) => {
    e.stopPropagation();
    setDuplicatingId(scanId);
    try {
      const response = await scanAPI.duplicate(scanId);
      const newScan = response.data;
      setScans([newScan, ...scans]);
      // Copy tags from original scan
      if (scanTagsMap[scanId]) {
        setScanTagsMap({
          ...scanTagsMap,
          [newScan.id]: scanTagsMap[scanId],
        });
      }
      toast.success('Scan duplicated successfully');
    } catch (error) {
      toast.error('Failed to duplicate scan');
    } finally {
      setDuplicatingId(null);
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.targets.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;

    const matchesTag = tagFilter === 'all' ||
      (scanTagsMap[scan.id] && scanTagsMap[scan.id].some((t) => t.id === tagFilter));

    return matchesSearch && matchesStatus && matchesTag;
  });

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!onSelectionChange) return;

    if (e.target.checked) {
      onSelectionChange(new Set(filteredScans.map((s) => s.id)));
    } else {
      onSelectionChange(new Set());
    }
  };

  const handleSelectOne = (id: string, checked: boolean) => {
    if (!onSelectionChange || !selectedIds) return;

    const newSelected = new Set(selectedIds);
    if (checked) {
      newSelected.add(id);
    } else {
      newSelected.delete(id);
    }
    onSelectionChange(newSelected);
  };

  const tagColors = [
    '#06b6d4', // cyan
    '#8b5cf6', // violet
    '#f59e0b', // amber
    '#10b981', // emerald
    '#ef4444', // red
    '#ec4899', // pink
    '#3b82f6', // blue
    '#84cc16', // lime
  ];

  if (loading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xl font-semibold text-white">Scan History</h3>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowTagManager(!showTagManager)}
              className="text-sm text-slate-400 hover:text-primary flex items-center gap-1"
              title="Manage tags"
            >
              <Tag className="h-4 w-4" />
              Tags
            </button>
            <span className="text-sm text-slate-400">
              {scans.length} scans
              {selectedIds && selectedIds.size > 0 && ` (${selectedIds.size} selected)`}
            </span>
          </div>
        </div>

        {/* Tag Manager Panel */}
        {showTagManager && (
          <div className="bg-dark-bg border border-dark-border rounded-lg p-3 space-y-3">
            <div className="flex items-center gap-2">
              <Input
                type="text"
                placeholder="New tag name..."
                value={newTagName}
                onChange={(e) => setNewTagName(e.target.value)}
                className="flex-1"
              />
              <div className="flex gap-1">
                {tagColors.map((color) => (
                  <button
                    key={color}
                    onClick={() => setNewTagColor(color)}
                    className={`w-6 h-6 rounded-full border-2 ${
                      newTagColor === color ? 'border-white' : 'border-transparent'
                    }`}
                    style={{ backgroundColor: color }}
                    title={color}
                  />
                ))}
              </div>
              <button
                onClick={handleCreateTag}
                disabled={!newTagName.trim()}
                className="px-3 py-1.5 bg-primary text-white rounded hover:bg-primary/80 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {allTags.map((tag) => (
                <span
                  key={tag.id}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded text-sm"
                  style={{ backgroundColor: tag.color + '20', color: tag.color }}
                >
                  {tag.name}
                  <button
                    onClick={() => handleDeleteTag(tag.id)}
                    className="hover:opacity-70"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
              {allTags.length === 0 && (
                <span className="text-sm text-slate-500">No tags yet</span>
              )}
            </div>
          </div>
        )}

        <Input
          type="text"
          placeholder="Search by name, target, or customer..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          icon={<Search className="h-5 w-5" />}
        />

        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center space-x-2">
              <Filter className="h-4 w-4 text-slate-400" />
              <span className="text-slate-400">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-dark-bg border border-dark-border text-slate-300 rounded px-2 py-1 focus:outline-none focus:border-primary"
              >
                <option value="all">All</option>
                <option value="pending">Pending</option>
                <option value="running">Running</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
              </select>
            </div>

            {allTags.length > 0 && (
              <div className="flex items-center space-x-2">
                <Tag className="h-4 w-4 text-slate-400" />
                <span className="text-slate-400">Tag:</span>
                <select
                  value={tagFilter}
                  onChange={(e) => setTagFilter(e.target.value)}
                  className="bg-dark-bg border border-dark-border text-slate-300 rounded px-2 py-1 focus:outline-none focus:border-primary"
                >
                  <option value="all">All Tags</option>
                  {allTags.map((tag) => (
                    <option key={tag.id} value={tag.id}>
                      {tag.name}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {onSelectionChange && (
            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="select-all"
                checked={selectedIds?.size === filteredScans.length && filteredScans.length > 0}
                onChange={handleSelectAll}
                className="rounded border-dark-border bg-dark-bg text-primary focus:ring-primary"
              />
              <label htmlFor="select-all" className="text-sm text-slate-400 cursor-pointer">
                Select All
              </label>
            </div>
          )}
        </div>

        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {filteredScans.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              {searchTerm || statusFilter !== 'all' || tagFilter !== 'all'
                ? 'No scans match your filters'
                : 'No scans yet. Create your first scan above.'}
            </div>
          ) : (
            filteredScans.map((scan) => (
              <div key={scan.id} className="flex items-center space-x-2">
                {onSelectionChange && (
                  <input
                    type="checkbox"
                    checked={selectedIds?.has(scan.id) || false}
                    onChange={(e) => handleSelectOne(scan.id, e.target.checked)}
                    className="rounded border-dark-border bg-dark-bg text-primary focus:ring-primary flex-shrink-0"
                  />
                )}
                <div className="flex-1 relative group">
                  <ScanCard
                    scan={scan}
                    isActive={activeScan?.id === scan.id}
                    onClick={() => setActiveScan(scan)}
                    tags={scanTagsMap[scan.id]}
                  />
                  {/* Duplicate button - shown on hover */}
                  <button
                    onClick={(e) => handleDuplicateScan(e, scan.id)}
                    disabled={duplicatingId === scan.id}
                    className="absolute top-2 right-12 p-1.5 bg-dark-bg/90 border border-dark-border rounded opacity-0 group-hover:opacity-100 transition-opacity hover:border-primary hover:text-primary disabled:opacity-50"
                    title="Duplicate scan"
                  >
                    {duplicatingId === scan.id ? (
                      <LoadingSpinner className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </Card>
  );
};

export default ScanList;
