import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { useScanStore } from '../../store/scanStore';
import { scanAPI } from '../../services/api';
import ScanCard from './ScanCard';
import Card from '../ui/Card';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Search, Filter } from 'lucide-react';

interface ScanListProps {
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
}

const ScanList: React.FC<ScanListProps> = ({ selectedIds, onSelectionChange }) => {
  const { scans, activeScan, setScans, setActiveScan } = useScanStore();
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const response = await scanAPI.getAll();
      setScans(response.data);
    } catch (error) {
      toast.error('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.targets.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;

    return matchesSearch && matchesStatus;
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
          <span className="text-sm text-slate-400">
            {scans.length} scans
            {selectedIds && selectedIds.size > 0 && ` (${selectedIds.size} selected)`}
          </span>
        </div>

        <Input
          type="text"
          placeholder="Search by name, target, or customer..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          icon={<Search className="h-5 w-5" />}
        />

        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-sm">
            <Filter className="h-4 w-4 text-slate-400" />
            <span className="text-slate-400">Filter:</span>
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
              {searchTerm || statusFilter !== 'all'
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
                <div className="flex-1">
                  <ScanCard
                    scan={scan}
                    isActive={activeScan?.id === scan.id}
                    onClick={() => setActiveScan(scan)}
                  />
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
