import React, { useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { useScanStore } from '../../store/scanStore';
import { scanAPI } from '../../services/api';
import ScanCard from './ScanCard';
import Card from '../ui/Card';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Search, Filter } from 'lucide-react';

const ScanList: React.FC = () => {
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
          <span className="text-sm text-slate-400">{scans.length} scans</span>
        </div>

        <Input
          type="text"
          placeholder="Search by name, target, or customer..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          icon={<Search className="h-5 w-5" />}
        />

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

        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {filteredScans.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              {searchTerm || statusFilter !== 'all'
                ? 'No scans match your filters'
                : 'No scans yet. Create your first scan above.'}
            </div>
          ) : (
            filteredScans.map((scan) => (
              <ScanCard
                key={scan.id}
                scan={scan}
                isActive={activeScan?.id === scan.id}
                onClick={() => setActiveScan(scan)}
              />
            ))
          )}
        </div>
      </div>
    </Card>
  );
};

export default ScanList;
