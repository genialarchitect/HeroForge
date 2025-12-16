import React, { useEffect, useState } from 'react';
import { Activity, Clock, CheckCircle, XCircle, Loader } from 'lucide-react';
import WidgetContainer from './WidgetContainer';
import { formatDistanceToNow } from 'date-fns';

interface Scan {
  id: string;
  name: string;
  status: string;
  created_at: string;
  completed_at?: string;
}

interface RecentScansWidgetProps {
  onRemove?: () => void;
}

const RecentScansWidget: React.FC<RecentScansWidgetProps> = ({ onRemove }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/recent_scans', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setScans(data.scans || []);
    } catch (error) {
      console.error('Failed to fetch recent scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'running':
        return <Loader className="h-4 w-4 text-blue-500 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-yellow-500" />;
    }
  };

  return (
    <WidgetContainer
      title="Recent Scans"
      icon={<Activity className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : scans.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No recent scans
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors"
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                {getStatusIcon(scan.status)}
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white truncate">{scan.name}</div>
                  <div className="text-xs text-slate-400">
                    {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                  </div>
                </div>
              </div>
              <div className="text-xs text-slate-400 capitalize">
                {scan.status}
              </div>
            </div>
          ))}
        </div>
      )}
    </WidgetContainer>
  );
};

export default RecentScansWidget;
