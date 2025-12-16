import React, { useEffect, useState } from 'react';
import { Calendar, Clock, Loader } from 'lucide-react';
import WidgetContainer from './WidgetContainer';
import { formatDistanceToNow } from 'date-fns';

interface ScheduledScan {
  id: string;
  name: string;
  schedule_type: string;
  next_run_at: string;
  is_active: boolean;
}

interface UpcomingScansWidgetProps {
  onRemove?: () => void;
}

const UpcomingScansWidget: React.FC<UpcomingScansWidgetProps> = ({ onRemove }) => {
  const [scans, setScans] = useState<ScheduledScan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/upcoming_scheduled_scans', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setScans(data.scans || []);
    } catch (error) {
      console.error('Failed to fetch upcoming scans:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <WidgetContainer
      title="Upcoming Scheduled Scans"
      icon={<Calendar className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : scans.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No upcoming scans
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors"
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <Clock className="h-4 w-4 text-primary flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white truncate">{scan.name}</div>
                  <div className="text-xs text-slate-400 capitalize">
                    {scan.schedule_type} scan
                  </div>
                </div>
              </div>
              <div className="text-xs text-slate-400">
                {formatDistanceToNow(new Date(scan.next_run_at), { addSuffix: true })}
              </div>
            </div>
          ))}
        </div>
      )}
    </WidgetContainer>
  );
};

export default UpcomingScansWidget;
