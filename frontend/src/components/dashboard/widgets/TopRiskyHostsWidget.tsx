import React, { useEffect, useState } from 'react';
import { Server, AlertTriangle, Loader } from 'lucide-react';
import WidgetContainer from './WidgetContainer';

interface RiskyHost {
  ip: string;
  hostname?: string;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  risk_score: number;
}

interface TopRiskyHostsWidgetProps {
  onRemove?: () => void;
}

const TopRiskyHostsWidget: React.FC<TopRiskyHostsWidgetProps> = ({ onRemove }) => {
  const [hosts, setHosts] = useState<RiskyHost[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/top_risky_hosts', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setHosts(data.hosts || []);
    } catch (error) {
      console.error('Failed to fetch risky hosts:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 50) return 'text-red-500';
    if (score >= 20) return 'text-orange-500';
    return 'text-yellow-500';
  };

  return (
    <WidgetContainer
      title="Top Risky Hosts"
      icon={<AlertTriangle className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : hosts.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No risky hosts found
        </div>
      ) : (
        <div className="space-y-2">
          {hosts.map((host, index) => (
            <div
              key={host.ip}
              className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border hover:border-primary transition-colors"
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <div className={`text-xl font-bold ${getRiskColor(host.risk_score)}`}>
                  {index + 1}
                </div>
                <Server className="h-4 w-4 text-slate-400" />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white truncate">
                    {host.hostname || host.ip}
                  </div>
                  {host.hostname && (
                    <div className="text-xs text-slate-400">{host.ip}</div>
                  )}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <div className="text-sm font-semibold text-white">
                  {host.vulnerability_count} vulns
                </div>
                <div className="flex gap-2 text-xs">
                  {host.critical_count > 0 && (
                    <span className="text-red-500">{host.critical_count}C</span>
                  )}
                  {host.high_count > 0 && (
                    <span className="text-orange-500">{host.high_count}H</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </WidgetContainer>
  );
};

export default TopRiskyHostsWidget;
