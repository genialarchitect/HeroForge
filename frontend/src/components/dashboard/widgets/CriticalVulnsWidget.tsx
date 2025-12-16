import React, { useEffect, useState } from 'react';
import { AlertOctagon, Loader } from 'lucide-react';
import WidgetContainer from './WidgetContainer';
import { formatDistanceToNow } from 'date-fns';

interface Vulnerability {
  id: string;
  host_ip: string;
  vulnerability_id: string;
  severity: string;
  status: string;
  created_at: string;
}

interface CriticalVulnsWidgetProps {
  onRemove?: () => void;
}

const CriticalVulnsWidget: React.FC<CriticalVulnsWidgetProps> = ({ onRemove }) => {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/critical_vulns', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setVulns(data.vulnerabilities || []);
    } catch (error) {
      console.error('Failed to fetch critical vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <WidgetContainer
      title="Critical Vulnerabilities"
      icon={<AlertOctagon className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : vulns.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No critical vulnerabilities
        </div>
      ) : (
        <div className="space-y-2">
          {vulns.map((vuln) => (
            <div
              key={vuln.id}
              className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-red-900/30 hover:border-red-500 transition-colors"
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <AlertOctagon className="h-4 w-4 text-red-500 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="font-medium text-white truncate">
                    {vuln.vulnerability_id}
                  </div>
                  <div className="text-xs text-slate-400">
                    {vuln.host_ip} • {formatDistanceToNow(new Date(vuln.created_at), { addSuffix: true })}
                  </div>
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <div className="px-2 py-1 bg-red-900/30 text-red-500 text-xs font-semibold rounded">
                  {vuln.severity.toUpperCase()}
                </div>
                <div className="text-xs text-slate-400 capitalize">
                  {vuln.status.replace('_', ' ')}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </WidgetContainer>
  );
};

export default CriticalVulnsWidget;
