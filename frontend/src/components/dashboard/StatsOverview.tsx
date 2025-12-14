import React, { useMemo } from 'react';
import { Activity, Server, AlertTriangle, Shield } from 'lucide-react';
import { useScanStore } from '../../store/scanStore';
import { getAggregateStats } from '../../utils/riskScoring';
import Card from '../ui/Card';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  subtitle?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color, subtitle }) => {
  return (
    <Card className="p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
          <p className={`text-3xl font-bold ${color} mb-1`}>{value}</p>
          {subtitle && <p className="text-slate-500 text-xs">{subtitle}</p>}
        </div>
        <div className={`${color.replace('text-', 'bg-')}/20 p-3 rounded-lg`}>
          {icon}
        </div>
      </div>
    </Card>
  );
};

const StatsOverview: React.FC = () => {
  const { scans, results } = useScanStore();

  const stats = useMemo(() => {
    // Get all completed scans
    const completedScans = scans.filter(s => s.status === 'completed');

    // Aggregate all hosts from all scans
    const allHosts = Array.from(results.values()).flat();

    return {
      ...getAggregateStats(allHosts),
      completedScans: completedScans.length,
    };
  }, [scans, results]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      <StatCard
        title="Completed Scans"
        value={stats.completedScans}
        icon={<Activity className="h-6 w-6 text-primary" />}
        color="text-primary"
        subtitle={`${scans.filter(s => s.status === 'running').length} running`}
      />

      <StatCard
        title="Hosts Discovered"
        value={stats.totalHosts}
        icon={<Server className="h-6 w-6 text-blue-400" />}
        color="text-blue-400"
        subtitle={`${stats.totalPorts} open ports`}
      />

      <StatCard
        title="Total Vulnerabilities"
        value={stats.totalVulnerabilities}
        icon={<AlertTriangle className="h-6 w-6 text-yellow-400" />}
        color="text-yellow-400"
        subtitle={`Across all scans`}
      />

      <StatCard
        title="Critical Findings"
        value={stats.criticalVulnerabilities}
        icon={<Shield className="h-6 w-6 text-severity-critical" />}
        color="text-severity-critical"
        subtitle={`Requires immediate attention`}
      />
    </div>
  );
};

export default StatsOverview;
