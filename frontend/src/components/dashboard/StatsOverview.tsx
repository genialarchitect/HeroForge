import React, { useMemo } from 'react';
import { Activity, Server, AlertTriangle, Shield } from 'lucide-react';
import { useScanStore } from '../../store/scanStore';
import { getAggregateStats } from '../../utils/riskScoring';
import ClickableStatCard from '../ui/ClickableStatCard';

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
      <ClickableStatCard
        title="Completed Scans"
        value={stats.completedScans}
        icon={<Activity className="h-6 w-6 text-primary" />}
        color="text-primary"
        subtitle={`${scans.filter(s => s.status === 'running').length} running`}
        to="/dashboard?tab=scans"
      />

      <ClickableStatCard
        title="Hosts Discovered"
        value={stats.totalHosts}
        icon={<Server className="h-6 w-6 text-blue-400" />}
        color="text-blue-400"
        subtitle={`${stats.totalPorts} open ports`}
        to="/assets"
      />

      <ClickableStatCard
        title="Total Vulnerabilities"
        value={stats.totalVulnerabilities}
        icon={<AlertTriangle className="h-6 w-6 text-yellow-400" />}
        color="text-yellow-400"
        subtitle={`Across all scans`}
        to="/vulnerabilities"
      />

      <ClickableStatCard
        title="Critical Findings"
        value={stats.criticalVulnerabilities}
        icon={<Shield className="h-6 w-6 text-severity-critical" />}
        color="text-severity-critical"
        subtitle={`Requires immediate attention`}
        to="/vulnerabilities?severity=critical"
      />
    </div>
  );
};

export default StatsOverview;
