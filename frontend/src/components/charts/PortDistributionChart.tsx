import React, { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { HostInfo } from '../../types';
import { getPortDistribution } from '../../utils/riskScoring';
import Card from '../ui/Card';

interface PortDistributionChartProps {
  hosts: HostInfo[];
}

const PORT_COLORS: Record<number, string> = {
  21: '#f97316',   // FTP - orange
  22: '#22c55e',   // SSH - green
  23: '#ef4444',   // Telnet - red (insecure)
  25: '#3b82f6',   // SMTP - blue
  53: '#8b5cf6',   // DNS - purple
  80: '#06b6d4',   // HTTP - cyan
  110: '#3b82f6',  // POP3 - blue
  143: '#3b82f6',  // IMAP - blue
  443: '#10b981',  // HTTPS - green
  445: '#f59e0b',  // SMB - amber
  3306: '#ec4899', // MySQL - pink
  3389: '#ef4444', // RDP - red
  5432: '#3b82f6', // PostgreSQL - blue
  8080: '#06b6d4', // HTTP Alt - cyan
};

const DEFAULT_COLOR = '#64748b'; // slate-500

const PortDistributionChart: React.FC<PortDistributionChartProps> = ({ hosts }) => {
  const chartData = useMemo(() => {
    return getPortDistribution(hosts).map(item => ({
      ...item,
      displayName: `${item.port} (${item.service})`,
      color: PORT_COLORS[item.port] || DEFAULT_COLOR,
    }));
  }, [hosts]);

  if (chartData.length === 0) {
    return (
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Port Distribution</h3>
        <div className="flex items-center justify-center h-64 text-slate-400">
          <p>No open ports found</p>
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold text-white mb-4">
        Top Open Ports
        <span className="text-sm font-normal text-slate-400 ml-2">
          (Across all hosts)
        </span>
      </h3>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis type="number" stroke="#cbd5e1" />
          <YAxis
            dataKey="displayName"
            type="category"
            width={90}
            stroke="#cbd5e1"
            tick={{ fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#fff',
            }}
            formatter={(value: number, _name: string, props: any) => [
              `${value} hosts`,
              props.payload.service,
            ]}
            labelFormatter={(label: string) => `Port ${chartData.find(d => d.displayName === label)?.port}`}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default PortDistributionChart;
