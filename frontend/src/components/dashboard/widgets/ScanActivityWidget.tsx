import React, { useEffect, useState } from 'react';
import { BarChart3, Loader } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import WidgetContainer from './WidgetContainer';

interface ChartDataPoint {
  date: string;
  count: number;
}

interface ScanActivityWidgetProps {
  onRemove?: () => void;
}

const ScanActivityWidget: React.FC<ScanActivityWidgetProps> = ({ onRemove }) => {
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await fetch('/api/dashboard/data/scan_activity_chart', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const result = await response.json();
      setChartData(result.data || []);
    } catch (error) {
      console.error('Failed to fetch scan activity:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <WidgetContainer
      title="Scan Activity (Last 30 Days)"
      icon={<BarChart3 className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : chartData.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          No scan activity data
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis
              dataKey="date"
              stroke="#9ca3af"
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              tickFormatter={(value) => {
                const date = new Date(value);
                return `${date.getMonth() + 1}/${date.getDate()}`;
              }}
            />
            <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: 12 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '0.5rem',
                color: '#fff',
              }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={{ fill: '#3b82f6', r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </WidgetContainer>
  );
};

export default ScanActivityWidget;
