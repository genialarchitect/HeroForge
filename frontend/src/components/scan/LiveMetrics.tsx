import React, { useEffect, useState } from 'react';
import { Server, Wifi, Code, AlertTriangle, Shield } from 'lucide-react';

interface LiveMetricsProps {
  hostsFound: number;
  portsOpen: number;
  servicesDetected: number;
  vulnerabilitiesFound: number;
  criticalVulns?: number;
  highVulns?: number;
  mediumVulns?: number;
  lowVulns?: number;
}

interface AnimatedCounterProps {
  value: number;
  duration?: number;
}

const AnimatedCounter: React.FC<AnimatedCounterProps> = ({ value, duration = 500 }) => {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    if (displayValue === value) return;

    const startValue = displayValue;
    const diff = value - startValue;
    const startTime = Date.now();

    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);

      // Ease out cubic
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      const currentValue = Math.round(startValue + diff * easeProgress);

      setDisplayValue(currentValue);

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [value, duration]);

  return <span className="tabular-nums">{displayValue.toLocaleString()}</span>;
};

const LiveMetrics: React.FC<LiveMetricsProps> = ({
  hostsFound,
  portsOpen,
  servicesDetected,
  vulnerabilitiesFound,
  criticalVulns = 0,
  highVulns = 0,
  mediumVulns = 0,
  lowVulns = 0,
}) => {
  const metrics = [
    {
      label: 'Hosts Found',
      value: hostsFound,
      icon: Server,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30',
    },
    {
      label: 'Open Ports',
      value: portsOpen,
      icon: Wifi,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/30',
    },
    {
      label: 'Services Detected',
      value: servicesDetected,
      icon: Code,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/30',
    },
    {
      label: 'Vulnerabilities',
      value: vulnerabilitiesFound,
      icon: AlertTriangle,
      color: vulnerabilitiesFound > 0 ? 'text-red-400' : 'text-slate-500',
      bgColor: vulnerabilitiesFound > 0 ? 'bg-red-500/10' : 'bg-slate-500/10',
      borderColor: vulnerabilitiesFound > 0 ? 'border-red-500/30' : 'border-slate-500/30',
    },
  ];

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical':
        return 'bg-severity-critical text-white';
      case 'high':
        return 'bg-severity-high text-white';
      case 'medium':
        return 'bg-severity-medium text-white';
      case 'low':
        return 'bg-severity-low text-white';
      default:
        return 'bg-slate-600 text-white';
    }
  };

  return (
    <div className="space-y-4">
      {/* Main Metrics Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {metrics.map((metric) => {
          const Icon = metric.icon;
          return (
            <div
              key={metric.label}
              className={`relative overflow-hidden rounded-lg border ${metric.borderColor} ${metric.bgColor} p-4 transition-all duration-300 hover:scale-105`}
            >
              <div className="flex items-center justify-between mb-2">
                <Icon className={`h-5 w-5 ${metric.color}`} />
                {metric.value > 0 && (
                  <div className="absolute top-2 right-2 w-2 h-2 rounded-full bg-current animate-pulse-dot" />
                )}
              </div>
              <div className="space-y-1">
                <p className="text-2xl font-bold text-white">
                  <AnimatedCounter value={metric.value} />
                </p>
                <p className="text-xs text-slate-400 font-medium">{metric.label}</p>
              </div>

              {/* Decorative gradient overlay */}
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent pointer-events-none" />
            </div>
          );
        })}
      </div>

      {/* Vulnerability Breakdown */}
      {vulnerabilitiesFound > 0 && (
        <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="h-4 w-4 text-red-400" />
            <h4 className="text-sm font-semibold text-white">Vulnerability Breakdown</h4>
          </div>

          <div className="flex flex-wrap gap-2">
            {criticalVulns > 0 && (
              <div className={`px-3 py-1.5 rounded-lg text-xs font-medium ${getSeverityColor('critical')}`}>
                <span className="font-bold"><AnimatedCounter value={criticalVulns} /></span> Critical
              </div>
            )}
            {highVulns > 0 && (
              <div className={`px-3 py-1.5 rounded-lg text-xs font-medium ${getSeverityColor('high')}`}>
                <span className="font-bold"><AnimatedCounter value={highVulns} /></span> High
              </div>
            )}
            {mediumVulns > 0 && (
              <div className={`px-3 py-1.5 rounded-lg text-xs font-medium ${getSeverityColor('medium')}`}>
                <span className="font-bold"><AnimatedCounter value={mediumVulns} /></span> Medium
              </div>
            )}
            {lowVulns > 0 && (
              <div className={`px-3 py-1.5 rounded-lg text-xs font-medium ${getSeverityColor('low')}`}>
                <span className="font-bold"><AnimatedCounter value={lowVulns} /></span> Low
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveMetrics;
