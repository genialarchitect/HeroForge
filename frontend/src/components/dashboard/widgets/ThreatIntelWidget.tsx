import React, { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  AlertTriangle,
  Bug,
  Skull,
  Globe,
  ExternalLink,
  Loader,
  ChevronRight,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import WidgetContainer from './WidgetContainer';
import { threatIntelAPI } from '../../../services/api';
import type { ThreatAlert, ThreatSeverity, AlertType } from '../../../types';

interface ThreatIntelWidgetProps {
  onRemove?: () => void;
  limit?: number;
}

const severityColors: Record<ThreatSeverity, string> = {
  critical: 'bg-red-900/30 text-red-500 border-red-500/50',
  high: 'bg-orange-900/30 text-orange-500 border-orange-500/50',
  medium: 'bg-yellow-900/30 text-yellow-500 border-yellow-500/50',
  low: 'bg-blue-900/30 text-blue-500 border-blue-500/50',
  info: 'bg-slate-700/30 text-slate-400 border-slate-500/50',
};

const alertTypeIcons: Record<AlertType, React.ReactNode> = {
  exposed_service: <Globe className="h-4 w-4" />,
  exploit_available: <Bug className="h-4 w-4" />,
  known_exploited_vulnerability: <Skull className="h-4 w-4" />,
  critical_cve: <AlertTriangle className="h-4 w-4" />,
  new_cve: <AlertTriangle className="h-4 w-4" />,
  ransomware_threat: <Skull className="h-4 w-4" />,
  misconfiguration: <Shield className="h-4 w-4" />,
};

const ThreatIntelWidget: React.FC<ThreatIntelWidgetProps> = ({
  onRemove,
  limit = 5,
}) => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['threatAlerts', 'widget', limit],
    queryFn: async () => {
      const response = await threatIntelAPI.getAlerts({ limit });
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });

  const alerts = data?.alerts || [];
  const total = data?.total || 0;

  // Count by severity for summary
  const criticalCount = alerts.filter((a) => a.severity === 'critical').length;
  const highCount = alerts.filter((a) => a.severity === 'high').length;
  const kevCount = alerts.filter((a) => a.in_cisa_kev).length;
  const exploitCount = alerts.filter((a) => a.exploit_available).length;

  return (
    <WidgetContainer
      title="Threat Intelligence"
      icon={<Shield className="h-5 w-5" />}
      onRemove={onRemove}
    >
      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader className="h-6 w-6 text-primary animate-spin" />
        </div>
      ) : error ? (
        <div className="text-center text-red-400 py-8">
          Failed to load threat alerts
        </div>
      ) : alerts.length === 0 ? (
        <div className="text-center text-slate-400 py-8">
          <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No active threat alerts</p>
          <p className="text-xs mt-1">
            Run threat intel enrichment on your scans to generate alerts
          </p>
        </div>
      ) : (
        <>
          {/* Summary Stats */}
          <div className="grid grid-cols-4 gap-2 mb-4">
            <div className="bg-dark-bg rounded-lg p-2 text-center border border-dark-border">
              <div className="text-lg font-bold text-red-400">{criticalCount}</div>
              <div className="text-xs text-slate-400">Critical</div>
            </div>
            <div className="bg-dark-bg rounded-lg p-2 text-center border border-dark-border">
              <div className="text-lg font-bold text-orange-400">{highCount}</div>
              <div className="text-xs text-slate-400">High</div>
            </div>
            <div className="bg-dark-bg rounded-lg p-2 text-center border border-dark-border">
              <div className="text-lg font-bold text-yellow-400">{kevCount}</div>
              <div className="text-xs text-slate-400">KEV</div>
            </div>
            <div className="bg-dark-bg rounded-lg p-2 text-center border border-dark-border">
              <div className="text-lg font-bold text-primary">{exploitCount}</div>
              <div className="text-xs text-slate-400">Exploits</div>
            </div>
          </div>

          {/* Alerts List */}
          <div className="space-y-2">
            {alerts.slice(0, limit).map((alert) => (
              <AlertRow key={alert.id} alert={alert} />
            ))}
          </div>

          {/* View More Link */}
          {total > limit && (
            <div className="mt-3 text-center">
              <a
                href="/threat-intel"
                className="text-sm text-primary hover:underline flex items-center justify-center gap-1"
              >
                View all {total} alerts
                <ChevronRight className="h-4 w-4" />
              </a>
            </div>
          )}
        </>
      )}
    </WidgetContainer>
  );
};

interface AlertRowProps {
  alert: ThreatAlert;
}

const AlertRow: React.FC<AlertRowProps> = ({ alert }) => {
  const icon = alertTypeIcons[alert.alert_type] || <AlertTriangle className="h-4 w-4" />;
  const severityClass = severityColors[alert.severity] || severityColors.info;

  return (
    <div
      className={`flex items-center justify-between p-3 bg-dark-bg rounded-lg border ${
        alert.severity === 'critical'
          ? 'border-red-900/50'
          : alert.severity === 'high'
          ? 'border-orange-900/50'
          : 'border-dark-border'
      } hover:border-primary/50 transition-colors`}
    >
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div className={`p-1.5 rounded ${severityClass}`}>{icon}</div>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-white text-sm truncate" title={alert.title}>
            {alert.title}
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-2">
            <span>{alert.source}</span>
            <span className="text-slate-600">|</span>
            <span>
              {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
            </span>
          </div>
        </div>
      </div>
      <div className="flex flex-col items-end gap-1 ml-2">
        <div className={`px-2 py-0.5 text-xs font-semibold rounded ${severityClass}`}>
          {alert.severity.toUpperCase()}
        </div>
        <div className="flex gap-1">
          {alert.in_cisa_kev && (
            <span className="px-1.5 py-0.5 text-xs bg-red-900/30 text-red-400 rounded">
              KEV
            </span>
          )}
          {alert.exploit_available && (
            <span className="px-1.5 py-0.5 text-xs bg-purple-900/30 text-purple-400 rounded">
              Exploit
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelWidget;
