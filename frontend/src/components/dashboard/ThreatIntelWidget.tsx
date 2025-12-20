import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Shield,
  ExternalLink,
  Bug,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Skull,
  Globe,
  Database,
  Info,
} from 'lucide-react';
import { toast } from 'react-toastify';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { threatIntelAPI } from '../../services/api';
import type { ThreatAlert, ThreatAlertAsset, ThreatSeverity, AlertType, ThreatSource } from '../../types';

interface ThreatIntelWidgetProps {
  scanId?: string;
  limit?: number;
  compact?: boolean;
}

const severityColors: Record<ThreatSeverity, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/50',
};

const alertTypeIcons: Record<AlertType, React.ReactNode> = {
  exposed_service: <Globe className="h-4 w-4" />,
  exploit_available: <Bug className="h-4 w-4" />,
  known_exploited_vulnerability: <Skull className="h-4 w-4" />,
  critical_cve: <AlertTriangle className="h-4 w-4" />,
  new_cve: <AlertCircle className="h-4 w-4" />,
  ransomware_threat: <Skull className="h-4 w-4" />,
  misconfiguration: <Shield className="h-4 w-4" />,
};

const sourceIcons: Record<ThreatSource, React.ReactNode> = {
  Shodan: <Globe className="h-3 w-3" />,
  ExploitDB: <Bug className="h-3 w-3" />,
  'NVD CVE': <Database className="h-3 w-3" />,
  'CISA KEV': <Shield className="h-3 w-3" />,
  Manual: <Info className="h-3 w-3" />,
};

const ThreatIntelWidget: React.FC<ThreatIntelWidgetProps> = ({
  scanId,
  limit = 10,
  compact = false,
}) => {
  const queryClient = useQueryClient();
  const [expandedAlerts, setExpandedAlerts] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<ThreatSeverity | 'all'>('all');

  // Fetch alerts
  const { data: alertsData, isLoading, error, refetch } = useQuery({
    queryKey: ['threatAlerts', scanId, limit, severityFilter],
    queryFn: async () => {
      const params: { limit?: number; scan_id?: string; severity?: string } = { limit };
      if (scanId) params.scan_id = scanId;
      if (severityFilter !== 'all') params.severity = severityFilter;
      const response = await threatIntelAPI.getAlerts(params);
      return response.data;
    },
    refetchInterval: 60000, // Refresh every minute
  });

  // Fetch API status
  const { data: apiStatus } = useQuery({
    queryKey: ['threatIntelStatus'],
    queryFn: async () => {
      const response = await threatIntelAPI.getStatus();
      return response.data;
    },
    staleTime: 300000, // 5 minutes
  });

  // Acknowledge alert mutation
  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => threatIntelAPI.acknowledgeAlert(alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threatAlerts'] });
      toast.success('Alert acknowledged');
    },
    onError: () => {
      toast.error('Failed to acknowledge alert');
    },
  });

  const toggleExpanded = (alertId: string) => {
    setExpandedAlerts((prev) => {
      const next = new Set(prev);
      if (next.has(alertId)) {
        next.delete(alertId);
      } else {
        next.add(alertId);
      }
      return next;
    });
  };

  const alerts = alertsData?.alerts || [];
  const totalAlerts = alertsData?.total || 0;

  // Count by severity
  const severityCounts = alerts.reduce(
    (acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1;
      return acc;
    },
    {} as Record<ThreatSeverity, number>
  );

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatAlertType = (type: AlertType): string => {
    return type.split('_').map((word: string) => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
  };

  if (isLoading) {
    return (
      <Card className="p-6">
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="h-6 w-6 text-primary animate-spin" />
          <span className="ml-2 text-slate-400">Loading threat intelligence...</span>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-6">
        <div className="flex items-center justify-center py-8 text-red-400">
          <AlertCircle className="h-6 w-6 mr-2" />
          <span>Failed to load threat intelligence data</span>
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold text-white">Threat Intelligence</h3>
          {totalAlerts > 0 && (
            <span className="px-2 py-0.5 text-xs font-medium bg-primary/20 text-primary rounded-full">
              {totalAlerts}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* API Status Indicator */}
          {apiStatus && (
            <div className="flex items-center gap-1 text-xs text-slate-400">
              {apiStatus.shodan_available ? (
                <span className="flex items-center gap-1 text-green-400">
                  <CheckCircle className="h-3 w-3" />
                  Shodan
                </span>
              ) : (
                <span className="flex items-center gap-1 text-slate-500">
                  <Globe className="h-3 w-3" />
                  Shodan (not configured)
                </span>
              )}
            </div>
          )}
          <Button
            variant="secondary"
            size="sm"
            onClick={() => refetch()}
            className="p-1"
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Severity Summary */}
      {!compact && (
        <div className="flex gap-2 mb-4 flex-wrap">
          <button
            onClick={() => setSeverityFilter('all')}
            className={`px-2 py-1 text-xs rounded border transition-colors ${
              severityFilter === 'all'
                ? 'bg-primary/20 text-primary border-primary'
                : 'bg-dark-bg text-slate-400 border-dark-border hover:border-slate-500'
            }`}
          >
            All ({totalAlerts})
          </button>
          {(['critical', 'high', 'medium', 'low'] as ThreatSeverity[]).map((severity) => (
            <button
              key={severity}
              onClick={() => setSeverityFilter(severity)}
              className={`px-2 py-1 text-xs rounded border transition-colors ${
                severityFilter === severity
                  ? severityColors[severity]
                  : 'bg-dark-bg text-slate-400 border-dark-border hover:border-slate-500'
              }`}
            >
              {severity.charAt(0).toUpperCase() + severity.slice(1)} ({severityCounts[severity] || 0})
            </button>
          ))}
        </div>
      )}

      {/* Alerts List */}
      {alerts.length === 0 ? (
        <div className="text-center py-8 text-slate-400">
          <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
          <p>No threat alerts found</p>
          {!apiStatus?.shodan_available && (
            <p className="text-xs mt-2">
              Configure SHODAN_API_KEY to enable external threat intelligence
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              isExpanded={expandedAlerts.has(alert.id)}
              onToggle={() => toggleExpanded(alert.id)}
              onAcknowledge={() => acknowledgeMutation.mutate(alert.id)}
              compact={compact}
              formatDate={formatDate}
              formatAlertType={formatAlertType}
            />
          ))}
        </div>
      )}

      {/* View More Link */}
      {totalAlerts > limit && (
        <div className="mt-4 text-center">
          <span className="text-sm text-slate-400">
            Showing {alerts.length} of {totalAlerts} alerts
          </span>
        </div>
      )}
    </Card>
  );
};

interface AlertCardProps {
  alert: ThreatAlert;
  isExpanded: boolean;
  onToggle: () => void;
  onAcknowledge: () => void;
  compact: boolean;
  formatDate: (date: string) => string;
  formatAlertType: (type: AlertType) => string;
}

const AlertCard: React.FC<AlertCardProps> = ({
  alert,
  isExpanded,
  onToggle,
  onAcknowledge,
  compact,
  formatDate,
  formatAlertType,
}) => {
  return (
    <div
      className={`border rounded-lg transition-colors ${
        severityColors[alert.severity]
      } bg-opacity-5`}
    >
      {/* Alert Header */}
      <div
        className="flex items-start gap-3 p-3 cursor-pointer hover:bg-dark-hover/50"
        onClick={onToggle}
      >
        <div className={`p-1.5 rounded ${severityColors[alert.severity]}`}>
          {alertTypeIcons[alert.alert_type]}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-white truncate">{alert.title}</span>
            {alert.in_cisa_kev && (
              <Badge variant="severity" type="critical" className="text-xs">
                CISA KEV
              </Badge>
            )}
            {alert.exploit_available && (
              <Badge variant="severity" type="high" className="text-xs">
                Exploit Available
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2 mt-1 text-xs text-slate-400">
            <span className="flex items-center gap-1">
              {sourceIcons[alert.source]}
              {alert.source}
            </span>
            <span>|</span>
            <span>{formatAlertType(alert.alert_type)}</span>
            <span>|</span>
            <span>{formatDate(alert.created_at)}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant="severity"
            type={alert.severity === 'info' ? 'low' : alert.severity}
          >
            {alert.severity.toUpperCase()}
          </Badge>
          {isExpanded ? (
            <ChevronUp className="h-4 w-4 text-slate-400" />
          ) : (
            <ChevronDown className="h-4 w-4 text-slate-400" />
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="border-t border-dark-border p-3 space-y-3">
          {/* Description */}
          <div>
            <p className="text-sm text-slate-300">{alert.description}</p>
          </div>

          {/* Affected Assets */}
          {alert.affected_assets.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-1">Affected Assets</h5>
              <div className="flex flex-wrap gap-2">
                {alert.affected_assets.map((asset: ThreatAlertAsset, idx: number) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 text-xs bg-dark-bg border border-dark-border rounded"
                  >
                    {asset.ip}
                    {asset.port && `:${asset.port}`}
                    {asset.service && ` (${asset.service})`}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* CVE IDs */}
          {alert.cve_ids.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-1">Related CVEs</h5>
              <div className="flex flex-wrap gap-2">
                {alert.cve_ids.map((cve: string) => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-0.5 text-xs bg-red-500/10 text-red-400 border border-red-500/30 rounded hover:bg-red-500/20 flex items-center gap-1"
                  >
                    {cve}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {alert.recommendations.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-1">Recommendations</h5>
              <ul className="list-disc list-inside text-sm text-slate-300 space-y-1">
                {alert.recommendations.map((rec: string, idx: number) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            </div>
          )}

          {/* References */}
          {alert.references.length > 0 && (
            <div>
              <h5 className="text-xs font-medium text-slate-400 mb-1">References</h5>
              <div className="flex flex-wrap gap-2">
                {alert.references.slice(0, 5).map((refUrl: string, idx: number) => (
                  <a
                    key={idx}
                    href={refUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-primary hover:underline flex items-center gap-1 truncate max-w-xs"
                  >
                    <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    {new URL(refUrl).hostname}
                  </a>
                ))}
                {alert.references.length > 5 && (
                  <span className="text-xs text-slate-400">
                    +{alert.references.length - 5} more
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" size="sm" onClick={onAcknowledge}>
              <CheckCircle className="h-4 w-4 mr-1" />
              Acknowledge
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatIntelWidget;
