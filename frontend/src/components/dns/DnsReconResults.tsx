import React, { useState } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import { Globe, Shield, AlertTriangle, CheckCircle, XCircle, Server, Clock, ChevronDown, ChevronRight } from 'lucide-react';

interface DnsRecord {
  record_type: string;
  value: string;
  ttl?: number;
}

interface DnsReconResult {
  domain: string;
  records: Record<string, DnsRecord[]>;
  subdomains_found: string[];
  zone_transfer_vulnerable: boolean;
  zone_transfer_error?: string;
  dnssec_enabled: boolean;
  nameservers: string[];
  reverse_dns: Record<string, string>;
  scan_timestamp: string;
}

interface DnsReconResultsProps {
  result: DnsReconResult;
  onClose?: () => void;
}

const DnsReconResults: React.FC<DnsReconResultsProps> = ({ result, onClose }) => {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    overview: true,
    records: true,
    subdomains: true,
    security: true,
  });

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const recordTypeOrder = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA'];
  const sortedRecordTypes = Object.keys(result.records).sort((a, b) => {
    const aIndex = recordTypeOrder.indexOf(a);
    const bIndex = recordTypeOrder.indexOf(b);
    if (aIndex === -1 && bIndex === -1) return a.localeCompare(b);
    if (aIndex === -1) return 1;
    if (bIndex === -1) return -1;
    return aIndex - bIndex;
  });

  const securityScore = calculateSecurityScore(result);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="w-6 h-6 text-blue-500" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900">{result.domain}</h2>
            <p className="text-sm text-gray-500">
              Scanned on {new Date(result.scan_timestamp).toLocaleString()}
            </p>
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
          >
            Close
          </button>
        )}
      </div>

      {/* Overview Card */}
      <Card>
        <div className="p-4">
          <button
            onClick={() => toggleSection('overview')}
            className="flex items-center justify-between w-full text-left"
          >
            <h3 className="text-lg font-semibold text-gray-900">Overview</h3>
            {expandedSections.overview ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </button>

          {expandedSections.overview && (
            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-blue-50 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <Globe className="w-5 h-5 text-blue-600" />
                  <span className="text-sm font-medium text-gray-600">DNS Records</span>
                </div>
                <p className="mt-2 text-2xl font-bold text-gray-900">
                  {Object.values(result.records).reduce((sum, records) => sum + records.length, 0)}
                </p>
                <p className="text-xs text-gray-500">
                  {Object.keys(result.records).length} types
                </p>
              </div>

              <div className="bg-green-50 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-green-600" />
                  <span className="text-sm font-medium text-gray-600">Subdomains</span>
                </div>
                <p className="mt-2 text-2xl font-bold text-gray-900">
                  {result.subdomains_found.length}
                </p>
                <p className="text-xs text-gray-500">discovered</p>
              </div>

              <div className="bg-purple-50 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-purple-600" />
                  <span className="text-sm font-medium text-gray-600">Nameservers</span>
                </div>
                <p className="mt-2 text-2xl font-bold text-gray-900">
                  {result.nameservers.length}
                </p>
                <p className="text-xs text-gray-500">configured</p>
              </div>

              <div
                className={`rounded-lg p-4 ${
                  securityScore >= 80
                    ? 'bg-green-50'
                    : securityScore >= 50
                    ? 'bg-yellow-50'
                    : 'bg-red-50'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield
                    className={`w-5 h-5 ${
                      securityScore >= 80
                        ? 'text-green-600'
                        : securityScore >= 50
                        ? 'text-yellow-600'
                        : 'text-red-600'
                    }`}
                  />
                  <span className="text-sm font-medium text-gray-600">Security Score</span>
                </div>
                <p className="mt-2 text-2xl font-bold text-gray-900">{securityScore}%</p>
                <p className="text-xs text-gray-500">
                  {securityScore >= 80 ? 'Good' : securityScore >= 50 ? 'Fair' : 'Poor'}
                </p>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Security Issues Card */}
      <Card>
        <div className="p-4">
          <button
            onClick={() => toggleSection('security')}
            className="flex items-center justify-between w-full text-left"
          >
            <h3 className="text-lg font-semibold text-gray-900">Security Analysis</h3>
            {expandedSections.security ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </button>

          {expandedSections.security && (
            <div className="mt-4 space-y-3">
              <SecurityItem
                label="DNSSEC"
                enabled={result.dnssec_enabled}
                description={
                  result.dnssec_enabled
                    ? 'Domain signing is enabled, providing authenticity and integrity'
                    : 'Domain signing is not enabled - consider enabling DNSSEC for better security'
                }
              />

              <SecurityItem
                label="Zone Transfer (AXFR)"
                enabled={!result.zone_transfer_vulnerable}
                description={
                  result.zone_transfer_vulnerable
                    ? 'Zone transfer is allowed - this is a security risk that exposes all DNS records'
                    : 'Zone transfer is properly restricted'
                }
                error={result.zone_transfer_error}
              />
            </div>
          )}
        </div>
      </Card>

      {/* DNS Records Card */}
      <Card>
        <div className="p-4">
          <button
            onClick={() => toggleSection('records')}
            className="flex items-center justify-between w-full text-left"
          >
            <h3 className="text-lg font-semibold text-gray-900">DNS Records</h3>
            {expandedSections.records ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </button>

          {expandedSections.records && (
            <div className="mt-4 space-y-4">
              {sortedRecordTypes.map((recordType) => (
                <RecordTypeSection
                  key={recordType}
                  recordType={recordType}
                  records={result.records[recordType]}
                  reverseDns={result.reverse_dns}
                />
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* Subdomains Card */}
      {result.subdomains_found.length > 0 && (
        <Card>
          <div className="p-4">
            <button
              onClick={() => toggleSection('subdomains')}
              className="flex items-center justify-between w-full text-left"
            >
              <h3 className="text-lg font-semibold text-gray-900">
                Discovered Subdomains ({result.subdomains_found.length})
              </h3>
              {expandedSections.subdomains ? (
                <ChevronDown className="w-5 h-5 text-gray-400" />
              ) : (
                <ChevronRight className="w-5 h-5 text-gray-400" />
              )}
            </button>

            {expandedSections.subdomains && (
              <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {result.subdomains_found.map((subdomain) => (
                  <div
                    key={subdomain}
                    className="flex items-center gap-2 p-2 bg-gray-50 rounded border border-gray-200"
                  >
                    <Server className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <span className="text-sm font-mono text-gray-700 truncate">
                      {subdomain}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};

const SecurityItem: React.FC<{
  label: string;
  enabled: boolean;
  description: string;
  error?: string;
}> = ({ label, enabled, description, error }) => (
  <div className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg border border-gray-200">
    {enabled ? (
      <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
    ) : (
      <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
    )}
    <div className="flex-1">
      <div className="flex items-center gap-2">
        <span className="font-medium text-gray-900">{label}</span>
        <Badge variant={enabled ? 'success' : 'warning'}>
          {enabled ? 'Enabled' : 'Disabled'}
        </Badge>
      </div>
      <p className="mt-1 text-sm text-gray-600">{description}</p>
      {error && (
        <p className="mt-1 text-xs text-gray-500 font-mono bg-gray-100 p-2 rounded">
          {error}
        </p>
      )}
    </div>
  </div>
);

const RecordTypeSection: React.FC<{
  recordType: string;
  records: DnsRecord[];
  reverseDns: Record<string, string>;
}> = ({ recordType, records, reverseDns }) => {
  const [expanded, setExpanded] = useState(recordType === 'A' || recordType === 'AAAA');

  const getRecordTypeBadgeColor = (type: string): 'primary' | 'success' | 'warning' | 'danger' => {
    switch (type) {
      case 'A':
      case 'AAAA':
        return 'primary';
      case 'MX':
        return 'success';
      case 'NS':
        return 'warning';
      default:
        return 'primary';
    }
  };

  return (
    <div className="border border-gray-200 rounded-lg">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between w-full p-3 text-left hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Badge variant={getRecordTypeBadgeColor(recordType)}>{recordType}</Badge>
          <span className="text-sm font-medium text-gray-700">
            {records.length} {records.length === 1 ? 'record' : 'records'}
          </span>
        </div>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-gray-400" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-400" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-gray-200">
          {records.map((record, index) => (
            <div
              key={index}
              className="p-3 border-b border-gray-100 last:border-b-0 hover:bg-gray-50"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <code className="text-sm text-gray-900 break-all">{record.value}</code>
                  {reverseDns[record.value] && (
                    <div className="mt-1 flex items-center gap-2 text-xs text-gray-500">
                      <span className="font-medium">Reverse DNS:</span>
                      <code className="text-gray-700">{reverseDns[record.value]}</code>
                    </div>
                  )}
                </div>
                {record.ttl && (
                  <div className="flex items-center gap-1 text-xs text-gray-500 flex-shrink-0">
                    <Clock className="w-3 h-3" />
                    <span>{formatTTL(record.ttl)}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

function calculateSecurityScore(result: DnsReconResult): number {
  let score = 100;

  // DNSSEC not enabled: -30 points
  if (!result.dnssec_enabled) {
    score -= 30;
  }

  // Zone transfer vulnerable: -50 points (critical)
  if (result.zone_transfer_vulnerable) {
    score -= 50;
  }

  // No nameservers: -20 points
  if (result.nameservers.length === 0) {
    score -= 20;
  }

  return Math.max(0, score);
}

function formatTTL(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export default DnsReconResults;
