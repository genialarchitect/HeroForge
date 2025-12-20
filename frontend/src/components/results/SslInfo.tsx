import React, { useState } from 'react';
import { SslInfo as SslInfoType, SslGradeLevel } from '../../types';
import Badge from '../ui/Badge';
import { SslGradeBadge } from './SslGradeBadge';
import { SslGradeBreakdown } from './SslGradeBreakdown';
import { Shield, AlertTriangle, CheckCircle, XCircle, Lock, Clock, Server, Maximize2 } from 'lucide-react';

interface SslInfoProps {
  sslInfo: SslInfoType;
  port: number;
  hostname?: string;
}

// Get colors for large grade display
function getLargeGradeColors(grade: SslGradeLevel): { bg: string; text: string; glow: string } {
  switch (grade) {
    case 'A+':
      return { bg: 'from-emerald-500 to-emerald-600', text: 'text-white', glow: 'shadow-emerald-500/30' };
    case 'A':
      return { bg: 'from-green-500 to-green-600', text: 'text-white', glow: 'shadow-green-500/30' };
    case 'A-':
      return { bg: 'from-green-400 to-green-500', text: 'text-white', glow: 'shadow-green-400/30' };
    case 'B+':
    case 'B':
    case 'B-':
      return { bg: 'from-yellow-400 to-yellow-500', text: 'text-gray-900', glow: 'shadow-yellow-400/30' };
    case 'C':
      return { bg: 'from-orange-500 to-orange-600', text: 'text-white', glow: 'shadow-orange-500/30' };
    case 'D':
      return { bg: 'from-red-400 to-red-500', text: 'text-white', glow: 'shadow-red-400/30' };
    case 'F':
      return { bg: 'from-red-600 to-red-700', text: 'text-white', glow: 'shadow-red-600/30' };
    case 'T':
      return { bg: 'from-purple-500 to-purple-600', text: 'text-white', glow: 'shadow-purple-500/30' };
    case 'M':
      return { bg: 'from-fuchsia-500 to-fuchsia-600', text: 'text-white', glow: 'shadow-fuchsia-500/30' };
    default:
      return { bg: 'from-gray-500 to-gray-600', text: 'text-white', glow: '' };
  }
}

const SslInfoComponent: React.FC<SslInfoProps> = ({ sslInfo, port, hostname }) => {
  const [showFullBreakdown, setShowFullBreakdown] = useState(false);

  // Determine overall security status
  const getSecurityStatus = () => {
    if (sslInfo.cert_expired || sslInfo.hostname_mismatch) {
      return 'critical';
    }
    if (
      sslInfo.weak_protocols.length > 0 ||
      sslInfo.weak_ciphers.length > 0 ||
      sslInfo.self_signed
    ) {
      return 'warning';
    }
    if (!sslInfo.hsts_enabled && port === 443) {
      return 'info';
    }
    return 'good';
  };

  const status = getSecurityStatus();

  // Get color classes based on days until expiry
  const getExpiryColor = () => {
    if (sslInfo.cert_expired) return 'text-red-400';
    if (!sslInfo.days_until_expiry) return 'text-slate-400';
    if (sslInfo.days_until_expiry < 30) return 'text-yellow-400';
    if (sslInfo.days_until_expiry < 90) return 'text-blue-400';
    return 'text-green-400';
  };

  // If full breakdown modal is shown
  if (showFullBreakdown) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80">
        <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto">
          <button
            onClick={() => setShowFullBreakdown(false)}
            className="absolute top-4 right-4 z-10 p-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-400 hover:text-white transition-colors"
          >
            <XCircle className="w-6 h-6" />
          </button>
          <SslGradeBreakdown sslInfo={sslInfo} hostname={hostname} />
        </div>
      </div>
    );
  }

  return (
    <div className="mt-3 space-y-3 border-t border-dark-border pt-3">
      {/* SSL Grade Badge - Show prominent grade if available */}
      {sslInfo.ssl_grade && (
        <div className="relative">
          <SslGradeBadge grade={sslInfo.ssl_grade} showDetails={true} animate={true} />
          {/* Button to show full breakdown */}
          <button
            onClick={() => setShowFullBreakdown(true)}
            className="absolute top-3 right-12 p-1.5 text-gray-400 hover:text-cyan-400 hover:bg-gray-700/50 rounded transition-colors"
            title="View detailed SSL/TLS breakdown"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="flex items-center gap-2">
        <Lock className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold text-white">SSL/TLS Certificate</span>
        {!sslInfo.ssl_grade && (
          <>
            {status === 'critical' && (
              <Badge variant="severity" type="critical">
                Critical Issues
              </Badge>
            )}
            {status === 'warning' && (
              <Badge variant="severity" type="high">
                Security Issues
              </Badge>
            )}
            {status === 'good' && (
              <Badge variant="severity" type="low">
                Secure
              </Badge>
            )}
          </>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        {/* Certificate Status */}
        <div className="bg-dark-bg rounded p-2">
          <div className="flex items-center gap-1 mb-1">
            {sslInfo.cert_valid && !sslInfo.cert_expired ? (
              <CheckCircle className="h-3 w-3 text-green-500" />
            ) : (
              <XCircle className="h-3 w-3 text-red-500" />
            )}
            <span className="font-medium text-slate-300">Certificate Status</span>
          </div>
          <div className={sslInfo.cert_expired ? 'text-red-400' : 'text-green-400'}>
            {sslInfo.cert_expired ? 'Expired' : 'Valid'}
          </div>
        </div>

        {/* Expiry */}
        <div className="bg-dark-bg rounded p-2">
          <div className="flex items-center gap-1 mb-1">
            <Clock className="h-3 w-3 text-slate-400" />
            <span className="font-medium text-slate-300">Expires In</span>
          </div>
          <div className={getExpiryColor()}>
            {sslInfo.days_until_expiry !== null
              ? sslInfo.cert_expired
                ? `${Math.abs(sslInfo.days_until_expiry)} days ago`
                : `${sslInfo.days_until_expiry} days`
              : 'Unknown'}
          </div>
        </div>

        {/* Subject */}
        <div className="bg-dark-bg rounded p-2 col-span-2">
          <div className="flex items-center gap-1 mb-1">
            <Server className="h-3 w-3 text-slate-400" />
            <span className="font-medium text-slate-300">Subject</span>
          </div>
          <div className="text-slate-400 truncate" title={sslInfo.subject}>
            {sslInfo.subject}
          </div>
        </div>

        {/* Issuer */}
        <div className="bg-dark-bg rounded p-2 col-span-2">
          <div className="flex items-center gap-1 mb-1">
            <Shield className="h-3 w-3 text-slate-400" />
            <span className="font-medium text-slate-300">Issuer</span>
          </div>
          <div className="text-slate-400 truncate" title={sslInfo.issuer}>
            {sslInfo.issuer}
          </div>
        </div>

        {/* Validity Period */}
        <div className="bg-dark-bg rounded p-2">
          <span className="font-medium text-slate-300">Valid From</span>
          <div className="text-slate-400 text-[10px] mt-1">
            {new Date(sslInfo.valid_from).toLocaleDateString()}
          </div>
        </div>

        <div className="bg-dark-bg rounded p-2">
          <span className="font-medium text-slate-300">Valid Until</span>
          <div className="text-slate-400 text-[10px] mt-1">
            {new Date(sslInfo.valid_until).toLocaleDateString()}
          </div>
        </div>
      </div>

      {/* Security Issues */}
      {(sslInfo.self_signed ||
        sslInfo.hostname_mismatch ||
        sslInfo.weak_protocols.length > 0 ||
        sslInfo.weak_ciphers.length > 0 ||
        !sslInfo.hsts_enabled ||
        sslInfo.chain_issues.length > 0) && (
        <div className="space-y-2">
          <div className="flex items-center gap-1 text-sm font-medium text-yellow-400">
            <AlertTriangle className="h-4 w-4" />
            Security Findings
          </div>

          {sslInfo.self_signed && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-2 text-xs">
              <div className="text-yellow-400 font-medium">Self-Signed Certificate</div>
              <div className="text-slate-400 mt-1">
                Certificate is not from a trusted Certificate Authority
              </div>
            </div>
          )}

          {sslInfo.hostname_mismatch && (
            <div className="bg-red-500/10 border border-red-500/20 rounded p-2 text-xs">
              <div className="text-red-400 font-medium">Hostname Mismatch</div>
              <div className="text-slate-400 mt-1">
                Certificate does not match the hostname
              </div>
            </div>
          )}

          {sslInfo.weak_protocols.length > 0 && (
            <div className="bg-red-500/10 border border-red-500/20 rounded p-2 text-xs">
              <div className="text-red-400 font-medium">Weak Protocols</div>
              <div className="text-slate-400 mt-1">
                {sslInfo.weak_protocols.join(', ')}
              </div>
            </div>
          )}

          {sslInfo.weak_ciphers.length > 0 && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-2 text-xs">
              <div className="text-yellow-400 font-medium">Weak Ciphers</div>
              <div className="text-slate-400 mt-1 max-h-16 overflow-y-auto">
                {sslInfo.weak_ciphers.join(', ')}
              </div>
            </div>
          )}

          {!sslInfo.hsts_enabled && port === 443 && (
            <div className="bg-blue-500/10 border border-blue-500/20 rounded p-2 text-xs">
              <div className="text-blue-400 font-medium">HSTS Not Enabled</div>
              <div className="text-slate-400 mt-1">
                HTTP Strict Transport Security header not detected
              </div>
            </div>
          )}

          {sslInfo.chain_issues.length > 0 && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-2 text-xs">
              <div className="text-yellow-400 font-medium">Certificate Chain Issues</div>
              <div className="text-slate-400 mt-1">
                {sslInfo.chain_issues.join(', ')}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Protocols */}
      {sslInfo.protocols.length > 0 && (
        <div className="bg-dark-bg rounded p-2">
          <div className="text-xs font-medium text-slate-300 mb-1">Supported Protocols</div>
          <div className="flex flex-wrap gap-1">
            {sslInfo.protocols.map((protocol) => (
              <span
                key={protocol}
                className={`px-2 py-0.5 rounded text-[10px] ${
                  sslInfo.weak_protocols.includes(protocol)
                    ? 'bg-red-500/20 text-red-400'
                    : 'bg-green-500/20 text-green-400'
                }`}
              >
                {protocol}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* HSTS Info */}
      {sslInfo.hsts_enabled && (
        <div className="bg-dark-bg rounded p-2">
          <div className="text-xs font-medium text-slate-300 mb-1">HSTS</div>
          <div className="flex items-center gap-2 text-xs">
            <CheckCircle className="h-3 w-3 text-green-500" />
            <span className="text-green-400">Enabled</span>
            {sslInfo.hsts_max_age && (
              <span className="text-slate-400">
                (max-age: {sslInfo.hsts_max_age.toLocaleString()}s)
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SslInfoComponent;
