import React from 'react';
import { SslInfo as SslInfoType } from '../../types';
import Badge from '../ui/Badge';
import { SslGradeBadge } from './SslGradeBadge';
import { Shield, AlertTriangle, CheckCircle, XCircle, Lock, Clock, Server } from 'lucide-react';

interface SslInfoProps {
  sslInfo: SslInfoType;
  port: number;
}

const SslInfoComponent: React.FC<SslInfoProps> = ({ sslInfo, port }) => {
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

  return (
    <div className="mt-3 space-y-3 border-t border-dark-border pt-3">
      {/* SSL Grade Badge - Show if grade is available */}
      {sslInfo.ssl_grade && (
        <SslGradeBadge grade={sslInfo.ssl_grade} showDetails={true} />
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
