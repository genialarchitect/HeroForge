import React from 'react';
import {
  Shield,
  Lock,
  Key,
  FileCheck,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  ExternalLink,
  Server,
  Clock,
} from 'lucide-react';
import type { SslInfo, SslGrade, SslGradeLevel, SslVulnerabilitySeverity } from '../../types';

interface SslGradeBreakdownProps {
  sslInfo: SslInfo;
  hostname?: string;
}

// Get color for score
function getScoreColor(score: number): string {
  if (score >= 90) return 'text-emerald-400';
  if (score >= 80) return 'text-green-400';
  if (score >= 70) return 'text-lime-400';
  if (score >= 60) return 'text-yellow-400';
  if (score >= 50) return 'text-orange-400';
  return 'text-red-400';
}

// Get background color for score bar
function getScoreBgColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500';
  if (score >= 80) return 'bg-green-500';
  if (score >= 70) return 'bg-lime-500';
  if (score >= 60) return 'bg-yellow-500';
  if (score >= 50) return 'bg-orange-500';
  return 'bg-red-500';
}

// Get grade colors
function getGradeColors(grade: SslGradeLevel): { bg: string; text: string; border: string } {
  switch (grade) {
    case 'A+':
      return { bg: 'bg-emerald-500', text: 'text-white', border: 'border-emerald-600' };
    case 'A':
      return { bg: 'bg-green-500', text: 'text-white', border: 'border-green-600' };
    case 'A-':
      return { bg: 'bg-green-400', text: 'text-white', border: 'border-green-500' };
    case 'B+':
      return { bg: 'bg-lime-500', text: 'text-white', border: 'border-lime-600' };
    case 'B':
      return { bg: 'bg-yellow-500', text: 'text-gray-900', border: 'border-yellow-600' };
    case 'B-':
      return { bg: 'bg-yellow-400', text: 'text-gray-900', border: 'border-yellow-500' };
    case 'C':
      return { bg: 'bg-orange-500', text: 'text-white', border: 'border-orange-600' };
    case 'D':
      return { bg: 'bg-red-400', text: 'text-white', border: 'border-red-500' };
    case 'F':
      return { bg: 'bg-red-600', text: 'text-white', border: 'border-red-700' };
    case 'T':
      return { bg: 'bg-purple-600', text: 'text-white', border: 'border-purple-700' };
    case 'M':
      return { bg: 'bg-fuchsia-600', text: 'text-white', border: 'border-fuchsia-700' };
    default:
      return { bg: 'bg-gray-500', text: 'text-white', border: 'border-gray-600' };
  }
}

// Get severity badge classes
function getSeverityClasses(severity: SslVulnerabilitySeverity): string {
  switch (severity) {
    case 'Critical':
      return 'bg-red-600 text-white';
    case 'High':
      return 'bg-orange-500 text-white';
    case 'Medium':
      return 'bg-yellow-500 text-gray-900';
    case 'Low':
      return 'bg-blue-500 text-white';
    case 'Informational':
      return 'bg-gray-500 text-white';
    default:
      return 'bg-gray-500 text-white';
  }
}

// Score breakdown bar
function ScoreBar({
  label,
  score,
  icon: Icon,
  description,
}: {
  label: string;
  score: number;
  icon: React.ElementType;
  description?: string;
}) {
  return (
    <div className="bg-gray-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Icon className="w-5 h-5 text-gray-400" />
          <span className="font-medium text-gray-200">{label}</span>
        </div>
        <span className={`font-bold text-lg ${getScoreColor(score)}`}>{score}/100</span>
      </div>
      <div className="h-3 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${getScoreBgColor(score)} transition-all duration-500`}
          style={{ width: `${score}%` }}
        />
      </div>
      {description && <p className="text-xs text-gray-500 mt-2">{description}</p>}
    </div>
  );
}

// Protocol list item
function ProtocolItem({ protocol, isWeak }: { protocol: string; isWeak: boolean }) {
  return (
    <div
      className={`flex items-center gap-2 px-3 py-2 rounded-lg ${
        isWeak ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'
      }`}
    >
      {isWeak ? (
        <XCircle className="w-4 h-4 text-red-400" />
      ) : (
        <CheckCircle className="w-4 h-4 text-green-400" />
      )}
      <span className={isWeak ? 'text-red-300' : 'text-green-300'}>{protocol}</span>
      {isWeak && <span className="text-xs text-red-400 ml-auto">Weak</span>}
    </div>
  );
}

// Cipher item
function CipherItem({ cipher, isWeak }: { cipher: string; isWeak: boolean }) {
  return (
    <div
      className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm ${
        isWeak ? 'bg-red-500/10 text-red-300' : 'bg-gray-700/50 text-gray-300'
      }`}
    >
      {isWeak && <AlertTriangle className="w-3 h-3 text-red-400" />}
      <span className="font-mono text-xs truncate">{cipher}</span>
    </div>
  );
}

export function SslGradeBreakdown({ sslInfo, hostname }: SslGradeBreakdownProps) {
  const grade = sslInfo.ssl_grade;

  if (!grade) {
    return (
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <p className="text-gray-400 text-center">SSL grade information not available</p>
      </div>
    );
  }

  const gradeColors = getGradeColors(grade.grade);
  const isSpecialGrade = grade.grade === 'T' || grade.grade === 'M';

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700 overflow-hidden">
      {/* Header with grade */}
      <div className="bg-gradient-to-r from-gray-800 to-gray-900 p-6 border-b border-gray-700">
        <div className="flex items-center gap-6">
          {/* Large grade badge */}
          <div
            className={`flex items-center justify-center w-24 h-24 rounded-xl font-bold text-4xl shadow-xl ${gradeColors.bg} ${gradeColors.text} border-4 ${gradeColors.border}`}
          >
            {grade.grade}
          </div>

          <div className="flex-1">
            <h2 className="text-xl font-bold text-white mb-2">
              SSL/TLS Security Grade
              {hostname && <span className="text-gray-400 font-normal ml-2">for {hostname}</span>}
            </h2>

            {isSpecialGrade ? (
              <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${
                grade.grade === 'T' ? 'bg-purple-500/20 text-purple-300' : 'bg-fuchsia-500/20 text-fuchsia-300'
              }`}>
                <AlertTriangle className="w-4 h-4" />
                <span>
                  {grade.grade === 'T'
                    ? 'Certificate not trusted (self-signed or untrusted CA)'
                    : 'Certificate hostname mismatch'}
                </span>
              </div>
            ) : (
              <div className="flex items-center gap-4">
                <div className="text-gray-400">
                  <span className="text-2xl font-bold text-white">{grade.overall_score}</span>
                  <span className="text-gray-500">/100</span>
                </div>
                {grade.grade_capped && grade.cap_reason && (
                  <div className="flex items-center gap-2 text-yellow-400 text-sm">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Grade capped</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Score breakdown */}
      <div className="p-6 space-y-6">
        {/* Score bars */}
        <div>
          <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Score Breakdown
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ScoreBar
              label="Protocol Support"
              score={grade.protocol_score}
              icon={Lock}
              description="TLS version support and configuration"
            />
            <ScoreBar
              label="Cipher Strength"
              score={grade.cipher_score}
              icon={Key}
              description="Encryption algorithms and key sizes"
            />
            <ScoreBar
              label="Certificate"
              score={grade.certificate_score}
              icon={FileCheck}
              description="Certificate validity and chain"
            />
            <ScoreBar
              label="Key Exchange"
              score={grade.key_exchange_score}
              icon={Shield}
              description="Forward secrecy and key exchange methods"
            />
          </div>
        </div>

        {/* Certificate info */}
        <div>
          <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-cyan-400" />
            Certificate Details
          </h3>
          <div className="bg-gray-800 rounded-lg p-4 space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wider">Subject</span>
                <p className="text-gray-200 font-mono text-sm truncate" title={sslInfo.subject}>
                  {sslInfo.subject}
                </p>
              </div>
              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wider">Issuer</span>
                <p className="text-gray-200 font-mono text-sm truncate" title={sslInfo.issuer}>
                  {sslInfo.issuer}
                </p>
              </div>
              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wider">Valid From</span>
                <p className="text-gray-200">{new Date(sslInfo.valid_from).toLocaleDateString()}</p>
              </div>
              <div>
                <span className="text-xs text-gray-500 uppercase tracking-wider">Valid Until</span>
                <div className="flex items-center gap-2">
                  <p className={sslInfo.cert_expired ? 'text-red-400' : 'text-gray-200'}>
                    {new Date(sslInfo.valid_until).toLocaleDateString()}
                  </p>
                  {sslInfo.days_until_expiry !== null && (
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        sslInfo.cert_expired
                          ? 'bg-red-500/20 text-red-400'
                          : sslInfo.days_until_expiry < 30
                          ? 'bg-yellow-500/20 text-yellow-400'
                          : 'bg-green-500/20 text-green-400'
                      }`}
                    >
                      {sslInfo.cert_expired
                        ? `Expired ${Math.abs(sslInfo.days_until_expiry)} days ago`
                        : `${sslInfo.days_until_expiry} days`}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Status badges */}
            <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-700">
              {sslInfo.self_signed && (
                <span className="inline-flex items-center gap-1 px-2 py-1 bg-purple-500/20 text-purple-400 text-xs rounded">
                  <AlertTriangle className="w-3 h-3" />
                  Self-Signed
                </span>
              )}
              {sslInfo.hostname_mismatch && (
                <span className="inline-flex items-center gap-1 px-2 py-1 bg-fuchsia-500/20 text-fuchsia-400 text-xs rounded">
                  <XCircle className="w-3 h-3" />
                  Hostname Mismatch
                </span>
              )}
              {sslInfo.hsts_enabled ? (
                <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
                  <CheckCircle className="w-3 h-3" />
                  HSTS Enabled
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded">
                  <AlertTriangle className="w-3 h-3" />
                  HSTS Not Enabled
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Protocols */}
        <div>
          <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            Protocol Support
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
            {sslInfo.protocols.map((protocol) => (
              <ProtocolItem
                key={protocol}
                protocol={protocol}
                isWeak={sslInfo.weak_protocols.includes(protocol)}
              />
            ))}
          </div>
        </div>

        {/* Cipher suites */}
        {sslInfo.cipher_suites.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <Key className="w-5 h-5 text-cyan-400" />
              Cipher Suites
              <span className="text-sm font-normal text-gray-500">
                ({sslInfo.cipher_suites.length})
              </span>
            </h3>
            <div className="bg-gray-800 rounded-lg p-4 max-h-48 overflow-y-auto">
              <div className="flex flex-wrap gap-2">
                {sslInfo.cipher_suites.map((cipher) => (
                  <CipherItem
                    key={cipher}
                    cipher={cipher}
                    isWeak={sslInfo.weak_ciphers.includes(cipher)}
                  />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Vulnerabilities */}
        {grade.vulnerabilities_found.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Security Issues
              <span className="text-sm font-normal text-red-400">
                ({grade.vulnerabilities_found.length})
              </span>
            </h3>
            <div className="space-y-3">
              {grade.vulnerabilities_found.map((vuln, idx) => (
                <div
                  key={`${vuln.id}-${idx}`}
                  className="bg-gray-800 rounded-lg p-4 border border-gray-700"
                >
                  <div className="flex items-start gap-3">
                    <span
                      className={`px-2 py-0.5 text-xs font-medium rounded flex-shrink-0 ${getSeverityClasses(
                        vuln.severity
                      )}`}
                    >
                      {vuln.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-gray-200">{vuln.name}</span>
                        {vuln.cve && (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-cyan-400 font-mono hover:underline flex items-center gap-1"
                          >
                            {vuln.cve}
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                      <p className="text-sm text-gray-400 mt-1">{vuln.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendations */}
        {grade.recommendations.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-green-400" />
              Recommendations
            </h3>
            <div className="bg-gray-800 rounded-lg p-4 space-y-2">
              {grade.recommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start gap-3 text-sm">
                  <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <span className="text-gray-300">{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Chain issues */}
        {sslInfo.chain_issues.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
              <Server className="w-5 h-5 text-yellow-400" />
              Certificate Chain Issues
            </h3>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 space-y-2">
              {sslInfo.chain_issues.map((issue, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm text-yellow-300">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{issue}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* All good message */}
        {grade.vulnerabilities_found.length === 0 &&
          grade.recommendations.length === 0 &&
          sslInfo.chain_issues.length === 0 && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-6 flex items-center justify-center gap-3">
              <CheckCircle className="w-6 h-6 text-emerald-400" />
              <span className="text-emerald-300 text-lg">
                Excellent! SSL/TLS configuration meets best practices.
              </span>
            </div>
          )}
      </div>
    </div>
  );
}

export default SslGradeBreakdown;
