import React, { useState, useEffect } from 'react';
import { Shield, ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Info, Lock, Key, FileCheck, ShieldAlert, ShieldX } from 'lucide-react';
import type { SslGrade, SslGradeLevel, SslVulnerability, SslVulnerabilitySeverity } from '../../types';

interface SslGradeBadgeProps {
  grade: SslGrade;
  showDetails?: boolean;
  compact?: boolean;
  animate?: boolean;
}

// Get color classes for grade level
function getGradeColors(grade: SslGradeLevel): { bg: string; text: string; border: string; glow?: string } {
  switch (grade) {
    case 'A+':
      return { bg: 'bg-emerald-500', text: 'text-white', border: 'border-emerald-600', glow: 'shadow-emerald-500/50' };
    case 'A':
      return { bg: 'bg-green-500', text: 'text-white', border: 'border-green-600', glow: 'shadow-green-500/50' };
    case 'A-':
      return { bg: 'bg-green-400', text: 'text-white', border: 'border-green-500', glow: 'shadow-green-400/50' };
    case 'B+':
      return { bg: 'bg-lime-500', text: 'text-white', border: 'border-lime-600', glow: 'shadow-lime-500/50' };
    case 'B':
      return { bg: 'bg-yellow-500', text: 'text-gray-900', border: 'border-yellow-600', glow: 'shadow-yellow-500/50' };
    case 'B-':
      return { bg: 'bg-yellow-400', text: 'text-gray-900', border: 'border-yellow-500', glow: 'shadow-yellow-400/50' };
    case 'C':
      return { bg: 'bg-orange-500', text: 'text-white', border: 'border-orange-600', glow: 'shadow-orange-500/50' };
    case 'D':
      return { bg: 'bg-red-400', text: 'text-white', border: 'border-red-500', glow: 'shadow-red-400/50' };
    case 'F':
      return { bg: 'bg-red-600', text: 'text-white', border: 'border-red-700', glow: 'shadow-red-600/50' };
    case 'T':
      // Trust issues - purple/violet to indicate trust problem
      return { bg: 'bg-purple-600', text: 'text-white', border: 'border-purple-700', glow: 'shadow-purple-600/50' };
    case 'M':
      // Mismatch - magenta/pink to indicate hostname mismatch
      return { bg: 'bg-fuchsia-600', text: 'text-white', border: 'border-fuchsia-700', glow: 'shadow-fuchsia-600/50' };
    default:
      return { bg: 'bg-gray-500', text: 'text-white', border: 'border-gray-600' };
  }
}

// Get grade description for tooltips
function getGradeDescription(grade: SslGradeLevel): string {
  switch (grade) {
    case 'A+':
      return 'Excellent - Best possible SSL/TLS configuration with HSTS';
    case 'A':
      return 'Very Good - Strong SSL/TLS configuration';
    case 'A-':
      return 'Good - Minor improvements possible';
    case 'B+':
    case 'B':
    case 'B-':
      return 'Acceptable - Some security issues present';
    case 'C':
      return 'Weak - Significant security issues';
    case 'D':
      return 'Poor - Serious security vulnerabilities';
    case 'F':
      return 'Failed - Critical security issues';
    case 'T':
      return 'Trust Issue - Certificate not from a trusted CA (self-signed)';
    case 'M':
      return 'Mismatch - Certificate hostname does not match';
    default:
      return 'Unknown - Grade could not be determined';
  }
}

// Get icon for special grades
function getGradeIcon(grade: SslGradeLevel): React.ElementType | null {
  switch (grade) {
    case 'T':
      return ShieldAlert;
    case 'M':
      return ShieldX;
    default:
      return null;
  }
}

// Get color for score bar
function getScoreColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500';
  if (score >= 80) return 'bg-green-500';
  if (score >= 70) return 'bg-lime-500';
  if (score >= 60) return 'bg-yellow-500';
  if (score >= 50) return 'bg-orange-500';
  return 'bg-red-500';
}

// Get severity colors
function getSeverityColors(severity: SslVulnerabilitySeverity): { bg: string; text: string } {
  switch (severity) {
    case 'Critical':
      return { bg: 'bg-red-600', text: 'text-white' };
    case 'High':
      return { bg: 'bg-orange-500', text: 'text-white' };
    case 'Medium':
      return { bg: 'bg-yellow-500', text: 'text-gray-900' };
    case 'Low':
      return { bg: 'bg-blue-500', text: 'text-white' };
    case 'Informational':
      return { bg: 'bg-gray-500', text: 'text-white' };
    default:
      return { bg: 'bg-gray-500', text: 'text-white' };
  }
}

// Score bar component
function ScoreBar({ label, score, icon: Icon }: { label: string; score: number; icon: React.ElementType }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2 text-gray-300">
          <Icon className="w-4 h-4" />
          <span>{label}</span>
        </div>
        <span className="font-mono text-gray-200">{score}/100</span>
      </div>
      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${getScoreColor(score)} transition-all duration-300`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

// Vulnerability item component
function VulnerabilityItem({ vuln }: { vuln: SslVulnerability }) {
  const colors = getSeverityColors(vuln.severity);

  return (
    <div className="bg-gray-800 rounded-lg p-3 border border-gray-700">
      <div className="flex items-start gap-3">
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${colors.bg} ${colors.text}`}>
          {vuln.severity}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-200">{vuln.name}</span>
            {vuln.cve && (
              <span className="text-xs text-cyan-400 font-mono">{vuln.cve}</span>
            )}
          </div>
          <p className="text-sm text-gray-400 mt-1">{vuln.description}</p>
        </div>
      </div>
    </div>
  );
}

export function SslGradeBadge({ grade, showDetails = true, compact = false, animate = true }: SslGradeBadgeProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isRevealed, setIsRevealed] = useState(!animate);
  const colors = getGradeColors(grade.grade);
  const GradeIcon = getGradeIcon(grade.grade);
  const isSpecialGrade = grade.grade === 'T' || grade.grade === 'M';

  // Animation effect for grade reveal
  useEffect(() => {
    if (animate && !isRevealed) {
      const timer = setTimeout(() => setIsRevealed(true), 100);
      return () => clearTimeout(timer);
    }
  }, [animate, isRevealed]);

  if (compact) {
    // Compact mode - just show the grade badge with tooltip
    return (
      <div
        className={`inline-flex items-center justify-center w-8 h-8 rounded-lg font-bold text-sm
          ${colors.bg} ${colors.text} border ${colors.border}
          ${isRevealed ? 'opacity-100 scale-100' : 'opacity-0 scale-75'}
          ${colors.glow ? `shadow-lg ${colors.glow}` : ''}
          transition-all duration-300 ease-out`}
        title={`SSL/TLS Grade: ${grade.grade} - ${getGradeDescription(grade.grade)} (Score: ${grade.overall_score}/100)`}
      >
        {GradeIcon ? <GradeIcon className="w-4 h-4" /> : grade.grade}
      </div>
    );
  }

  return (
    <div className="bg-gray-800/50 rounded-lg border border-gray-700">
      {/* Header with grade and toggle */}
      <div
        className={`flex items-center justify-between p-3 ${showDetails ? 'cursor-pointer hover:bg-gray-800/80' : ''} transition-colors`}
        onClick={() => showDetails && setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center gap-3">
          <div
            className={`flex items-center justify-center w-12 h-12 rounded-lg font-bold text-xl
              ${colors.bg} ${colors.text} border-2 ${colors.border}
              ${isRevealed ? 'opacity-100 scale-100' : 'opacity-0 scale-75'}
              ${colors.glow ? `shadow-lg ${colors.glow}` : ''}
              transition-all duration-500 ease-out`}
          >
            {GradeIcon ? <GradeIcon className="w-6 h-6" /> : grade.grade}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-gray-200 font-medium">SSL/TLS Grade</span>
              {isSpecialGrade && (
                <span className={`text-xs px-2 py-0.5 rounded ${
                  grade.grade === 'T' ? 'bg-purple-500/20 text-purple-400' : 'bg-fuchsia-500/20 text-fuchsia-400'
                }`}>
                  {grade.grade === 'T' ? 'Trust Issue' : 'Hostname Mismatch'}
                </span>
              )}
              {!isSpecialGrade && grade.grade_capped && (
                <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded">
                  Capped
                </span>
              )}
            </div>
            <div className="text-sm text-gray-400">
              {isSpecialGrade ? (
                <span>{getGradeDescription(grade.grade)}</span>
              ) : (
                <>
                  Overall Score: {grade.overall_score}/100
                  {grade.vulnerabilities_found.length > 0 && (
                    <span className="ml-2 text-red-400">
                      ({grade.vulnerabilities_found.length} issue{grade.vulnerabilities_found.length !== 1 ? 's' : ''})
                    </span>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {showDetails && (
          <button className="text-gray-400 hover:text-gray-200 p-1 transition-colors">
            {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
        )}
      </div>

      {/* Expanded details */}
      {showDetails && isExpanded && (
        <div className="border-t border-gray-700 p-4 space-y-4">
          {/* Cap reason if applicable */}
          {grade.grade_capped && grade.cap_reason && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
              <div>
                <span className="text-yellow-400 font-medium">Grade Capped</span>
                <p className="text-sm text-yellow-300/80 mt-1">{grade.cap_reason}</p>
              </div>
            </div>
          )}

          {/* Score breakdown */}
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Score Breakdown
            </h4>
            <div className="grid gap-3">
              <ScoreBar label="Protocol" score={grade.protocol_score} icon={Lock} />
              <ScoreBar label="Cipher Suites" score={grade.cipher_score} icon={Key} />
              <ScoreBar label="Certificate" score={grade.certificate_score} icon={FileCheck} />
              <ScoreBar label="Key Exchange" score={grade.key_exchange_score} icon={Shield} />
            </div>
          </div>

          {/* Vulnerabilities */}
          {grade.vulnerabilities_found.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Issues Found ({grade.vulnerabilities_found.length})
              </h4>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {grade.vulnerabilities_found.map((vuln, idx) => (
                  <VulnerabilityItem key={`${vuln.id}-${idx}`} vuln={vuln} />
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {grade.recommendations.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-400" />
                Recommendations ({grade.recommendations.length})
              </h4>
              <ul className="space-y-2">
                {grade.recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-gray-400">
                    <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Perfect score message */}
          {grade.vulnerabilities_found.length === 0 && grade.recommendations.length === 0 && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3 flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-500" />
              <span className="text-emerald-400">
                Excellent! No security issues or recommendations found.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default SslGradeBadge;
