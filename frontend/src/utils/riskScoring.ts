import { HostInfo } from '../types';

/**
 * Severity weight mapping for risk score calculation
 */
const SEVERITY_WEIGHTS = {
  Critical: 10,
  High: 7,
  Medium: 4,
  Low: 1,
} as const;

/**
 * Calculate risk score for a host based on vulnerabilities and port exposure
 * @param host - Host information including vulnerabilities and ports
 * @returns Risk score (0-100)
 */
export function calculateHostRiskScore(host: HostInfo): number {
  let score = 0;

  // Calculate vulnerability score
  const vulnScore = host.vulnerabilities.reduce((acc, vuln) => {
    return acc + SEVERITY_WEIGHTS[vuln.severity];
  }, 0);

  // Port exposure factor (more open ports = higher exposure)
  const openPorts = host.ports.filter(p => p.state === 'Open').length;
  const portExposure = Math.min(openPorts * 2, 30); // Cap at 30 points

  // Combine scores
  score = vulnScore + portExposure;

  // Normalize to 0-100 scale
  return Math.min(Math.round(score), 100);
}

/**
 * Get risk level category based on risk score
 * @param score - Risk score (0-100)
 * @returns Risk level category
 */
export function getRiskLevel(score: number): 'Critical' | 'High' | 'Medium' | 'Low' {
  if (score >= 70) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

/**
 * Calculate total vulnerability count by severity for multiple hosts
 * @param hosts - Array of host information
 * @returns Object with count per severity level
 */
export function getVulnerabilityDistribution(hosts: HostInfo[]): Record<string, number> {
  const distribution = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  hosts.forEach(host => {
    host.vulnerabilities.forEach(vuln => {
      distribution[vuln.severity]++;
    });
  });

  return distribution;
}

/**
 * Calculate port distribution across hosts
 * @param hosts - Array of host information
 * @returns Array of {port, count, service} sorted by count
 */
export function getPortDistribution(hosts: HostInfo[]): Array<{ port: number; count: number; service: string }> {
  const portMap = new Map<number, { count: number; service: string }>();

  hosts.forEach(host => {
    host.ports
      .filter(p => p.state === 'Open')
      .forEach(port => {
        const existing = portMap.get(port.port);
        if (existing) {
          existing.count++;
        } else {
          portMap.set(port.port, {
            count: 1,
            service: port.service?.name || `Port ${port.port}`,
          });
        }
      });
  });

  return Array.from(portMap.entries())
    .map(([port, data]) => ({ port, ...data }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10); // Top 10 ports
}

/**
 * Get aggregate statistics across all scans
 * @param hosts - Array of all hosts from all scans
 * @returns Statistics object
 */
export function getAggregateStats(hosts: HostInfo[]) {
  const totalHosts = hosts.length;
  const totalPorts = hosts.reduce((acc, host) => acc + host.ports.filter(p => p.state === 'Open').length, 0);
  const vulnerabilities = getVulnerabilityDistribution(hosts);
  const totalVulnerabilities = Object.values(vulnerabilities).reduce((a, b) => a + b, 0);
  const criticalVulnerabilities = vulnerabilities.Critical;

  return {
    totalHosts,
    totalPorts,
    totalVulnerabilities,
    criticalVulnerabilities,
    vulnerabilities,
  };
}
