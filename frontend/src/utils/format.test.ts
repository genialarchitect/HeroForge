import { describe, it, expect } from 'vitest';

// Utility functions commonly used in the app
describe('Formatting Utilities', () => {
  describe('formatDate', () => {
    const formatDate = (date: Date | string): string => {
      const d = new Date(date);
      return d.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    };

    it('should format date correctly', () => {
      const date = new Date('2026-01-15');
      const formatted = formatDate(date);
      expect(formatted).toContain('Jan');
      expect(formatted).toContain('15');
      expect(formatted).toContain('2026');
    });

    it('should handle string dates', () => {
      const formatted = formatDate('2026-01-15');
      expect(formatted).toContain('2026');
    });
  });

  describe('formatBytes', () => {
    const formatBytes = (bytes: number): string => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    it('should format bytes correctly', () => {
      expect(formatBytes(0)).toBe('0 B');
      expect(formatBytes(1024)).toBe('1 KB');
      expect(formatBytes(1048576)).toBe('1 MB');
      expect(formatBytes(1073741824)).toBe('1 GB');
    });
  });

  describe('formatDuration', () => {
    const formatDuration = (seconds: number): string => {
      if (seconds < 60) return `${seconds}s`;
      if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
      }
      const hours = Math.floor(seconds / 3600);
      const mins = Math.floor((seconds % 3600) / 60);
      return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
    };

    it('should format seconds', () => {
      expect(formatDuration(30)).toBe('30s');
    });

    it('should format minutes', () => {
      expect(formatDuration(90)).toBe('1m 30s');
      expect(formatDuration(120)).toBe('2m');
    });

    it('should format hours', () => {
      expect(formatDuration(3600)).toBe('1h');
      expect(formatDuration(3660)).toBe('1h 1m');
    });
  });

  describe('truncateText', () => {
    const truncateText = (text: string, maxLength: number): string => {
      if (text.length <= maxLength) return text;
      return text.slice(0, maxLength - 3) + '...';
    };

    it('should not truncate short text', () => {
      expect(truncateText('Hello', 10)).toBe('Hello');
    });

    it('should truncate long text', () => {
      expect(truncateText('Hello World', 8)).toBe('Hello...');
    });
  });

  describe('formatPercentage', () => {
    const formatPercentage = (value: number, decimals = 1): string => {
      return `${value.toFixed(decimals)}%`;
    };

    it('should format percentage', () => {
      expect(formatPercentage(75.5)).toBe('75.5%');
      expect(formatPercentage(100)).toBe('100.0%');
      expect(formatPercentage(33.333, 2)).toBe('33.33%');
    });
  });

  describe('formatNumber', () => {
    const formatNumber = (num: number): string => {
      if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
      if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
      return num.toString();
    };

    it('should format large numbers', () => {
      expect(formatNumber(100)).toBe('100');
      expect(formatNumber(1500)).toBe('1.5K');
      expect(formatNumber(1500000)).toBe('1.5M');
    });
  });
});

describe('Validation Utilities', () => {
  describe('isValidEmail', () => {
    const isValidEmail = (email: string): boolean => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(email);
    };

    it('should validate correct emails', () => {
      expect(isValidEmail('test@heroforge.io')).toBe(true);
      expect(isValidEmail('user.name@example.com')).toBe(true);
    });

    it('should reject invalid emails', () => {
      expect(isValidEmail('invalid')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
      expect(isValidEmail('test@')).toBe(false);
    });
  });

  describe('isValidIP', () => {
    const isValidIP = (ip: string): boolean => {
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipRegex.test(ip)) return false;
      const parts = ip.split('.').map(Number);
      return parts.every(part => part >= 0 && part <= 255);
    };

    it('should validate correct IPs', () => {
      expect(isValidIP('192.168.1.1')).toBe(true);
      expect(isValidIP('10.0.0.1')).toBe(true);
      expect(isValidIP('255.255.255.255')).toBe(true);
    });

    it('should reject invalid IPs', () => {
      expect(isValidIP('192.168.1.256')).toBe(false);
      expect(isValidIP('192.168.1')).toBe(false);
      expect(isValidIP('not.an.ip.address')).toBe(false);
    });
  });

  describe('isValidCIDR', () => {
    const isValidCIDR = (cidr: string): boolean => {
      const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
      if (!cidrRegex.test(cidr)) return false;
      const [ip, mask] = cidr.split('/');
      const parts = ip.split('.').map(Number);
      const maskNum = parseInt(mask);
      return parts.every(p => p >= 0 && p <= 255) && maskNum >= 0 && maskNum <= 32;
    };

    it('should validate correct CIDRs', () => {
      expect(isValidCIDR('192.168.1.0/24')).toBe(true);
      expect(isValidCIDR('10.0.0.0/8')).toBe(true);
    });

    it('should reject invalid CIDRs', () => {
      expect(isValidCIDR('192.168.1.0/33')).toBe(false);
      expect(isValidCIDR('192.168.1.0')).toBe(false);
    });
  });
});

describe('Security Severity Utilities', () => {
  describe('getSeverityColor', () => {
    const getSeverityColor = (severity: string): string => {
      const colors: Record<string, string> = {
        critical: 'red-500',
        high: 'orange-500',
        medium: 'yellow-500',
        low: 'blue-500',
        info: 'gray-500',
      };
      return colors[severity.toLowerCase()] || 'gray-500';
    };

    it('should return correct colors for severities', () => {
      expect(getSeverityColor('critical')).toBe('red-500');
      expect(getSeverityColor('high')).toBe('orange-500');
      expect(getSeverityColor('medium')).toBe('yellow-500');
      expect(getSeverityColor('low')).toBe('blue-500');
      expect(getSeverityColor('info')).toBe('gray-500');
    });

    it('should handle case insensitivity', () => {
      expect(getSeverityColor('CRITICAL')).toBe('red-500');
      expect(getSeverityColor('High')).toBe('orange-500');
    });
  });

  describe('getSeverityScore', () => {
    const getSeverityScore = (severity: string): number => {
      const scores: Record<string, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      };
      return scores[severity.toLowerCase()] ?? 0;
    };

    it('should return correct scores', () => {
      expect(getSeverityScore('critical')).toBe(4);
      expect(getSeverityScore('high')).toBe(3);
      expect(getSeverityScore('medium')).toBe(2);
      expect(getSeverityScore('low')).toBe(1);
      expect(getSeverityScore('info')).toBe(0);
    });
  });
});
