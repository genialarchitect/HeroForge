import React, { useState } from 'react';
import { toast } from 'react-toastify';
import Card from '../ui/Card';
import Input from '../ui/Input';
import Button from '../ui/Button';
import Checkbox from '../ui/Checkbox';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Globe, Shield, AlertTriangle } from 'lucide-react';
import { webappAPI } from '../../services/api';

interface WebAppScanFormProps {
  onSuccess?: (scanId: string) => void;
}

const WebAppScanForm: React.FC<WebAppScanFormProps> = ({ onSuccess }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPages, setMaxPages] = useState(100);
  const [respectRobotsTxt, setRespectRobotsTxt] = useState(true);
  const [checksEnabled, setChecksEnabled] = useState({
    headers: true,
    forms: true,
    sqli: true,
    xss: true,
    info_disclosure: true,
  });
  const [loading, setLoading] = useState(false);

  const handleCheckChange = (check: string) => {
    setChecksEnabled(prev => ({
      ...prev,
      [check]: !prev[check as keyof typeof checksEnabled],
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!targetUrl.trim()) {
      toast.error('Please enter a target URL');
      return;
    }

    // Basic URL validation
    try {
      const url = new URL(targetUrl);
      if (!['http:', 'https:'].includes(url.protocol)) {
        toast.error('URL must start with http:// or https://');
        return;
      }
    } catch {
      toast.error('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    // Validate at least one check is enabled
    const enabledChecks = Object.entries(checksEnabled)
      .filter(([_, enabled]) => enabled)
      .map(([check, _]) => check);

    if (enabledChecks.length === 0) {
      toast.error('Please enable at least one security check');
      return;
    }

    setLoading(true);

    try {
      const response = await webappAPI.startScan({
        target_url: targetUrl.trim(),
        max_depth: maxDepth,
        max_pages: maxPages,
        respect_robots_txt: respectRobotsTxt,
        checks_enabled: enabledChecks,
      });

      toast.success(`Web application scan started for ${targetUrl}`);

      if (onSuccess && response.data.scan_id) {
        onSuccess(response.data.scan_id);
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      const errorMessage = axiosError.response?.data?.error || 'Failed to start web application scan';
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <div className="p-6">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-6 h-6 text-purple-500" />
          <div>
            <h2 className="text-xl font-bold text-gray-900">Web Application Security Scan</h2>
            <p className="text-sm text-gray-500">
              Scan web applications for common vulnerabilities and misconfigurations
            </p>
          </div>
        </div>

        <div className="mb-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-yellow-800">
            <strong>Security Notice:</strong> Only scan web applications you own or have explicit
            permission to test. Unauthorized scanning may be illegal.
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="targetUrl" className="block text-sm font-medium text-gray-700 mb-1">
              Target URL *
            </label>
            <Input
              id="targetUrl"
              type="text"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              disabled={loading}
            />
            <p className="text-xs text-gray-500 mt-1">
              Full URL including http:// or https://
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="maxDepth" className="block text-sm font-medium text-gray-700 mb-1">
                Max Crawl Depth
              </label>
              <Input
                id="maxDepth"
                type="number"
                min="1"
                max="10"
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value) || 3)}
                disabled={loading}
              />
              <p className="text-xs text-gray-500 mt-1">
                How many levels deep to crawl (1-10)
              </p>
            </div>

            <div>
              <label htmlFor="maxPages" className="block text-sm font-medium text-gray-700 mb-1">
                Max Pages
              </label>
              <Input
                id="maxPages"
                type="number"
                min="1"
                max="1000"
                value={maxPages}
                onChange={(e) => setMaxPages(parseInt(e.target.value) || 100)}
                disabled={loading}
              />
              <p className="text-xs text-gray-500 mt-1">
                Maximum pages to crawl (1-1000)
              </p>
            </div>
          </div>

          <div>
            <Checkbox
              id="respectRobotsTxt"
              checked={respectRobotsTxt}
              onChange={(checked) => setRespectRobotsTxt(checked)}
              label="Respect robots.txt"
              disabled={loading}
            />
            <p className="text-xs text-gray-500 ml-6 mt-1">
              Skip URLs disallowed in robots.txt
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Security Checks
            </label>
            <div className="space-y-2">
              <Checkbox
                id="check_headers"
                checked={checksEnabled.headers}
                onChange={() => handleCheckChange('headers')}
                label="Security Headers"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 ml-6">
                Check for missing or insecure HTTP security headers
              </p>

              <Checkbox
                id="check_forms"
                checked={checksEnabled.forms}
                onChange={() => handleCheckChange('forms')}
                label="Form Analysis"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 ml-6">
                Detect forms and check for insecure configurations
              </p>

              <Checkbox
                id="check_sqli"
                checked={checksEnabled.sqli}
                onChange={() => handleCheckChange('sqli')}
                label="SQL Injection Testing"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 ml-6">
                Test for SQL injection vulnerabilities (error-based)
              </p>

              <Checkbox
                id="check_xss"
                checked={checksEnabled.xss}
                onChange={() => handleCheckChange('xss')}
                label="Cross-Site Scripting (XSS)"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 ml-6">
                Test for reflected XSS vulnerabilities
              </p>

              <Checkbox
                id="check_info_disclosure"
                checked={checksEnabled.info_disclosure}
                onChange={() => handleCheckChange('info_disclosure')}
                label="Information Disclosure"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 ml-6">
                Check for sensitive information in responses
              </p>
            </div>
          </div>

          <div className="flex gap-3 pt-2">
            <Button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" />
                  Starting Scan...
                </>
              ) : (
                <>
                  <Globe className="w-4 h-4" />
                  Start Web App Scan
                </>
              )}
            </Button>
          </div>
        </form>
      </div>
    </Card>
  );
};

export default WebAppScanForm;
