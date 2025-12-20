import React, { useState } from 'react';
import { toast } from 'react-toastify';
import Card from '../ui/Card';
import Input from '../ui/Input';
import Button from '../ui/Button';
import Checkbox from '../ui/Checkbox';
import LoadingSpinner from '../ui/LoadingSpinner';
import { Globe, Search, AlertCircle } from 'lucide-react';
import { dnsAPI } from '../../services/api';

interface DnsReconFormProps {
  onSuccess?: (result: any) => void;
}

const DnsReconForm: React.FC<DnsReconFormProps> = ({ onSuccess }) => {
  const [domain, setDomain] = useState('');
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [timeoutSecs, setTimeoutSecs] = useState(30);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!domain.trim()) {
      toast.error('Please enter a domain name');
      return;
    }

    // Basic domain validation
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    if (!domainRegex.test(domain.trim())) {
      toast.error('Please enter a valid domain name (e.g., example.com)');
      return;
    }

    setLoading(true);

    try {
      const response = await dnsAPI.performRecon({
        domain: domain.trim(),
        includeSubdomains,
        timeoutSecs,
      });

      toast.success(`DNS reconnaissance completed for ${domain}`);

      if (onSuccess) {
        onSuccess(response.data);
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      const errorMessage = axiosError.response?.data?.error || 'Failed to perform DNS reconnaissance';
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <div className="p-6">
        <div className="flex items-center gap-3 mb-6">
          <Globe className="w-6 h-6 text-blue-500" />
          <div>
            <h2 className="text-xl font-bold text-gray-900">DNS Reconnaissance</h2>
            <p className="text-sm text-gray-500">
              Enumerate DNS records, discover subdomains, and check security configuration
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="domain" className="block text-sm font-medium text-gray-700 mb-1">
              Domain Name *
            </label>
            <Input
              id="domain"
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              disabled={loading}
              className="font-mono"
            />
            <p className="mt-1 text-xs text-gray-500">
              Enter the domain name to investigate (without http:// or www)
            </p>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-1">What this scan includes:</p>
                <ul className="list-disc list-inside space-y-1 ml-2">
                  <li>DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, etc.)</li>
                  <li>Subdomain discovery using built-in wordlist</li>
                  <li>Zone transfer vulnerability check (AXFR)</li>
                  <li>DNSSEC configuration check</li>
                  <li>Reverse DNS lookups</li>
                </ul>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <Checkbox
              id="includeSubdomains"
              checked={includeSubdomains}
              onChange={(checked) => setIncludeSubdomains(checked)}
              disabled={loading}
              label="Enumerate subdomains"
            />

            <div>
              <label htmlFor="timeout" className="block text-sm font-medium text-gray-700 mb-1">
                Timeout (seconds)
              </label>
              <Input
                id="timeout"
                type="number"
                min={10}
                max={300}
                value={timeoutSecs}
                onChange={(e) => setTimeoutSecs(parseInt(e.target.value) || 30)}
                disabled={loading}
              />
              <p className="mt-1 text-xs text-gray-500">
                Maximum time to wait for each DNS query (10-300 seconds)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-4 border-t border-gray-200">
            <Button
              type="submit"
              disabled={loading || !domain.trim()}
              className="flex items-center gap-2"
            >
              {loading ? (
                <>
                  <LoadingSpinner size="sm" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Start DNS Reconnaissance</span>
                </>
              )}
            </Button>

            {loading && (
              <span className="text-sm text-gray-500">
                This may take a few minutes depending on the domain...
              </span>
            )}
          </div>
        </form>
      </div>
    </Card>
  );
};

export default DnsReconForm;
