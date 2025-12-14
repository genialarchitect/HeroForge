import React, { useState } from 'react';
import { toast } from 'react-toastify';
import Button from '../ui/Button';
import Input from '../ui/Input';
import Checkbox from '../ui/Checkbox';
import Card from '../ui/Card';
import { scanAPI } from '../../services/api';
import { useScanStore } from '../../store/scanStore';
import { Target, Hash, Cpu, Search } from 'lucide-react';
import { EnumDepth, EnumService } from '../../types';

const ENUM_SERVICES: { id: EnumService; label: string; category: string }[] = [
  { id: 'http', label: 'HTTP', category: 'Web' },
  { id: 'https', label: 'HTTPS', category: 'Web' },
  { id: 'dns', label: 'DNS', category: 'Network' },
  { id: 'smb', label: 'SMB', category: 'Network' },
  { id: 'ftp', label: 'FTP', category: 'Network' },
  { id: 'ssh', label: 'SSH', category: 'Network' },
  { id: 'smtp', label: 'SMTP', category: 'Network' },
  { id: 'ldap', label: 'LDAP', category: 'Network' },
  { id: 'mysql', label: 'MySQL', category: 'Database' },
  { id: 'postgresql', label: 'PostgreSQL', category: 'Database' },
  { id: 'mongodb', label: 'MongoDB', category: 'Database' },
  { id: 'redis', label: 'Redis', category: 'Database' },
  { id: 'elasticsearch', label: 'Elasticsearch', category: 'Database' },
];

const ScanForm: React.FC = () => {
  const [name, setName] = useState('');
  const [customer, setCustomer] = useState('');
  const [target, setTarget] = useState('');
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1000);
  const [threads, setThreads] = useState(100);
  const [osDetection, setOsDetection] = useState(true);
  const [serviceDetection, setServiceDetection] = useState(true);
  const [vulnScan, setVulnScan] = useState(false);
  const [enableEnumeration, setEnableEnumeration] = useState(false);
  const [enumDepth, setEnumDepth] = useState<EnumDepth>('light');
  const [selectedServices, setSelectedServices] = useState<EnumService[]>([]);
  const [loading, setLoading] = useState(false);

  const { addScan } = useScanStore();

  const validateTarget = (input: string): boolean => {
    // IP address regex
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    // CIDR regex
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    // IP range regex
    const rangeRegex = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;

    return ipRegex.test(input) || cidrRegex.test(input) || rangeRegex.test(input);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!name.trim()) {
      toast.error('Please enter a scan name');
      return;
    }

    if (!target.trim()) {
      toast.error('Please enter a target');
      return;
    }

    if (!validateTarget(target.trim())) {
      toast.error('Invalid target format. Use IP (192.168.1.1), CIDR (192.168.1.0/24), or range (192.168.1.1-192.168.1.100)');
      return;
    }

    if (portStart < 1 || portEnd > 65535 || portStart > portEnd) {
      toast.error('Invalid port range');
      return;
    }

    setLoading(true);
    try {
      const response = await scanAPI.create({
        name: name.trim(),
        targets: [target.trim()],
        port_range: [portStart, portEnd],
        threads,
        enable_os_detection: osDetection,
        enable_service_detection: serviceDetection,
        enable_vuln_scan: vulnScan,
        enable_enumeration: enableEnumeration,
        enum_depth: enableEnumeration ? enumDepth : undefined,
        enum_services: enableEnumeration && selectedServices.length > 0 ? selectedServices : undefined,
      });

      addScan(response.data);
      toast.success('Scan started successfully!');

      // Reset form
      setName('');
      setTarget('');
      setCustomer('');
      setPortStart(1);
      setPortEnd(1000);
      setThreads(100);
      setEnableEnumeration(false);
      setEnumDepth('light');
      setSelectedServices([]);
    } catch (error: any) {
      const message = error.response?.data?.error || 'Failed to start scan';
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const toggleService = (service: EnumService) => {
    setSelectedServices((prev) =>
      prev.includes(service)
        ? prev.filter((s) => s !== service)
        : [...prev, service]
    );
  };

  return (
    <Card>
      <h3 className="text-xl font-semibold text-white mb-4">Create New Scan</h3>
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Scan Name"
          type="text"
          placeholder="Production Network Scan"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <Input
          label="Customer Tag (Optional)"
          type="text"
          placeholder="ACME Corp"
          value={customer}
          onChange={(e) => setCustomer(e.target.value)}
          icon={<Hash className="h-5 w-5" />}
        />

        <Input
          label="Target"
          type="text"
          placeholder="192.168.1.0/24 or 10.0.0.1-10.0.0.100"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          icon={<Target className="h-5 w-5" />}
          required
        />

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Start Port"
            type="number"
            min={1}
            max={65535}
            value={portStart}
            onChange={(e) => setPortStart(Number(e.target.value))}
          />
          <Input
            label="End Port"
            type="number"
            min={1}
            max={65535}
            value={portEnd}
            onChange={(e) => setPortEnd(Number(e.target.value))}
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">
            Threads: {threads}
          </label>
          <div className="flex items-center space-x-3">
            <Cpu className="h-5 w-5 text-slate-400" />
            <input
              type="range"
              min={1}
              max={100}
              value={threads}
              onChange={(e) => setThreads(Number(e.target.value))}
              className="w-full h-2 bg-dark-surface rounded-lg appearance-none cursor-pointer slider"
            />
          </div>
        </div>

        <div className="space-y-2 border-t border-dark-border pt-4">
          <p className="text-sm font-medium text-slate-300 mb-2">Scan Options</p>
          <Checkbox
            label="Enable OS Detection"
            checked={osDetection}
            onChange={setOsDetection}
          />
          <Checkbox
            label="Enable Service Detection"
            checked={serviceDetection}
            onChange={setServiceDetection}
          />
          <Checkbox
            label="Enable Vulnerability Scanning"
            checked={vulnScan}
            onChange={setVulnScan}
          />
        </div>

        {/* Enumeration Options */}
        <div className="space-y-3 border-t border-dark-border pt-4">
          <div className="flex items-center space-x-2">
            <Search className="h-5 w-5 text-cyan-400" />
            <p className="text-sm font-medium text-slate-300">Service Enumeration</p>
          </div>
          <Checkbox
            label="Enable Deep Service Enumeration"
            checked={enableEnumeration}
            onChange={setEnableEnumeration}
          />

          {enableEnumeration && (
            <div className="ml-4 space-y-4 animate-fadeIn">
              {/* Depth Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Enumeration Depth
                </label>
                <select
                  value={enumDepth}
                  onChange={(e) => setEnumDepth(e.target.value as EnumDepth)}
                  className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                >
                  <option value="passive">Passive - Banner analysis only</option>
                  <option value="light">Light - Common checks (default)</option>
                  <option value="aggressive">Aggressive - Full enumeration</option>
                </select>
              </div>

              {/* Service Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Services to Enumerate (leave empty for all detected)
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {ENUM_SERVICES.map((service) => (
                    <button
                      key={service.id}
                      type="button"
                      onClick={() => toggleService(service.id)}
                      className={`px-3 py-1.5 text-sm rounded-md border transition-colors ${
                        selectedServices.includes(service.id)
                          ? 'bg-cyan-600 border-cyan-500 text-white'
                          : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500'
                      }`}
                    >
                      {service.label}
                    </button>
                  ))}
                </div>
                {selectedServices.length > 0 && (
                  <p className="mt-2 text-xs text-slate-500">
                    Selected: {selectedServices.join(', ')}
                  </p>
                )}
              </div>
            </div>
          )}
        </div>

        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={loading}
          className="w-full"
        >
          Start Scan
        </Button>
      </form>
    </Card>
  );
};

export default ScanForm;
