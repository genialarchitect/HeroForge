import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import Button from '../ui/Button';
import Input from '../ui/Input';
import Checkbox from '../ui/Checkbox';
import Card from '../ui/Card';
import TagInput from './TagInput';
import { scanAPI, targetGroupAPI, templateAPI, vpnAPI, crmAPI, scanTagAPI, exclusionsAPI } from '../../services/api';
import { useScanStore } from '../../store/scanStore';
import { Target, Cpu, Search, Radio, Wifi, FolderOpen, Save, Zap, Radar, Globe, EyeOff, Shield, Building2, ClipboardList, Ban } from 'lucide-react';
import { EnumDepth, EnumService, ScanType, TargetGroup, ScanPreset, VpnConfig, Customer, Engagement, ScanTag, ScanExclusion } from '../../types';

const SCAN_TYPES: { id: ScanType; label: string; description: string }[] = [
  { id: 'tcp_connect', label: 'TCP Connect', description: 'Standard TCP scan (most reliable)' },
  { id: 'udp', label: 'UDP Only', description: 'UDP port scanning (requires root)' },
  { id: 'comprehensive', label: 'Comprehensive', description: 'TCP + UDP scanning (thorough)' },
  { id: 'syn', label: 'SYN Stealth', description: 'Half-open TCP scan (requires root)' },
];

const ENUM_SERVICES: { id: EnumService; label: string; category: string }[] = [
  { id: 'http', label: 'HTTP', category: 'Web' },
  { id: 'https', label: 'HTTPS', category: 'Web' },
  { id: 'dns', label: 'DNS', category: 'Network' },
  { id: 'smb', label: 'SMB', category: 'Network' },
  { id: 'ftp', label: 'FTP', category: 'Network' },
  { id: 'ssh', label: 'SSH', category: 'Network' },
  { id: 'smtp', label: 'SMTP', category: 'Network' },
  { id: 'ldap', label: 'LDAP', category: 'Network' },
  { id: 'rdp', label: 'RDP', category: 'Remote' },
  { id: 'vnc', label: 'VNC', category: 'Remote' },
  { id: 'telnet', label: 'Telnet', category: 'Remote' },
  { id: 'snmp', label: 'SNMP', category: 'Network' },
  { id: 'mysql', label: 'MySQL', category: 'Database' },
  { id: 'postgresql', label: 'PostgreSQL', category: 'Database' },
  { id: 'mongodb', label: 'MongoDB', category: 'Database' },
  { id: 'redis', label: 'Redis', category: 'Database' },
  { id: 'elasticsearch', label: 'Elasticsearch', category: 'Database' },
];

const ScanForm: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [portStart, setPortStart] = useState(1);
  const [portEnd, setPortEnd] = useState(1000);
  const [threads, setThreads] = useState(100);
  const [scanType, setScanType] = useState<ScanType>('tcp_connect');
  const [udpPortStart, setUdpPortStart] = useState(53);
  const [udpPortEnd, setUdpPortEnd] = useState(500);
  const [udpRetries, setUdpRetries] = useState(2);
  const [osDetection, setOsDetection] = useState(true);
  const [serviceDetection, setServiceDetection] = useState(true);
  const [vulnScan, setVulnScan] = useState(false);
  const [enableEnumeration, setEnableEnumeration] = useState(false);
  const [enumDepth, setEnumDepth] = useState<EnumDepth>('light');
  const [selectedServices, setSelectedServices] = useState<EnumService[]>([]);
  const [loading, setLoading] = useState(false);
  const [targetGroups, setTargetGroups] = useState<TargetGroup[]>([]);
  const [saveAsTemplate, setSaveAsTemplate] = useState(false);
  const [templateName, setTemplateName] = useState('');
  const [templateDescription, setTemplateDescription] = useState('');
  const [presets, setPresets] = useState<ScanPreset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null);
  const [vpnConfigs, setVpnConfigs] = useState<VpnConfig[]>([]);
  const [selectedVpn, setSelectedVpn] = useState<string>('');
  // CRM Integration
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [selectedCustomerId, setSelectedCustomerId] = useState<string>('');
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedEngagementId, setSelectedEngagementId] = useState<string>('');
  // Tags
  const [allTags, setAllTags] = useState<ScanTag[]>([]);
  const [selectedTagIds, setSelectedTagIds] = useState<string[]>([]);
  // Exclusions
  const [exclusions, setExclusions] = useState<ScanExclusion[]>([]);
  const [selectedExclusionIds, setSelectedExclusionIds] = useState<string[]>([]);
  const [skipGlobalExclusions, setSkipGlobalExclusions] = useState(false);

  const { addScan } = useScanStore();

  const showUdpOptions = scanType === 'udp' || scanType === 'comprehensive';

  useEffect(() => {
    loadTargetGroups();
    loadPresets();
    loadVpnConfigs();
    loadCustomers();
    loadTags();
    loadExclusions();
  }, []);

  // Handle URL parameter for pre-selecting customer (e.g., from customer detail page)
  useEffect(() => {
    const customerParam = searchParams.get('customer');
    if (customerParam && customers.length > 0) {
      const customer = customers.find(c => c.id === customerParam);
      if (customer) {
        setSelectedCustomerId(customerParam);
      }
    }
  }, [searchParams, customers]);

  // Load engagements when customer changes
  useEffect(() => {
    if (selectedCustomerId) {
      loadEngagements(selectedCustomerId);
    } else {
      setEngagements([]);
      setSelectedEngagementId('');
    }
  }, [selectedCustomerId]);

  const loadTargetGroups = async () => {
    try {
      const response = await targetGroupAPI.getAll();
      setTargetGroups(response.data);
    } catch (error) {
      console.error('Failed to load target groups:', error);
    }
  };

  const loadPresets = async () => {
    try {
      const response = await scanAPI.getPresets();
      setPresets(response.data);
    } catch (error) {
      console.error('Failed to load scan presets:', error);
    }
  };

  const loadVpnConfigs = async () => {
    try {
      const response = await vpnAPI.getConfigs();
      setVpnConfigs(response.data);
      // Auto-select default VPN if available
      const defaultVpn = response.data.find((v: VpnConfig) => v.is_default);
      if (defaultVpn) {
        setSelectedVpn(defaultVpn.id);
      }
    } catch (error) {
      console.error('Failed to load VPN configs:', error);
    }
  };

  const loadCustomers = async () => {
    try {
      const response = await crmAPI.customers.getAll('active');
      setCustomers(response.data);
    } catch (error) {
      console.error('Failed to load customers:', error);
    }
  };

  const loadTags = async () => {
    try {
      const response = await scanTagAPI.getAll();
      setAllTags(response.data);
    } catch (error) {
      console.error('Failed to load tags:', error);
    }
  };

  const loadExclusions = async () => {
    try {
      const response = await exclusionsAPI.getAll();
      setExclusions(response.data);
    } catch (error) {
      console.error('Failed to load exclusions:', error);
    }
  };

  const loadEngagements = async (customerId: string) => {
    try {
      const response = await crmAPI.engagements.getByCustomer(customerId);
      // Filter to only show active engagements (planning or in_progress)
      const activeEngagements = response.data.filter(
        (e: Engagement) => e.status === 'planning' || e.status === 'in_progress'
      );
      setEngagements(activeEngagements);
    } catch (error) {
      console.error('Failed to load engagements:', error);
      setEngagements([]);
    }
  };

  const useTargetGroup = (group: TargetGroup) => {
    const targets = JSON.parse(group.targets || '[]');
    setTarget(targets.join(', '));
  };

  const applyPreset = (preset: ScanPreset) => {
    setSelectedPreset(preset.id);

    // Special handling for web app scan preset
    if (preset.id === 'webapp') {
      // Set specific web ports instead of the range
      setPortStart(80);
      setPortEnd(8443);
    } else {
      setPortStart(preset.port_range[0]);
      setPortEnd(preset.port_range[1]);
    }

    setThreads(preset.threads);
    setScanType(preset.scan_type);
    setOsDetection(preset.enable_os_detection);
    setServiceDetection(preset.enable_service_detection);
    setVulnScan(preset.enable_vuln_scan);
    setEnableEnumeration(preset.enable_enumeration);

    if (preset.enum_depth) {
      setEnumDepth(preset.enum_depth);
    }

    if (preset.udp_port_range) {
      setUdpPortStart(preset.udp_port_range[0]);
      setUdpPortEnd(preset.udp_port_range[1]);
    }

    if (preset.udp_retries) {
      setUdpRetries(preset.udp_retries);
    }

    if (preset.enum_services) {
      setSelectedServices(preset.enum_services);
    } else {
      setSelectedServices([]);
    }

    toast.success(`Applied "${preset.name}" preset`);
  };

  const getPresetIcon = (iconName: string) => {
    switch (iconName) {
      case 'Zap':
        return Zap;
      case 'Radar':
        return Radar;
      case 'Globe':
        return Globe;
      case 'EyeOff':
        return EyeOff;
      default:
        return Zap;
    }
  };

  const validateSingleTarget = (input: string): boolean => {
    const trimmed = input.trim();
    // IP address regex
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    // CIDR regex
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    // IP range regex
    const rangeRegex = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
    // Hostname regex (basic)
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;

    return ipRegex.test(trimmed) || cidrRegex.test(trimmed) || rangeRegex.test(trimmed) || hostnameRegex.test(trimmed);
  };

  const parseTargets = (input: string): string[] => {
    return input
      .split(/[,\n]/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
  };

  const validateTargets = (input: string): boolean => {
    const targets = parseTargets(input);
    if (targets.length === 0) return false;
    return targets.every(validateSingleTarget);
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

    if (!validateTargets(target)) {
      toast.error('Invalid target format. Use IP (192.168.1.1), CIDR (192.168.1.0/24), range, or hostname. Separate multiple targets with commas.');
      return;
    }

    if (portStart < 1 || portEnd > 65535 || portStart > portEnd) {
      toast.error('Invalid port range');
      return;
    }

    const targets = parseTargets(target);
    setLoading(true);
    try {
      const response = await scanAPI.create({
        name: name.trim(),
        targets,
        port_range: [portStart, portEnd],
        threads,
        scan_type: scanType,
        udp_port_range: showUdpOptions ? [udpPortStart, udpPortEnd] : undefined,
        udp_retries: showUdpOptions ? udpRetries : undefined,
        enable_os_detection: osDetection,
        enable_service_detection: serviceDetection,
        enable_vuln_scan: vulnScan,
        enable_enumeration: enableEnumeration,
        enum_depth: enableEnumeration ? enumDepth : undefined,
        enum_services: enableEnumeration && selectedServices.length > 0 ? selectedServices : undefined,
        vpn_config_id: selectedVpn || undefined,
        customer_id: selectedCustomerId || undefined,
        engagement_id: selectedEngagementId || undefined,
        tag_ids: selectedTagIds.length > 0 ? selectedTagIds : undefined,
        exclusion_ids: selectedExclusionIds.length > 0 ? selectedExclusionIds : undefined,
        skip_global_exclusions: skipGlobalExclusions || undefined,
      });

      addScan(response.data);
      toast.success('Scan started successfully!');

      // Save as template if requested
      if (saveAsTemplate && templateName.trim()) {
        try {
          await templateAPI.create({
            name: templateName.trim(),
            description: templateDescription.trim() || undefined,
            config: {
              targets,
              port_range: [portStart, portEnd],
              threads,
              scan_type: scanType,
              udp_port_range: showUdpOptions ? [udpPortStart, udpPortEnd] : undefined,
              udp_retries: showUdpOptions ? udpRetries : undefined,
              enable_os_detection: osDetection,
              enable_service_detection: serviceDetection,
              enable_vuln_scan: vulnScan,
              enable_enumeration: enableEnumeration,
              enum_depth: enableEnumeration ? enumDepth : undefined,
              enum_services: enableEnumeration && selectedServices.length > 0 ? selectedServices : undefined,
            },
          });
          toast.success('Template saved!');
        } catch (templateError: unknown) {
          console.error('Failed to save template:', templateError);
          toast.warning('Scan started but template save failed');
        }
      }

      // Reset form
      setName('');
      setTarget('');
      setPortStart(1);
      setPortEnd(1000);
      setThreads(100);
      setScanType('tcp_connect');
      setUdpPortStart(53);
      setUdpPortEnd(500);
      setUdpRetries(2);
      setEnableEnumeration(false);
      setEnumDepth('light');
      setSelectedServices([]);
      setSaveAsTemplate(false);
      setTemplateName('');
      setTemplateDescription('');
      setSelectedCustomerId('');
      setSelectedEngagementId('');
      setSelectedTagIds([]);
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      const message = axiosError.response?.data?.error || 'Failed to start scan';
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
        {/* Scan Presets */}
        {presets.length > 0 && (
          <div className="space-y-3 pb-4 border-b border-dark-border">
            <div className="flex items-center space-x-2">
              <Zap className="h-5 w-5 text-yellow-400" />
              <p className="text-sm font-medium text-slate-300">Quick Presets</p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {presets.map((preset) => {
                const IconComponent = getPresetIcon(preset.icon);
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => applyPreset(preset)}
                    className={`px-3 py-3 text-sm rounded-lg border transition-all text-left ${
                      selectedPreset === preset.id
                        ? 'bg-gradient-to-br from-yellow-600/20 to-orange-600/20 border-yellow-500 text-white shadow-lg'
                        : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500 hover:bg-dark-surface/50'
                    }`}
                  >
                    <div className="flex items-center space-x-2 mb-1">
                      <IconComponent className={`h-4 w-4 ${selectedPreset === preset.id ? 'text-yellow-400' : 'text-slate-500'}`} />
                      <div className="font-medium">{preset.name}</div>
                    </div>
                    <div className="text-xs opacity-70 line-clamp-2">{preset.description}</div>
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-slate-500 italic">
              Select a preset to auto-configure scan settings, or customize manually below.
            </p>
          </div>
        )}

        <Input
          label="Scan Name"
          type="text"
          placeholder="Production Network Scan"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        {/* Tags */}
        <TagInput
          selectedTagIds={selectedTagIds}
          onChange={setSelectedTagIds}
          existingTags={allTags}
          onTagsChange={setAllTags}
        />

        {/* CRM Integration */}
        <div className="space-y-3 pb-4 border-b border-dark-border">
          <div className="flex items-center space-x-2">
            <Building2 className="h-5 w-5 text-indigo-400" />
            <p className="text-sm font-medium text-slate-300">Customer Association (Optional)</p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-2">
                Customer
              </label>
              <select
                value={selectedCustomerId}
                onChange={(e) => {
                  setSelectedCustomerId(e.target.value);
                  setSelectedEngagementId('');
                }}
                className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              >
                <option value="">No customer</option>
                {customers.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-2">
                Engagement
              </label>
              <select
                value={selectedEngagementId}
                onChange={(e) => setSelectedEngagementId(e.target.value)}
                disabled={!selectedCustomerId || engagements.length === 0}
                className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <option value="">
                  {!selectedCustomerId
                    ? 'Select customer first'
                    : engagements.length === 0
                      ? 'No active engagements'
                      : 'No engagement'}
                </option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name} ({e.engagement_type.replace('_', ' ')})
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p className="text-xs text-slate-500">
            Link this scan to a customer and engagement for tracking and reporting.
          </p>
        </div>

        {/* Exclusions */}
        {exclusions.length > 0 && (
          <div className="space-y-3 pb-4 border-b border-dark-border">
            <div className="flex items-center space-x-2">
              <Ban className="h-5 w-5 text-orange-400" />
              <p className="text-sm font-medium text-slate-300">Exclusions (Optional)</p>
            </div>

            {/* Global exclusions notice */}
            {exclusions.filter(e => e.is_global).length > 0 && (
              <div className="flex items-center justify-between p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-green-400" />
                  <span className="text-sm text-green-400">
                    {exclusions.filter(e => e.is_global).length} global exclusion(s) will be applied
                  </span>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={skipGlobalExclusions}
                    onChange={(e) => setSkipGlobalExclusions(e.target.checked)}
                    className="w-4 h-4 rounded bg-dark-bg border-dark-border text-orange-500 focus:ring-orange-500 focus:ring-offset-dark-bg"
                  />
                  <span className="text-xs text-slate-400">Skip global exclusions</span>
                </label>
              </div>
            )}

            {/* Per-scan exclusions selection */}
            {exclusions.filter(e => !e.is_global).length > 0 && (
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  Additional exclusions for this scan
                </label>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {exclusions.filter(e => !e.is_global).map((exc) => (
                    <label
                      key={exc.id}
                      className="flex items-center gap-3 p-2 bg-dark-surface rounded-lg cursor-pointer hover:bg-dark-border/30 transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={selectedExclusionIds.includes(exc.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedExclusionIds([...selectedExclusionIds, exc.id]);
                          } else {
                            setSelectedExclusionIds(selectedExclusionIds.filter(id => id !== exc.id));
                          }
                        }}
                        className="w-4 h-4 rounded bg-dark-bg border-dark-border text-primary focus:ring-primary focus:ring-offset-dark-bg"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-white">{exc.name}</span>
                          <span className="text-xs px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400">
                            {exc.exclusion_type.replace('_', ' ')}
                          </span>
                        </div>
                        <code className="text-xs text-slate-400 font-mono">{exc.value}</code>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            )}

            <p className="text-xs text-slate-500">
              Exclusions prevent scanning specific hosts or ports. Configure them in Settings.
            </p>
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="block text-sm font-medium text-slate-300">Target</label>
            {targetGroups.length > 0 && (
              <div className="flex items-center gap-2">
                <FolderOpen className="h-3 w-3 text-slate-500" />
                <span className="text-xs text-slate-500">Use group:</span>
                {targetGroups.slice(0, 3).map((g) => (
                  <button
                    key={g.id}
                    type="button"
                    onClick={() => useTargetGroup(g)}
                    className="px-2 py-0.5 text-xs rounded border border-dark-border text-slate-400 hover:text-white hover:border-primary transition-colors"
                    style={{ borderLeftColor: g.color, borderLeftWidth: 3 }}
                  >
                    {g.name}
                  </button>
                ))}
                {targetGroups.length > 3 && (
                  <span className="text-xs text-slate-500">+{targetGroups.length - 3}</span>
                )}
              </div>
            )}
          </div>
          <Input
            type="text"
            placeholder="192.168.1.0/24, 10.0.0.1-10.0.0.100, or hostname"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            icon={<Target className="h-5 w-5" />}
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Start Port"
            type="number"
            min={1}
            max={65535}
            value={portStart}
            onChange={(e) => {
              setPortStart(Number(e.target.value));
              setSelectedPreset(null);
            }}
          />
          <Input
            label="End Port"
            type="number"
            min={1}
            max={65535}
            value={portEnd}
            onChange={(e) => {
              setPortEnd(Number(e.target.value));
              setSelectedPreset(null);
            }}
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
              onChange={(e) => {
                setThreads(Number(e.target.value));
                setSelectedPreset(null);
              }}
              className="w-full h-2 bg-dark-surface rounded-lg appearance-none cursor-pointer slider"
            />
          </div>
        </div>

        {/* Scan Type Selection */}
        <div className="space-y-3 border-t border-dark-border pt-4">
          <div className="flex items-center space-x-2">
            <Radio className="h-5 w-5 text-primary" />
            <p className="text-sm font-medium text-slate-300">Scan Type</p>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {SCAN_TYPES.map((type) => (
              <button
                key={type.id}
                type="button"
                onClick={() => {
                  setScanType(type.id);
                  setSelectedPreset(null);
                }}
                className={`px-3 py-2 text-sm rounded-lg border transition-colors text-left ${
                  scanType === type.id
                    ? 'bg-primary/20 border-primary text-white'
                    : 'bg-dark-surface border-dark-border text-slate-400 hover:border-slate-500'
                }`}
              >
                <div className="font-medium">{type.label}</div>
                <div className="text-xs opacity-70">{type.description}</div>
              </button>
            ))}
          </div>

          {/* UDP Options */}
          {showUdpOptions && (
            <div className="ml-4 space-y-3 animate-fadeIn">
              <div className="flex items-center space-x-2">
                <Wifi className="h-4 w-4 text-cyan-400" />
                <p className="text-sm font-medium text-slate-400">UDP Options</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="UDP Start Port"
                  type="number"
                  min={1}
                  max={65535}
                  value={udpPortStart}
                  onChange={(e) => setUdpPortStart(Number(e.target.value))}
                />
                <Input
                  label="UDP End Port"
                  type="number"
                  min={1}
                  max={65535}
                  value={udpPortEnd}
                  onChange={(e) => setUdpPortEnd(Number(e.target.value))}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-2">
                  UDP Retries: {udpRetries}
                </label>
                <input
                  type="range"
                  min={1}
                  max={5}
                  value={udpRetries}
                  onChange={(e) => setUdpRetries(Number(e.target.value))}
                  className="w-full h-2 bg-dark-surface rounded-lg appearance-none cursor-pointer slider"
                />
              </div>
            </div>
          )}
        </div>

        {/* VPN Selection */}
        {vpnConfigs.length > 0 && (
          <div className="space-y-3 border-t border-dark-border pt-4">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-green-400" />
              <p className="text-sm font-medium text-slate-300">VPN Connection</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-400 mb-2">
                Route scan through VPN (optional)
              </label>
              <select
                value={selectedVpn}
                onChange={(e) => setSelectedVpn(e.target.value)}
                className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-white focus:ring-2 focus:ring-green-500 focus:border-transparent"
              >
                <option value="">No VPN - Direct connection</option>
                {vpnConfigs.map((vpn) => (
                  <option key={vpn.id} value={vpn.id}>
                    {vpn.name} ({vpn.vpn_type.toUpperCase()})
                    {vpn.is_default ? ' (Default)' : ''}
                  </option>
                ))}
              </select>
              <p className="mt-1 text-xs text-slate-500">
                VPN connects before scan and disconnects when complete. Configure VPNs in Settings.
              </p>
            </div>
          </div>
        )}

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

        {/* Save as Template */}
        <div className="space-y-3 border-t border-dark-border pt-4">
          <div className="flex items-center space-x-2">
            <Save className="h-5 w-5 text-purple-400" />
            <p className="text-sm font-medium text-slate-300">Save Configuration</p>
          </div>
          <Checkbox
            label="Save this scan configuration as a template"
            checked={saveAsTemplate}
            onChange={setSaveAsTemplate}
          />

          {saveAsTemplate && (
            <div className="ml-4 space-y-3 animate-fadeIn">
              <Input
                label="Template Name"
                type="text"
                placeholder="Production Network Scan Template"
                value={templateName}
                onChange={(e) => setTemplateName(e.target.value)}
              />
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-1">
                  Template Description (Optional)
                </label>
                <textarea
                  value={templateDescription}
                  onChange={(e) => setTemplateDescription(e.target.value)}
                  className="w-full bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  rows={2}
                  placeholder="Quick template for scanning production servers"
                />
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
