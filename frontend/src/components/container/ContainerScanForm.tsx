import React, { useState } from 'react';
import { Play, Box, FileCode, Server, Layers, AlertTriangle, Info } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Checkbox } from '../ui/Checkbox';
import type { ContainerScanType, CreateContainerScanRequest, ContainerScanTypeInfo } from '../../types';

interface ContainerScanFormProps {
  onSubmit: (data: CreateContainerScanRequest) => void;
  isLoading?: boolean;
  scanTypes?: ContainerScanTypeInfo[];
}

const defaultScanTypes: ContainerScanTypeInfo[] = [
  {
    id: 'image',
    name: 'Container Image Scan',
    description: 'Scan Docker/OCI images for vulnerabilities and misconfigurations',
    requires_registry: true,
    requires_k8s: false,
  },
  {
    id: 'dockerfile',
    name: 'Dockerfile Analysis',
    description: 'Analyze Dockerfiles for security best practices and potential issues',
    requires_registry: false,
    requires_k8s: false,
  },
  {
    id: 'runtime',
    name: 'Container Runtime Scan',
    description: 'Scan running containers for runtime security issues',
    requires_registry: false,
    requires_k8s: false,
  },
  {
    id: 'k8s_manifest',
    name: 'K8s Manifest Analysis',
    description: 'Analyze Kubernetes manifests for security configurations',
    requires_registry: false,
    requires_k8s: true,
  },
  {
    id: 'k8s_cluster',
    name: 'K8s Cluster Assessment',
    description: 'Comprehensive Kubernetes cluster security assessment',
    requires_registry: false,
    requires_k8s: true,
  },
  {
    id: 'comprehensive',
    name: 'Comprehensive Scan',
    description: 'Full container and Kubernetes security assessment',
    requires_registry: true,
    requires_k8s: true,
  },
];

const scanTypeIcons: Record<ContainerScanType, React.ReactNode> = {
  image: <Box className="w-5 h-5" />,
  dockerfile: <FileCode className="w-5 h-5" />,
  runtime: <Server className="w-5 h-5" />,
  k8s_manifest: <Layers className="w-5 h-5" />,
  k8s_cluster: <Layers className="w-5 h-5" />,
  comprehensive: <AlertTriangle className="w-5 h-5" />,
};

export function ContainerScanForm({ onSubmit, isLoading, scanTypes = defaultScanTypes }: ContainerScanFormProps) {
  const [name, setName] = useState('');
  const [scanType, setScanType] = useState<ContainerScanType>('image');
  const [target, setTarget] = useState('');
  const [registryUrl, setRegistryUrl] = useState('');
  const [registryUsername, setRegistryUsername] = useState('');
  const [registryPassword, setRegistryPassword] = useState('');
  const [k8sContext, setK8sContext] = useState('');
  const [k8sNamespace, setK8sNamespace] = useState('');
  const [demoMode, setDemoMode] = useState(false);

  const selectedType = scanTypes.find((t) => t.id === scanType);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const data: CreateContainerScanRequest = {
      name: name || `Container Scan - ${new Date().toLocaleString()}`,
      scan_type: scanType,
      target,
      demo_mode: demoMode,
    };

    if (selectedType?.requires_registry && registryUrl) {
      data.registry_url = registryUrl;
      if (registryUsername) data.registry_username = registryUsername;
      if (registryPassword) data.registry_password = registryPassword;
    }

    if (selectedType?.requires_k8s) {
      if (k8sContext) data.k8s_context = k8sContext;
      if (k8sNamespace) data.k8s_namespace = k8sNamespace;
    }

    onSubmit(data);
  };

  const getPlaceholder = () => {
    switch (scanType) {
      case 'image':
        return 'e.g., nginx:latest, myregistry.com/myapp:v1.0';
      case 'dockerfile':
        return 'Path to Dockerfile or directory containing Dockerfile';
      case 'runtime':
        return 'Container ID or name';
      case 'k8s_manifest':
        return 'Path to Kubernetes manifest(s) or directory';
      case 'k8s_cluster':
        return 'Kubernetes cluster context name';
      case 'comprehensive':
        return 'Image name or K8s namespace';
      default:
        return 'Enter target';
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Scan Name */}
      <div>
        <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
          Scan Name
        </label>
        <Input
          id="name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Optional: Give your scan a name"
        />
      </div>

      {/* Scan Type Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-3">
          Scan Type
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {scanTypes.map((type) => (
            <button
              key={type.id}
              type="button"
              onClick={() => setScanType(type.id)}
              className={`p-4 rounded-lg border-2 text-left transition-all ${
                scanType === type.id
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
              }`}
            >
              <div className="flex items-center gap-3 mb-2">
                <div className={scanType === type.id ? 'text-cyan-400' : 'text-gray-400'}>
                  {scanTypeIcons[type.id]}
                </div>
                <span className={`font-medium ${scanType === type.id ? 'text-cyan-400' : 'text-gray-200'}`}>
                  {type.name}
                </span>
              </div>
              <p className="text-sm text-gray-400">{type.description}</p>
              <div className="flex gap-2 mt-2">
                {type.requires_registry && (
                  <span className="text-xs px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded">
                    Registry
                  </span>
                )}
                {type.requires_k8s && (
                  <span className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded">
                    K8s
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Target Input */}
      <div>
        <label htmlFor="target" className="block text-sm font-medium text-gray-300 mb-2">
          Target
        </label>
        <Input
          id="target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={getPlaceholder()}
          required
        />
      </div>

      {/* Registry Settings */}
      {selectedType?.requires_registry && (
        <div className="space-y-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
          <h3 className="text-sm font-medium text-gray-300 flex items-center gap-2">
            <Box className="w-4 h-4" />
            Container Registry Settings
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label htmlFor="registryUrl" className="block text-xs text-gray-400 mb-1">
                Registry URL (optional)
              </label>
              <Input
                id="registryUrl"
                value={registryUrl}
                onChange={(e) => setRegistryUrl(e.target.value)}
                placeholder="e.g., registry.example.com"
              />
            </div>
            <div>
              <label htmlFor="registryUsername" className="block text-xs text-gray-400 mb-1">
                Username
              </label>
              <Input
                id="registryUsername"
                value={registryUsername}
                onChange={(e) => setRegistryUsername(e.target.value)}
                placeholder="Optional"
              />
            </div>
            <div>
              <label htmlFor="registryPassword" className="block text-xs text-gray-400 mb-1">
                Password/Token
              </label>
              <Input
                id="registryPassword"
                type="password"
                value={registryPassword}
                onChange={(e) => setRegistryPassword(e.target.value)}
                placeholder="Optional"
              />
            </div>
          </div>
        </div>
      )}

      {/* Kubernetes Settings */}
      {selectedType?.requires_k8s && (
        <div className="space-y-4 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
          <h3 className="text-sm font-medium text-gray-300 flex items-center gap-2">
            <Layers className="w-4 h-4" />
            Kubernetes Settings
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="k8sContext" className="block text-xs text-gray-400 mb-1">
                K8s Context (optional)
              </label>
              <Input
                id="k8sContext"
                value={k8sContext}
                onChange={(e) => setK8sContext(e.target.value)}
                placeholder="e.g., minikube, production-cluster"
              />
            </div>
            <div>
              <label htmlFor="k8sNamespace" className="block text-xs text-gray-400 mb-1">
                Namespace (optional)
              </label>
              <Input
                id="k8sNamespace"
                value={k8sNamespace}
                onChange={(e) => setK8sNamespace(e.target.value)}
                placeholder="e.g., default, production"
              />
            </div>
          </div>
        </div>
      )}

      {/* Demo Mode */}
      <div className="flex items-center gap-3 p-4 bg-yellow-500/10 rounded-lg border border-yellow-500/30">
        <Checkbox
          id="demoMode"
          checked={demoMode}
          onChange={(checked: boolean) => setDemoMode(checked)}
        />
        <div>
          <label htmlFor="demoMode" className="text-sm font-medium text-yellow-400 cursor-pointer">
            Demo Mode
          </label>
          <p className="text-xs text-gray-400">
            Run with simulated data for testing. No actual container scanning will be performed.
          </p>
        </div>
      </div>

      {/* Info Box */}
      <div className="flex items-start gap-3 p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
        <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-gray-300">
          <p className="font-medium text-blue-400 mb-1">Scanning Requirements</p>
          <ul className="list-disc list-inside text-gray-400 space-y-1">
            <li>Image scans require Trivy or Grype to be installed</li>
            <li>Runtime scans require Docker daemon access</li>
            <li>K8s scans require kubectl configured with cluster access</li>
          </ul>
        </div>
      </div>

      {/* Submit Button */}
      <div className="flex justify-end">
        <Button type="submit" disabled={isLoading || !target}>
          <Play className="w-4 h-4 mr-2" />
          {isLoading ? 'Starting Scan...' : 'Start Scan'}
        </Button>
      </div>
    </form>
  );
}
