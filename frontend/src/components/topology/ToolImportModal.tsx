import React, { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { toast } from 'react-toastify';
import api from '../../services/api';
import Button from '../ui/Button';
import {
  Upload,
  X,
  FileText,
  AlertCircle,
  CheckCircle,
  Loader2,
  Server,
  Monitor,
  HelpCircle,
} from 'lucide-react';

interface SupportedFormat {
  id: string;
  name: string;
  description: string;
  extensions: string[];
  exampleCommand: string | null;
}

interface ImportStats {
  hostsImported: number;
  portsDiscovered: number;
  sourceFormat: string;
}

interface NetworkNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: {
    label: string;
    deviceType: string;
    securityZone: string;
    ipAddress?: string;
    hostname?: string;
    ports?: Array<{ port: number; protocol: string; service?: string }>;
  };
}

interface NetworkEdge {
  id: string;
  source: string;
  target: string;
}

interface ToolImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportComplete: (nodes: NetworkNode[], edges: NetworkEdge[], stats: ImportStats) => void;
  engagementId?: string;
}

const ToolImportModal: React.FC<ToolImportModalProps> = ({
  isOpen,
  onClose,
  onImportComplete,
  engagementId,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [formats, setFormats] = useState<SupportedFormat[]>([]);
  const [selectedFormat, setSelectedFormat] = useState<string>('auto');
  const [mergeMode, setMergeMode] = useState<'merge' | 'replace' | 'append'>('merge');
  const [isUploading, setIsUploading] = useState(false);
  const [previewData, setPreviewData] = useState<{
    nodes: NetworkNode[];
    stats: ImportStats;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch supported formats
  useEffect(() => {
    const fetchFormats = async () => {
      try {
        const response = await api.get('/api/network-topology/import/formats');
        setFormats(response.data.formats || []);
      } catch (err) {
        console.error('Failed to fetch formats:', err);
      }
    };
    if (isOpen) {
      fetchFormats();
    }
  }, [isOpen]);

  // Handle file drop
  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setFile(acceptedFiles[0]);
      setError(null);
      setPreviewData(null);

      // Auto-detect format based on extension
      const filename = acceptedFiles[0].name.toLowerCase();
      if (filename.endsWith('.xml')) {
        setSelectedFormat('nmap_xml');
      } else if (filename.endsWith('.gnmap')) {
        setSelectedFormat('nmap_grepable');
      } else if (filename.endsWith('.json')) {
        setSelectedFormat('masscan_json');
      } else {
        setSelectedFormat('auto');
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/xml': ['.xml'],
      'application/xml': ['.xml'],
      'application/json': ['.json'],
      'text/plain': ['.txt', '.log', '.gnmap', '.greppable'],
    },
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024, // 10MB
  });

  // Upload and import file
  const handleImport = async () => {
    if (!file) {
      setError('Please select a file to import');
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const params = new URLSearchParams();
      if (selectedFormat !== 'auto') {
        params.append('format', selectedFormat);
      }
      params.append('mergeMode', mergeMode);
      if (engagementId) {
        params.append('engagementId', engagementId);
      }

      const response = await api.post(
        `/api/network-topology/import/tool?${params.toString()}`,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      if (response.data.success) {
        onImportComplete(response.data.nodes, response.data.edges, response.data.stats);
        toast.success(
          `Imported ${response.data.stats.hostsImported} hosts with ${response.data.stats.portsDiscovered} ports`
        );
        onClose();
      } else {
        setError(response.data.error || 'Import failed');
      }
    } catch (err: any) {
      const errorMsg = err.response?.data?.error || err.message || 'Import failed';
      setError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setIsUploading(false);
    }
  };

  // Reset state on close
  const handleClose = () => {
    setFile(null);
    setPreviewData(null);
    setError(null);
    setSelectedFormat('auto');
    setMergeMode('merge');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="p-6 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Upload className="w-6 h-6 text-cyan-400" />
              Import Network Topology
            </h2>
            <p className="text-sm text-gray-400 mt-1">
              Upload scan results from nmap, masscan, netcat, or rustscan
            </p>
          </div>
          <button onClick={handleClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Drop Zone */}
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
              isDragActive
                ? 'border-cyan-500 bg-cyan-500/10'
                : file
                ? 'border-green-500 bg-green-500/10'
                : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <input {...getInputProps()} />
            {file ? (
              <div className="flex items-center justify-center gap-3">
                <FileText className="w-10 h-10 text-green-400" />
                <div className="text-left">
                  <p className="text-white font-medium">{file.name}</p>
                  <p className="text-sm text-gray-400">
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setFile(null);
                    setPreviewData(null);
                  }}
                  className="ml-4 text-gray-400 hover:text-red-400"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            ) : (
              <>
                <Upload className="w-12 h-12 text-gray-500 mx-auto mb-3" />
                <p className="text-gray-300">
                  {isDragActive
                    ? 'Drop the file here...'
                    : 'Drag & drop a scan file, or click to select'}
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Supports: .xml, .gnmap, .json, .txt, .log (max 10MB)
                </p>
              </>
            )}
          </div>

          {/* Format Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              File Format
            </label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value)}
              className="w-full p-2.5 bg-gray-900 border border-gray-600 rounded-lg text-white"
            >
              <option value="auto">Auto-detect</option>
              {formats.map((format) => (
                <option key={format.id} value={format.id}>
                  {format.name}
                </option>
              ))}
            </select>
            {selectedFormat !== 'auto' && formats.find((f) => f.id === selectedFormat) && (
              <p className="text-xs text-gray-500 mt-1">
                {formats.find((f) => f.id === selectedFormat)?.description}
              </p>
            )}
          </div>

          {/* Merge Mode */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Import Mode
            </label>
            <div className="grid grid-cols-3 gap-3">
              {[
                {
                  value: 'merge',
                  label: 'Merge',
                  desc: 'Add new hosts, update existing',
                },
                {
                  value: 'replace',
                  label: 'Replace',
                  desc: 'Replace all existing nodes',
                },
                {
                  value: 'append',
                  label: 'Append',
                  desc: 'Add all nodes (may duplicate)',
                },
              ].map((mode) => (
                <button
                  key={mode.value}
                  onClick={() => setMergeMode(mode.value as 'merge' | 'replace' | 'append')}
                  className={`p-3 rounded-lg border text-left transition-colors ${
                    mergeMode === mode.value
                      ? 'border-cyan-500 bg-cyan-500/10'
                      : 'border-gray-600 hover:border-gray-500'
                  }`}
                >
                  <div className="font-medium text-white">{mode.label}</div>
                  <div className="text-xs text-gray-400">{mode.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Supported Formats Info */}
          <div className="bg-gray-900 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <HelpCircle className="w-4 h-4 text-gray-400" />
              <span className="text-sm font-medium text-gray-300">
                Supported Tool Commands
              </span>
            </div>
            <div className="space-y-2 text-xs font-mono text-gray-500">
              <div>
                <span className="text-cyan-400">nmap:</span>{' '}
                nmap -sV -oX output.xml &lt;target&gt;
              </div>
              <div>
                <span className="text-cyan-400">nmap (grep):</span>{' '}
                nmap -sV -oG output.gnmap &lt;target&gt;
              </div>
              <div>
                <span className="text-cyan-400">masscan:</span>{' '}
                masscan -p1-65535 -oJ output.json &lt;target&gt;
              </div>
              <div>
                <span className="text-cyan-400">netcat:</span>{' '}
                nc -zv &lt;host&gt; 1-1000 2&gt;&amp;1 | tee output.txt
              </div>
              <div>
                <span className="text-cyan-400">rustscan:</span>{' '}
                rustscan -a &lt;target&gt; --greppable &gt; output.txt
              </div>
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
          <Button variant="secondary" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleImport} disabled={!file || isUploading}>
            {isUploading ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Importing...
              </>
            ) : (
              <>
                <Upload className="w-4 h-4 mr-2" />
                Import
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ToolImportModal;
