import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  Binary,
  Upload,
  Search,
  Trash2,
  FileCode,
  Shield,
  Lock,
  Package,
  ChevronRight,
  ChevronDown,
  Copy,
  Download,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  BarChart3,
  FileText,
  List,
  Grid,
  RefreshCw,
} from 'lucide-react';
import { binaryAnalysisAPI } from '../services/api';
import Layout from '../components/layout/Layout';
import type {
  BinarySampleSummary,
  BinarySampleDetail,
  BinaryExtractedString,
  BinaryImport,
  BinaryExport,
  BinaryAnalysisStats,
} from '../types';

// Helper to format file size
const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

// Helper to get entropy color
const getEntropyColor = (entropy: number): string => {
  if (entropy >= 7.5) return 'text-red-400';
  if (entropy >= 7.0) return 'text-orange-400';
  if (entropy >= 6.0) return 'text-yellow-400';
  return 'text-green-400';
};

// Stats Card Component
const StatsCard: React.FC<{ title: string; value: string | number; icon: React.ReactNode; color: string }> = ({
  title, value, icon, color
}) => (
  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-400 text-sm">{title}</p>
        <p className="text-2xl font-bold text-white mt-1">{value}</p>
      </div>
      <div className={`p-3 rounded-lg ${color}`}>
        {icon}
      </div>
    </div>
  </div>
);

// Upload Zone Component
const UploadZone: React.FC<{ onUpload: (file: File) => void; isUploading: boolean }> = ({ onUpload, isUploading }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) onUpload(file);
  }, [onUpload]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onUpload(file);
  };

  return (
    <div
      className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
        isDragging
          ? 'border-cyan-500 bg-cyan-500/10'
          : 'border-gray-600 hover:border-gray-500'
      }`}
      onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
    >
      {isUploading ? (
        <div className="flex flex-col items-center">
          <Loader2 className="w-12 h-12 text-cyan-500 animate-spin mb-4" />
          <p className="text-gray-300">Uploading and analyzing...</p>
        </div>
      ) : (
        <>
          <Upload className="w-12 h-12 text-gray-500 mx-auto mb-4" />
          <p className="text-gray-300 mb-2">Drag and drop a binary file here</p>
          <p className="text-gray-500 text-sm mb-4">Supports PE (.exe, .dll) and ELF files</p>
          <label className="cursor-pointer">
            <span className="bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition-colors">
              Browse Files
            </span>
            <input
              type="file"
              className="hidden"
              onChange={handleFileSelect}
              accept=".exe,.dll,.so,.elf,.bin"
            />
          </label>
        </>
      )}
    </div>
  );
};

// Sample Row Component
const SampleRow: React.FC<{
  sample: BinarySampleSummary;
  onSelect: () => void;
  onDelete: () => void;
}> = ({ sample, onSelect, onDelete }) => (
  <tr
    className="border-b border-gray-700 hover:bg-gray-800/50 cursor-pointer transition-colors"
    onClick={onSelect}
  >
    <td className="px-4 py-3">
      <div className="flex items-center space-x-3">
        <FileCode className="w-5 h-5 text-cyan-500" />
        <div>
          <p className="text-white font-medium">{sample.filename}</p>
          <p className="text-gray-500 text-xs font-mono">{sample.sha256.substring(0, 16)}...</p>
        </div>
      </div>
    </td>
    <td className="px-4 py-3 text-gray-300">{sample.file_type}</td>
    <td className="px-4 py-3 text-gray-300">{formatFileSize(sample.file_size)}</td>
    <td className="px-4 py-3">
      <span className={getEntropyColor(sample.entropy)}>
        {sample.entropy.toFixed(2)}
      </span>
    </td>
    <td className="px-4 py-3">
      {sample.is_packed ? (
        <span className="flex items-center text-orange-400">
          <Package className="w-4 h-4 mr-1" />
          {sample.packer_name || 'Packed'}
        </span>
      ) : (
        <span className="text-gray-500">-</span>
      )}
    </td>
    <td className="px-4 py-3">
      <span className={`px-2 py-1 rounded text-xs ${
        sample.analysis_status === 'completed'
          ? 'bg-green-500/20 text-green-400'
          : sample.analysis_status === 'failed'
          ? 'bg-red-500/20 text-red-400'
          : 'bg-yellow-500/20 text-yellow-400'
      }`}>
        {sample.analysis_status}
      </span>
    </td>
    <td className="px-4 py-3">
      <button
        onClick={(e) => { e.stopPropagation(); onDelete(); }}
        className="p-2 text-gray-400 hover:text-red-400 transition-colors"
      >
        <Trash2 className="w-4 h-4" />
      </button>
    </td>
  </tr>
);

// Sample Detail Modal Component
const SampleDetailModal: React.FC<{
  sampleId: string;
  onClose: () => void;
}> = ({ sampleId, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'sections' | 'strings' | 'imports' | 'exports' | 'hex'>('overview');
  const [hexOffset, setHexOffset] = useState(0);

  const { data: sample, isLoading } = useQuery({
    queryKey: ['binary-sample', sampleId],
    queryFn: () => binaryAnalysisAPI.getSample(sampleId).then(r => r.data),
  });

  const { data: stringsData } = useQuery({
    queryKey: ['binary-strings', sampleId],
    queryFn: () => binaryAnalysisAPI.getStrings(sampleId, { limit: 500 }).then(r => r.data),
    enabled: activeTab === 'strings',
  });

  const { data: importsData } = useQuery({
    queryKey: ['binary-imports', sampleId],
    queryFn: () => binaryAnalysisAPI.getImports(sampleId).then(r => r.data),
    enabled: activeTab === 'imports',
  });

  const { data: exportsData } = useQuery({
    queryKey: ['binary-exports', sampleId],
    queryFn: () => binaryAnalysisAPI.getExports(sampleId).then(r => r.data),
    enabled: activeTab === 'exports',
  });

  const { data: hexData } = useQuery({
    queryKey: ['binary-hex', sampleId, hexOffset],
    queryFn: () => binaryAnalysisAPI.getHexDump(sampleId, hexOffset, 512).then(r => r.data),
    enabled: activeTab === 'hex',
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  if (isLoading) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-900 rounded-lg p-8">
          <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
        </div>
      </div>
    );
  }

  if (!sample) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-lg w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center space-x-3">
            <FileCode className="w-6 h-6 text-cyan-500" />
            <div>
              <h2 className="text-xl font-bold text-white">{sample.filename}</h2>
              <p className="text-gray-400 text-sm">{sample.file_type} | {formatFileSize(sample.file_size)}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <XCircle className="w-6 h-6" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700">
          {(['overview', 'sections', 'strings', 'imports', 'exports', 'hex'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === tab
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-4">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Hashes */}
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Shield className="w-5 h-5 mr-2 text-cyan-500" />
                  Hashes
                </h3>
                <div className="space-y-3">
                  {[
                    { label: 'MD5', value: sample.md5 },
                    { label: 'SHA1', value: sample.sha1 },
                    { label: 'SHA256', value: sample.sha256 },
                    { label: 'SSDeep', value: sample.ssdeep },
                    { label: 'Imphash', value: sample.imphash },
                  ].map(({ label, value }) => value && (
                    <div key={label} className="flex items-center justify-between">
                      <span className="text-gray-400 text-sm">{label}:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-white font-mono text-sm truncate max-w-[300px]">{value}</span>
                        <button
                          onClick={() => copyToClipboard(value, label)}
                          className="p-1 text-gray-400 hover:text-cyan-400"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analysis Info */}
              <div className="bg-gray-800 rounded-lg p-4">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <BarChart3 className="w-5 h-5 mr-2 text-cyan-500" />
                  Analysis
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-gray-400 text-sm">Entropy</p>
                    <p className={`text-lg font-bold ${getEntropyColor(sample.entropy)}`}>
                      {sample.entropy.toFixed(4)}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Packed</p>
                    <p className="text-lg font-bold">
                      {sample.is_packed ? (
                        <span className="text-orange-400">Yes ({sample.packer_name})</span>
                      ) : (
                        <span className="text-green-400">No</span>
                      )}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Strings</p>
                    <p className="text-lg font-bold text-white">{sample.strings_count}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 text-sm">Imports</p>
                    <p className="text-lg font-bold text-white">{sample.imports_count}</p>
                  </div>
                </div>
              </div>

              {/* PE Info */}
              {sample.pe_info && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                    <FileCode className="w-5 h-5 mr-2 text-cyan-500" />
                    PE Information
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-gray-400 text-sm">Machine Type</p>
                      <p className="text-white">{sample.pe_info.machine_type || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">Subsystem</p>
                      <p className="text-white">{sample.pe_info.subsystem || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">64-bit</p>
                      <p className="text-white">{sample.pe_info.is_64bit ? 'Yes' : 'No'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">DLL</p>
                      <p className="text-white">{sample.pe_info.is_dll ? 'Yes' : 'No'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">Entry Point</p>
                      <p className="text-white font-mono">0x{sample.pe_info.entry_point?.toString(16).toUpperCase()}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">Image Base</p>
                      <p className="text-white font-mono">0x{sample.pe_info.image_base?.toString(16).toUpperCase()}</p>
                    </div>
                    <div className="col-span-2">
                      <p className="text-gray-400 text-sm mb-2">Security Features</p>
                      <div className="flex flex-wrap gap-2">
                        {sample.pe_info.has_debug_info && (
                          <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs">Debug Info</span>
                        )}
                        {sample.pe_info.has_tls && (
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded text-xs">TLS Callbacks</span>
                        )}
                        {sample.pe_info.has_rich_header && (
                          <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs">Rich Header</span>
                        )}
                        {sample.pe_info.checksum_valid && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">Valid Checksum</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ELF Info */}
              {sample.elf_info && (
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                    <FileCode className="w-5 h-5 mr-2 text-cyan-500" />
                    ELF Information
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-gray-400 text-sm">Machine Type</p>
                      <p className="text-white">{sample.elf_info.machine_type || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">ELF Type</p>
                      <p className="text-white">{sample.elf_info.elf_type || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">OS/ABI</p>
                      <p className="text-white">{sample.elf_info.os_abi || 'Unknown'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400 text-sm">Entry Point</p>
                      <p className="text-white font-mono">0x{sample.elf_info.entry_point?.toString(16).toUpperCase()}</p>
                    </div>
                    <div className="col-span-2">
                      <p className="text-gray-400 text-sm mb-2">Security Features</p>
                      <div className="flex flex-wrap gap-2">
                        {sample.elf_info.is_pie && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">PIE</span>
                        )}
                        {sample.elf_info.has_relro && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">RELRO</span>
                        )}
                        {sample.elf_info.has_nx && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">NX</span>
                        )}
                        {sample.elf_info.has_stack_canary && (
                          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">Stack Canary</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'sections' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Virtual Address</th>
                    <th className="px-4 py-3">Virtual Size</th>
                    <th className="px-4 py-3">Raw Size</th>
                    <th className="px-4 py-3">Entropy</th>
                    <th className="px-4 py-3">Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {sample.sections.map((section, idx) => (
                    <tr key={idx} className="border-b border-gray-700/50">
                      <td className="px-4 py-3 font-mono text-cyan-400">{section.name}</td>
                      <td className="px-4 py-3 font-mono text-gray-300">0x{section.virtual_address.toString(16).toUpperCase()}</td>
                      <td className="px-4 py-3 text-gray-300">{formatFileSize(section.virtual_size)}</td>
                      <td className="px-4 py-3 text-gray-300">{formatFileSize(section.raw_size)}</td>
                      <td className={`px-4 py-3 ${getEntropyColor(section.entropy)}`}>{section.entropy.toFixed(2)}</td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          {section.is_executable && (
                            <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">X</span>
                          )}
                          {section.is_writable && (
                            <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">W</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'strings' && (
            <div className="space-y-2">
              {stringsData?.strings.slice(0, 200).map((str, idx) => (
                <div key={idx} className="flex items-center space-x-4 py-2 border-b border-gray-700/50">
                  <span className="text-gray-500 font-mono text-sm w-24">0x{str.offset.toString(16)}</span>
                  <span className="text-cyan-400 text-xs px-2 py-0.5 bg-cyan-500/20 rounded">{str.encoding}</span>
                  <span className="text-white font-mono break-all">{str.value}</span>
                  {str.string_type && (
                    <span className="text-xs text-gray-500">({str.string_type})</span>
                  )}
                </div>
              ))}
              {stringsData && stringsData.strings.length > 200 && (
                <p className="text-gray-500 text-center py-4">
                  Showing 200 of {stringsData.strings.length} strings
                </p>
              )}
            </div>
          )}

          {activeTab === 'imports' && (
            <div className="space-y-4">
              {importsData?.imports.map((imp, idx) => (
                <div key={idx} className="bg-gray-800 rounded-lg p-4">
                  <h4 className="text-cyan-400 font-mono mb-2">{imp.dll_name}</h4>
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                    {imp.functions.map((func, fidx) => (
                      <span key={fidx} className="text-gray-300 text-sm font-mono">{func}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'exports' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                    <th className="px-4 py-3">Ordinal</th>
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Address</th>
                  </tr>
                </thead>
                <tbody>
                  {exportsData?.exports.map((exp, idx) => (
                    <tr key={idx} className="border-b border-gray-700/50">
                      <td className="px-4 py-3 text-gray-500">{exp.ordinal}</td>
                      <td className="px-4 py-3 font-mono text-cyan-400">{exp.name}</td>
                      <td className="px-4 py-3 font-mono text-gray-300">0x{exp.address.toString(16).toUpperCase()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'hex' && (
            <div>
              <div className="flex items-center space-x-4 mb-4">
                <button
                  onClick={() => setHexOffset(Math.max(0, hexOffset - 512))}
                  disabled={hexOffset === 0}
                  className="px-3 py-1 bg-gray-700 text-white rounded disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="text-gray-400">
                  Offset: 0x{hexOffset.toString(16).toUpperCase()}
                </span>
                <button
                  onClick={() => setHexOffset(hexOffset + 512)}
                  className="px-3 py-1 bg-gray-700 text-white rounded"
                >
                  Next
                </button>
              </div>
              {hexData && (
                <pre className="bg-gray-950 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                  <span className="text-gray-500">{hexData.hex}</span>
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Main Page Component
const BinaryAnalysisPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [selectedSample, setSelectedSample] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'list' | 'grid'>('list');

  // Fetch samples
  const { data: samples, isLoading: samplesLoading, refetch } = useQuery({
    queryKey: ['binary-samples'],
    queryFn: () => binaryAnalysisAPI.listSamples({ limit: 100 }).then(r => r.data),
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['binary-stats'],
    queryFn: () => binaryAnalysisAPI.getStats().then(r => r.data),
  });

  // Upload mutation
  const uploadMutation = useMutation({
    mutationFn: (file: File) => binaryAnalysisAPI.uploadSample(file),
    onSuccess: (data) => {
      toast.success('Sample uploaded and analyzed successfully');
      queryClient.invalidateQueries({ queryKey: ['binary-samples'] });
      queryClient.invalidateQueries({ queryKey: ['binary-stats'] });
      setSelectedSample(data.data.id);
    },
    onError: (error: Error) => {
      toast.error(`Upload failed: ${error.message}`);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => binaryAnalysisAPI.deleteSample(id),
    onSuccess: () => {
      toast.success('Sample deleted');
      queryClient.invalidateQueries({ queryKey: ['binary-samples'] });
      queryClient.invalidateQueries({ queryKey: ['binary-stats'] });
    },
    onError: (error: Error) => {
      toast.error(`Delete failed: ${error.message}`);
    },
  });

  return (
    <Layout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center">
              <Binary className="w-8 h-8 mr-3 text-cyan-500" />
              Binary Analysis
            </h1>
            <p className="text-gray-400 mt-1">Upload and analyze PE/ELF binaries for malware research</p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw className="w-5 h-5" />
          </button>
        </div>

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatsCard
              title="Total Samples"
              value={stats.total_samples}
              icon={<FileCode className="w-6 h-6 text-white" />}
              color="bg-cyan-500/20"
            />
            <StatsCard
              title="Packed Samples"
              value={stats.packed_samples}
              icon={<Package className="w-6 h-6 text-white" />}
              color="bg-orange-500/20"
            />
            <StatsCard
              title="PE Files"
              value={stats.pe_samples}
              icon={<Shield className="w-6 h-6 text-white" />}
              color="bg-blue-500/20"
            />
            <StatsCard
              title="ELF Files"
              value={stats.elf_samples}
              icon={<Lock className="w-6 h-6 text-white" />}
              color="bg-purple-500/20"
            />
          </div>
        )}

        {/* Upload Zone */}
        <UploadZone
          onUpload={(file) => uploadMutation.mutate(file)}
          isUploading={uploadMutation.isPending}
        />

        {/* Samples List */}
        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between p-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Samples</h2>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setViewMode('list')}
                className={`p-2 rounded ${viewMode === 'list' ? 'bg-gray-700 text-white' : 'text-gray-400'}`}
              >
                <List className="w-4 h-4" />
              </button>
              <button
                onClick={() => setViewMode('grid')}
                className={`p-2 rounded ${viewMode === 'grid' ? 'bg-gray-700 text-white' : 'text-gray-400'}`}
              >
                <Grid className="w-4 h-4" />
              </button>
            </div>
          </div>

          {samplesLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="w-8 h-8 text-cyan-500 animate-spin" />
            </div>
          ) : samples && samples.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-gray-700">
                    <th className="px-4 py-3">File</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Size</th>
                    <th className="px-4 py-3">Entropy</th>
                    <th className="px-4 py-3">Packer</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {samples.map((sample) => (
                    <SampleRow
                      key={sample.id}
                      sample={sample}
                      onSelect={() => setSelectedSample(sample.id)}
                      onDelete={() => deleteMutation.mutate(sample.id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <FileCode className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No samples uploaded yet</p>
              <p className="text-sm mt-1">Upload a binary file to get started</p>
            </div>
          )}
        </div>

        {/* Detail Modal */}
        {selectedSample && (
          <SampleDetailModal
            sampleId={selectedSample}
            onClose={() => setSelectedSample(null)}
          />
        )}
      </div>
    </Layout>
  );
};

export default BinaryAnalysisPage;
