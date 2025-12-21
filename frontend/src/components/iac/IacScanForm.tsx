import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileCode, X, Play, AlertCircle, Loader2 } from 'lucide-react';
import { toast } from 'react-toastify';
import { iacAPI } from '../../services/api';
import Button from '../ui/Button';

interface IacScanFormProps {
  onScanCreated: (scanId: string) => void;
  customerId?: string;
  engagementId?: string;
}

interface UploadedFile {
  file: File;
  name: string;
  size: number;
  platform: string | null;
}

const SUPPORTED_EXTENSIONS = ['.tf', '.tf.json', '.json', '.yaml', '.yml', '.template'];

const detectPlatform = (filename: string, content: string): string | null => {
  const lower = filename.toLowerCase();

  // Terraform
  if (lower.endsWith('.tf') || lower.endsWith('.tf.json')) {
    return 'Terraform';
  }

  // CloudFormation
  if (lower.includes('cloudformation') || lower.endsWith('.template')) {
    return 'CloudFormation';
  }

  // Check content for CloudFormation
  if (content.includes('AWSTemplateFormatVersion') || content.includes('Resources:')) {
    return 'CloudFormation';
  }

  // Azure ARM
  if (lower.includes('azuredeploy') || lower.includes('maintemplate') || lower.endsWith('.arm.json')) {
    return 'Azure ARM';
  }

  // Check content for ARM
  if (content.includes('schema.management.azure.com')) {
    return 'Azure ARM';
  }

  // Check content for Terraform
  if (content.includes('resource "') || content.includes('provider "') || content.includes('variable "')) {
    return 'Terraform';
  }

  return null;
};

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const getPlatformColor = (platform: string | null): string => {
  switch (platform) {
    case 'Terraform':
      return 'bg-purple-500/20 text-purple-400';
    case 'CloudFormation':
      return 'bg-orange-500/20 text-orange-400';
    case 'Azure ARM':
      return 'bg-blue-500/20 text-blue-400';
    default:
      return 'bg-gray-500/20 text-gray-400';
  }
};

export default function IacScanForm({ onScanCreated, customerId, engagementId }: IacScanFormProps) {
  const [scanName, setScanName] = useState('');
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    setError(null);

    const newFiles: UploadedFile[] = [];

    for (const file of acceptedFiles) {
      // Check extension
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();
      const isValid = SUPPORTED_EXTENSIONS.some(supported =>
        file.name.toLowerCase().endsWith(supported)
      );

      if (!isValid) {
        toast.warning(`Skipped ${file.name}: unsupported file type`);
        continue;
      }

      // Read content to detect platform
      const content = await file.text();
      const platform = detectPlatform(file.name, content);

      if (!platform) {
        toast.warning(`Skipped ${file.name}: unable to detect IaC platform`);
        continue;
      }

      newFiles.push({
        file,
        name: file.name,
        size: file.size,
        platform,
      });
    }

    if (newFiles.length > 0) {
      setFiles(prev => [...prev, ...newFiles]);
      toast.success(`Added ${newFiles.length} file(s)`);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.tf', '.tf.json'],
      'application/json': ['.json'],
      'text/yaml': ['.yaml', '.yml'],
      'application/x-yaml': ['.yaml', '.yml'],
    },
    multiple: true,
  });

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (files.length === 0) {
      setError('Please upload at least one IaC file');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('name', scanName || `IaC Scan - ${new Date().toLocaleString()}`);

      if (customerId) {
        formData.append('customer_id', customerId);
      }
      if (engagementId) {
        formData.append('engagement_id', engagementId);
      }

      for (const uploadedFile of files) {
        formData.append('files', uploadedFile.file);
      }

      const response = await iacAPI.createScan(formData);
      toast.success('IaC scan started successfully');
      onScanCreated(response.data.id);
    } catch (err: unknown) {
      console.error('Failed to create IaC scan:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to create scan';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <h3 className="text-lg font-semibold text-white mb-4">Upload IaC Files</h3>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Scan Name */}
        <div>
          <label htmlFor="scan-name" className="block text-sm font-medium text-gray-300 mb-1">
            Scan Name (optional)
          </label>
          <input
            type="text"
            id="scan-name"
            value={scanName}
            onChange={e => setScanName(e.target.value)}
            placeholder="My IaC Security Scan"
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        {/* Dropzone */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
            isDragActive
              ? 'border-cyan-500 bg-cyan-500/10'
              : 'border-gray-600 hover:border-gray-500'
          }`}
        >
          <input {...getInputProps()} />
          <Upload className={`w-12 h-12 mx-auto mb-3 ${isDragActive ? 'text-cyan-400' : 'text-gray-400'}`} />
          <p className="text-gray-300 mb-1">
            {isDragActive ? 'Drop files here...' : 'Drag and drop IaC files here, or click to browse'}
          </p>
          <p className="text-sm text-gray-500">
            Supports: Terraform (.tf), CloudFormation (JSON/YAML), Azure ARM templates
          </p>
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="space-y-2">
            <div className="text-sm font-medium text-gray-300 mb-2">
              {files.length} file(s) ready to scan
            </div>
            {files.map((file, index) => (
              <div
                key={index}
                className="flex items-center justify-between bg-gray-700/50 rounded-lg px-3 py-2"
              >
                <div className="flex items-center gap-3">
                  <FileCode className="w-5 h-5 text-gray-400" />
                  <div>
                    <div className="text-sm text-white">{file.name}</div>
                    <div className="text-xs text-gray-400">{formatFileSize(file.size)}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs px-2 py-0.5 rounded ${getPlatformColor(file.platform)}`}>
                    {file.platform}
                  </span>
                  <button
                    type="button"
                    onClick={() => removeFile(index)}
                    className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}

        {/* Submit Button */}
        <Button
          type="submit"
          disabled={files.length === 0 || isSubmitting}
          className="w-full"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Starting Scan...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              Start IaC Security Scan
            </>
          )}
        </Button>
      </form>
    </div>
  );
}
