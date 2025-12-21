import React, { useState, useRef } from 'react';
import { toast } from 'react-toastify';
import { pluginsAPI } from '../../services/pluginsApi';
import Button from '../ui/Button';
import Input from '../ui/Input';
import {
  X,
  Upload,
  Link,
  AlertCircle,
  CheckCircle,
  Loader2,
  FileArchive,
  AlertTriangle,
} from 'lucide-react';

interface InstallPluginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInstalled: () => void;
}

type InstallMode = 'url' | 'file';

const InstallPluginModal: React.FC<InstallPluginModalProps> = ({
  isOpen,
  onClose,
  onInstalled,
}) => {
  const [mode, setMode] = useState<InstallMode>('url');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [enableAfterInstall, setEnableAfterInstall] = useState(true);
  const [isInstalling, setIsInstalling] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<{
    valid: boolean;
    errors: string[];
    warnings: string[];
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const resetForm = () => {
    setUrl('');
    setFile(null);
    setEnableAfterInstall(true);
    setValidationResult(null);
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      setValidationResult(null);
    }
  };

  const handleValidate = async () => {
    if (!file) {
      toast.error('Please select a file to validate');
      return;
    }

    setIsValidating(true);
    try {
      const response = await pluginsAPI.validatePlugin(file);
      setValidationResult(response.data);
      if (response.data.valid) {
        toast.success('Plugin validation passed');
      } else {
        toast.error('Plugin validation failed');
      }
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      toast.error(axiosError.response?.data?.error || 'Failed to validate plugin');
    } finally {
      setIsValidating(false);
    }
  };

  const handleInstall = async () => {
    if (mode === 'url' && !url.trim()) {
      toast.error('Please enter a plugin URL');
      return;
    }
    if (mode === 'file' && !file) {
      toast.error('Please select a plugin file');
      return;
    }

    setIsInstalling(true);
    try {
      if (mode === 'url') {
        await pluginsAPI.installFromUrl({
          url: url.trim(),
          enable: enableAfterInstall,
        });
      } else if (file) {
        await pluginsAPI.uploadPlugin(file, enableAfterInstall);
      }

      toast.success('Plugin installed successfully');
      onInstalled();
      handleClose();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: string | { error?: string } } };
      const errorMsg =
        typeof axiosError.response?.data === 'string'
          ? axiosError.response.data
          : axiosError.response?.data?.error || 'Failed to install plugin';
      toast.error(errorMsg);
    } finally {
      setIsInstalling(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-light-surface dark:bg-dark-surface rounded-lg shadow-xl max-w-lg w-full border border-light-border dark:border-dark-border">
        {/* Header */}
        <div className="p-6 border-b border-light-border dark:border-dark-border">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Upload className="h-5 w-5" />
              Install Plugin
            </h2>
            <button
              onClick={handleClose}
              className="text-slate-400 hover:text-slate-900 dark:hover:text-white"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Mode Toggle */}
          <div className="flex gap-2">
            <button
              onClick={() => {
                setMode('url');
                setValidationResult(null);
              }}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
                mode === 'url'
                  ? 'bg-primary/10 border-primary text-primary'
                  : 'border-light-border dark:border-dark-border text-slate-600 dark:text-slate-400 hover:border-primary/50'
              }`}
            >
              <Link className="h-4 w-4" />
              From URL
            </button>
            <button
              onClick={() => {
                setMode('file');
                setValidationResult(null);
              }}
              className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
                mode === 'file'
                  ? 'bg-primary/10 border-primary text-primary'
                  : 'border-light-border dark:border-dark-border text-slate-600 dark:text-slate-400 hover:border-primary/50'
              }`}
            >
              <FileArchive className="h-4 w-4" />
              Upload File
            </button>
          </div>

          {/* URL Input */}
          {mode === 'url' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Plugin URL
              </label>
              <Input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/plugin.zip"
                disabled={isInstalling}
              />
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Enter the URL of a plugin package (.zip file)
              </p>
            </div>
          )}

          {/* File Upload */}
          {mode === 'file' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                Plugin File
              </label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                onChange={handleFileChange}
                className="hidden"
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-light-border dark:border-dark-border rounded-lg p-6 text-center cursor-pointer hover:border-primary/50 transition-colors"
              >
                {file ? (
                  <div className="flex items-center justify-center gap-2">
                    <FileArchive className="h-8 w-8 text-primary" />
                    <div className="text-left">
                      <p className="font-medium text-slate-900 dark:text-white">{file.name}</p>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        {(file.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                  </div>
                ) : (
                  <div>
                    <Upload className="h-8 w-8 mx-auto text-slate-400 mb-2" />
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      Click to select a plugin file (.zip)
                    </p>
                  </div>
                )}
              </div>

              {file && (
                <div className="mt-2 flex justify-end">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleValidate}
                    disabled={isValidating}
                    className="flex items-center gap-1"
                  >
                    {isValidating ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <CheckCircle className="h-4 w-4" />
                    )}
                    Validate
                  </Button>
                </div>
              )}
            </div>
          )}

          {/* Validation Results */}
          {validationResult && (
            <div
              className={`p-3 rounded-lg border ${
                validationResult.valid
                  ? 'bg-green-500/10 border-green-500/30'
                  : 'bg-red-500/10 border-red-500/30'
              }`}
            >
              <div className="flex items-start gap-2">
                {validationResult.valid ? (
                  <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-red-500 flex-shrink-0" />
                )}
                <div className="flex-1">
                  <p
                    className={`font-medium ${
                      validationResult.valid ? 'text-green-600' : 'text-red-600'
                    }`}
                  >
                    {validationResult.valid ? 'Validation Passed' : 'Validation Failed'}
                  </p>

                  {validationResult.errors.length > 0 && (
                    <ul className="mt-1 text-sm text-red-500 list-disc list-inside">
                      {validationResult.errors.map((error, i) => (
                        <li key={i}>{error}</li>
                      ))}
                    </ul>
                  )}

                  {validationResult.warnings.length > 0 && (
                    <ul className="mt-1 text-sm text-amber-500 list-disc list-inside">
                      {validationResult.warnings.map((warning, i) => (
                        <li key={i} className="flex items-start gap-1">
                          <AlertTriangle className="h-3 w-3 mt-0.5 flex-shrink-0" />
                          {warning}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Enable after install */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enable-after-install"
              checked={enableAfterInstall}
              onChange={(e) => setEnableAfterInstall(e.target.checked)}
              className="rounded border-light-border dark:border-dark-border text-primary focus:ring-primary"
            />
            <label
              htmlFor="enable-after-install"
              className="text-sm text-slate-600 dark:text-slate-400"
            >
              Enable plugin after installation
            </label>
          </div>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-light-border dark:border-dark-border flex justify-end gap-3">
          <Button variant="secondary" onClick={handleClose} disabled={isInstalling}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleInstall}
            disabled={isInstalling || (mode === 'url' ? !url.trim() : !file)}
            className="flex items-center gap-2"
          >
            {isInstalling && <Loader2 className="h-4 w-4 animate-spin" />}
            Install Plugin
          </Button>
        </div>
      </div>
    </div>
  );
};

export default InstallPluginModal;
