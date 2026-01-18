import React, { useState, useRef, useCallback } from 'react';
import {
  Upload,
  Link as LinkIcon,
  Image,
  FileEdit,
  X,
  AlertCircle,
  CheckCircle,
  Clipboard,
} from 'lucide-react';
import type { AssessmentEvidence } from '../../../types';
import { assessmentEvidenceAPI } from '../../../services/api';
import Button from '../../ui/Button';
import Input from '../../ui/Input';

interface EvidenceUploaderProps {
  assessmentId: string;
  onEvidenceAdded: (evidence: AssessmentEvidence) => void;
}

type TabType = 'file' | 'link' | 'screenshot' | 'note';

interface TabConfig {
  id: TabType;
  label: string;
  icon: React.ReactNode;
}

const TABS: TabConfig[] = [
  { id: 'file', label: 'File Upload', icon: <Upload className="h-4 w-4" /> },
  { id: 'link', label: 'Link', icon: <LinkIcon className="h-4 w-4" /> },
  { id: 'screenshot', label: 'Screenshot', icon: <Image className="h-4 w-4" /> },
  { id: 'note', label: 'Note', icon: <FileEdit className="h-4 w-4" /> },
];

// Allowed file types
const ALLOWED_FILE_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
  'text/csv',
];

const ALLOWED_EXTENSIONS = [
  '.pdf',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.txt',
  '.csv',
];

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const EvidenceUploader: React.FC<EvidenceUploaderProps> = ({
  assessmentId,
  onEvidenceAdded,
}) => {
  const [activeTab, setActiveTab] = useState<TabType>('file');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // File upload state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Link state
  const [linkTitle, setLinkTitle] = useState('');
  const [linkUrl, setLinkUrl] = useState('');
  const [linkDescription, setLinkDescription] = useState('');

  // Screenshot state
  const [screenshotData, setScreenshotData] = useState<string | null>(null);
  const [screenshotTitle, setScreenshotTitle] = useState('');

  // Note state
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');

  // Clear messages after timeout
  const clearMessages = useCallback(() => {
    setTimeout(() => {
      setError(null);
      setSuccess(null);
    }, 5000);
  }, []);

  // Validate file
  const validateFile = (file: File): string | null => {
    if (!ALLOWED_FILE_TYPES.includes(file.type)) {
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (!ext || !ALLOWED_EXTENSIONS.includes(`.${ext}`)) {
        return `File type not allowed. Accepted types: ${ALLOWED_EXTENSIONS.join(', ')}`;
      }
    }
    if (file.size > MAX_FILE_SIZE) {
      return `File size exceeds ${MAX_FILE_SIZE / (1024 * 1024)}MB limit`;
    }
    return null;
  };

  // Handle file selection
  const handleFileSelect = (file: File) => {
    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      clearMessages();
      return;
    }
    setSelectedFile(file);
    setError(null);
  };

  // Handle file input change
  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  // Handle drag events
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  // Handle paste for screenshot
  const handlePaste = useCallback(
    (e: ClipboardEvent) => {
      if (activeTab !== 'screenshot') return;

      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.startsWith('image/')) {
          const file = items[i].getAsFile();
          if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
              setScreenshotData(event.target?.result as string);
            };
            reader.readAsDataURL(file);
          }
          break;
        }
      }
    },
    [activeTab]
  );

  // Set up paste listener
  React.useEffect(() => {
    document.addEventListener('paste', handlePaste);
    return () => {
      document.removeEventListener('paste', handlePaste);
    };
  }, [handlePaste]);

  // Upload file
  const uploadFile = async () => {
    if (!selectedFile) return;

    setIsUploading(true);
    setUploadProgress(0);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('title', selectedFile.name);
      formData.append('evidence_type', 'file');

      // Simulate progress (since axios doesn't support progress tracking easily)
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => Math.min(prev + 10, 90));
      }, 100);

      const response = await assessmentEvidenceAPI.upload(assessmentId, formData);

      clearInterval(progressInterval);
      setUploadProgress(100);

      onEvidenceAdded(response.data);
      setSelectedFile(null);
      setSuccess('File uploaded successfully');
      clearMessages();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to upload file');
      clearMessages();
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  // Add link
  const addLink = async () => {
    if (!linkUrl.trim() || !linkTitle.trim()) {
      setError('Please provide both title and URL');
      clearMessages();
      return;
    }

    // Validate URL
    try {
      new URL(linkUrl);
    } catch {
      setError('Please enter a valid URL');
      clearMessages();
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const response = await assessmentEvidenceAPI.addLink(
        assessmentId,
        linkTitle.trim(),
        linkUrl.trim(),
        linkDescription.trim() || undefined
      );

      onEvidenceAdded(response.data);
      setLinkTitle('');
      setLinkUrl('');
      setLinkDescription('');
      setSuccess('Link added successfully');
      clearMessages();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to add link');
      clearMessages();
    } finally {
      setIsUploading(false);
    }
  };

  // Upload screenshot
  const uploadScreenshot = async () => {
    if (!screenshotData || !screenshotTitle.trim()) {
      setError('Please paste a screenshot and provide a title');
      clearMessages();
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      // Convert base64 to blob
      const response = await fetch(screenshotData);
      const blob = await response.blob();
      const file = new File([blob], `screenshot-${Date.now()}.png`, {
        type: 'image/png',
      });

      const formData = new FormData();
      formData.append('file', file);
      formData.append('title', screenshotTitle.trim());
      formData.append('evidence_type', 'screenshot');

      const uploadResponse = await assessmentEvidenceAPI.upload(assessmentId, formData);

      onEvidenceAdded(uploadResponse.data);
      setScreenshotData(null);
      setScreenshotTitle('');
      setSuccess('Screenshot uploaded successfully');
      clearMessages();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to upload screenshot');
      clearMessages();
    } finally {
      setIsUploading(false);
    }
  };

  // Add note
  const addNote = async () => {
    if (!noteTitle.trim() || !noteContent.trim()) {
      setError('Please provide both title and content for the note');
      clearMessages();
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('title', noteTitle.trim());
      formData.append('content', noteContent.trim());
      formData.append('evidence_type', 'note');

      const response = await assessmentEvidenceAPI.upload(assessmentId, formData);

      onEvidenceAdded(response.data);
      setNoteTitle('');
      setNoteContent('');
      setSuccess('Note added successfully');
      clearMessages();
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to add note');
      clearMessages();
    } finally {
      setIsUploading(false);
    }
  };

  // Format file size
  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Render tab content
  const renderTabContent = () => {
    switch (activeTab) {
      case 'file':
        return (
          <div className="space-y-4">
            {/* Drag and drop zone */}
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer ${
                isDragging
                  ? 'border-primary bg-primary/10'
                  : 'border-dark-border hover:border-primary/50'
              }`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept={ALLOWED_EXTENSIONS.join(',')}
                onChange={handleFileInputChange}
                className="hidden"
              />
              <Upload className="h-10 w-10 text-slate-500 mx-auto mb-3" />
              <p className="text-slate-300 mb-1">
                Drag and drop a file here, or click to browse
              </p>
              <p className="text-sm text-slate-500">
                Accepted types: {ALLOWED_EXTENSIONS.join(', ')}
              </p>
              <p className="text-sm text-slate-500">
                Max size: {MAX_FILE_SIZE / (1024 * 1024)}MB
              </p>
            </div>

            {/* Selected file preview */}
            {selectedFile && (
              <div className="flex items-center justify-between p-3 bg-dark-bg rounded-lg border border-dark-border">
                <div className="flex items-center gap-3 min-w-0">
                  <Upload className="h-5 w-5 text-primary flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm text-white truncate">{selectedFile.name}</p>
                    <p className="text-xs text-slate-500">
                      {formatFileSize(selectedFile.size)}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedFile(null)}
                  className="text-slate-500 hover:text-slate-300 p-1"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}

            {/* Upload progress */}
            {isUploading && uploadProgress > 0 && (
              <div className="w-full bg-dark-border rounded-full h-2">
                <div
                  className="bg-primary h-2 rounded-full transition-all"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            )}

            <Button
              onClick={uploadFile}
              disabled={!selectedFile || isUploading}
              loading={isUploading}
              loadingText="Uploading..."
              className="w-full"
            >
              Upload File
            </Button>
          </div>
        );

      case 'link':
        return (
          <div className="space-y-4">
            <Input
              label="Title"
              placeholder="Enter a descriptive title"
              value={linkTitle}
              onChange={(e) => setLinkTitle(e.target.value)}
              required
            />
            <Input
              label="URL"
              type="url"
              placeholder="https://example.com/document"
              value={linkUrl}
              onChange={(e) => setLinkUrl(e.target.value)}
              required
            />
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">
                Description (optional)
              </label>
              <textarea
                className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 transition-colors focus-ring hover:border-dark-hover focus:border-primary"
                rows={3}
                placeholder="Add a brief description of the link"
                value={linkDescription}
                onChange={(e) => setLinkDescription(e.target.value)}
              />
            </div>
            <Button
              onClick={addLink}
              disabled={!linkUrl.trim() || !linkTitle.trim() || isUploading}
              loading={isUploading}
              loadingText="Adding..."
              className="w-full"
            >
              Add Link
            </Button>
          </div>
        );

      case 'screenshot':
        return (
          <div className="space-y-4">
            <Input
              label="Title"
              placeholder="Enter a title for this screenshot"
              value={screenshotTitle}
              onChange={(e) => setScreenshotTitle(e.target.value)}
              required
            />

            {/* Paste zone */}
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                screenshotData
                  ? 'border-green-500/50 bg-green-500/5'
                  : 'border-dark-border'
              }`}
            >
              {screenshotData ? (
                <div className="relative">
                  <img
                    src={screenshotData}
                    alt="Screenshot preview"
                    className="max-h-48 mx-auto rounded-lg"
                  />
                  <button
                    onClick={() => setScreenshotData(null)}
                    className="absolute top-2 right-2 p-1 bg-dark-bg rounded-full text-slate-400 hover:text-slate-200"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <>
                  <Clipboard className="h-10 w-10 text-slate-500 mx-auto mb-3" />
                  <p className="text-slate-300 mb-1">
                    Paste a screenshot from clipboard
                  </p>
                  <p className="text-sm text-slate-500">
                    Use Ctrl+V (or Cmd+V on Mac) to paste
                  </p>
                </>
              )}
            </div>

            <Button
              onClick={uploadScreenshot}
              disabled={!screenshotData || !screenshotTitle.trim() || isUploading}
              loading={isUploading}
              loadingText="Uploading..."
              className="w-full"
            >
              Upload Screenshot
            </Button>
          </div>
        );

      case 'note':
        return (
          <div className="space-y-4">
            <Input
              label="Title"
              placeholder="Enter a title for this note"
              value={noteTitle}
              onChange={(e) => setNoteTitle(e.target.value)}
              required
            />
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">
                Content <span className="text-red-400">*</span>
              </label>
              <textarea
                className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-lg text-slate-100 placeholder-slate-500 transition-colors focus-ring hover:border-dark-hover focus:border-primary"
                rows={6}
                placeholder="Enter your notes, observations, or documentation..."
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
              />
            </div>
            <Button
              onClick={addNote}
              disabled={!noteTitle.trim() || !noteContent.trim() || isUploading}
              loading={isUploading}
              loadingText="Adding..."
              className="w-full"
            >
              Add Note
            </Button>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
      <h3 className="text-lg font-semibold text-white mb-4">Add Evidence</h3>

      {/* Status messages */}
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-red-400">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {success && (
        <div className="mb-4 p-3 bg-green-500/10 border border-green-500/30 rounded-lg flex items-center gap-2 text-green-400">
          <CheckCircle className="h-4 w-4 flex-shrink-0" />
          <span className="text-sm">{success}</span>
        </div>
      )}

      {/* Tab navigation */}
      <div className="flex flex-wrap gap-1 mb-4 border-b border-dark-border pb-4">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-primary text-white'
                : 'text-slate-400 hover:text-slate-200 hover:bg-dark-hover'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {renderTabContent()}
    </div>
  );
};

export default EvidenceUploader;
