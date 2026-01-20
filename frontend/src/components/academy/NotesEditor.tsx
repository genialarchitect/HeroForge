import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Save, FileText, Clock } from 'lucide-react';

// Simple debounce implementation
function debounce<T extends (...args: Parameters<T>) => ReturnType<T>>(
  fn: T,
  delay: number
): T & { cancel: () => void } {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  const debouncedFn = ((...args: Parameters<T>) => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(() => {
      fn(...args);
    }, delay);
  }) as T & { cancel: () => void };

  debouncedFn.cancel = () => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  };

  return debouncedFn;
}

interface NotesEditorProps {
  initialContent?: string | null;
  onSave: (content: string) => Promise<void>;
  autoSave?: boolean;
  autoSaveDelay?: number;
}

const NotesEditor: React.FC<NotesEditorProps> = ({
  initialContent = '',
  onSave,
  autoSave = true,
  autoSaveDelay = 2000,
}) => {
  const [content, setContent] = useState(initialContent || '');
  const [isSaving, setIsSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Update content when initialContent changes
  useEffect(() => {
    if (initialContent !== null && initialContent !== undefined) {
      setContent(initialContent);
    }
  }, [initialContent]);

  // Manual save function
  const handleSave = async () => {
    if (!hasUnsavedChanges && lastSaved) return;

    setIsSaving(true);
    try {
      await onSave(content);
      setLastSaved(new Date());
      setHasUnsavedChanges(false);
    } catch (error) {
      console.error('Failed to save notes:', error);
    } finally {
      setIsSaving(false);
    }
  };

  // Debounced auto-save
  const debouncedSave = useCallback(
    debounce(async (newContent: string) => {
      if (!autoSave) return;
      setIsSaving(true);
      try {
        await onSave(newContent);
        setLastSaved(new Date());
        setHasUnsavedChanges(false);
      } catch (error) {
        console.error('Auto-save failed:', error);
      } finally {
        setIsSaving(false);
      }
    }, autoSaveDelay),
    [onSave, autoSave, autoSaveDelay]
  );

  // Handle content change
  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newContent = e.target.value;
    setContent(newContent);
    setHasUnsavedChanges(true);

    if (autoSave) {
      debouncedSave(newContent);
    }
  };

  // Handle keyboard shortcuts
  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Ctrl/Cmd + S to save
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      handleSave();
    }

    // Tab to indent
    if (e.key === 'Tab') {
      e.preventDefault();
      const textarea = textareaRef.current;
      if (!textarea) return;

      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;

      const newContent = content.substring(0, start) + '  ' + content.substring(end);
      setContent(newContent);
      setHasUnsavedChanges(true);

      // Restore cursor position
      setTimeout(() => {
        textarea.selectionStart = textarea.selectionEnd = start + 2;
      }, 0);
    }
  };

  // Format last saved time
  const formatLastSaved = () => {
    if (!lastSaved) return null;

    const now = new Date();
    const diff = Math.floor((now.getTime() - lastSaved.getTime()) / 1000);

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
    return lastSaved.toLocaleTimeString();
  };

  // Auto-resize textarea
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = 'auto';
      textarea.style.height = Math.max(200, textarea.scrollHeight) + 'px';
    }
  }, [content]);

  return (
    <div className="notes-editor bg-gray-800 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
        <div className="flex items-center space-x-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <span className="font-medium text-white">My Notes</span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Save status */}
          {isSaving ? (
            <span className="text-sm text-gray-400 flex items-center">
              <div className="w-3 h-3 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mr-2" />
              Saving...
            </span>
          ) : lastSaved ? (
            <span className="text-sm text-gray-500 flex items-center">
              <Clock className="w-3 h-3 mr-1" />
              Saved {formatLastSaved()}
            </span>
          ) : null}

          {/* Unsaved indicator */}
          {hasUnsavedChanges && !isSaving && (
            <span className="w-2 h-2 bg-yellow-500 rounded-full" title="Unsaved changes" />
          )}

          {/* Manual save button */}
          <button
            onClick={handleSave}
            disabled={isSaving || (!hasUnsavedChanges && lastSaved !== null)}
            className={`flex items-center px-3 py-1.5 rounded text-sm font-medium transition-colors ${
              hasUnsavedChanges
                ? 'bg-cyan-600 hover:bg-cyan-700 text-white'
                : 'bg-gray-700 text-gray-400 cursor-not-allowed'
            }`}
          >
            <Save className="w-4 h-4 mr-1" />
            Save
          </button>
        </div>
      </div>

      {/* Editor */}
      <div className="p-4">
        <textarea
          ref={textareaRef}
          value={content}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder="Take notes on this lesson...

Tips:
• Press Tab to indent
• Press Ctrl+S (Cmd+S) to save manually
• Your notes auto-save after you stop typing"
          className="w-full min-h-[200px] bg-gray-900 border border-gray-700 rounded-lg p-4 text-gray-300 placeholder-gray-600 resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent font-mono text-sm"
        />
      </div>

      {/* Footer with tips */}
      <div className="px-4 py-2 border-t border-gray-700 text-xs text-gray-500">
        <span className="mr-4">
          <kbd className="bg-gray-700 px-1.5 py-0.5 rounded">Ctrl</kbd> +{' '}
          <kbd className="bg-gray-700 px-1.5 py-0.5 rounded">S</kbd> to save
        </span>
        <span>
          <kbd className="bg-gray-700 px-1.5 py-0.5 rounded">Tab</kbd> to indent
        </span>
      </div>
    </div>
  );
};

export default NotesEditor;
