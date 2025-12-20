import React, { useState, useEffect, useRef } from 'react';
import { Tag, Plus, X, ChevronDown } from 'lucide-react';
import { scanTagAPI } from '../../services/api';
import type { ScanTag, TagSuggestion } from '../../types';

interface TagInputProps {
  selectedTagIds: string[];
  onChange: (tagIds: string[]) => void;
  existingTags: ScanTag[];
  onTagsChange?: (tags: ScanTag[]) => void;
}

const TagInput: React.FC<TagInputProps> = ({
  selectedTagIds,
  onChange,
  existingTags,
  onTagsChange,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [suggestions, setSuggestions] = useState<TagSuggestion[]>([]);
  const [showNewTagForm, setShowNewTagForm] = useState(false);
  const [newTagName, setNewTagName] = useState('');
  const [newTagColor, setNewTagColor] = useState('#06b6d4');
  const [creating, setCreating] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const tagColors = [
    '#06b6d4', // cyan
    '#8b5cf6', // violet
    '#f59e0b', // amber
    '#10b981', // emerald
    '#ef4444', // red
    '#ec4899', // pink
    '#3b82f6', // blue
    '#84cc16', // lime
  ];

  useEffect(() => {
    loadSuggestions();
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setShowNewTagForm(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const loadSuggestions = async () => {
    try {
      const response = await scanTagAPI.getSuggestions();
      setSuggestions(response.data);
    } catch (error) {
      console.error('Failed to load tag suggestions:', error);
    }
  };

  const selectedTags = existingTags.filter((t) => selectedTagIds.includes(t.id));

  const filteredExistingTags = existingTags.filter(
    (tag) =>
      !selectedTagIds.includes(tag.id) &&
      tag.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Group suggestions by category
  const groupedSuggestions = suggestions.reduce(
    (acc, suggestion) => {
      if (!acc[suggestion.category]) {
        acc[suggestion.category] = [];
      }
      // Only show suggestions that don't already exist as tags
      const alreadyExists = existingTags.some(
        (t) => t.name.toLowerCase() === suggestion.name.toLowerCase()
      );
      if (
        !alreadyExists &&
        suggestion.name.toLowerCase().includes(searchTerm.toLowerCase())
      ) {
        acc[suggestion.category].push(suggestion);
      }
      return acc;
    },
    {} as Record<string, TagSuggestion[]>
  );

  const toggleTag = (tagId: string) => {
    if (selectedTagIds.includes(tagId)) {
      onChange(selectedTagIds.filter((id) => id !== tagId));
    } else {
      onChange([...selectedTagIds, tagId]);
    }
  };

  const createTagFromSuggestion = async (suggestion: TagSuggestion) => {
    setCreating(true);
    try {
      const response = await scanTagAPI.create({
        name: suggestion.name,
        color: suggestion.color,
      });
      const newTag = response.data;
      if (onTagsChange) {
        onTagsChange([...existingTags, newTag]);
      }
      onChange([...selectedTagIds, newTag.id]);
      setSearchTerm('');
    } catch (error) {
      console.error('Failed to create tag:', error);
    } finally {
      setCreating(false);
    }
  };

  const createNewTag = async () => {
    if (!newTagName.trim()) return;
    setCreating(true);
    try {
      const response = await scanTagAPI.create({
        name: newTagName.trim(),
        color: newTagColor,
      });
      const newTag = response.data;
      if (onTagsChange) {
        onTagsChange([...existingTags, newTag]);
      }
      onChange([...selectedTagIds, newTag.id]);
      setNewTagName('');
      setShowNewTagForm(false);
    } catch (error) {
      console.error('Failed to create tag:', error);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <label className="block text-sm font-medium text-slate-300 mb-2">
        <div className="flex items-center gap-2">
          <Tag className="h-4 w-4 text-primary" />
          Tags (Optional)
        </div>
      </label>

      {/* Selected Tags Display */}
      <div
        className="min-h-[42px] px-3 py-2 bg-dark-surface border border-dark-border rounded-lg cursor-pointer flex flex-wrap gap-2 items-center"
        onClick={() => setIsOpen(!isOpen)}
      >
        {selectedTags.length > 0 ? (
          <>
            {selectedTags.map((tag) => (
              <span
                key={tag.id}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-sm"
                style={{ backgroundColor: tag.color + '20', color: tag.color }}
              >
                {tag.name}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleTag(tag.id);
                  }}
                  className="hover:opacity-70"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
          </>
        ) : (
          <span className="text-slate-500">Click to add tags...</span>
        )}
        <ChevronDown
          className={`h-4 w-4 text-slate-400 ml-auto transition-transform ${
            isOpen ? 'rotate-180' : ''
          }`}
        />
      </div>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-dark-bg border border-dark-border rounded-lg shadow-xl max-h-80 overflow-y-auto">
          {/* Search Input */}
          <div className="p-2 border-b border-dark-border">
            <input
              type="text"
              placeholder="Search or create tags..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-1.5 bg-dark-surface border border-dark-border rounded text-sm text-white focus:outline-none focus:border-primary"
              autoFocus
            />
          </div>

          <div className="p-2 space-y-3">
            {/* Existing Tags */}
            {filteredExistingTags.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
                  Your Tags
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {filteredExistingTags.map((tag) => (
                    <button
                      key={tag.id}
                      type="button"
                      onClick={() => toggleTag(tag.id)}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-sm transition-opacity hover:opacity-80"
                      style={{
                        backgroundColor: tag.color + '20',
                        color: tag.color,
                      }}
                    >
                      <Plus className="h-3 w-3" />
                      {tag.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Suggestions by Category */}
            {Object.entries(groupedSuggestions).map(
              ([category, categorySuggestions]) =>
                categorySuggestions.length > 0 && (
                  <div key={category}>
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
                      {category}
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {categorySuggestions.map((suggestion) => (
                        <button
                          key={suggestion.name}
                          type="button"
                          onClick={() => createTagFromSuggestion(suggestion)}
                          disabled={creating}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-sm transition-opacity hover:opacity-80 disabled:opacity-50"
                          style={{
                            backgroundColor: suggestion.color + '15',
                            color: suggestion.color,
                            border: `1px dashed ${suggestion.color}40`,
                          }}
                        >
                          <Plus className="h-3 w-3" />
                          {suggestion.name}
                        </button>
                      ))}
                    </div>
                  </div>
                )
            )}

            {/* Create New Tag */}
            {!showNewTagForm ? (
              <button
                type="button"
                onClick={() => {
                  setShowNewTagForm(true);
                  if (searchTerm) {
                    setNewTagName(searchTerm);
                  }
                }}
                className="w-full px-3 py-2 text-sm text-slate-400 border border-dashed border-dark-border rounded hover:border-primary hover:text-primary transition-colors flex items-center justify-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Create new tag{searchTerm ? `: "${searchTerm}"` : ''}
              </button>
            ) : (
              <div className="space-y-2 p-2 bg-dark-surface rounded-lg">
                <input
                  type="text"
                  placeholder="Tag name"
                  value={newTagName}
                  onChange={(e) => setNewTagName(e.target.value)}
                  className="w-full px-3 py-1.5 bg-dark-bg border border-dark-border rounded text-sm text-white focus:outline-none focus:border-primary"
                  autoFocus
                />
                <div className="flex gap-1">
                  {tagColors.map((color) => (
                    <button
                      key={color}
                      type="button"
                      onClick={() => setNewTagColor(color)}
                      className={`w-6 h-6 rounded-full border-2 ${
                        newTagColor === color
                          ? 'border-white'
                          : 'border-transparent'
                      }`}
                      style={{ backgroundColor: color }}
                    />
                  ))}
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={createNewTag}
                    disabled={!newTagName.trim() || creating}
                    className="flex-1 px-3 py-1.5 bg-primary text-white rounded text-sm hover:bg-primary/80 disabled:opacity-50"
                  >
                    Create
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowNewTagForm(false);
                      setNewTagName('');
                    }}
                    className="px-3 py-1.5 bg-dark-bg border border-dark-border text-slate-400 rounded text-sm hover:text-white"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default TagInput;
