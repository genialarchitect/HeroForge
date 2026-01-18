import React, { useState, useEffect } from 'react';
import { ChevronDown, Copy, Search, Info } from 'lucide-react';
import { placeholdersApi } from '../../services/legalApi';
import type { PlaceholderInfo } from '../../types/legal';
import { toast } from 'react-toastify';

interface PlaceholderPickerProps {
  onSelect?: (placeholder: string) => void;
  className?: string;
}

// Default placeholders (used if API fails)
const DEFAULT_PLACEHOLDERS: PlaceholderInfo[] = [
  { key: 'CLIENT_NAME', description: 'Customer/company name', source: 'customers.name', example: 'Acme Corporation' },
  { key: 'CLIENT_ADDRESS', description: 'Customer address', source: 'customers.address', example: '123 Business St, City, ST 12345' },
  { key: 'CLIENT_CONTACT_NAME', description: 'Primary contact name', source: 'contacts (primary)', example: 'John Smith' },
  { key: 'CLIENT_CONTACT_EMAIL', description: 'Primary contact email', source: 'contacts.email', example: 'john@acme.com' },
  { key: 'CLIENT_CONTACT_PHONE', description: 'Primary contact phone', source: 'contacts.phone', example: '(555) 123-4567' },
  { key: 'ENGAGEMENT_NAME', description: 'Engagement name', source: 'engagements.name', example: 'Q1 2024 Penetration Test' },
  { key: 'ENGAGEMENT_TYPE', description: 'Type of engagement', source: 'engagements.engagement_type', example: 'External Penetration Test' },
  { key: 'ENGAGEMENT_SCOPE', description: 'Testing scope/targets', source: 'engagements.scope', example: '192.168.1.0/24, *.acme.com' },
  { key: 'START_DATE', description: 'Engagement start date', source: 'engagements.start_date', example: 'January 15, 2024' },
  { key: 'END_DATE', description: 'Engagement end date', source: 'engagements.end_date', example: 'January 31, 2024' },
  { key: 'COMPANY_NAME', description: 'Your company name', source: 'system settings', example: 'HeroForge Security' },
  { key: 'CURRENT_DATE', description: 'Current date', source: 'dynamic', example: 'January 10, 2024' },
];

const PLACEHOLDER_CATEGORIES: { name: string; keys: string[] }[] = [
  { name: 'Client Information', keys: ['CLIENT_NAME', 'CLIENT_ADDRESS', 'CLIENT_CONTACT_NAME', 'CLIENT_CONTACT_EMAIL', 'CLIENT_CONTACT_PHONE'] },
  { name: 'Engagement Details', keys: ['ENGAGEMENT_NAME', 'ENGAGEMENT_TYPE', 'ENGAGEMENT_SCOPE', 'START_DATE', 'END_DATE'] },
  { name: 'Other', keys: ['COMPANY_NAME', 'CURRENT_DATE'] },
];

const PlaceholderPicker: React.FC<PlaceholderPickerProps> = ({ onSelect, className = '' }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [placeholders, setPlaceholders] = useState<PlaceholderInfo[]>(DEFAULT_PLACEHOLDERS);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategory, setExpandedCategory] = useState<string | null>('Client Information');

  useEffect(() => {
    // Try to fetch placeholders from API
    placeholdersApi.list()
      .then((data) => {
        if (data.length > 0) {
          setPlaceholders(data);
        }
      })
      .catch(() => {
        // Use defaults on error
      });
  }, []);

  const filteredPlaceholders = placeholders.filter(
    (p) =>
      p.key.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleCopy = (key: string) => {
    const placeholder = `{{${key}}}`;
    navigator.clipboard.writeText(placeholder);
    toast.success(`Copied ${placeholder} to clipboard`);
    if (onSelect) {
      onSelect(placeholder);
    }
  };

  const getCategoryPlaceholders = (categoryName: string) => {
    const category = PLACEHOLDER_CATEGORIES.find((c) => c.name === categoryName);
    if (!category) return [];
    return filteredPlaceholders.filter((p) => category.keys.includes(p.key));
  };

  return (
    <div className={`relative ${className}`}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-sm text-gray-300 hover:bg-gray-600 transition-colors"
      >
        <span>Insert Placeholder</span>
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />

          {/* Dropdown */}
          <div className="absolute z-50 mt-2 w-96 bg-gray-800 border border-gray-700 rounded-lg shadow-xl">
            {/* Search */}
            <div className="p-3 border-b border-gray-700">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search placeholders..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
            </div>

            {/* Placeholder List */}
            <div className="max-h-80 overflow-y-auto">
              {PLACEHOLDER_CATEGORIES.map((category) => {
                const categoryPlaceholders = getCategoryPlaceholders(category.name);
                if (categoryPlaceholders.length === 0) return null;

                return (
                  <div key={category.name} className="border-b border-gray-700 last:border-b-0">
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedCategory(expandedCategory === category.name ? null : category.name)
                      }
                      className="w-full flex items-center justify-between px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-700/50 transition-colors"
                    >
                      <span>{category.name}</span>
                      <ChevronDown
                        className={`w-4 h-4 transition-transform ${
                          expandedCategory === category.name ? 'rotate-180' : ''
                        }`}
                      />
                    </button>

                    {expandedCategory === category.name && (
                      <div className="pb-2">
                        {categoryPlaceholders.map((placeholder) => (
                          <div
                            key={placeholder.key}
                            className="px-4 py-2 hover:bg-gray-700/50 cursor-pointer group"
                            onClick={() => handleCopy(placeholder.key)}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <code className="px-2 py-0.5 bg-cyan-900/50 text-cyan-400 text-xs rounded font-mono">
                                  {`{{${placeholder.key}}}`}
                                </code>
                                <Copy className="w-3 h-3 text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity" />
                              </div>
                            </div>
                            <p className="text-xs text-gray-400 mt-1">{placeholder.description}</p>
                            <div className="flex items-center gap-1 mt-1">
                              <Info className="w-3 h-3 text-gray-500" />
                              <span className="text-xs text-gray-500">Example: {placeholder.example}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {filteredPlaceholders.length === 0 && (
                <div className="px-4 py-6 text-center text-gray-400 text-sm">
                  No placeholders found matching "{searchQuery}"
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="px-4 py-2 border-t border-gray-700 bg-gray-800/50">
              <p className="text-xs text-gray-500">
                Click a placeholder to copy it to your clipboard
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default PlaceholderPicker;
