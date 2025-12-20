import React, { useState, useEffect } from 'react';
import {
  Zap,
  Settings,
  Shield,
  Globe,
  EyeOff,
  FileText,
  Star,
  Lock,
  Clock,
  ChevronDown,
  ChevronUp,
  Check,
  X,
  Layers,
  PlayCircle
} from 'lucide-react';
import { templateAPI } from '../../services/api';
import { ScanTemplate, TemplateCategory, ScanTemplateConfig } from '../../types';
import { toast } from 'react-toastify';

interface TemplateSelectorProps {
  onSelect: (template: ScanTemplate | null) => void;
  selectedTemplateId?: string | null;
  className?: string;
}

const CATEGORY_CONFIG: Record<TemplateCategory, {
  label: string;
  icon: React.FC<{ className?: string }>;
  color: string;
  description: string;
}> = {
  quick: {
    label: 'Quick',
    icon: Zap,
    color: 'text-yellow-400',
    description: 'Fast, lightweight scans'
  },
  standard: {
    label: 'Standard',
    icon: Settings,
    color: 'text-blue-400',
    description: 'Balanced scanning approach'
  },
  comprehensive: {
    label: 'Comprehensive',
    icon: Shield,
    color: 'text-green-400',
    description: 'Thorough security assessment'
  },
  web: {
    label: 'Web',
    icon: Globe,
    color: 'text-purple-400',
    description: 'Web application focused'
  },
  stealth: {
    label: 'Stealth',
    icon: EyeOff,
    color: 'text-orange-400',
    description: 'Low-profile reconnaissance'
  },
  custom: {
    label: 'Custom',
    icon: FileText,
    color: 'text-slate-400',
    description: 'User-defined templates'
  },
};

const TemplateSelector: React.FC<TemplateSelectorProps> = ({
  onSelect,
  selectedTemplateId,
  className = ''
}) => {
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [systemTemplates, setSystemTemplates] = useState<ScanTemplate[]>([]);
  const [defaultTemplate, setDefaultTemplate] = useState<ScanTemplate | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [previewTemplate, setPreviewTemplate] = useState<ScanTemplate | null>(null);
  const [activeCategory, setActiveCategory] = useState<TemplateCategory | 'all'>('all');

  useEffect(() => {
    loadTemplates();
  }, []);

  const loadTemplates = async () => {
    try {
      setLoading(true);
      const [templatesRes, systemRes, defaultRes] = await Promise.all([
        templateAPI.getAll(),
        templateAPI.getSystem(),
        templateAPI.getDefault().catch(() => ({ data: null })),
      ]);

      setTemplates(templatesRes.data);
      setSystemTemplates(systemRes.data);
      setDefaultTemplate(defaultRes.data);
    } catch (error) {
      console.error('Failed to load templates:', error);
      toast.error('Failed to load scan templates');
    } finally {
      setLoading(false);
    }
  };

  const allTemplates = [...systemTemplates, ...templates];

  const filteredTemplates = activeCategory === 'all'
    ? allTemplates
    : allTemplates.filter(t => t.category === activeCategory);

  const selectedTemplate = allTemplates.find(t => t.id === selectedTemplateId);

  const handleSelectTemplate = (template: ScanTemplate) => {
    onSelect(template);
    setExpanded(false);
    setPreviewTemplate(null);
    toast.success(`Applied "${template.name}" template`);
  };

  const handleStartFromScratch = () => {
    onSelect(null);
    setExpanded(false);
    setPreviewTemplate(null);
  };

  const getCategoryIcon = (category: TemplateCategory) => {
    return CATEGORY_CONFIG[category]?.icon || FileText;
  };

  const getCategoryColor = (category: TemplateCategory) => {
    return CATEGORY_CONFIG[category]?.color || 'text-slate-400';
  };

  const formatDuration = (mins: number | null) => {
    if (!mins) return null;
    if (mins < 60) return `~${mins}m`;
    const hours = Math.floor(mins / 60);
    const remainingMins = mins % 60;
    return remainingMins > 0 ? `~${hours}h ${remainingMins}m` : `~${hours}h`;
  };

  const renderConfigPreview = (config: ScanTemplateConfig) => {
    const features: string[] = [];

    if (config.enable_os_detection) features.push('OS Detection');
    if (config.enable_service_detection) features.push('Service Detection');
    if (config.enable_vuln_scan) features.push('Vulnerability Scan');
    if (config.enable_enumeration) {
      features.push(`Enumeration (${config.enum_depth || 'light'})`);
    }

    return (
      <div className="space-y-2 text-sm">
        <div className="grid grid-cols-2 gap-2">
          <div className="text-slate-400">
            <span className="text-slate-500">Ports:</span> {config.port_range[0]}-{config.port_range[1]}
          </div>
          <div className="text-slate-400">
            <span className="text-slate-500">Threads:</span> {config.threads}
          </div>
          {config.scan_type && (
            <div className="text-slate-400">
              <span className="text-slate-500">Type:</span> {config.scan_type.replace('_', ' ')}
            </div>
          )}
          {config.udp_port_range && (
            <div className="text-slate-400">
              <span className="text-slate-500">UDP:</span> {config.udp_port_range[0]}-{config.udp_port_range[1]}
            </div>
          )}
        </div>
        {features.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {features.map((feature) => (
              <span
                key={feature}
                className="px-2 py-0.5 text-xs bg-dark-surface rounded-full text-slate-400 border border-dark-border"
              >
                {feature}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className={`bg-dark-card border border-dark-border rounded-lg p-4 ${className}`}>
        <div className="animate-pulse flex items-center space-x-3">
          <div className="h-8 w-8 bg-dark-surface rounded-lg"></div>
          <div className="flex-1">
            <div className="h-4 bg-dark-surface rounded w-1/3 mb-2"></div>
            <div className="h-3 bg-dark-surface rounded w-1/2"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`space-y-3 ${className}`}>
      {/* Header with toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Layers className="h-5 w-5 text-primary" />
          <span className="text-sm font-medium text-slate-300">Scan Template</span>
        </div>
        {defaultTemplate && !selectedTemplateId && (
          <button
            type="button"
            onClick={() => handleSelectTemplate(defaultTemplate)}
            className="text-xs text-yellow-400 hover:text-yellow-300 flex items-center gap-1"
          >
            <Star className="h-3 w-3" />
            Use Default
          </button>
        )}
      </div>

      {/* Selected template display / Selector trigger */}
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className={`w-full p-3 rounded-lg border transition-all text-left ${
          expanded
            ? 'bg-primary/10 border-primary'
            : 'bg-dark-card border-dark-border hover:border-slate-500'
        }`}
      >
        {selectedTemplate ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {React.createElement(getCategoryIcon(selectedTemplate.category), {
                className: `h-5 w-5 ${getCategoryColor(selectedTemplate.category)}`
              })}
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-white">{selectedTemplate.name}</span>
                  {selectedTemplate.is_system && (
                    <Lock className="h-3 w-3 text-slate-500" />
                  )}
                  {selectedTemplate.is_default && (
                    <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                  )}
                </div>
                {selectedTemplate.description && (
                  <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">
                    {selectedTemplate.description}
                  </p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {selectedTemplate.estimated_duration_mins && (
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDuration(selectedTemplate.estimated_duration_mins)}
                </span>
              )}
              {expanded ? (
                <ChevronUp className="h-4 w-4 text-slate-400" />
              ) : (
                <ChevronDown className="h-4 w-4 text-slate-400" />
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <PlayCircle className="h-5 w-5 text-slate-500" />
              <div>
                <span className="text-slate-400">Start from scratch</span>
                <p className="text-xs text-slate-500 mt-0.5">
                  Or select a template to pre-configure scan settings
                </p>
              </div>
            </div>
            {expanded ? (
              <ChevronUp className="h-4 w-4 text-slate-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-slate-400" />
            )}
          </div>
        )}
      </button>

      {/* Expanded template selector */}
      {expanded && (
        <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden animate-fadeIn">
          {/* Category tabs */}
          <div className="flex items-center gap-1 p-2 border-b border-dark-border bg-dark-surface overflow-x-auto">
            <button
              type="button"
              onClick={() => setActiveCategory('all')}
              className={`px-3 py-1.5 text-xs rounded-md whitespace-nowrap transition-colors ${
                activeCategory === 'all'
                  ? 'bg-primary text-white'
                  : 'text-slate-400 hover:text-white hover:bg-dark-border'
              }`}
            >
              All
            </button>
            {(Object.keys(CATEGORY_CONFIG) as TemplateCategory[]).map((category) => {
              const config = CATEGORY_CONFIG[category];
              const count = allTemplates.filter(t => t.category === category).length;
              if (count === 0) return null;

              const IconComponent = config.icon;
              return (
                <button
                  key={category}
                  type="button"
                  onClick={() => setActiveCategory(category)}
                  className={`px-3 py-1.5 text-xs rounded-md whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    activeCategory === category
                      ? 'bg-primary text-white'
                      : 'text-slate-400 hover:text-white hover:bg-dark-border'
                  }`}
                >
                  <IconComponent className="h-3 w-3" />
                  {config.label}
                  <span className="text-slate-500">({count})</span>
                </button>
              );
            })}
          </div>

          {/* Template list */}
          <div className="max-h-80 overflow-y-auto">
            {/* Start from scratch option */}
            <button
              type="button"
              onClick={handleStartFromScratch}
              className={`w-full p-3 border-b border-dark-border text-left transition-colors hover:bg-dark-surface flex items-center gap-3 ${
                !selectedTemplateId ? 'bg-dark-surface' : ''
              }`}
            >
              <div className="p-2 rounded-lg bg-dark-surface border border-dark-border">
                <PlayCircle className="h-5 w-5 text-slate-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-white">Start from scratch</span>
                  {!selectedTemplateId && (
                    <Check className="h-4 w-4 text-green-400" />
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Configure all scan settings manually
                </p>
              </div>
            </button>

            {/* Templates */}
            {filteredTemplates.map((template) => {
              const IconComponent = getCategoryIcon(template.category);
              const isSelected = selectedTemplateId === template.id;
              const isPreview = previewTemplate?.id === template.id;

              return (
                <div
                  key={template.id}
                  className={`border-b border-dark-border transition-colors ${
                    isSelected ? 'bg-primary/10' : 'hover:bg-dark-surface'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => handleSelectTemplate(template)}
                    onMouseEnter={() => setPreviewTemplate(template)}
                    onMouseLeave={() => setPreviewTemplate(null)}
                    className="w-full p-3 text-left flex items-start gap-3"
                  >
                    <div className={`p-2 rounded-lg border ${
                      isSelected
                        ? 'bg-primary/20 border-primary'
                        : 'bg-dark-surface border-dark-border'
                    }`}>
                      <IconComponent className={`h-5 w-5 ${getCategoryColor(template.category)}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-white">{template.name}</span>
                        {template.is_system && (
                          <span title="System Template">
                            <Lock className="h-3 w-3 text-slate-500" />
                          </span>
                        )}
                        {template.is_default && (
                          <span title="Default Template">
                            <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                          </span>
                        )}
                        {isSelected && (
                          <Check className="h-4 w-4 text-green-400" />
                        )}
                      </div>
                      {template.description && (
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">
                          {template.description}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500">
                        {template.estimated_duration_mins && (
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDuration(template.estimated_duration_mins)}
                          </span>
                        )}
                        {template.use_count > 0 && (
                          <span>Used {template.use_count} time{template.use_count !== 1 ? 's' : ''}</span>
                        )}
                      </div>
                    </div>
                  </button>

                  {/* Preview panel */}
                  {isPreview && (
                    <div className="px-3 pb-3 animate-fadeIn">
                      <div className="p-3 bg-dark-surface rounded-lg border border-dark-border">
                        <div className="text-xs font-medium text-slate-400 mb-2">Configuration Preview</div>
                        {renderConfigPreview(template.config)}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {filteredTemplates.length === 0 && (
              <div className="p-8 text-center text-slate-500">
                <FileText className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No templates in this category</p>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-2 border-t border-dark-border bg-dark-surface flex items-center justify-between">
            <span className="text-xs text-slate-500">
              {allTemplates.length} template{allTemplates.length !== 1 ? 's' : ''} available
            </span>
            <button
              type="button"
              onClick={() => setExpanded(false)}
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
            >
              <X className="h-3 w-3" />
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default TemplateSelector;
