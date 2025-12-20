import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { FileText, Download, Settings, X } from 'lucide-react';
import { reportAPI } from '../../services/api';
import type {
  ReportFormat,
  ReportTemplateId,
  ReportTemplate,
  CreateReportRequest,
  ReportOptions,
} from '../../types';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Input from '../ui/Input';
import LoadingSpinner from '../ui/LoadingSpinner';

interface ReportGeneratorProps {
  scanId: string;
  scanName: string;
  onClose: () => void;
  onReportCreated?: () => void;
}

const SECTION_LABELS: Record<string, string> = {
  tableOfContents: 'Table of Contents',
  executiveSummary: 'Executive Summary',
  riskOverview: 'Risk Overview',
  hostInventory: 'Host Inventory',
  portAnalysis: 'Port Analysis',
  vulnerabilityFindings: 'Vulnerability Findings',
  serviceEnumeration: 'Service Enumeration',
  remediationRecommendations: 'Remediation Recommendations',
  appendix: 'Appendix',
};

const ReportGenerator: React.FC<ReportGeneratorProps> = ({
  scanId,
  scanName,
  onClose,
  onReportCreated,
}) => {
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Form state
  const [name, setName] = useState(`${scanName} Report`);
  const [description, setDescription] = useState('');
  const [format, setFormat] = useState<ReportFormat>('pdf');
  const [templateId, setTemplateId] = useState<ReportTemplateId>('technical');
  const [selectedSections, setSelectedSections] = useState<string[]>([]);
  const [options, setOptions] = useState<ReportOptions>({
    include_charts: true,
    company_name: '',
    assessor_name: '',
    classification: 'Confidential',
  });

  useEffect(() => {
    loadTemplates();
  }, []);

  useEffect(() => {
    // When template changes, set default sections
    const template = templates.find((t) => t.id === templateId);
    if (template) {
      setSelectedSections(template.default_sections);
    }
  }, [templateId, templates]);

  const loadTemplates = async () => {
    try {
      const response = await reportAPI.getTemplates();
      setTemplates(response.data);
      // Set initial sections from default template
      const defaultTemplate = response.data.find((t) => t.id === 'technical');
      if (defaultTemplate) {
        setSelectedSections(defaultTemplate.default_sections);
      }
    } catch (error) {
      toast.error('Failed to load report templates');
    } finally {
      setLoading(false);
    }
  };

  const handleSectionToggle = (section: string) => {
    setSelectedSections((prev) =>
      prev.includes(section) ? prev.filter((s) => s !== section) : [...prev, section]
    );
  };

  const handleGenerate = async () => {
    if (!name.trim()) {
      toast.error('Please enter a report name');
      return;
    }

    if (selectedSections.length === 0) {
      toast.error('Please select at least one section');
      return;
    }

    setGenerating(true);
    try {
      const request: CreateReportRequest = {
        scan_id: scanId,
        name: name.trim(),
        description: description.trim() || undefined,
        format,
        template_id: templateId,
        sections: selectedSections,
        options,
      };

      await reportAPI.create(request);
      toast.success('Report generation started');
      onReportCreated?.();
      onClose();
    } catch (error: unknown) {
      const axiosError = error as { response?: { data?: { error?: string } } };
      const message = axiosError.response?.data?.error || 'Failed to create report';
      toast.error(message);
    } finally {
      setGenerating(false);
    }
  };

  const selectedTemplate = templates.find((t) => t.id === templateId);

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <Card className="w-full max-w-2xl mx-4">
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <Card className="w-full max-w-2xl my-8">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <FileText className="h-6 w-6 text-primary" />
            <h2 className="text-xl font-semibold text-white">Generate Report</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-dark-surface rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-slate-400" />
          </button>
        </div>

        <div className="space-y-6">
          {/* Report Name */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Report Name
            </label>
            <Input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter report name"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Description (optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of the report"
              className="w-full bg-dark-surface border border-dark-border rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              rows={2}
            />
          </div>

          {/* Template Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Report Template
            </label>
            <div className="grid grid-cols-3 gap-3">
              {templates.map((template) => (
                <button
                  key={template.id}
                  onClick={() => setTemplateId(template.id as ReportTemplateId)}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    templateId === template.id
                      ? 'border-primary bg-primary/10'
                      : 'border-dark-border hover:border-primary/50'
                  }`}
                >
                  <p className="font-medium text-white">{template.name}</p>
                  <p className="text-xs text-slate-400 mt-1">{template.description}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Format Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Output Format
            </label>
            <div className="flex gap-3">
              {selectedTemplate?.supports_formats.map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setFormat(fmt as ReportFormat)}
                  className={`px-6 py-3 rounded-lg border font-medium transition-all flex items-center gap-2 ${
                    format === fmt
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-dark-border text-slate-400 hover:border-primary/50'
                  }`}
                >
                  <Download className="h-4 w-4" />
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Sections */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Included Sections
            </label>
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(SECTION_LABELS).map(([key, label]) => (
                <label
                  key={key}
                  className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedSections.includes(label)
                      ? 'border-primary bg-primary/10'
                      : 'border-dark-border hover:border-primary/50'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedSections.includes(label)}
                    onChange={() => handleSectionToggle(label)}
                    className="w-4 h-4 rounded border-dark-border text-primary focus:ring-primary"
                  />
                  <span className="text-sm text-white">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Advanced Options Toggle */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors"
          >
            <Settings className="h-4 w-4" />
            {showAdvanced ? 'Hide' : 'Show'} Advanced Options
          </button>

          {/* Advanced Options */}
          {showAdvanced && (
            <div className="space-y-4 p-4 bg-dark-surface rounded-lg border border-dark-border">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Company Name
                  </label>
                  <Input
                    type="text"
                    value={options.company_name || ''}
                    onChange={(e) =>
                      setOptions({ ...options, company_name: e.target.value })
                    }
                    placeholder="Your Company"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Assessor Name
                  </label>
                  <Input
                    type="text"
                    value={options.assessor_name || ''}
                    onChange={(e) =>
                      setOptions({ ...options, assessor_name: e.target.value })
                    }
                    placeholder="Security Analyst"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Classification
                </label>
                <select
                  value={options.classification || ''}
                  onChange={(e) =>
                    setOptions({ ...options, classification: e.target.value })
                  }
                  className="w-full bg-dark-bg border border-dark-border rounded-lg px-4 py-3 text-white focus:ring-2 focus:ring-primary focus:border-transparent"
                >
                  <option value="">None</option>
                  <option value="Public">Public</option>
                  <option value="Internal">Internal</option>
                  <option value="Confidential">Confidential</option>
                  <option value="Restricted">Restricted</option>
                </select>
              </div>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options.include_charts}
                  onChange={(e) =>
                    setOptions({ ...options, include_charts: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-dark-border text-primary focus:ring-primary"
                />
                <span className="text-sm text-white">Include visual charts</span>
              </label>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-dark-border">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={handleGenerate} disabled={generating}>
              {generating ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4 mr-2" />
                  Generate Report
                </>
              )}
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default ReportGenerator;
