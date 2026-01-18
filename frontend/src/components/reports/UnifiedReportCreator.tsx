import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'react-toastify';
import {
  FileText,
  ChevronRight,
  ChevronLeft,
  Check,
  Settings,
  File,
  FileType,
  FileJson,
  Code,
  Target,
  Layout,
  ListChecks,
  Sparkles,
} from 'lucide-react';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import { reportAPI, scanAPI } from '../../services/api';
import {
  REPORT_SECTIONS,
  REPORT_TEMPLATES,
  getDefaultSections,
  getTemplate,
} from './sectionConfig';
import type {
  ReportFormat,
  ReportTemplateId,
  ScanResult,
  ReportTemplate,
} from '../../types';

interface UnifiedReportCreatorProps {
  onReportCreated: () => void;
  initialScanId?: string;
}

type WizardStep = 'scan' | 'template' | 'customize' | 'generate';

const STEPS: { id: WizardStep; label: string; icon: React.ReactNode }[] = [
  { id: 'scan', label: 'Select Scan', icon: <Target className="w-4 h-4" /> },
  { id: 'template', label: 'Choose Template', icon: <Layout className="w-4 h-4" /> },
  { id: 'customize', label: 'Customize', icon: <ListChecks className="w-4 h-4" /> },
  { id: 'generate', label: 'Generate', icon: <Sparkles className="w-4 h-4" /> },
];

const FORMAT_ICONS: Record<string, React.ReactNode> = {
  pdf: <File className="w-4 h-4 text-red-400" />,
  html: <FileType className="w-4 h-4 text-orange-400" />,
  json: <FileJson className="w-4 h-4 text-blue-400" />,
  markdown: <Code className="w-4 h-4 text-slate-400" />,
  csv: <FileText className="w-4 h-4 text-green-400" />,
};

export default function UnifiedReportCreator({
  onReportCreated,
  initialScanId,
}: UnifiedReportCreatorProps) {
  const queryClient = useQueryClient();
  const [currentStep, setCurrentStep] = useState<WizardStep>('scan');

  // Form state
  const [selectedScanId, setSelectedScanId] = useState(initialScanId || '');
  const [templateId, setTemplateId] = useState<ReportTemplateId>('technical');
  const [format, setFormat] = useState<ReportFormat>('pdf');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [useTemplateDefaults, setUseTemplateDefaults] = useState(true);
  const [selectedSections, setSelectedSections] = useState<string[]>([]);
  const [includeBranding, setIncludeBranding] = useState(true);
  const [companyName, setCompanyName] = useState('');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeScreenshots, setIncludeScreenshots] = useState(true);

  // Fetch completed scans
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans-for-report'],
    queryFn: async () => {
      const response = await scanAPI.getAll();
      return response.data;
    },
  });

  // Fetch templates from API (as backup for formats)
  const { data: templatesFromApi } = useQuery({
    queryKey: ['report-templates'],
    queryFn: async () => {
      const response = await reportAPI.getTemplates();
      return response.data as ReportTemplate[];
    },
  });

  // Initialize sections when template changes
  useEffect(() => {
    if (useTemplateDefaults) {
      setSelectedSections(getDefaultSections(templateId));
    }
  }, [templateId, useTemplateDefaults]);

  // Auto-generate report name when scan is selected
  useEffect(() => {
    if (selectedScanId && scansData) {
      const scan = scansData.find((s: ScanResult) => s.id === selectedScanId);
      if (scan) {
        setName(`${scan.name} - Report`);
      }
    }
  }, [selectedScanId, scansData]);

  // Get available formats for current template
  const currentTemplate = getTemplate(templateId);
  const apiTemplate = templatesFromApi?.find((t) => t.id === templateId);
  const availableFormats =
    apiTemplate?.supports_formats || currentTemplate?.supportsFormats || ['pdf', 'html', 'json'];

  // Ensure selected format is valid for template
  useEffect(() => {
    if (!availableFormats.includes(format)) {
      setFormat(availableFormats[0] as ReportFormat);
    }
  }, [availableFormats, format]);

  // Create report mutation
  const createMutation = useMutation({
    mutationFn: (data: {
      scan_id: string;
      name: string;
      description?: string;
      format: ReportFormat;
      template_id: ReportTemplateId;
      sections: string[];
      options?: {
        include_branding?: boolean;
        company_name?: string;
        include_charts?: boolean;
        include_screenshots?: boolean;
      };
    }) => reportAPI.create(data),
    onSuccess: () => {
      toast.success('Report generation started');
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      onReportCreated();
    },
    onError: (err: { response?: { data?: { error?: string } } }) => {
      toast.error(err.response?.data?.error || 'Failed to create report');
    },
  });

  const completedScans = (scansData || []).filter(
    (s: ScanResult) => s.status === 'completed'
  );

  const canProceed = (): boolean => {
    switch (currentStep) {
      case 'scan':
        return !!selectedScanId;
      case 'template':
        return !!templateId && !!format;
      case 'customize':
        return (
          (useTemplateDefaults || selectedSections.length > 0) && name.trim().length > 0
        );
      case 'generate':
        return true;
      default:
        return false;
    }
  };

  const handleNext = () => {
    const stepIndex = STEPS.findIndex((s) => s.id === currentStep);
    if (stepIndex < STEPS.length - 1) {
      setCurrentStep(STEPS[stepIndex + 1].id);
    }
  };

  const handleBack = () => {
    const stepIndex = STEPS.findIndex((s) => s.id === currentStep);
    if (stepIndex > 0) {
      setCurrentStep(STEPS[stepIndex - 1].id);
    }
  };

  const handleGenerate = () => {
    const sectionsToSubmit = useTemplateDefaults
      ? getDefaultSections(templateId)
      : selectedSections;

    createMutation.mutate({
      scan_id: selectedScanId,
      name: name.trim(),
      description: description.trim() || undefined,
      format,
      template_id: templateId,
      sections: sectionsToSubmit,
      options: {
        include_branding: includeBranding,
        company_name: companyName.trim() || undefined,
        include_charts: includeCharts,
        include_screenshots: includeScreenshots,
      },
    });
  };

  const handleSectionToggle = (sectionId: string) => {
    setSelectedSections((prev) =>
      prev.includes(sectionId)
        ? prev.filter((s) => s !== sectionId)
        : [...prev, sectionId]
    );
  };

  const selectedScan = scansData?.find((s: ScanResult) => s.id === selectedScanId);

  const currentStepIndex = STEPS.findIndex((s) => s.id === currentStep);

  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700">
      {/* Progress Steps */}
      <div className="p-4 border-b border-slate-700">
        <div className="flex items-center justify-between">
          {STEPS.map((step, index) => (
            <React.Fragment key={step.id}>
              <button
                onClick={() => {
                  // Only allow going back to previous steps
                  if (index < currentStepIndex) {
                    setCurrentStep(step.id);
                  }
                }}
                disabled={index > currentStepIndex}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
                  currentStep === step.id
                    ? 'bg-cyan-500/20 text-cyan-400'
                    : index < currentStepIndex
                    ? 'text-slate-400 hover:text-white cursor-pointer'
                    : 'text-slate-600 cursor-not-allowed'
                }`}
              >
                <div
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                    index < currentStepIndex
                      ? 'bg-cyan-500 text-white'
                      : currentStep === step.id
                      ? 'bg-cyan-500/30 text-cyan-400 border border-cyan-500'
                      : 'bg-slate-700 text-slate-500'
                  }`}
                >
                  {index < currentStepIndex ? (
                    <Check className="w-3 h-3" />
                  ) : (
                    index + 1
                  )}
                </div>
                <span className="hidden sm:inline text-sm">{step.label}</span>
              </button>
              {index < STEPS.length - 1 && (
                <ChevronRight className="w-4 h-4 text-slate-600" />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Step Content */}
      <div className="p-6">
        {/* Step 1: Select Scan */}
        {currentStep === 'scan' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-medium text-white mb-2">
                Select a Completed Scan
              </h3>
              <p className="text-sm text-slate-400 mb-4">
                Choose a scan to generate a report from. Only completed scans are shown.
              </p>
            </div>

            {scansLoading ? (
              <div className="flex items-center justify-center py-8">
                <LoadingSpinner />
              </div>
            ) : completedScans.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <Target className="w-12 h-12 mx-auto mb-3 text-slate-600" />
                <p>No completed scans available</p>
                <p className="text-sm mt-1">Run a scan first to generate reports</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {completedScans.map((scan: ScanResult) => (
                  <button
                    key={scan.id}
                    onClick={() => setSelectedScanId(scan.id)}
                    className={`w-full p-4 rounded-lg border text-left transition-all ${
                      selectedScanId === scan.id
                        ? 'bg-cyan-500/10 border-cyan-500/50'
                        : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium text-white">{scan.name}</div>
                        <div className="text-sm text-slate-400">
                          {new Date(scan.created_at).toLocaleString()}
                        </div>
                      </div>
                      {selectedScanId === scan.id && (
                        <Check className="w-5 h-5 text-cyan-400" />
                      )}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Step 2: Choose Template */}
        {currentStep === 'template' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-white mb-2">
                Choose Report Template
              </h3>
              <p className="text-sm text-slate-400 mb-4">
                Select a template that matches your audience and requirements.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {REPORT_TEMPLATES.map((template) => (
                <button
                  key={template.id}
                  onClick={() => setTemplateId(template.id as ReportTemplateId)}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    templateId === template.id
                      ? 'bg-cyan-500/10 border-cyan-500/50'
                      : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                  }`}
                >
                  <div className="font-medium text-white mb-1">{template.name}</div>
                  <div className="text-sm text-slate-400">{template.description}</div>
                  <div className="flex gap-1 mt-2">
                    {template.supportsFormats.map((fmt) => (
                      <span
                        key={fmt}
                        className="px-1.5 py-0.5 bg-slate-600 rounded text-xs text-slate-300 uppercase"
                      >
                        {fmt}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Output Format
              </label>
              <div className="flex flex-wrap gap-2">
                {availableFormats.map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setFormat(fmt as ReportFormat)}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${
                      format === fmt
                        ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400'
                        : 'bg-slate-700 border-slate-600 text-slate-300 hover:border-slate-500'
                    }`}
                  >
                    {FORMAT_ICONS[fmt] || <FileText className="w-4 h-4" />}
                    <span className="uppercase">{fmt}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Step 3: Customize */}
        {currentStep === 'customize' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-white mb-2">
                Customize Report
              </h3>
              <p className="text-sm text-slate-400 mb-4">
                Configure the report name, sections, and options.
              </p>
            </div>

            {/* Report Name */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Report Name *
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Security Assessment Report"
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
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
                placeholder="Brief description of the assessment..."
                rows={2}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>

            {/* Template Defaults Checkbox */}
            <div className="p-4 bg-slate-700/50 rounded-lg border border-slate-600">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useTemplateDefaults}
                  onChange={(e) => {
                    setUseTemplateDefaults(e.target.checked);
                    if (e.target.checked) {
                      setSelectedSections(getDefaultSections(templateId));
                    }
                  }}
                  className="w-4 h-4 rounded bg-slate-600 border-slate-500 text-cyan-500 focus:ring-cyan-500"
                />
                <div>
                  <span className="text-white font-medium">
                    Use template defaults
                  </span>
                  <p className="text-sm text-slate-400">
                    Include all sections recommended for the {templateId} template
                  </p>
                </div>
              </label>
            </div>

            {/* Section Selection (when not using defaults) */}
            {!useTemplateDefaults && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Select Sections
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {REPORT_SECTIONS.map((section) => (
                    <label
                      key={section.id}
                      className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                        selectedSections.includes(section.id)
                          ? 'bg-cyan-500/10 border-cyan-500/50'
                          : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedSections.includes(section.id)}
                        onChange={() => handleSectionToggle(section.id)}
                        className="w-4 h-4 rounded bg-slate-600 border-slate-500 text-cyan-500 focus:ring-cyan-500"
                      />
                      <div>
                        <span className="text-sm text-white">{section.label}</span>
                        {section.description && (
                          <p className="text-xs text-slate-500">
                            {section.description}
                          </p>
                        )}
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Advanced Options */}
            <details className="group">
              <summary className="flex items-center gap-2 cursor-pointer text-sm text-slate-400 hover:text-white">
                <Settings className="w-4 h-4" />
                Advanced Options
                <ChevronRight className="w-4 h-4 transition-transform group-open:rotate-90" />
              </summary>
              <div className="mt-4 space-y-4 p-4 bg-slate-700/30 rounded-lg">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={includeBranding}
                    onChange={(e) => setIncludeBranding(e.target.checked)}
                    className="w-4 h-4 rounded bg-slate-600 border-slate-500 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-slate-300">Include company branding</span>
                </label>

                {includeBranding && (
                  <input
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    placeholder="Company name for branding"
                    className="w-full bg-slate-700 border border-slate-600 rounded-lg px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                )}

                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={includeCharts}
                    onChange={(e) => setIncludeCharts(e.target.checked)}
                    className="w-4 h-4 rounded bg-slate-600 border-slate-500 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-slate-300">Include charts and visualizations</span>
                </label>

                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={includeScreenshots}
                    onChange={(e) => setIncludeScreenshots(e.target.checked)}
                    className="w-4 h-4 rounded bg-slate-600 border-slate-500 text-cyan-500 focus:ring-cyan-500"
                  />
                  <span className="text-sm text-slate-300">Include screenshots</span>
                </label>
              </div>
            </details>
          </div>
        )}

        {/* Step 4: Generate (Summary) */}
        {currentStep === 'generate' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-medium text-white mb-2">
                Review & Generate
              </h3>
              <p className="text-sm text-slate-400 mb-4">
                Review your settings and generate the report.
              </p>
            </div>

            <div className="bg-slate-700/50 rounded-lg p-4 space-y-3">
              <div className="flex justify-between">
                <span className="text-slate-400">Scan:</span>
                <span className="text-white font-medium">{selectedScan?.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Report Name:</span>
                <span className="text-white font-medium">{name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Template:</span>
                <span className="text-white font-medium capitalize">{templateId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Format:</span>
                <span className="text-white font-medium uppercase">{format}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Sections:</span>
                <span className="text-white font-medium">
                  {useTemplateDefaults
                    ? `${getDefaultSections(templateId).length} (template defaults)`
                    : `${selectedSections.length} selected`}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 p-4 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              <p className="text-sm text-cyan-300">
                Report generation typically takes a few moments. You&apos;ll be notified
                when it&apos;s ready.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Footer Navigation */}
      <div className="p-4 border-t border-slate-700 flex items-center justify-between">
        <div>
          {currentStep !== 'scan' && (
            <Button variant="secondary" onClick={handleBack}>
              <ChevronLeft className="w-4 h-4 mr-2" />
              Back
            </Button>
          )}
        </div>

        <div>
          {currentStep !== 'generate' ? (
            <Button onClick={handleNext} disabled={!canProceed()}>
              Next
              <ChevronRight className="w-4 h-4 ml-2" />
            </Button>
          ) : (
            <Button onClick={handleGenerate} disabled={createMutation.isPending}>
              {createMutation.isPending ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4 mr-2" />
                  Generate Report
                </>
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
