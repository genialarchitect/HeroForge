import React from 'react';
import type { MethodologyTemplate } from '../../types';
import { BookOpen, ClipboardList, ExternalLink } from 'lucide-react';

interface TemplateListProps {
  templates: MethodologyTemplate[];
  onSelectTemplate: (template: MethodologyTemplate) => void;
}

const TemplateList: React.FC<TemplateListProps> = ({
  templates,
  onSelectTemplate,
}) => {
  const parseCategories = (categoriesJson: string | null): string[] => {
    if (!categoriesJson) return [];
    try {
      return JSON.parse(categoriesJson);
    } catch {
      return [];
    }
  };

  if (templates.length === 0) {
    return (
      <div className="bg-dark-surface rounded-lg border border-dark-border p-8 text-center">
        <BookOpen className="h-12 w-12 text-slate-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-white mb-2">No Templates Available</h3>
        <p className="text-slate-400">
          Methodology templates will appear here once configured.
        </p>
      </div>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {templates.map((template) => {
        const categories = parseCategories(template.categories);

        return (
          <div
            key={template.id}
            className="bg-dark-surface rounded-lg border border-dark-border p-6 hover:border-primary/50 transition-colors"
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <BookOpen className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    {template.name}
                  </h3>
                  {template.version && (
                    <span className="text-sm text-slate-400">
                      Version {template.version}
                    </span>
                  )}
                </div>
              </div>
              {template.is_system && (
                <span className="px-2 py-1 text-xs bg-blue-500/20 text-blue-400 rounded">
                  System
                </span>
              )}
            </div>

            {template.description && (
              <p className="text-slate-400 text-sm mb-4">{template.description}</p>
            )}

            <div className="flex items-center gap-4 mb-4 text-sm text-slate-400">
              <span className="flex items-center gap-1">
                <ClipboardList className="h-4 w-4" />
                {template.item_count} items
              </span>
              <span className="flex items-center gap-1">
                {categories.length} categories
              </span>
            </div>

            {categories.length > 0 && (
              <div className="mb-4">
                <div className="flex flex-wrap gap-1">
                  {categories.slice(0, 5).map((category, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 text-xs bg-dark-hover text-slate-300 rounded"
                    >
                      {category}
                    </span>
                  ))}
                  {categories.length > 5 && (
                    <span className="px-2 py-0.5 text-xs bg-dark-hover text-slate-400 rounded">
                      +{categories.length - 5} more
                    </span>
                  )}
                </div>
              </div>
            )}

            <button
              onClick={() => onSelectTemplate(template)}
              className="w-full px-4 py-2 bg-primary/10 text-primary rounded-lg hover:bg-primary/20 transition-colors flex items-center justify-center gap-2"
            >
              <ClipboardList className="h-4 w-4" />
              Create Checklist
            </button>
          </div>
        );
      })}
    </div>
  );
};

export default TemplateList;
