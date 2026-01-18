import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Plus,
  Search,
  Edit,
  Trash2,
  Copy,
  Eye,
  Lock,
  RefreshCw,
  ArrowLeft,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { templatesApi } from '../../services/legalApi';
import type { LegalDocumentTemplate, DocumentType } from '../../types/legal';
import { getDocumentTypeLabel } from '../../types/legal';
import DocumentPreview from '../../components/legal/DocumentPreview';

const DOCUMENT_TYPE_ICONS: Record<string, string> = {
  roe: '📋',
  ato: '🔐',
  nda: '🤫',
  sow: '📝',
  msa: '📄',
};

const LegalTemplatesPage: React.FC = () => {
  const navigate = useNavigate();
  const [templates, setTemplates] = useState<LegalDocumentTemplate[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<DocumentType | 'all'>('all');
  const [previewTemplate, setPreviewTemplate] = useState<LegalDocumentTemplate | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const fetchTemplates = async () => {
    setIsLoading(true);
    try {
      const data = await templatesApi.list();
      setTemplates(data);
    } catch (error) {
      toast.error('Failed to load templates');
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTemplates();
  }, []);

  const filteredTemplates = templates.filter((template) => {
    const matchesSearch =
      template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (template.description?.toLowerCase() || '').includes(searchQuery.toLowerCase());
    const matchesType = selectedType === 'all' || template.document_type === selectedType;
    return matchesSearch && matchesType;
  });

  const systemTemplates = filteredTemplates.filter((t) => t.is_system);
  const customTemplates = filteredTemplates.filter((t) => !t.is_system);

  const handleDuplicate = async (template: LegalDocumentTemplate) => {
    try {
      await templatesApi.create({
        name: `${template.name} (Copy)`,
        document_type: template.document_type as DocumentType,
        description: template.description || undefined,
        content_html: template.content_html,
      });
      toast.success('Template duplicated');
      fetchTemplates();
    } catch (error) {
      toast.error('Failed to duplicate template');
    }
  };

  const handleDelete = async (templateId: string) => {
    try {
      await templatesApi.delete(templateId);
      toast.success('Template deleted');
      setDeleteConfirm(null);
      fetchTemplates();
    } catch (error) {
      toast.error('Failed to delete template');
    }
  };

  const TemplateCard: React.FC<{ template: LegalDocumentTemplate }> = ({ template }) => (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 hover:border-gray-600 transition-colors group">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{DOCUMENT_TYPE_ICONS[template.document_type] || '📄'}</span>
          <div>
            <h3 className="text-white font-medium flex items-center gap-2">
              {template.name}
              {template.is_system && (
                <span className="flex items-center gap-1 text-xs text-gray-500">
                  <Lock className="w-3 h-3" />
                  System
                </span>
              )}
            </h3>
            <p className="text-xs text-cyan-400">{getDocumentTypeLabel(template.document_type)}</p>
          </div>
        </div>
      </div>

      {template.description && (
        <p className="text-gray-400 text-sm mb-4 line-clamp-2">{template.description}</p>
      )}

      <div className="flex items-center justify-between pt-3 border-t border-gray-700">
        <span className="text-xs text-gray-500">
          Updated {new Date(template.updated_at).toLocaleDateString()}
        </span>

        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={() => setPreviewTemplate(template)}
            className="p-2 text-gray-400 hover:text-white transition-colors"
            title="Preview"
          >
            <Eye className="w-4 h-4" />
          </button>

          <button
            onClick={() => handleDuplicate(template)}
            className="p-2 text-gray-400 hover:text-cyan-400 transition-colors"
            title="Duplicate"
          >
            <Copy className="w-4 h-4" />
          </button>

          {!template.is_system && (
            <>
              <button
                onClick={() => navigate(`/legal/templates/${template.id}/edit`)}
                className="p-2 text-gray-400 hover:text-white transition-colors"
                title="Edit"
              >
                <Edit className="w-4 h-4" />
              </button>

              <button
                onClick={() => setDeleteConfirm(template.id)}
                className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                title="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/legal/documents')}
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white">Document Templates</h1>
            <p className="text-gray-400 mt-1">Manage templates for legal documents</p>
          </div>
        </div>
        <button
          onClick={() => navigate('/legal/templates/new')}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Template
        </button>
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4 mb-6">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search templates..."
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value as DocumentType | 'all')}
          className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="all">All Types</option>
          <option value="roe">Rules of Engagement</option>
          <option value="ato">Authorization to Test</option>
          <option value="nda">Non-Disclosure Agreement</option>
          <option value="sow">Statement of Work</option>
          <option value="msa">Master Service Agreement</option>
        </select>

        <button
          onClick={fetchTemplates}
          className="p-2 text-gray-400 hover:text-white border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
        </div>
      ) : (
        <>
          {/* System Templates */}
          {systemTemplates.length > 0 && (
            <div className="mb-8">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Lock className="w-4 h-4 text-gray-500" />
                System Templates
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {systemTemplates.map((template) => (
                  <TemplateCard key={template.id} template={template} />
                ))}
              </div>
            </div>
          )}

          {/* Custom Templates */}
          {customTemplates.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold text-white mb-4">Custom Templates</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {customTemplates.map((template) => (
                  <TemplateCard key={template.id} template={template} />
                ))}
              </div>
            </div>
          )}

          {filteredTemplates.length === 0 && (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-400 font-medium">No templates found</p>
              <p className="text-gray-500 text-sm mt-1">
                {searchQuery || selectedType !== 'all'
                  ? 'Try adjusting your search or filters'
                  : 'Create a new template to get started'}
              </p>
            </div>
          )}
        </>
      )}

      {/* Preview Modal */}
      {previewTemplate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-gray-900 rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <div>
                <h3 className="text-lg font-semibold text-white">{previewTemplate.name}</h3>
                <p className="text-sm text-gray-400">{getDocumentTypeLabel(previewTemplate.document_type)}</p>
              </div>
              <button
                onClick={() => setPreviewTemplate(null)}
                className="p-2 text-gray-400 hover:text-white transition-colors"
              >
                &times;
              </button>
            </div>
            <div className="p-6 overflow-y-auto flex-1">
              <DocumentPreview contentHtml={previewTemplate.content_html} showSignatureBlocks={false} />
            </div>
            <div className="flex items-center justify-end gap-3 p-4 border-t border-gray-700">
              <button
                onClick={() => handleDuplicate(previewTemplate)}
                className="px-4 py-2 text-gray-300 hover:text-white border border-gray-600 rounded-lg transition-colors"
              >
                <Copy className="w-4 h-4 inline mr-2" />
                Duplicate
              </button>
              <button
                onClick={() => {
                  navigate('/legal/documents/new', { state: { templateId: previewTemplate.id } });
                }}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors"
              >
                Use Template
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h4 className="text-lg font-semibold text-white mb-2">Delete Template</h4>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete this template? This action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirm)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default LegalTemplatesPage;
