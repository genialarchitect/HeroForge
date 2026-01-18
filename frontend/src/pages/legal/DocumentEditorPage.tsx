import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  FileText,
  Save,
  Send,
  Download,
  ArrowLeft,
  Eye,
  Edit,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  RefreshCw,
  Bell,
  Ban,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { documentsApi, templatesApi } from '../../services/legalApi';
import { crmAPI } from '../../services/api';
import type {
  DocumentDetail,
  LegalDocumentTemplate,
  DocumentType,
  DocumentStatus,
  AddSignatureRequest,
} from '../../types/legal';
import { getDocumentTypeLabel, getStatusConfig } from '../../types/legal';
import { DocumentPreview, SignatureBlockConfig, PlaceholderPicker } from '../../components/legal';

interface Engagement {
  id: string;
  name: string;
  customer_id: string;
}

interface Customer {
  id: string;
  name: string;
}

const StatusBadge: React.FC<{ status: DocumentStatus }> = ({ status }) => {
  const config = getStatusConfig(status);
  const icons: Record<DocumentStatus, React.ReactNode> = {
    draft: <FileText className="w-4 h-4" />,
    pending_signature: <Clock className="w-4 h-4" />,
    partially_signed: <AlertCircle className="w-4 h-4" />,
    fully_signed: <CheckCircle className="w-4 h-4" />,
    voided: <XCircle className="w-4 h-4" />,
  };

  return (
    <span className={`flex items-center gap-1.5 text-sm font-medium px-3 py-1 rounded-full ${config.color}`}>
      {icons[status]}
      {config.label}
    </span>
  );
};

const DocumentEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const isNew = !id || id === 'new';

  // State
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [documentDetail, setDocumentDetail] = useState<DocumentDetail | null>(null);
  const [templates, setTemplates] = useState<LegalDocumentTemplate[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [customers, setCustomers] = useState<Customer[]>([]);

  // Form state
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('');
  const [selectedEngagementId, setSelectedEngagementId] = useState<string>('');
  const [documentName, setDocumentName] = useState('');
  const [documentType, setDocumentType] = useState<DocumentType>('roe');
  const [contentHtml, setContentHtml] = useState('');
  const [showPreview, setShowPreview] = useState(false);
  const [voidReason, setVoidReason] = useState('');
  const [showVoidModal, setShowVoidModal] = useState(false);

  // Load initial data
  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      try {
        const [templatesData, engagementsRes, customersRes] = await Promise.all([
          templatesApi.list(),
          crmAPI.engagements.getAll(),
          crmAPI.customers.getAll(),
        ]);
        const engagementsData = engagementsRes.data;
        const customersData = customersRes.data;

        setTemplates(templatesData);
        setEngagements(engagementsData);
        setCustomers(customersData);

        if (!isNew && id) {
          const docDetail = await documentsApi.get(id);
          setDocumentDetail(docDetail);
          setDocumentName(docDetail.document.name);
          setDocumentType(docDetail.document.document_type as DocumentType);
          setContentHtml(docDetail.document.content_html);
          setSelectedEngagementId(docDetail.document.engagement_id);
        } else {
          // Check for template passed via location state
          const templateId = (location.state as { templateId?: string })?.templateId;
          if (templateId) {
            setSelectedTemplateId(templateId);
            const template = templatesData.find((t: LegalDocumentTemplate) => t.id === templateId);
            if (template) {
              setDocumentType(template.document_type as DocumentType);
              setContentHtml(template.content_html);
              setDocumentName(`${template.name} - ${new Date().toLocaleDateString()}`);
            }
          }
        }
      } catch (error) {
        toast.error('Failed to load data');
        console.error(error);
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, [id, isNew, location.state]);

  // Handle template selection
  const handleTemplateChange = (templateId: string) => {
    setSelectedTemplateId(templateId);
    const template = templates.find((t) => t.id === templateId);
    if (template) {
      setDocumentType(template.document_type as DocumentType);
      setContentHtml(template.content_html);
      if (!documentName) {
        setDocumentName(`${template.name} - ${new Date().toLocaleDateString()}`);
      }
    }
  };

  // Get customer name from engagement
  const getCustomerForEngagement = (engagementId: string): Customer | undefined => {
    const engagement = engagements.find((e) => e.id === engagementId);
    if (!engagement) return undefined;
    return customers.find((c) => c.id === engagement.customer_id);
  };

  // Save document
  const handleSave = async () => {
    if (!documentName.trim()) {
      toast.error('Please enter a document name');
      return;
    }

    if (!selectedEngagementId) {
      toast.error('Please select an engagement');
      return;
    }

    const customer = getCustomerForEngagement(selectedEngagementId);
    if (!customer) {
      toast.error('Could not find customer for selected engagement');
      return;
    }

    setIsSaving(true);
    try {
      if (isNew) {
        const newDoc = await documentsApi.create({
          template_id: selectedTemplateId || undefined,
          engagement_id: selectedEngagementId,
          customer_id: customer.id,
          document_type: documentType,
          name: documentName,
          content_html: contentHtml,
        });
        toast.success('Document created');
        navigate(`/legal/documents/${newDoc.id}`);
      } else if (documentDetail) {
        await documentsApi.update(documentDetail.document.id, {
          name: documentName,
          content_html: contentHtml,
        });
        toast.success('Document saved');
        // Refresh data
        const updated = await documentsApi.get(documentDetail.document.id);
        setDocumentDetail(updated);
      }
    } catch (error) {
      toast.error('Failed to save document');
    } finally {
      setIsSaving(false);
    }
  };

  // Add signature
  const handleAddSignature = async (data: AddSignatureRequest) => {
    if (!documentDetail) return;
    try {
      await documentsApi.addSignature(documentDetail.document.id, data);
      const updated = await documentsApi.get(documentDetail.document.id);
      setDocumentDetail(updated);
      toast.success('Signer added');
    } catch (error) {
      toast.error('Failed to add signer');
    }
  };

  // Remove signature
  const handleRemoveSignature = async (signatureId: string) => {
    if (!documentDetail) return;
    try {
      await documentsApi.removeSignature(documentDetail.document.id, signatureId);
      const updated = await documentsApi.get(documentDetail.document.id);
      setDocumentDetail(updated);
      toast.success('Signer removed');
    } catch (error) {
      toast.error('Failed to remove signer');
    }
  };

  // Send for signature
  const handleSendForSignature = async () => {
    if (!documentDetail) return;
    if (documentDetail.signatures.length === 0) {
      toast.error('Please add at least one signer before sending');
      return;
    }
    try {
      await documentsApi.sendForSignature(documentDetail.document.id);
      const updated = await documentsApi.get(documentDetail.document.id);
      setDocumentDetail(updated);
      toast.success('Document sent for signature');
    } catch (error) {
      toast.error('Failed to send document');
    }
  };

  // Send reminder
  const handleSendReminder = async () => {
    if (!documentDetail) return;
    try {
      const result = await documentsApi.sendReminder(documentDetail.document.id);
      toast.success(`Sent ${result.reminders_sent} reminder(s)`);
    } catch (error) {
      toast.error('Failed to send reminders');
    }
  };

  // Download PDF
  const handleDownloadPdf = async () => {
    if (!documentDetail) return;
    try {
      const blob = await documentsApi.downloadPdf(documentDetail.document.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${documentDetail.document.name}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      toast.error('Failed to download PDF');
    }
  };

  // Void document
  const handleVoid = async () => {
    if (!documentDetail || !voidReason.trim()) return;
    try {
      await documentsApi.void(documentDetail.document.id, { reason: voidReason });
      const updated = await documentsApi.get(documentDetail.document.id);
      setDocumentDetail(updated);
      setShowVoidModal(false);
      setVoidReason('');
      toast.success('Document voided');
    } catch (error) {
      toast.error('Failed to void document');
    }
  };

  const isDraft = !documentDetail || documentDetail.document.status === 'draft';
  const canEdit = isDraft;
  const canSend = documentDetail?.document.status === 'draft' && documentDetail.signatures.length > 0;
  const canRemind =
    documentDetail?.document.status === 'pending_signature' ||
    documentDetail?.document.status === 'partially_signed';
  const canVoid =
    documentDetail?.document.status !== 'voided' && documentDetail?.document.status !== 'draft';
  const canDownload = documentDetail?.document.status === 'fully_signed';

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/legal/documents')}
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white">
              {isNew ? 'New Document' : documentDetail?.document.name || 'Document'}
            </h1>
            {!isNew && documentDetail && (
              <div className="flex items-center gap-3 mt-1">
                <span className="text-gray-400 text-sm">{getDocumentTypeLabel(documentDetail.document.document_type)}</span>
                <StatusBadge status={documentDetail.document.status} />
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {canEdit && (
            <button
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
            >
              <Save className="w-4 h-4" />
              {isSaving ? 'Saving...' : 'Save'}
            </button>
          )}

          {canSend && (
            <button
              onClick={handleSendForSignature}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-medium rounded-lg transition-colors"
            >
              <Send className="w-4 h-4" />
              Send for Signature
            </button>
          )}

          {canRemind && (
            <button
              onClick={handleSendReminder}
              className="flex items-center gap-2 px-4 py-2 border border-gray-600 text-gray-300 hover:text-white hover:border-gray-500 rounded-lg transition-colors"
            >
              <Bell className="w-4 h-4" />
              Send Reminder
            </button>
          )}

          {canDownload && (
            <button
              onClick={handleDownloadPdf}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-medium rounded-lg transition-colors"
            >
              <Download className="w-4 h-4" />
              Download PDF
            </button>
          )}

          {canVoid && (
            <button
              onClick={() => setShowVoidModal(true)}
              className="flex items-center gap-2 px-4 py-2 border border-red-600 text-red-400 hover:bg-red-600 hover:text-white rounded-lg transition-colors"
            >
              <Ban className="w-4 h-4" />
              Void
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Document Details */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Document Details</h2>

            <div className="space-y-4">
              {isNew && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Template</label>
                    <select
                      value={selectedTemplateId}
                      onChange={(e) => handleTemplateChange(e.target.value)}
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      <option value="">Select a template (optional)</option>
                      {templates.map((template) => (
                        <option key={template.id} value={template.id}>
                          {template.name} ({getDocumentTypeLabel(template.document_type)})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Engagement</label>
                    <select
                      value={selectedEngagementId}
                      onChange={(e) => setSelectedEngagementId(e.target.value)}
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      required
                    >
                      <option value="">Select an engagement</option>
                      {engagements.map((engagement) => {
                        const customer = customers.find((c) => c.id === engagement.customer_id);
                        return (
                          <option key={engagement.id} value={engagement.id}>
                            {engagement.name} {customer ? `(${customer.name})` : ''}
                          </option>
                        );
                      })}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Document Type</label>
                    <select
                      value={documentType}
                      onChange={(e) => setDocumentType(e.target.value as DocumentType)}
                      className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      <option value="roe">Rules of Engagement</option>
                      <option value="ato">Authorization to Test</option>
                      <option value="nda">Non-Disclosure Agreement</option>
                      <option value="sow">Statement of Work</option>
                      <option value="msa">Master Service Agreement</option>
                    </select>
                  </div>
                </>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Document Name</label>
                <input
                  type="text"
                  value={documentName}
                  onChange={(e) => setDocumentName(e.target.value)}
                  disabled={!canEdit}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50"
                  placeholder="Enter document name"
                />
              </div>
            </div>
          </div>

          {/* Content Editor */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Content</h2>
              <div className="flex items-center gap-2">
                {canEdit && <PlaceholderPicker onSelect={(p) => setContentHtml((prev) => prev + p)} />}
                <button
                  onClick={() => setShowPreview(!showPreview)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
                    showPreview
                      ? 'bg-cyan-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:text-white'
                  }`}
                >
                  {showPreview ? <Edit className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  {showPreview ? 'Edit' : 'Preview'}
                </button>
              </div>
            </div>

            {showPreview ? (
              <DocumentPreview
                contentHtml={contentHtml}
                signatures={documentDetail?.signatures || []}
                showSignatureBlocks={!!documentDetail}
              />
            ) : (
              <textarea
                value={contentHtml}
                onChange={(e) => setContentHtml(e.target.value)}
                disabled={!canEdit}
                className="w-full h-[500px] px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 resize-y"
                placeholder="Enter document HTML content..."
              />
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Signature Configuration */}
          {!isNew && documentDetail && (
            <SignatureBlockConfig
              signatures={documentDetail.signatures}
              onAdd={handleAddSignature}
              onRemove={handleRemoveSignature}
              isEditable={canEdit}
            />
          )}

          {/* History */}
          {!isNew && documentDetail && documentDetail.history.length > 0 && (
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Activity History</h3>
              <div className="space-y-3 max-h-80 overflow-y-auto">
                {documentDetail.history.map((entry) => (
                  <div key={entry.id} className="flex items-start gap-3 text-sm">
                    <div className="w-2 h-2 mt-1.5 rounded-full bg-cyan-500 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-gray-300">{entry.action}</p>
                      {entry.actor_email && (
                        <p className="text-gray-500 text-xs truncate">{entry.actor_email}</p>
                      )}
                      <p className="text-gray-500 text-xs">
                        {new Date(entry.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Void Modal */}
      {showVoidModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
            <h4 className="text-lg font-semibold text-white mb-2">Void Document</h4>
            <p className="text-gray-400 text-sm mb-4">
              This will invalidate the document and prevent any further signatures. This action cannot be undone.
            </p>
            <textarea
              value={voidReason}
              onChange={(e) => setVoidReason(e.target.value)}
              className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none"
              rows={3}
              placeholder="Enter reason for voiding..."
            />
            <div className="flex items-center justify-end gap-3 mt-4">
              <button
                onClick={() => {
                  setShowVoidModal(false);
                  setVoidReason('');
                }}
                className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleVoid}
                disabled={!voidReason.trim()}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                Void Document
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DocumentEditorPage;
