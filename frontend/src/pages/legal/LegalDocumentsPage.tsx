import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FileText,
  Plus,
  Search,
  Filter,
  Eye,
  Send,
  Download,
  Trash2,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  RefreshCw,
} from 'lucide-react';
import { toast } from 'react-toastify';
import { documentsApi } from '../../services/legalApi';
import type { DocumentListItem, DocumentStats, DocumentStatus } from '../../types/legal';
import { getDocumentTypeLabel, getStatusConfig } from '../../types/legal';

const StatusIcon: React.FC<{ status: DocumentStatus }> = ({ status }) => {
  switch (status) {
    case 'fully_signed':
      return <CheckCircle className="w-4 h-4 text-green-500" />;
    case 'partially_signed':
      return <AlertCircle className="w-4 h-4 text-blue-500" />;
    case 'pending_signature':
      return <Clock className="w-4 h-4 text-yellow-500" />;
    case 'voided':
      return <XCircle className="w-4 h-4 text-red-500" />;
    default:
      return <FileText className="w-4 h-4 text-gray-500" />;
  }
};

const LegalDocumentsPage: React.FC = () => {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState<DocumentListItem[]>([]);
  const [stats, setStats] = useState<DocumentStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<DocumentStatus | 'all'>('all');

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [docsData, statsData] = await Promise.all([
        documentsApi.list(statusFilter === 'all' ? undefined : statusFilter),
        documentsApi.getStats(),
      ]);
      setDocuments(docsData);
      setStats(statsData);
    } catch (error) {
      toast.error('Failed to load documents');
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [statusFilter]);

  const filteredDocuments = documents.filter(
    (doc) =>
      doc.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      doc.customer_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      doc.engagement_name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSendForSignature = async (docId: string) => {
    try {
      await documentsApi.sendForSignature(docId);
      toast.success('Document sent for signature');
      fetchData();
    } catch (error) {
      toast.error('Failed to send document');
    }
  };

  const handleDownloadPdf = async (docId: string, docName: string) => {
    try {
      const blob = await documentsApi.downloadPdf(docId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${docName}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      toast.error('Failed to download PDF');
    }
  };

  const handleDelete = async (docId: string) => {
    if (!confirm('Are you sure you want to delete this document?')) return;
    try {
      await documentsApi.delete(docId);
      toast.success('Document deleted');
      fetchData();
    } catch (error) {
      toast.error('Failed to delete document');
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Legal Documents</h1>
          <p className="text-gray-400 mt-1">Manage pre-engagement documents and signatures</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/legal/templates')}
            className="px-4 py-2 text-gray-300 hover:text-white border border-gray-600 hover:border-gray-500 rounded-lg transition-colors"
          >
            <FileText className="w-4 h-4 inline mr-2" />
            Templates
          </button>
          <button
            onClick={() => navigate('/legal/documents/new')}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Document
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer transition-colors ${
              statusFilter === 'draft' ? 'ring-2 ring-cyan-500' : 'hover:border-gray-600'
            }`}
            onClick={() => setStatusFilter(statusFilter === 'draft' ? 'all' : 'draft')}
          >
            <div className="flex items-center gap-2 text-gray-400 mb-1">
              <FileText className="w-4 h-4" />
              <span className="text-xs font-medium">Draft</span>
            </div>
            <p className="text-2xl font-bold text-white">{stats.draft}</p>
          </div>

          <div
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer transition-colors ${
              statusFilter === 'pending_signature' ? 'ring-2 ring-cyan-500' : 'hover:border-gray-600'
            }`}
            onClick={() => setStatusFilter(statusFilter === 'pending_signature' ? 'all' : 'pending_signature')}
          >
            <div className="flex items-center gap-2 text-yellow-400 mb-1">
              <Clock className="w-4 h-4" />
              <span className="text-xs font-medium">Pending</span>
            </div>
            <p className="text-2xl font-bold text-white">{stats.pending_signature}</p>
          </div>

          <div
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer transition-colors ${
              statusFilter === 'partially_signed' ? 'ring-2 ring-cyan-500' : 'hover:border-gray-600'
            }`}
            onClick={() => setStatusFilter(statusFilter === 'partially_signed' ? 'all' : 'partially_signed')}
          >
            <div className="flex items-center gap-2 text-blue-400 mb-1">
              <AlertCircle className="w-4 h-4" />
              <span className="text-xs font-medium">Partial</span>
            </div>
            <p className="text-2xl font-bold text-white">{stats.partially_signed}</p>
          </div>

          <div
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer transition-colors ${
              statusFilter === 'fully_signed' ? 'ring-2 ring-cyan-500' : 'hover:border-gray-600'
            }`}
            onClick={() => setStatusFilter(statusFilter === 'fully_signed' ? 'all' : 'fully_signed')}
          >
            <div className="flex items-center gap-2 text-green-400 mb-1">
              <CheckCircle className="w-4 h-4" />
              <span className="text-xs font-medium">Signed</span>
            </div>
            <p className="text-2xl font-bold text-white">{stats.fully_signed}</p>
          </div>

          <div
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer transition-colors ${
              statusFilter === 'voided' ? 'ring-2 ring-cyan-500' : 'hover:border-gray-600'
            }`}
            onClick={() => setStatusFilter(statusFilter === 'voided' ? 'all' : 'voided')}
          >
            <div className="flex items-center gap-2 text-red-400 mb-1">
              <XCircle className="w-4 h-4" />
              <span className="text-xs font-medium">Voided</span>
            </div>
            <p className="text-2xl font-bold text-white">{stats.voided}</p>
          </div>
        </div>
      )}

      {/* Search and Filters */}
      <div className="flex items-center gap-4 mb-6">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search documents..."
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
        </div>

        <button
          onClick={fetchData}
          className="p-2 text-gray-400 hover:text-white border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Documents Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-900/50">
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Document
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Customer
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Signatures
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Updated
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2" />
                  Loading documents...
                </td>
              </tr>
            ) : filteredDocuments.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-gray-400">
                  <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="font-medium">No documents found</p>
                  <p className="text-sm mt-1">Create a new document to get started</p>
                </td>
              </tr>
            ) : (
              filteredDocuments.map((doc) => {
                const statusConfig = getStatusConfig(doc.status);
                return (
                  <tr key={doc.id} className="hover:bg-gray-700/50 transition-colors">
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-white font-medium">{doc.name}</p>
                        <p className="text-gray-400 text-sm">{doc.engagement_name}</p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-gray-300 text-sm">{getDocumentTypeLabel(doc.document_type)}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-gray-300 text-sm">{doc.customer_name}</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <StatusIcon status={doc.status} />
                        <span className={`text-xs font-medium px-2 py-1 rounded ${statusConfig.color}`}>
                          {statusConfig.label}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-gray-300 text-sm">
                        {doc.signed_count}/{doc.signature_count}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-gray-400 text-sm">
                        {new Date(doc.updated_at).toLocaleDateString()}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => navigate(`/legal/documents/${doc.id}`)}
                          className="p-2 text-gray-400 hover:text-white transition-colors"
                          title="View"
                        >
                          <Eye className="w-4 h-4" />
                        </button>

                        {doc.status === 'draft' && doc.signature_count > 0 && (
                          <button
                            onClick={() => handleSendForSignature(doc.id)}
                            className="p-2 text-cyan-400 hover:text-cyan-300 transition-colors"
                            title="Send for Signature"
                          >
                            <Send className="w-4 h-4" />
                          </button>
                        )}

                        {doc.status === 'fully_signed' && (
                          <button
                            onClick={() => handleDownloadPdf(doc.id, doc.name)}
                            className="p-2 text-green-400 hover:text-green-300 transition-colors"
                            title="Download PDF"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        )}

                        {doc.status === 'draft' && (
                          <button
                            onClick={() => handleDelete(doc.id)}
                            className="p-2 text-gray-400 hover:text-red-400 transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default LegalDocumentsPage;
