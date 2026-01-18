import React, { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import {
  CheckSquare,
  Square,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  FileText,
  Upload,
  Download,
  History,
  Users,
  Calendar,
  AlertCircle,
  CheckCircle,
  XCircle,
  MinusCircle,
  Clock,
  Eye,
  Edit2,
  Save,
  X,
  Paperclip,
  Image,
  File,
  Link2,
  BarChart3,
  Filter,
  RefreshCw,
} from 'lucide-react';
import {
  clientComplianceAPI,
  complianceAPI,
  crmAPI,
  type ClientComplianceChecklist,
  type ClientComplianceItem,
  type ClientComplianceEvidence,
  type CreateClientChecklistRequest,
  type UpdateItemRequest,
} from '../services/api';
import { type ComplianceFramework } from '../types/compliance';
import { type Customer } from '../types/crm';
import Layout from '../components/layout/Layout';

// Status badge component
const StatusBadge: React.FC<{ status: string; type?: 'checklist' | 'item' }> = ({ status, type = 'item' }) => {
  const configs: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
    // Checklist statuses
    not_started: { bg: 'bg-gray-700', text: 'Not Started', icon: <Clock className="w-3 h-3" /> },
    in_progress: { bg: 'bg-blue-900/50 text-blue-400', text: 'In Progress', icon: <RefreshCw className="w-3 h-3" /> },
    under_review: { bg: 'bg-yellow-900/50 text-yellow-400', text: 'Under Review', icon: <Eye className="w-3 h-3" /> },
    completed: { bg: 'bg-green-900/50 text-green-400', text: 'Completed', icon: <CheckCircle className="w-3 h-3" /> },
    archived: { bg: 'bg-gray-800 text-gray-500', text: 'Archived', icon: <FileText className="w-3 h-3" /> },
    // Item statuses
    not_assessed: { bg: 'bg-gray-700', text: 'Not Assessed', icon: <Clock className="w-3 h-3" /> },
    compliant: { bg: 'bg-green-900/50 text-green-400', text: 'Compliant', icon: <CheckCircle className="w-3 h-3" /> },
    non_compliant: { bg: 'bg-red-900/50 text-red-400', text: 'Non-Compliant', icon: <XCircle className="w-3 h-3" /> },
    not_applicable: { bg: 'bg-gray-600', text: 'N/A', icon: <MinusCircle className="w-3 h-3" /> },
  };

  const config = configs[status] || configs.not_assessed;

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${config.bg}`}>
      {config.icon}
      {config.text}
    </span>
  );
};

// Progress bar component
const ProgressBar: React.FC<{ value: number; className?: string }> = ({ value, className }) => (
  <div className={`h-2 bg-gray-700 rounded-full overflow-hidden ${className}`}>
    <div
      className={`h-full rounded-full transition-all ${
        value >= 80 ? 'bg-green-500' : value >= 50 ? 'bg-yellow-500' : value >= 20 ? 'bg-orange-500' : 'bg-red-500'
      }`}
      style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
    />
  </div>
);

// Evidence item component
const EvidenceItem: React.FC<{
  evidence: ClientComplianceEvidence;
  onDelete: (id: string) => void;
  onDownload: (id: string) => void;
}> = ({ evidence, onDelete, onDownload }) => {
  const iconMap: Record<string, React.ReactNode> = {
    image: <Image className="w-4 h-4 text-purple-400" />,
    screenshot: <Image className="w-4 h-4 text-purple-400" />,
    document: <FileText className="w-4 h-4 text-blue-400" />,
    file: <File className="w-4 h-4 text-gray-400" />,
    link: <Link2 className="w-4 h-4 text-cyan-400" />,
    note: <FileText className="w-4 h-4 text-yellow-400" />,
  };

  return (
    <div className="flex items-center justify-between p-2 bg-gray-700 rounded group">
      <div className="flex items-center gap-2 flex-1 min-w-0">
        {iconMap[evidence.evidence_type] || iconMap.file}
        <div className="flex-1 min-w-0">
          <p className="text-sm text-gray-200 truncate">{evidence.title}</p>
          {evidence.file_name && (
            <p className="text-xs text-gray-500 truncate">{evidence.file_name}</p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        {evidence.file_path && (
          <button
            onClick={() => onDownload(evidence.id)}
            className="p-1 text-gray-400 hover:text-cyan-400 rounded"
            title="Download"
          >
            <Download className="w-4 h-4" />
          </button>
        )}
        <button
          onClick={() => onDelete(evidence.id)}
          className="p-1 text-gray-400 hover:text-red-400 rounded"
          title="Delete"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};

// Checklist item row component
const ChecklistItemRow: React.FC<{
  item: ClientComplianceItem;
  onToggleCheck: (id: string, checked: boolean) => void;
  onUpdateStatus: (id: string, status: string) => void;
  onViewDetails: (item: ClientComplianceItem) => void;
  isSelected: boolean;
  onSelect: (id: string, selected: boolean) => void;
}> = ({ item, onToggleCheck, onUpdateStatus, onViewDetails, isSelected, onSelect }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-gray-700 last:border-b-0">
      <div className="flex items-center gap-3 p-3 hover:bg-gray-800/50">
        {/* Bulk select checkbox */}
        <input
          type="checkbox"
          checked={isSelected}
          onChange={(e) => onSelect(item.id, e.target.checked)}
          className="w-4 h-4 rounded border-gray-600 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-800"
        />

        {/* Control checkbox */}
        <button
          onClick={() => onToggleCheck(item.id, !item.is_checked)}
          className="flex-shrink-0"
        >
          {item.is_checked ? (
            <CheckSquare className="w-5 h-5 text-cyan-400" />
          ) : (
            <Square className="w-5 h-5 text-gray-500 hover:text-gray-400" />
          )}
        </button>

        {/* Expand/collapse */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex-shrink-0 text-gray-500 hover:text-gray-400"
        >
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>

        {/* Control info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-500">{item.control_id}</span>
            {item.is_automated && (
              <span className="text-xs px-1.5 py-0.5 bg-purple-900/50 text-purple-400 rounded">
                Automated
              </span>
            )}
            {item.category && (
              <span className="text-xs px-1.5 py-0.5 bg-gray-700 text-gray-400 rounded">
                {item.category}
              </span>
            )}
          </div>
          <p className={`text-sm ${item.is_checked ? 'text-gray-400 line-through' : 'text-gray-200'}`}>
            {item.control_title}
          </p>
        </div>

        {/* Status */}
        <StatusBadge status={item.status} />

        {/* Actions */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => onViewDetails(item)}
            className="p-1.5 text-gray-400 hover:text-cyan-400 rounded hover:bg-gray-700"
            title="View Details"
          >
            <Eye className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="px-12 py-3 bg-gray-800/30 text-sm">
          {item.control_description && (
            <p className="text-gray-400 mb-2">{item.control_description}</p>
          )}
          <div className="flex flex-wrap gap-4 text-xs text-gray-500">
            {item.notes && <span>Notes: {item.notes}</span>}
            {item.findings && <span>Findings: {item.findings.substring(0, 100)}...</span>}
            {item.assigned_to && <span>Assigned: {item.assigned_to}</span>}
            {item.due_date && <span>Due: {new Date(item.due_date).toLocaleDateString()}</span>}
          </div>
        </div>
      )}
    </div>
  );
};

// Create checklist modal
const CreateChecklistModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  customers: Customer[];
  frameworks: ComplianceFramework[];
  onSubmit: (data: CreateClientChecklistRequest) => void;
}> = ({ isOpen, onClose, customers, frameworks, onSubmit }) => {
  const [formData, setFormData] = useState<CreateClientChecklistRequest>({
    customer_id: '',
    framework_id: '',
    name: '',
    description: '',
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg">
        <h3 className="text-lg font-semibold text-gray-100 mb-4">Create Compliance Checklist</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Customer *</label>
            <select
              value={formData.customer_id}
              onChange={(e) => setFormData({ ...formData, customer_id: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
            >
              <option value="">Select Customer</option>
              {customers.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Framework *</label>
            <select
              value={formData.framework_id}
              onChange={(e) => setFormData({ ...formData, framework_id: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
            >
              <option value="">Select Framework</option>
              {frameworks.map((f) => (
                <option key={f.id} value={f.id}>{f.name}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              placeholder="e.g., Q1 2024 PCI DSS Assessment"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              rows={3}
              placeholder="Optional description..."
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-gray-200"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              if (!formData.customer_id || !formData.framework_id || !formData.name) {
                toast.error('Please fill in all required fields');
                return;
              }
              onSubmit(formData);
            }}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded"
          >
            Create Checklist
          </button>
        </div>
      </div>
    </div>
  );
};

// Item detail modal
const ItemDetailModal: React.FC<{
  item: ClientComplianceItem | null;
  checklistId: string;
  onClose: () => void;
  onSave: (id: string, data: UpdateItemRequest) => void;
}> = ({ item, checklistId, onClose, onSave }) => {
  const [formData, setFormData] = useState<UpdateItemRequest>({});
  const [evidenceList, setEvidenceList] = useState<ClientComplianceEvidence[]>([]);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (item && checklistId) {
      setFormData({
        status: item.status,
        notes: item.notes || '',
        findings: item.findings || '',
        remediation_steps: item.remediation_steps || '',
        compensating_controls: item.compensating_controls || '',
      });
      // Load evidence
      clientComplianceAPI.listItemEvidence(checklistId, item.id).then((res: { data: { evidence: ClientComplianceEvidence[] } }) => {
        setEvidenceList(res.data.evidence);
      });
    }
  }, [item, checklistId]);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.length || !item || !checklistId) return;

    setUploading(true);
    const uploadFormData = new FormData();
    uploadFormData.append('file', e.target.files[0]);
    uploadFormData.append('title', e.target.files[0].name);

    try {
      const res = await clientComplianceAPI.uploadEvidence(checklistId, item.id, uploadFormData);
      setEvidenceList([res.data, ...evidenceList]);
      toast.success('Evidence uploaded');
    } catch (err) {
      toast.error('Failed to upload evidence');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteEvidence = async (evidenceId: string) => {
    if (!item || !checklistId) return;
    try {
      await clientComplianceAPI.deleteEvidence(checklistId, item.id, evidenceId);
      setEvidenceList(evidenceList.filter((e) => e.id !== evidenceId));
      toast.success('Evidence deleted');
    } catch (err) {
      toast.error('Failed to delete evidence');
    }
  };

  const handleDownloadEvidence = async (evidenceId: string) => {
    if (!item || !checklistId) return;
    try {
      const res = await clientComplianceAPI.downloadEvidence(checklistId, item.id, evidenceId);
      const evidence = evidenceList.find((e) => e.id === evidenceId);
      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = evidence?.file_name || 'download';
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      toast.error('Failed to download evidence');
    }
  };

  if (!item) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <p className="text-xs font-mono text-gray-500">{item.control_id}</p>
            <h3 className="text-lg font-semibold text-gray-100">{item.control_title}</h3>
          </div>
          <button onClick={onClose} className="p-1 text-gray-400 hover:text-gray-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-4">
          {item.control_description && (
            <p className="text-sm text-gray-400">{item.control_description}</p>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Status</label>
              <select
                value={formData.status || 'not_assessed'}
                onChange={(e) => setFormData({ ...formData, status: e.target.value as any })}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              >
                <option value="not_assessed">Not Assessed</option>
                <option value="in_progress">In Progress</option>
                <option value="compliant">Compliant</option>
                <option value="non_compliant">Non-Compliant</option>
                <option value="not_applicable">Not Applicable</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Notes</label>
            <textarea
              value={formData.notes || ''}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              rows={2}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Findings</label>
            <textarea
              value={formData.findings || ''}
              onChange={(e) => setFormData({ ...formData, findings: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              rows={3}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Remediation Steps</label>
            <textarea
              value={formData.remediation_steps || ''}
              onChange={(e) => setFormData({ ...formData, remediation_steps: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              rows={3}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Compensating Controls</label>
            <textarea
              value={formData.compensating_controls || ''}
              onChange={(e) => setFormData({ ...formData, compensating_controls: e.target.value })}
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200"
              rows={2}
            />
          </div>

          {/* Evidence section */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm text-gray-400">Evidence</label>
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
              >
                <Upload className="w-3 h-3" />
                {uploading ? 'Uploading...' : 'Upload'}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleUpload}
                className="hidden"
              />
            </div>
            <div className="space-y-2 max-h-40 overflow-auto">
              {evidenceList.length === 0 ? (
                <p className="text-xs text-gray-500 text-center py-4">No evidence attached</p>
              ) : (
                evidenceList.map((e) => (
                  <EvidenceItem
                    key={e.id}
                    evidence={e}
                    onDelete={handleDeleteEvidence}
                    onDownload={handleDownloadEvidence}
                  />
                ))
              )}
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-gray-700 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-400 hover:text-gray-200"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(item.id, formData)}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded flex items-center gap-2"
          >
            <Save className="w-4 h-4" />
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
};

// Main page component
const ClientCompliancePage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const customerId = searchParams.get('customer');
  const checklistId = searchParams.get('checklist');

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedItem, setSelectedItem] = useState<ClientComplianceItem | null>(null);
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Fetch customers
  const { data: customersData } = useQuery({
    queryKey: ['customers'],
    queryFn: async () => {
      const res = await crmAPI.customers.getAll();
      return res.data;
    },
  });

  // Fetch frameworks
  const { data: frameworksData } = useQuery({
    queryKey: ['frameworks'],
    queryFn: async () => {
      const res = await complianceAPI.getFrameworks();
      return res.data;
    },
  });

  // Fetch checklists
  const { data: checklistsData, refetch: refetchChecklists } = useQuery({
    queryKey: ['clientChecklists', customerId],
    queryFn: async () => {
      const res = await clientComplianceAPI.listChecklists(customerId ? { customer_id: customerId } : undefined);
      return res.data;
    },
    enabled: !!customerId,
  });

  // Fetch current checklist
  const { data: currentChecklist, refetch: refetchChecklist } = useQuery({
    queryKey: ['clientChecklist', checklistId],
    queryFn: async () => {
      const res = await clientComplianceAPI.getChecklist(checklistId!);
      return res.data;
    },
    enabled: !!checklistId,
  });

  // Fetch checklist items
  const { data: itemsData, refetch: refetchItems } = useQuery({
    queryKey: ['clientChecklistItems', checklistId],
    queryFn: async () => {
      const res = await clientComplianceAPI.listItems(checklistId!);
      return res.data;
    },
    enabled: !!checklistId,
  });

  // Create checklist mutation
  const createChecklistMutation = useMutation({
    mutationFn: clientComplianceAPI.createChecklist,
    onSuccess: async (res) => {
      toast.success('Checklist created');
      setShowCreateModal(false);
      // Populate with framework controls
      await clientComplianceAPI.populateChecklist(res.data.id, res.data.framework_id);
      queryClient.invalidateQueries({ queryKey: ['clientChecklists'] });
      setSearchParams({ customer: res.data.customer_id, checklist: res.data.id });
    },
    onError: () => toast.error('Failed to create checklist'),
  });

  // Update item mutation
  const updateItemMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateItemRequest }) =>
      clientComplianceAPI.updateItem(checklistId!, id, data),
    onSuccess: () => {
      toast.success('Item updated');
      refetchItems();
      refetchChecklist();
      setSelectedItem(null);
    },
    onError: () => toast.error('Failed to update item'),
  });

  // Bulk checkbox mutation
  const bulkCheckboxMutation = useMutation({
    mutationFn: ({ itemIds, isChecked }: { itemIds: string[]; isChecked: boolean }) =>
      clientComplianceAPI.bulkUpdateCheckboxes(checklistId!, { item_ids: itemIds, is_checked: isChecked }),
    onSuccess: () => {
      toast.success('Items updated');
      refetchItems();
      setSelectedItems(new Set());
    },
    onError: () => toast.error('Failed to update items'),
  });

  // Sync scans mutation
  const syncScansMutation = useMutation({
    mutationFn: (checklistId: string) => clientComplianceAPI.syncScans(checklistId),
    onSuccess: (res) => {
      const data = res.data;
      if (data.updated_items > 0) {
        toast.success(`Synced ${data.synced_count} scans, updated ${data.updated_items} controls with ${data.findings_count} findings`);
      } else if (data.synced_count > 0) {
        toast.info(`Analyzed ${data.synced_count} scans but no matching controls found`);
      } else {
        toast.warning('No scans found for this customer');
      }
      refetchItems();
      refetchChecklists();
    },
    onError: () => toast.error('Failed to sync scan results'),
  });

  const handleToggleCheck = (id: string, checked: boolean) => {
    updateItemMutation.mutate({ id, data: { is_checked: checked } });
  };

  const handleUpdateStatus = (id: string, status: string) => {
    updateItemMutation.mutate({ id, data: { status: status as any } });
  };

  const handleSelectItem = (id: string, selected: boolean) => {
    const newSelected = new Set(selectedItems);
    if (selected) {
      newSelected.add(id);
    } else {
      newSelected.delete(id);
    }
    setSelectedItems(newSelected);
  };

  const handleSelectAll = (selected: boolean) => {
    if (selected && itemsData?.items) {
      setSelectedItems(new Set(itemsData.items.map((i) => i.id)));
    } else {
      setSelectedItems(new Set());
    }
  };

  const handleBulkCheck = (isChecked: boolean) => {
    if (selectedItems.size === 0) return;
    bulkCheckboxMutation.mutate({ itemIds: Array.from(selectedItems), isChecked });
  };

  // Get unique categories
  const categories = React.useMemo(() => {
    if (!itemsData?.items) return [];
    return [...new Set(itemsData.items.map((i) => i.category).filter(Boolean))] as string[];
  }, [itemsData]);

  // Filter items
  const filteredItems = React.useMemo(() => {
    if (!itemsData?.items) return [];
    let filtered = itemsData.items;
    if (categoryFilter) {
      filtered = filtered.filter((i) => i.category === categoryFilter);
    }
    if (statusFilter) {
      filtered = filtered.filter((i) => i.status === statusFilter);
    }
    return filtered;
  }, [itemsData, categoryFilter, statusFilter]);

  // Group items by category
  const groupedItems = React.useMemo(() => {
    const groups: Record<string, ClientComplianceItem[]> = {};
    for (const item of filteredItems) {
      const cat = item.category || 'Uncategorized';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(item);
    }
    return groups;
  }, [filteredItems]);

  const customers = customersData || [];
  const frameworks = frameworksData?.frameworks || [];
  const checklists = checklistsData?.checklists || [];

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Client Compliance Checklists</h1>
            <p className="text-slate-400 text-sm">
              Manage compliance assessments with checkboxes and evidence for each client
            </p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Checklist
          </button>
        </div>

        <div className="grid grid-cols-12 gap-6">
          {/* Sidebar - Customer/Checklist selection */}
          <div className="col-span-3">
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Select Customer</h3>
              <select
                value={customerId || ''}
                onChange={(e) => setSearchParams(e.target.value ? { customer: e.target.value } : {})}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-gray-200 mb-4"
              >
                <option value="">All Customers</option>
                {customers.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>

              {customerId && (
                <>
                  <h3 className="text-sm font-semibold text-gray-400 mb-3">Checklists</h3>
                  <div className="space-y-2 max-h-96 overflow-auto">
                    {checklists.length === 0 ? (
                      <p className="text-sm text-gray-500 text-center py-4">No checklists found</p>
                    ) : (
                      checklists.map((cl) => (
                        <button
                          key={cl.id}
                          onClick={() => setSearchParams({ customer: cl.customer_id, checklist: cl.id })}
                          className={`w-full text-left p-3 rounded transition-colors ${
                            checklistId === cl.id
                              ? 'bg-cyan-900/30 border border-cyan-500'
                              : 'bg-gray-700 hover:bg-gray-600'
                          }`}
                        >
                          <p className="text-sm font-medium text-gray-200">{cl.name}</p>
                          <div className="flex items-center justify-between mt-1">
                            <StatusBadge status={cl.status} type="checklist" />
                            <span className="text-xs text-gray-500">
                              {cl.overall_score.toFixed(0)}%
                            </span>
                          </div>
                          <ProgressBar value={cl.overall_score} className="mt-2" />
                        </button>
                      ))
                    )}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Main content - Checklist items */}
          <div className="col-span-9">
            {currentChecklist ? (
              <div className="bg-gray-800 rounded-lg">
                {/* Checklist header */}
                <div className="p-4 border-b border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <h2 className="text-xl font-semibold">{currentChecklist.name}</h2>
                      <p className="text-sm text-gray-400">{currentChecklist.description}</p>
                    </div>
                    <StatusBadge status={currentChecklist.status} type="checklist" />
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-5 gap-4 mt-4">
                    <div className="text-center">
                      <p className="text-2xl font-bold text-cyan-400">{currentChecklist.overall_score.toFixed(0)}%</p>
                      <p className="text-xs text-gray-500">Score</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold">{currentChecklist.total_controls}</p>
                      <p className="text-xs text-gray-500">Total</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-green-400">{currentChecklist.compliant_controls}</p>
                      <p className="text-xs text-gray-500">Compliant</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-red-400">{currentChecklist.non_compliant_controls}</p>
                      <p className="text-xs text-gray-500">Non-Compliant</p>
                    </div>
                    <div className="text-center">
                      <p className="text-2xl font-bold text-gray-400">{currentChecklist.not_applicable_controls}</p>
                      <p className="text-xs text-gray-500">N/A</p>
                    </div>
                  </div>
                  <ProgressBar value={currentChecklist.overall_score} className="mt-4" />
                </div>

                {/* Toolbar */}
                <div className="p-3 border-b border-gray-700 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={selectedItems.size === filteredItems.length && filteredItems.length > 0}
                      onChange={(e) => handleSelectAll(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span className="text-sm text-gray-400">
                      {selectedItems.size > 0 ? `${selectedItems.size} selected` : 'Select all'}
                    </span>

                    {selectedItems.size > 0 && (
                      <div className="flex items-center gap-2 ml-4">
                        <button
                          onClick={() => handleBulkCheck(true)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-green-900/50 text-green-400 rounded hover:bg-green-900/70"
                        >
                          <CheckSquare className="w-3 h-3" />
                          Check All
                        </button>
                        <button
                          onClick={() => handleBulkCheck(false)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600"
                        >
                          <Square className="w-3 h-3" />
                          Uncheck All
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-4">
                    {/* Sync Scans button */}
                    <button
                      onClick={() => checklistId && syncScansMutation.mutate(checklistId)}
                      disabled={syncScansMutation.isPending || !checklistId}
                      className="flex items-center gap-2 px-3 py-1.5 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded text-sm transition-colors"
                      title="Populate checklist with results from automated scans"
                    >
                      <RefreshCw className={`w-4 h-4 ${syncScansMutation.isPending ? 'animate-spin' : ''}`} />
                      {syncScansMutation.isPending ? 'Syncing...' : 'Sync Scans'}
                    </button>

                    <div className="flex items-center gap-2">
                      <Filter className="w-4 h-4 text-gray-500" />
                      <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
                      >
                        <option value="">All Statuses</option>
                        <option value="not_assessed">Not Assessed</option>
                        <option value="in_progress">In Progress</option>
                        <option value="compliant">Compliant</option>
                        <option value="non_compliant">Non-Compliant</option>
                        <option value="not_applicable">Not Applicable</option>
                      </select>
                    </div>
                    <select
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
                    >
                      <option value="">All Categories</option>
                      {categories.map((cat) => (
                        <option key={cat} value={cat}>{cat}</option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Items list */}
                <div className="max-h-[calc(100vh-400px)] overflow-auto">
                  {Object.entries(groupedItems).map(([category, items]) => (
                    <div key={category}>
                      <div className="px-4 py-2 bg-gray-900/50 sticky top-0">
                        <h4 className="text-sm font-medium text-gray-400">{category}</h4>
                      </div>
                      {items.map((item) => (
                        <ChecklistItemRow
                          key={item.id}
                          item={item}
                          onToggleCheck={handleToggleCheck}
                          onUpdateStatus={handleUpdateStatus}
                          onViewDetails={setSelectedItem}
                          isSelected={selectedItems.has(item.id)}
                          onSelect={handleSelectItem}
                        />
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="bg-gray-800 rounded-lg p-12 text-center">
                <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-300 mb-2">No Checklist Selected</h3>
                <p className="text-gray-500 mb-4">
                  Select a customer and checklist from the sidebar, or create a new one.
                </p>
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded"
                >
                  <Plus className="w-4 h-4" />
                  Create Checklist
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Modals */}
      <CreateChecklistModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        customers={customers}
        frameworks={frameworks}
        onSubmit={(data) => createChecklistMutation.mutate(data)}
      />

      <ItemDetailModal
        item={selectedItem}
        checklistId={checklistId || ''}
        onClose={() => setSelectedItem(null)}
        onSave={(id, data) => updateItemMutation.mutate({ id, data })}
      />
    </Layout>
  );
};

export default ClientCompliancePage;
