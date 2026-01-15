import React, { useState, useEffect, useRef, useCallback } from 'react';
import { toast } from 'react-toastify';
import Layout from '../components/layout/Layout';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import {
  Shield,
  Upload,
  Download,
  Printer,
  FileJson,
  FileSpreadsheet,
  CheckCircle,
  XCircle,
  AlertTriangle,
  MinusCircle,
  HelpCircle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  FileText,
  Calendar,
  User,
  Building,
  Target,
  GripVertical,
  Bot,
  MessageSquare,
  Edit3,
  Save,
  X,
} from 'lucide-react';
import api from '../services/api';

// ============================================================================
// Types for ATO Map
// ============================================================================

type ControlStatus =
  | 'Compliant'
  | 'NonCompliant'
  | 'PartiallyCompliant'
  | 'NotApplicable'
  | 'NotAssessed'
  | 'ManualOverride';

interface AtoControl {
  id: string;
  controlId: string;
  title: string;
  status: ControlStatus;
  evidenceCount: number;
  poamId?: string;
  lastAssessed?: string;
  assessor?: string;
  notes?: string;
  children?: AtoControl[]; // Nested child controls (e.g., AC-1(1), AC-1(2))
  parentId?: string;
}

interface AtoControlFamily {
  id: string;
  name: string;
  abbreviation: string;
  controls: AtoControl[];
  compliantCount: number;
  nonCompliantCount: number;
  partialCount: number;
  notAssessedCount: number;
  notApplicableCount: number;
  order?: number; // For drag-and-drop ordering
}

interface AtoMapData {
  systemName: string;
  systemId?: string;
  organization?: string;
  authorizingOfficial?: string;
  assessmentDate?: string;
  targetAtoDate?: string;
  baseline: 'Low' | 'Moderate' | 'High';
  framework: string;
  controlFamilies: AtoControlFamily[];
  overallScore: number;
  poamCount: number;
}

interface ImportData {
  systemName?: string;
  organization?: string;
  baseline?: string;
  controls: Array<{
    controlId: string;
    status: string;
    evidenceCount?: number;
    poamId?: string;
    notes?: string;
    parentId?: string;
  }>;
}

// Zeus action types for AI integration (matches backend format)
interface ZeusAction {
  type: 'update_status' | 'bulk_update' | 'focus_family' | 'highlight_status' | 'export';
  controlId?: string;
  familyId?: string;
  newStatus?: string;
  targetStatus?: string;
  notes?: string;
}

// ============================================================================
// NIST 800-53 Control Families
// ============================================================================

const NIST_CONTROL_FAMILIES = [
  { id: 'AC', name: 'Access Control', abbreviation: 'AC' },
  { id: 'AT', name: 'Awareness and Training', abbreviation: 'AT' },
  { id: 'AU', name: 'Audit and Accountability', abbreviation: 'AU' },
  { id: 'CA', name: 'Assessment, Authorization, and Monitoring', abbreviation: 'CA' },
  { id: 'CM', name: 'Configuration Management', abbreviation: 'CM' },
  { id: 'CP', name: 'Contingency Planning', abbreviation: 'CP' },
  { id: 'IA', name: 'Identification and Authentication', abbreviation: 'IA' },
  { id: 'IR', name: 'Incident Response', abbreviation: 'IR' },
  { id: 'MA', name: 'Maintenance', abbreviation: 'MA' },
  { id: 'MP', name: 'Media Protection', abbreviation: 'MP' },
  { id: 'PE', name: 'Physical and Environmental Protection', abbreviation: 'PE' },
  { id: 'PL', name: 'Planning', abbreviation: 'PL' },
  { id: 'PM', name: 'Program Management', abbreviation: 'PM' },
  { id: 'PS', name: 'Personnel Security', abbreviation: 'PS' },
  { id: 'PT', name: 'PII Processing and Transparency', abbreviation: 'PT' },
  { id: 'RA', name: 'Risk Assessment', abbreviation: 'RA' },
  { id: 'SA', name: 'System and Services Acquisition', abbreviation: 'SA' },
  { id: 'SC', name: 'System and Communications Protection', abbreviation: 'SC' },
  { id: 'SI', name: 'System and Information Integrity', abbreviation: 'SI' },
  { id: 'SR', name: 'Supply Chain Risk Management', abbreviation: 'SR' },
];

// ============================================================================
// Helper Functions
// ============================================================================

const getStatusColor = (status: ControlStatus): string => {
  switch (status) {
    case 'Compliant':
      return 'bg-green-500';
    case 'NonCompliant':
      return 'bg-red-500';
    case 'PartiallyCompliant':
      return 'bg-yellow-500';
    case 'NotApplicable':
      return 'bg-gray-500';
    case 'NotAssessed':
      return 'bg-blue-500';
    case 'ManualOverride':
      return 'bg-purple-500';
    default:
      return 'bg-gray-400';
  }
};

const getStatusIcon = (status: ControlStatus) => {
  switch (status) {
    case 'Compliant':
      return <CheckCircle className="w-4 h-4 text-green-400" />;
    case 'NonCompliant':
      return <XCircle className="w-4 h-4 text-red-400" />;
    case 'PartiallyCompliant':
      return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
    case 'NotApplicable':
      return <MinusCircle className="w-4 h-4 text-gray-400" />;
    case 'NotAssessed':
      return <HelpCircle className="w-4 h-4 text-blue-400" />;
    case 'ManualOverride':
      return <RefreshCw className="w-4 h-4 text-purple-400" />;
    default:
      return <HelpCircle className="w-4 h-4 text-gray-400" />;
  }
};

const countControlsRecursive = (controls: AtoControl[]): {
  compliantCount: number;
  nonCompliantCount: number;
  partialCount: number;
  notAssessedCount: number;
  notApplicableCount: number;
  total: number;
} => {
  let compliantCount = 0;
  let nonCompliantCount = 0;
  let partialCount = 0;
  let notAssessedCount = 0;
  let notApplicableCount = 0;
  let total = 0;

  const countControl = (control: AtoControl) => {
    total++;
    switch (control.status) {
      case 'Compliant': compliantCount++; break;
      case 'NonCompliant': nonCompliantCount++; break;
      case 'PartiallyCompliant': partialCount++; break;
      case 'NotAssessed': notAssessedCount++; break;
      case 'NotApplicable': notApplicableCount++; break;
    }
    if (control.children) {
      control.children.forEach(countControl);
    }
  };

  controls.forEach(countControl);
  return { compliantCount, nonCompliantCount, partialCount, notAssessedCount, notApplicableCount, total };
};

const calculateFamilyStats = (controls: AtoControl[]) => {
  return countControlsRecursive(controls);
};

const calculateOverallScore = (families: AtoControlFamily[]): number => {
  let totalControls = 0;
  let compliantControls = 0;
  let partialControls = 0;

  families.forEach(family => {
    const stats = countControlsRecursive(family.controls);
    const assessable = stats.total - stats.notApplicableCount - stats.notAssessedCount;
    totalControls += assessable;
    compliantControls += stats.compliantCount;
    partialControls += stats.partialCount;
  });

  if (totalControls === 0) return 0;
  return Math.round(((compliantControls + partialControls * 0.5) / totalControls) * 100);
};

// ============================================================================
// Sample/Demo Data Generator with Nested Controls
// ============================================================================

const generateSampleData = (): AtoMapData => {
  const controlFamilies: AtoControlFamily[] = NIST_CONTROL_FAMILIES.map((family, index) => {
    // Generate sample controls for each family with nested children
    const controlCount = Math.floor(Math.random() * 10) + 5;
    const controls: AtoControl[] = [];

    for (let i = 1; i <= controlCount; i++) {
      const rand = Math.random();
      let status: ControlStatus;
      if (rand < 0.5) status = 'Compliant';
      else if (rand < 0.65) status = 'PartiallyCompliant';
      else if (rand < 0.75) status = 'NonCompliant';
      else if (rand < 0.85) status = 'NotAssessed';
      else status = 'NotApplicable';

      // Generate child controls (enhancements) for some controls
      const childCount = Math.random() < 0.4 ? Math.floor(Math.random() * 3) + 1 : 0;
      const children: AtoControl[] = [];

      for (let j = 1; j <= childCount; j++) {
        const childRand = Math.random();
        let childStatus: ControlStatus;
        if (childRand < 0.5) childStatus = 'Compliant';
        else if (childRand < 0.65) childStatus = 'PartiallyCompliant';
        else if (childRand < 0.75) childStatus = 'NonCompliant';
        else if (childRand < 0.85) childStatus = 'NotAssessed';
        else childStatus = 'NotApplicable';

        children.push({
          id: `${family.id}-${i}(${j})`,
          controlId: `${family.abbreviation}-${i}(${j})`,
          title: `${family.name} Control ${i} Enhancement ${j}`,
          status: childStatus,
          evidenceCount: childStatus === 'Compliant' ? Math.floor(Math.random() * 3) + 1 : 0,
          poamId: childStatus === 'NonCompliant' ? `POA&M-${Math.floor(Math.random() * 100) + 1}` : undefined,
          lastAssessed: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          parentId: `${family.id}-${i}`,
        });
      }

      controls.push({
        id: `${family.id}-${i}`,
        controlId: `${family.abbreviation}-${i}`,
        title: `${family.name} Control ${i}`,
        status,
        evidenceCount: status === 'Compliant' ? Math.floor(Math.random() * 5) + 1 : 0,
        poamId: status === 'NonCompliant' ? `POA&M-${Math.floor(Math.random() * 100) + 1}` : undefined,
        lastAssessed: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        children: children.length > 0 ? children : undefined,
      });
    }

    const stats = calculateFamilyStats(controls);

    return {
      id: family.id,
      name: family.name,
      abbreviation: family.abbreviation,
      controls,
      order: index,
      ...stats,
    };
  });

  const countPoams = (controls: AtoControl[]): number => {
    let count = 0;
    controls.forEach(c => {
      if (c.poamId) count++;
      if (c.children) count += countPoams(c.children);
    });
    return count;
  };

  const poamCount = controlFamilies.reduce(
    (sum, f) => sum + countPoams(f.controls),
    0
  );

  return {
    systemName: 'Sample Information System',
    systemId: 'SYS-2024-001',
    organization: 'Sample Organization',
    authorizingOfficial: 'Jane Smith, CISO',
    assessmentDate: new Date().toISOString().split('T')[0],
    targetAtoDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    baseline: 'Moderate',
    framework: 'NIST 800-53 Rev 5',
    controlFamilies,
    overallScore: calculateOverallScore(controlFamilies),
    poamCount,
  };
};

// ============================================================================
// Draggable Control Family Card
// ============================================================================

interface ControlRowProps {
  control: AtoControl;
  depth: number;
  expandedControls: Set<string>;
  onToggleControl: (controlId: string) => void;
  onEditControl: (control: AtoControl) => void;
}

const ControlRow: React.FC<ControlRowProps> = ({
  control,
  depth,
  expandedControls,
  onToggleControl,
  onEditControl,
}) => {
  const hasChildren = control.children && control.children.length > 0;
  const isExpanded = expandedControls.has(control.id);

  return (
    <>
      <tr className={`border-t border-gray-700 ${depth > 0 ? 'bg-gray-800/50' : ''}`}>
        <td className="py-2" style={{ paddingLeft: `${depth * 24 + 8}px` }}>
          <div className="flex items-center gap-2">
            {hasChildren ? (
              <button
                onClick={() => onToggleControl(control.id)}
                className="p-0.5 hover:bg-gray-700 rounded"
              >
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-gray-400" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-gray-400" />
                )}
              </button>
            ) : (
              <span className="w-5" />
            )}
            <span className="font-mono text-cyan-400">{control.controlId}</span>
          </div>
        </td>
        <td className="py-2">
          <div className="flex items-center gap-2">
            {getStatusIcon(control.status)}
            <span className="text-gray-300">{control.status}</span>
          </div>
        </td>
        <td className="py-2 text-gray-400">
          {control.evidenceCount > 0 ? `${control.evidenceCount} items` : '-'}
        </td>
        <td className="py-2">
          {control.poamId ? (
            <span className="text-red-400 font-mono">{control.poamId}</span>
          ) : (
            <span className="text-gray-500">-</span>
          )}
        </td>
        <td className="py-2 text-gray-400">{control.lastAssessed || '-'}</td>
        <td className="py-2">
          <button
            onClick={() => onEditControl(control)}
            className="p-1 hover:bg-gray-700 rounded text-gray-400 hover:text-cyan-400"
            title="Edit control"
          >
            <Edit3 className="w-4 h-4" />
          </button>
        </td>
      </tr>
      {/* Render children if expanded */}
      {hasChildren && isExpanded && control.children!.map(child => (
        <ControlRow
          key={child.id}
          control={child}
          depth={depth + 1}
          expandedControls={expandedControls}
          onToggleControl={onToggleControl}
          onEditControl={onEditControl}
        />
      ))}
    </>
  );
};

interface ControlFamilyCardProps {
  family: AtoControlFamily;
  expanded: boolean;
  onToggle: () => void;
  expandedControls: Set<string>;
  onToggleControl: (controlId: string) => void;
  onEditControl: (control: AtoControl) => void;
  // Drag and drop props
  isDragging?: boolean;
  onDragStart: (e: React.DragEvent, familyId: string) => void;
  onDragOver: (e: React.DragEvent) => void;
  onDrop: (e: React.DragEvent, familyId: string) => void;
  onDragEnd: () => void;
}

const ControlFamilyCard: React.FC<ControlFamilyCardProps> = ({
  family,
  expanded,
  onToggle,
  expandedControls,
  onToggleControl,
  onEditControl,
  isDragging,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
}) => {
  const stats = countControlsRecursive(family.controls);
  const total = stats.total;
  const compliantPercent = total > 0 ? (stats.compliantCount / total) * 100 : 0;
  const partialPercent = total > 0 ? (stats.partialCount / total) * 100 : 0;
  const nonCompliantPercent = total > 0 ? (stats.nonCompliantCount / total) * 100 : 0;
  const notAssessedPercent = total > 0 ? (stats.notAssessedCount / total) * 100 : 0;
  const naPercent = total > 0 ? (stats.notApplicableCount / total) * 100 : 0;

  return (
    <div
      className={`bg-gray-800 rounded-lg border border-gray-700 overflow-hidden print:break-inside-avoid transition-all ${
        isDragging ? 'opacity-50 border-cyan-500' : ''
      }`}
      draggable
      onDragStart={(e) => onDragStart(e, family.id)}
      onDragOver={onDragOver}
      onDrop={(e) => onDrop(e, family.id)}
      onDragEnd={onDragEnd}
    >
      <div className="flex items-center">
        {/* Drag handle */}
        <div
          className="px-2 py-4 cursor-grab active:cursor-grabbing hover:bg-gray-700 print:hidden"
          title="Drag to reorder"
        >
          <GripVertical className="w-5 h-5 text-gray-500" />
        </div>

        <button
          onClick={onToggle}
          className="flex-1 p-4 flex items-center justify-between hover:bg-gray-750 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-gray-700 flex items-center justify-center font-bold text-cyan-400">
              {family.abbreviation}
            </div>
            <div className="text-left">
              <h3 className="font-semibold text-white">{family.name}</h3>
              <p className="text-sm text-gray-400">{total} controls</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex gap-2 text-xs">
              <span className="px-2 py-1 rounded bg-green-500/20 text-green-400">{stats.compliantCount}</span>
              <span className="px-2 py-1 rounded bg-yellow-500/20 text-yellow-400">{stats.partialCount}</span>
              <span className="px-2 py-1 rounded bg-red-500/20 text-red-400">{stats.nonCompliantCount}</span>
              <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-400">{stats.notAssessedCount}</span>
            </div>
            {expanded ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </div>
        </button>
      </div>

      {/* Progress bar */}
      <div className="h-2 flex">
        <div className="bg-green-500" style={{ width: `${compliantPercent}%` }} />
        <div className="bg-yellow-500" style={{ width: `${partialPercent}%` }} />
        <div className="bg-red-500" style={{ width: `${nonCompliantPercent}%` }} />
        <div className="bg-blue-500" style={{ width: `${notAssessedPercent}%` }} />
        <div className="bg-gray-500" style={{ width: `${naPercent}%` }} />
      </div>

      {/* Expanded control list */}
      {expanded && (
        <div className="p-4 border-t border-gray-700 bg-gray-850">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="pb-2 font-medium">Control</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Evidence</th>
                <th className="pb-2 font-medium">POA&M</th>
                <th className="pb-2 font-medium">Last Assessed</th>
                <th className="pb-2 font-medium w-10"></th>
              </tr>
            </thead>
            <tbody>
              {family.controls.map(control => (
                <ControlRow
                  key={control.id}
                  control={control}
                  depth={0}
                  expandedControls={expandedControls}
                  onToggleControl={onToggleControl}
                  onEditControl={onEditControl}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// Control Edit Modal
// ============================================================================

interface EditControlModalProps {
  control: AtoControl | null;
  onClose: () => void;
  onSave: (control: AtoControl) => void;
}

const EditControlModal: React.FC<EditControlModalProps> = ({ control, onClose, onSave }) => {
  const [editedControl, setEditedControl] = useState<AtoControl | null>(control);

  useEffect(() => {
    setEditedControl(control);
  }, [control]);

  if (!control || !editedControl) return null;

  const handleSave = () => {
    onSave(editedControl);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 print:hidden">
      <div className="bg-gray-800 rounded-lg w-full max-w-lg">
        <div className="p-6 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-xl font-bold text-white">Edit Control</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Control ID</label>
            <div className="text-white font-mono">{editedControl.controlId}</div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Status</label>
            <select
              value={editedControl.status}
              onChange={(e) => setEditedControl({ ...editedControl, status: e.target.value as ControlStatus })}
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            >
              <option value="Compliant">Compliant</option>
              <option value="PartiallyCompliant">Partially Compliant</option>
              <option value="NonCompliant">Non-Compliant</option>
              <option value="NotAssessed">Not Assessed</option>
              <option value="NotApplicable">Not Applicable</option>
              <option value="ManualOverride">Manual Override</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Evidence Count</label>
            <input
              type="number"
              min="0"
              value={editedControl.evidenceCount}
              onChange={(e) => setEditedControl({ ...editedControl, evidenceCount: parseInt(e.target.value) || 0 })}
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">POA&M ID</label>
            <input
              type="text"
              value={editedControl.poamId || ''}
              onChange={(e) => setEditedControl({ ...editedControl, poamId: e.target.value || undefined })}
              placeholder="e.g., POA&M-001"
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Notes</label>
            <textarea
              value={editedControl.notes || ''}
              onChange={(e) => setEditedControl({ ...editedControl, notes: e.target.value || undefined })}
              placeholder="Assessment notes..."
              rows={3}
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Assessor</label>
            <input
              type="text"
              value={editedControl.assessor || ''}
              onChange={(e) => setEditedControl({ ...editedControl, assessor: e.target.value || undefined })}
              placeholder="Assessor name"
              className="w-full p-2 bg-gray-900 border border-gray-600 rounded-lg text-white"
            />
          </div>
        </div>

        <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSave}>
            <Save className="w-4 h-4 mr-2" />
            Save Changes
          </Button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Zeus AI Assistant Panel
// ============================================================================

interface ZeusPanelProps {
  atoData: AtoMapData | null;
  onAction: (action: ZeusAction) => void;
}

const ZeusPanel: React.FC<ZeusPanelProps> = ({ atoData, onAction }) => {
  const [isAwake, setIsAwake] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [prompt, setPrompt] = useState('');
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string }>>([]);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!prompt.trim() || !atoData) return;

    const userMessage = prompt;
    setPrompt('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      // Call the Zeus/AI endpoint with ATO context
      const response = await api.post('/api/ato-map/zeus', {
        prompt: userMessage,
        context: {
          systemName: atoData.systemName,
          overallScore: atoData.overallScore,
          poamCount: atoData.poamCount,
          families: atoData.controlFamilies.map(f => ({
            id: f.id,
            name: f.name,
            stats: countControlsRecursive(f.controls),
          })),
        },
      });

      const assistantMessage = response.data.message || 'Action completed.';
      setMessages(prev => [...prev, { role: 'assistant', content: assistantMessage }]);

      // If Zeus returned an action, execute it
      if (response.data.action) {
        onAction(response.data.action);
        toast.success('Zeus action applied');
      }
    } catch (error: unknown) {
      console.error('Zeus error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `I encountered an error processing your request. You can still use me to help analyze the ATO data or suggest actions. Error: ${errorMessage}`
      }]);
    } finally {
      setLoading(false);
    }
  };

  const quickActions = [
    { label: 'Analyze gaps', prompt: 'What are the main compliance gaps in this ATO assessment?' },
    { label: 'Prioritize POA&Ms', prompt: 'Help me prioritize the POA&M items by risk.' },
    { label: 'Generate summary', prompt: 'Generate an executive summary of the current ATO status.' },
    { label: 'Recommend actions', prompt: 'What controls should I focus on to improve the overall score?' },
  ];

  const handleWakeUp = () => {
    setIsAwake(true);
    setIsMinimized(false);
  };

  const handleMinimize = () => {
    setIsMinimized(true);
  };

  const handleClose = () => {
    setIsAwake(false);
    setIsMinimized(false);
  };

  // Show floating button when not awake OR when minimized
  if (!isAwake || isMinimized) {
    return (
      <button
        onClick={handleWakeUp}
        className={`fixed bottom-6 right-6 p-4 rounded-full shadow-lg z-40 print:hidden transition-all ${
          isMinimized
            ? 'bg-purple-500 hover:bg-purple-400 ring-2 ring-purple-300 ring-offset-2 ring-offset-gray-900'
            : 'bg-purple-600 hover:bg-purple-500'
        }`}
        title={isMinimized ? 'Restore Zeus' : 'Ask Zeus AI Assistant'}
      >
        <Bot className="w-6 h-6 text-white" />
        {/* Show indicator when minimized with active conversation */}
        {isMinimized && messages.length > 0 && (
          <span className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-pulse" />
        )}
      </button>
    );
  }

  return (
    <>
      <div className="fixed bottom-6 right-6 w-96 bg-gray-800 rounded-lg shadow-xl border border-gray-700 z-50 print:hidden">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-purple-400" />
            <span className="font-semibold text-white">Zeus AI Assistant</span>
          </div>
          <div className="flex items-center gap-1">
            {/* Minimize Button */}
            <button
              onClick={handleMinimize}
              className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
              title="Minimize"
            >
              <MinusCircle className="w-4 h-4" />
            </button>
            {/* Close Button */}
            <button
              onClick={handleClose}
              className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="h-64 overflow-y-auto p-4 space-y-3">
          {messages.length === 0 && (
            <div className="text-center text-gray-400 py-8">
              <Bot className="w-12 h-12 mx-auto mb-2 text-purple-400/50" />
              <p className="text-sm">Ask me about your ATO assessment or use quick actions below.</p>
            </div>
          )}
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`p-3 rounded-lg ${
                msg.role === 'user'
                  ? 'bg-cyan-500/20 text-cyan-100 ml-8'
                  : 'bg-gray-700 text-gray-100 mr-8'
              }`}
            >
              {msg.content}
            </div>
          ))}
          {loading && (
            <div className="flex items-center gap-2 text-gray-400">
              <LoadingSpinner />
              <span className="text-sm">Zeus is thinking...</span>
            </div>
          )}
        </div>

        {/* Quick actions */}
        <div className="px-4 py-2 border-t border-gray-700">
          <div className="flex flex-wrap gap-1">
            {quickActions.map((action, idx) => (
              <button
                key={idx}
                onClick={() => setPrompt(action.prompt)}
                className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 rounded text-gray-300"
              >
                {action.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input */}
        <div className="p-4 border-t border-gray-700">
          <div className="flex gap-2">
            <input
              type="text"
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
              placeholder="Ask Zeus..."
              className="flex-1 p-2 bg-gray-900 border border-gray-600 rounded-lg text-white text-sm"
              disabled={loading}
            />
            <Button onClick={handleSubmit} disabled={loading || !prompt.trim()}>
              <MessageSquare className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </div>
    </>
  );
};

// ============================================================================
// Import Modal
// ============================================================================

interface ImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImport: (data: AtoMapData) => void;
}

const ImportModal: React.FC<ImportModalProps> = ({ isOpen, onClose, onImport }) => {
  const [importType, setImportType] = useState<'json' | 'csv' | 'heroforge'>('heroforge');
  const [jsonText, setJsonText] = useState('');
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    try {
      const text = await file.text();

      if (importType === 'json') {
        const data = JSON.parse(text) as ImportData;
        const atoData = convertImportToAtoMap(data);
        onImport(atoData);
        toast.success('ATO Map data imported successfully');
        onClose();
      } else if (importType === 'csv') {
        const atoData = parseCSVToAtoMap(text);
        onImport(atoData);
        toast.success('CSV data imported successfully');
        onClose();
      }
    } catch (error) {
      console.error('Import error:', error);
      toast.error('Failed to import data. Please check the file format.');
    } finally {
      setLoading(false);
    }
  };

  const handleJsonImport = () => {
    try {
      const data = JSON.parse(jsonText) as ImportData;
      const atoData = convertImportToAtoMap(data);
      onImport(atoData);
      toast.success('ATO Map data imported successfully');
      onClose();
    } catch (error) {
      console.error('JSON parse error:', error);
      toast.error('Invalid JSON format');
    }
  };

  const loadFromHeroForge = async () => {
    setLoading(true);
    try {
      const response = await api.get('/api/ato-map');
      if (response.data && response.data.controlFamilies) {
        onImport(response.data);
        toast.success('Loaded compliance data from HeroForge');
        onClose();
      } else {
        // Fall back to sample data
        const sampleData = generateSampleData();
        onImport(sampleData);
        toast.success('Loaded sample compliance data');
        onClose();
      }
    } catch (error) {
      console.error('Load error:', error);
      // Fall back to sample data
      const sampleData = generateSampleData();
      onImport(sampleData);
      toast.info('Loaded sample data (API not available)');
      onClose();
    } finally {
      setLoading(false);
    }
  };

  const convertImportToAtoMap = (data: ImportData): AtoMapData => {
    const familyMap = new Map<string, AtoControl[]>();
    const childMap = new Map<string, AtoControl[]>();

    // Initialize all families
    NIST_CONTROL_FAMILIES.forEach(f => familyMap.set(f.id, []));

    // First pass: separate parents and children
    data.controls.forEach(ctrl => {
      const controlId = ctrl.controlId;
      const familyId = controlId.split('-')[0].toUpperCase();

      const control: AtoControl = {
        id: controlId,
        controlId: controlId,
        title: `Control ${controlId}`,
        status: (ctrl.status as ControlStatus) || 'NotAssessed',
        evidenceCount: ctrl.evidenceCount || 0,
        poamId: ctrl.poamId,
        notes: ctrl.notes,
        parentId: ctrl.parentId,
      };

      // Check if this is a child control (has parentheses like AC-1(1))
      const parentMatch = controlId.match(/^([A-Z]+-\d+)\(\d+\)$/);
      if (parentMatch || ctrl.parentId) {
        const parentId = ctrl.parentId || parentMatch![1];
        if (!childMap.has(parentId)) {
          childMap.set(parentId, []);
        }
        childMap.get(parentId)!.push(control);
      } else {
        if (familyMap.has(familyId)) {
          familyMap.get(familyId)!.push(control);
        }
      }
    });

    // Second pass: attach children to parents
    familyMap.forEach(controls => {
      controls.forEach(control => {
        const children = childMap.get(control.controlId);
        if (children && children.length > 0) {
          control.children = children;
        }
      });
    });

    const controlFamilies: AtoControlFamily[] = NIST_CONTROL_FAMILIES.map((family, idx) => {
      const controls = familyMap.get(family.id) || [];
      const stats = calculateFamilyStats(controls);
      return {
        id: family.id,
        name: family.name,
        abbreviation: family.abbreviation,
        controls,
        order: idx,
        ...stats,
      };
    }).filter(f => f.controls.length > 0);

    return {
      systemName: data.systemName || 'Imported System',
      organization: data.organization,
      baseline: (data.baseline as 'Low' | 'Moderate' | 'High') || 'Moderate',
      framework: 'NIST 800-53 Rev 5',
      controlFamilies,
      overallScore: calculateOverallScore(controlFamilies),
      poamCount: controlFamilies.reduce((sum, f) => {
        let count = 0;
        const countPoams = (ctrls: AtoControl[]) => {
          ctrls.forEach(c => {
            if (c.poamId) count++;
            if (c.children) countPoams(c.children);
          });
        };
        countPoams(f.controls);
        return sum + count;
      }, 0),
    };
  };

  const parseCSVToAtoMap = (csvText: string): AtoMapData => {
    const lines = csvText.trim().split('\n');
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase());

    const controls: ImportData['controls'] = [];

    for (let i = 1; i < lines.length; i++) {
      const values = lines[i].split(',').map(v => v.trim());
      const row: Record<string, string> = {};
      headers.forEach((h, idx) => {
        row[h] = values[idx] || '';
      });

      controls.push({
        controlId: row['control_id'] || row['controlid'] || row['control'] || '',
        status: row['status'] || 'NotAssessed',
        evidenceCount: parseInt(row['evidence_count'] || row['evidence'] || '0', 10),
        poamId: row['poam_id'] || row['poam'] || undefined,
        notes: row['notes'] || undefined,
        parentId: row['parent_id'] || row['parentid'] || undefined,
      });
    }

    return convertImportToAtoMap({ controls });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 print:hidden">
      <div className="bg-gray-800 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-auto">
        <div className="p-6 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white">Import ATO Map Data</h2>
          <p className="text-gray-400 mt-1">Load compliance assessment data</p>
        </div>

        <div className="p-6">
          {/* Import type selector */}
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => setImportType('heroforge')}
              className={`flex-1 p-4 rounded-lg border ${
                importType === 'heroforge'
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-gray-600 hover:border-gray-500'
              }`}
            >
              <Shield className="w-6 h-6 mx-auto mb-2 text-cyan-400" />
              <div className="text-sm font-medium text-white">HeroForge Data</div>
              <div className="text-xs text-gray-400">Load from scans</div>
            </button>
            <button
              onClick={() => setImportType('json')}
              className={`flex-1 p-4 rounded-lg border ${
                importType === 'json'
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-gray-600 hover:border-gray-500'
              }`}
            >
              <FileJson className="w-6 h-6 mx-auto mb-2 text-yellow-400" />
              <div className="text-sm font-medium text-white">JSON File</div>
              <div className="text-xs text-gray-400">Import JSON</div>
            </button>
            <button
              onClick={() => setImportType('csv')}
              className={`flex-1 p-4 rounded-lg border ${
                importType === 'csv'
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-gray-600 hover:border-gray-500'
              }`}
            >
              <FileSpreadsheet className="w-6 h-6 mx-auto mb-2 text-green-400" />
              <div className="text-sm font-medium text-white">CSV File</div>
              <div className="text-xs text-gray-400">Import spreadsheet</div>
            </button>
          </div>

          {/* Import options based on type */}
          {importType === 'heroforge' && (
            <div className="text-center py-8">
              <Shield className="w-16 h-16 mx-auto mb-4 text-cyan-400" />
              <p className="text-gray-300 mb-4">
                Load compliance assessment data from your HeroForge scans and manual assessments.
              </p>
              <Button onClick={loadFromHeroForge} disabled={loading}>
                {loading ? <LoadingSpinner /> : 'Load HeroForge Data'}
              </Button>
            </div>
          )}

          {importType === 'json' && (
            <div>
              <div className="mb-4">
                <input
                  type="file"
                  ref={fileInputRef}
                  accept=".json"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <Button
                  variant="secondary"
                  onClick={() => fileInputRef.current?.click()}
                  className="w-full"
                  disabled={loading}
                >
                  <Upload className="w-4 h-4 mr-2" />
                  Upload JSON File
                </Button>
              </div>
              <div className="text-center text-gray-500 my-4">— or paste JSON below —</div>
              <textarea
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder='{"systemName": "My System", "controls": [{"controlId": "AC-1", "status": "Compliant"}]}'
                className="w-full h-40 p-3 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 font-mono text-sm"
              />
              <Button onClick={handleJsonImport} className="mt-4 w-full" disabled={!jsonText.trim()}>
                Import JSON
              </Button>
            </div>
          )}

          {importType === 'csv' && (
            <div>
              <div className="bg-gray-900 p-4 rounded-lg mb-4">
                <p className="text-sm text-gray-400 mb-2">Expected CSV format:</p>
                <code className="text-xs text-cyan-400">
                  control_id,status,evidence_count,poam_id,notes,parent_id<br />
                  AC-1,Compliant,3,,Reviewed annually,<br />
                  AC-1(1),Compliant,1,,Enhancement 1,AC-1<br />
                  AC-2,NonCompliant,0,POA&M-001,Needs remediation,
                </code>
              </div>
              <input
                type="file"
                ref={fileInputRef}
                accept=".csv"
                onChange={handleFileUpload}
                className="hidden"
              />
              <Button
                onClick={() => fileInputRef.current?.click()}
                className="w-full"
                disabled={loading}
              >
                <Upload className="w-4 h-4 mr-2" />
                Upload CSV File
              </Button>
            </div>
          )}
        </div>

        <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// Main Component
// ============================================================================

// Engagement type for selector
interface Engagement {
  id: string;
  name: string;
  customer_name?: string;
  status: string;
}

const AtoMapPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [atoData, setAtoData] = useState<AtoMapData | null>(null);
  const [expandedFamilies, setExpandedFamilies] = useState<Set<string>>(new Set());
  const [expandedControls, setExpandedControls] = useState<Set<string>>(new Set());
  const [showImportModal, setShowImportModal] = useState(false);
  const [editingControl, setEditingControl] = useState<AtoControl | null>(null);
  const [draggedFamily, setDraggedFamily] = useState<string | null>(null);
  const [highlightedStatus, setHighlightedStatus] = useState<ControlStatus | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selectedEngagement, setSelectedEngagement] = useState<string>('');
  const [dataSource, setDataSource] = useState<'real' | 'sample'>('real');
  const printRef = useRef<HTMLDivElement>(null);

  // Fetch engagements list on mount
  useEffect(() => {
    const fetchEngagements = async () => {
      try {
        const response = await api.get('/api/engagements');
        const engagementList = response.data.engagements || response.data || [];
        setEngagements(engagementList);

        // Auto-select first engagement if available
        if (engagementList.length > 0) {
          setSelectedEngagement(engagementList[0].id);
        }
      } catch (error) {
        console.error('Failed to fetch engagements:', error);
        // Fall back to sample data if no engagements available
        setDataSource('sample');
      }
    };
    fetchEngagements();
  }, []);

  // Fetch ATO data when engagement changes or on initial load
  useEffect(() => {
    const fetchAtoData = async () => {
      setLoading(true);

      try {
        let response;

        if (selectedEngagement && dataSource === 'real') {
          // Fetch real data for the selected engagement
          response = await api.get(`/api/ato-map/engagement/${selectedEngagement}`);
        } else if (dataSource === 'real') {
          // Fetch general ATO data (from any assessments)
          response = await api.get('/api/ato-map');
        } else {
          // Fetch sample data
          response = await api.get('/api/ato-map/sample');
        }

        const data = response.data;

        // Check if we have meaningful data (not just empty controls)
        const hasRealAssessments = data.controlFamilies?.some(
          (f: AtoControlFamily) => f.controls.some((c: AtoControl) => c.status !== 'NotAssessed')
        );

        if (!hasRealAssessments && dataSource === 'real') {
          // No real assessments found, notify user
          toast.info('No assessment data found. Showing framework controls for assessment.');
        }

        setAtoData(data);
      } catch (error) {
        console.error('Failed to fetch ATO data:', error);
        // Fall back to sample data on error
        toast.warning('Could not load assessment data. Using sample data.');
        setAtoData(generateSampleData());
        setDataSource('sample');
      } finally {
        setLoading(false);
      }
    };

    fetchAtoData();
  }, [selectedEngagement, dataSource]);

  const toggleFamily = (familyId: string) => {
    const newExpanded = new Set(expandedFamilies);
    if (newExpanded.has(familyId)) {
      newExpanded.delete(familyId);
    } else {
      newExpanded.add(familyId);
    }
    setExpandedFamilies(newExpanded);
  };

  const toggleControl = (controlId: string) => {
    const newExpanded = new Set(expandedControls);
    if (newExpanded.has(controlId)) {
      newExpanded.delete(controlId);
    } else {
      newExpanded.add(controlId);
    }
    setExpandedControls(newExpanded);
  };

  const expandAll = () => {
    if (atoData) {
      setExpandedFamilies(new Set(atoData.controlFamilies.map(f => f.id)));
      // Also expand all controls with children
      const allControlIds: string[] = [];
      atoData.controlFamilies.forEach(f => {
        f.controls.forEach(c => {
          if (c.children && c.children.length > 0) {
            allControlIds.push(c.id);
          }
        });
      });
      setExpandedControls(new Set(allControlIds));
    }
  };

  const collapseAll = () => {
    setExpandedFamilies(new Set());
    setExpandedControls(new Set());
  };

  // Drag and drop handlers
  const handleDragStart = (e: React.DragEvent, familyId: string) => {
    setDraggedFamily(familyId);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = (e: React.DragEvent, targetFamilyId: string) => {
    e.preventDefault();
    if (!draggedFamily || !atoData || draggedFamily === targetFamilyId) return;

    const families = [...atoData.controlFamilies];
    const draggedIndex = families.findIndex(f => f.id === draggedFamily);
    const targetIndex = families.findIndex(f => f.id === targetFamilyId);

    if (draggedIndex === -1 || targetIndex === -1) return;

    // Reorder
    const [removed] = families.splice(draggedIndex, 1);
    families.splice(targetIndex, 0, removed);

    // Update order property
    families.forEach((f, idx) => {
      f.order = idx;
    });

    setAtoData({ ...atoData, controlFamilies: families });
    toast.success('Control family order updated');
  };

  const handleDragEnd = () => {
    setDraggedFamily(null);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportJSON = () => {
    if (!atoData) return;

    const exportData = {
      exportDate: new Date().toISOString(),
      ...atoData,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ato-map-${atoData.systemName.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('ATO Map exported as JSON');
  };

  const handleExportCSV = () => {
    if (!atoData) return;

    const rows = [['Control Family', 'Control ID', 'Parent ID', 'Status', 'Evidence Count', 'POA&M ID', 'Last Assessed', 'Notes']];

    const addControlRow = (familyName: string, control: AtoControl, parentId?: string) => {
      rows.push([
        familyName,
        control.controlId,
        parentId || '',
        control.status,
        String(control.evidenceCount),
        control.poamId || '',
        control.lastAssessed || '',
        control.notes || '',
      ]);
      if (control.children) {
        control.children.forEach(child => addControlRow(familyName, child, control.controlId));
      }
    };

    atoData.controlFamilies.forEach(family => {
      family.controls.forEach(control => addControlRow(family.name, control));
    });

    const csv = rows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ato-map-${atoData.systemName.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('ATO Map exported as CSV');
  };

  const handleImport = (data: AtoMapData) => {
    setAtoData(data);
  };

  const handleEditControl = (control: AtoControl) => {
    setEditingControl(control);
  };

  const handleSaveControl = (updatedControl: AtoControl) => {
    if (!atoData) return;

    const updateControlInList = (controls: AtoControl[]): AtoControl[] => {
      return controls.map(c => {
        if (c.id === updatedControl.id) {
          return { ...updatedControl, children: c.children };
        }
        if (c.children) {
          return { ...c, children: updateControlInList(c.children) };
        }
        return c;
      });
    };

    const updatedFamilies = atoData.controlFamilies.map(f => ({
      ...f,
      controls: updateControlInList(f.controls),
    }));

    // Recalculate stats
    updatedFamilies.forEach(f => {
      const stats = calculateFamilyStats(f.controls);
      Object.assign(f, stats);
    });

    setAtoData({
      ...atoData,
      controlFamilies: updatedFamilies,
      overallScore: calculateOverallScore(updatedFamilies),
    });

    toast.success(`Control ${updatedControl.controlId} updated`);
  };

  const handleZeusAction = (action: ZeusAction) => {
    if (!atoData) return;

    console.log('Zeus action:', action);

    // Handle different action types
    switch (action.type) {
      case 'update_status':
        if (action.controlId && action.newStatus) {
          // Find and update the control (including nested children)
          const updateControlsRecursive = (controls: AtoControl[]): AtoControl[] => {
            return controls.map(c => {
              if (c.controlId === action.controlId) {
                return { ...c, status: action.newStatus as ControlStatus, notes: action.notes || c.notes };
              }
              if (c.children && c.children.length > 0) {
                return { ...c, children: updateControlsRecursive(c.children) };
              }
              return c;
            });
          };

          const updatedFamilies = atoData.controlFamilies.map(f => ({
            ...f,
            controls: updateControlsRecursive(f.controls),
          }));
          setAtoData({ ...atoData, controlFamilies: updatedFamilies });
          toast.success(`Control ${action.controlId} updated to ${action.newStatus}`);
        }
        break;

      case 'bulk_update':
        // Handle bulk updates - update all controls matching targetStatus
        if (action.targetStatus && action.newStatus) {
          const bulkUpdateRecursive = (controls: AtoControl[]): AtoControl[] => {
            return controls.map(c => {
              const updated = c.status === action.targetStatus
                ? { ...c, status: action.newStatus as ControlStatus, notes: action.notes || c.notes }
                : c;
              if (c.children && c.children.length > 0) {
                return { ...updated, children: bulkUpdateRecursive(c.children) };
              }
              return updated;
            });
          };

          const updatedFamilies = atoData.controlFamilies.map(f => {
            // If familyId is specified, only update that family
            if (action.familyId && f.id !== action.familyId) {
              return f;
            }
            return {
              ...f,
              controls: bulkUpdateRecursive(f.controls),
            };
          });
          setAtoData({ ...atoData, controlFamilies: updatedFamilies });
          toast.success(`Bulk updated ${action.targetStatus} controls to ${action.newStatus}`);
        }
        break;

      case 'focus_family':
        if (action.familyId) {
          // Expand the family and scroll to it
          setExpandedFamilies(prev => new Set([...prev, action.familyId!]));
          const element = document.getElementById(`family-${action.familyId}`);
          if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
          toast.info(`Focused on ${action.familyId} family`);
        }
        break;

      case 'highlight_status':
        if (action.targetStatus) {
          // Highlight controls with the specified status
          setHighlightedStatus(action.targetStatus as ControlStatus);
          toast.info(`Highlighting ${action.targetStatus} controls`);
        }
        break;

      case 'export':
        // Trigger export dialog
        toast.info('Opening export options...');
        break;

      default:
        console.log('Unknown Zeus action type:', action.type);
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </Layout>
    );
  }

  if (!atoData) {
    return (
      <Layout>
        <div className="text-center py-12">
          <Shield className="w-16 h-16 mx-auto mb-4 text-gray-600" />
          <h2 className="text-xl font-bold text-white mb-2">No ATO Map Data</h2>
          <p className="text-gray-400 mb-4">Import compliance data to generate the ATO map.</p>
          <Button onClick={() => setShowImportModal(true)}>
            <Upload className="w-4 h-4 mr-2" />
            Import Data
          </Button>
        </div>
      </Layout>
    );
  }

  const stats = atoData.controlFamilies.reduce(
    (acc, f) => {
      const familyStats = countControlsRecursive(f.controls);
      return {
        total: acc.total + familyStats.total,
        compliant: acc.compliant + familyStats.compliantCount,
        partial: acc.partial + familyStats.partialCount,
        nonCompliant: acc.nonCompliant + familyStats.nonCompliantCount,
        notAssessed: acc.notAssessed + familyStats.notAssessedCount,
      };
    },
    { total: 0, compliant: 0, partial: 0, nonCompliant: 0, notAssessed: 0 }
  );

  return (
    <Layout>
      <div ref={printRef} className="ato-map-container">
        {/* Print-only header */}
        <div className="hidden print:block mb-8 text-center border-b-2 border-gray-300 pb-4">
          <h1 className="text-2xl font-bold">Authority to Operate (ATO) Assessment Map</h1>
          <p className="text-gray-600">{atoData.systemName}</p>
          <p className="text-sm text-gray-500">Generated: {new Date().toLocaleDateString()}</p>
        </div>

        {/* Header */}
        <div className="flex items-center justify-between mb-6 print:hidden">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              ATO Assessment Map
            </h1>
            <p className="text-gray-400 mt-1">
              Authority to Operate control assessment visualization
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setShowImportModal(true)}>
              <Upload className="w-4 h-4 mr-2" />
              Import
            </Button>
            <div className="relative group">
              <Button variant="secondary">
                <Download className="w-4 h-4 mr-2" />
                Export
                <ChevronDown className="w-4 h-4 ml-2" />
              </Button>
              <div className="absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-lg border border-gray-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                <button
                  onClick={handleExportJSON}
                  className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <FileJson className="w-4 h-4" />
                  Export as JSON
                </button>
                <button
                  onClick={handleExportCSV}
                  className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <FileSpreadsheet className="w-4 h-4" />
                  Export as CSV
                </button>
              </div>
            </div>
            <Button onClick={handlePrint}>
              <Printer className="w-4 h-4 mr-2" />
              Print
            </Button>
          </div>
        </div>

        {/* Engagement Selector and Data Source Toggle */}
        <div className="flex flex-wrap items-center gap-4 mb-6 print:hidden">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Engagement:</label>
            <select
              value={selectedEngagement}
              onChange={(e) => setSelectedEngagement(e.target.value)}
              className="px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm min-w-[200px]"
              disabled={dataSource === 'sample'}
            >
              <option value="">All Assessments</option>
              {engagements.map((eng) => (
                <option key={eng.id} value={eng.id}>
                  {eng.name} {eng.customer_name ? `(${eng.customer_name})` : ''}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Data Source:</label>
            <div className="flex bg-gray-800 rounded-lg border border-gray-600 overflow-hidden">
              <button
                onClick={() => setDataSource('real')}
                className={`px-3 py-2 text-sm ${
                  dataSource === 'real'
                    ? 'bg-cyan-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Real Data
              </button>
              <button
                onClick={() => setDataSource('sample')}
                className={`px-3 py-2 text-sm ${
                  dataSource === 'sample'
                    ? 'bg-cyan-500 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Sample Data
              </button>
            </div>
          </div>
          {dataSource === 'sample' && (
            <span className="text-xs text-yellow-400 bg-yellow-500/10 px-2 py-1 rounded">
              Using sample data - no real assessments loaded
            </span>
          )}
          {dataSource === 'real' && engagements.length === 0 && (
            <span className="text-xs text-orange-400 bg-orange-500/10 px-2 py-1 rounded">
              No engagements found - create an engagement to load real data
            </span>
          )}
        </div>

        {/* System Information Card */}
        <Card className="mb-6 print:shadow-none print:border print:border-gray-300">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 p-6">
            <div>
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                <FileText className="w-4 h-4" />
                System Name
              </div>
              <div className="text-white font-semibold">{atoData.systemName}</div>
              {atoData.systemId && (
                <div className="text-xs text-gray-500">ID: {atoData.systemId}</div>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                <Building className="w-4 h-4" />
                Organization
              </div>
              <div className="text-white font-semibold">{atoData.organization || 'Not specified'}</div>
            </div>
            <div>
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                <User className="w-4 h-4" />
                Authorizing Official
              </div>
              <div className="text-white font-semibold">{atoData.authorizingOfficial || 'Not specified'}</div>
            </div>
            <div>
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                <Target className="w-4 h-4" />
                Baseline
              </div>
              <div className="text-white font-semibold">{atoData.baseline}</div>
              <div className="text-xs text-gray-500">{atoData.framework}</div>
            </div>
          </div>
          <div className="border-t border-gray-700 px-6 py-4 flex items-center justify-between bg-gray-800/50 print:bg-gray-100">
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-gray-400" />
                <span className="text-gray-400">Assessment Date:</span>
                <span className="text-white">{atoData.assessmentDate || 'Ongoing'}</span>
              </div>
              {atoData.targetAtoDate && (
                <div className="flex items-center gap-2">
                  <Target className="w-4 h-4 text-cyan-400" />
                  <span className="text-gray-400">Target ATO:</span>
                  <span className="text-cyan-400">{atoData.targetAtoDate}</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-4">
              {atoData.poamCount > 0 && (
                <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-sm">
                  {atoData.poamCount} POA&M Items
                </span>
              )}
            </div>
          </div>
        </Card>

        {/* Overall Score and Summary */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
          {/* Overall Score */}
          <Card className="md:col-span-2 print:shadow-none print:border print:border-gray-300">
            <div className="p-6 text-center">
              <div className="text-6xl font-bold mb-2" style={{
                color: atoData.overallScore >= 80 ? '#22c55e' :
                       atoData.overallScore >= 60 ? '#eab308' :
                       atoData.overallScore >= 40 ? '#f97316' : '#ef4444'
              }}>
                {atoData.overallScore}%
              </div>
              <div className="text-gray-400">Overall Compliance Score</div>
              <div className="mt-4 h-3 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${atoData.overallScore}%`,
                    backgroundColor: atoData.overallScore >= 80 ? '#22c55e' :
                                     atoData.overallScore >= 60 ? '#eab308' :
                                     atoData.overallScore >= 40 ? '#f97316' : '#ef4444'
                  }}
                />
              </div>
            </div>
          </Card>

          {/* Stats */}
          <Card className="print:shadow-none print:border print:border-gray-300">
            <div className="p-4 text-center">
              <div className="text-3xl font-bold text-green-400">{stats.compliant}</div>
              <div className="text-sm text-gray-400">Compliant</div>
              <div className="text-xs text-gray-500 mt-1">
                {stats.total > 0 ? Math.round((stats.compliant / stats.total) * 100) : 0}%
              </div>
            </div>
          </Card>
          <Card className="print:shadow-none print:border print:border-gray-300">
            <div className="p-4 text-center">
              <div className="text-3xl font-bold text-yellow-400">{stats.partial}</div>
              <div className="text-sm text-gray-400">Partial</div>
              <div className="text-xs text-gray-500 mt-1">
                {stats.total > 0 ? Math.round((stats.partial / stats.total) * 100) : 0}%
              </div>
            </div>
          </Card>
          <Card className="print:shadow-none print:border print:border-gray-300">
            <div className="p-4 text-center">
              <div className="text-3xl font-bold text-red-400">{stats.nonCompliant}</div>
              <div className="text-sm text-gray-400">Non-Compliant</div>
              <div className="text-xs text-gray-500 mt-1">
                {stats.total > 0 ? Math.round((stats.nonCompliant / stats.total) * 100) : 0}%
              </div>
            </div>
          </Card>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap gap-4 mb-6 text-sm print:text-xs">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-green-500" />
            <span className="text-gray-300">Compliant</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-yellow-500" />
            <span className="text-gray-300">Partially Compliant</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-red-500" />
            <span className="text-gray-300">Non-Compliant</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-blue-500" />
            <span className="text-gray-300">Not Assessed</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-gray-500" />
            <span className="text-gray-300">Not Applicable</span>
          </div>
          <div className="ml-auto flex gap-2 print:hidden">
            <Button variant="secondary" size="sm" onClick={expandAll}>
              Expand All
            </Button>
            <Button variant="secondary" size="sm" onClick={collapseAll}>
              Collapse All
            </Button>
          </div>
        </div>

        {/* Drag hint */}
        <div className="text-xs text-gray-500 mb-2 flex items-center gap-2 print:hidden">
          <GripVertical className="w-4 h-4" />
          Drag control families to reorder
        </div>

        {/* Control Family Grid */}
        <div className="space-y-4">
          {atoData.controlFamilies.map(family => (
            <ControlFamilyCard
              key={family.id}
              family={family}
              expanded={expandedFamilies.has(family.id)}
              onToggle={() => toggleFamily(family.id)}
              expandedControls={expandedControls}
              onToggleControl={toggleControl}
              onEditControl={handleEditControl}
              isDragging={draggedFamily === family.id}
              onDragStart={handleDragStart}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onDragEnd={handleDragEnd}
            />
          ))}
        </div>

        {/* Print Footer */}
        <div className="hidden print:block mt-8 pt-4 border-t border-gray-300 text-center text-sm text-gray-500">
          <p>Generated by HeroForge Security Assessment Platform</p>
          <p>Report Date: {new Date().toLocaleString()}</p>
        </div>
      </div>

      {/* Import Modal */}
      <ImportModal
        isOpen={showImportModal}
        onClose={() => setShowImportModal(false)}
        onImport={handleImport}
      />

      {/* Edit Control Modal */}
      <EditControlModal
        control={editingControl}
        onClose={() => setEditingControl(null)}
        onSave={handleSaveControl}
      />

      {/* Zeus AI Assistant */}
      <ZeusPanel atoData={atoData} onAction={handleZeusAction} />

      {/* Print Styles */}
      <style>{`
        @media print {
          body {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .ato-map-container {
            padding: 0;
            max-width: none;
          }
          .bg-gray-800, .bg-gray-900 {
            background-color: white !important;
          }
          .text-white, .text-gray-300 {
            color: black !important;
          }
          .text-gray-400, .text-gray-500 {
            color: #666 !important;
          }
          .border-gray-700 {
            border-color: #ccc !important;
          }
        }
      `}</style>
    </Layout>
  );
};

export default AtoMapPage;
