import React, { useState, useEffect } from 'react';
import { Layout as LayoutIcon, Save, Plus, X } from 'lucide-react';
import GridLayout from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import {
  RecentScansWidget,
  VulnerabilitySummaryWidget,
  ComplianceScoresWidget,
  ScanActivityWidget,
  TopRiskyHostsWidget,
  CriticalVulnsWidget,
  UpcomingScansWidget,
  ThreatIntelWidget,
  MyAssignmentsWidget,
} from './widgets';

// Widget-specific configuration types
interface RecentScansWidgetConfig {
  limit?: number;
}

interface VulnerabilitySummaryWidgetConfig {
  showChart?: boolean;
}

interface ComplianceScoresWidgetConfig {
  frameworks?: string[];
}

interface ScanActivityWidgetConfig {
  period?: 'week' | 'month' | 'year';
}

interface TopRiskyHostsWidgetConfig {
  limit?: number;
}

interface CriticalVulnsWidgetConfig {
  limit?: number;
}

interface UpcomingScansWidgetConfig {
  limit?: number;
}

interface ThreatIntelWidgetConfig {
  limit?: number;
}

interface MyAssignmentsWidgetConfig {
  limit?: number;
}

type WidgetConfigOptions =
  | RecentScansWidgetConfig
  | VulnerabilitySummaryWidgetConfig
  | ComplianceScoresWidgetConfig
  | ScanActivityWidgetConfig
  | TopRiskyHostsWidgetConfig
  | CriticalVulnsWidgetConfig
  | UpcomingScansWidgetConfig
  | ThreatIntelWidgetConfig
  | MyAssignmentsWidgetConfig
  | Record<string, never>; // Empty config

interface WidgetConfig {
  id: string;
  widget_type: string;
  x: number;
  y: number;
  w: number;
  h: number;
  config?: WidgetConfigOptions;
}

interface DashboardCustomizerProps {
  editMode?: boolean;
  onEditModeChange?: (editMode: boolean) => void;
}

const WIDGET_TYPES = [
  { type: 'recent_scans', label: 'Recent Scans', minW: 4, minH: 2 },
  { type: 'vulnerability_summary', label: 'Vulnerability Summary', minW: 4, minH: 2 },
  { type: 'compliance_scores', label: 'Compliance Scores', minW: 4, minH: 2 },
  { type: 'scan_activity_chart', label: 'Scan Activity', minW: 6, minH: 3 },
  { type: 'top_risky_hosts', label: 'Top Risky Hosts', minW: 4, minH: 3 },
  { type: 'critical_vulns', label: 'Critical Vulnerabilities', minW: 4, minH: 2 },
  { type: 'upcoming_scheduled_scans', label: 'Upcoming Scans', minW: 4, minH: 2 },
  { type: 'threat_intel', label: 'Threat Intelligence', minW: 4, minH: 3 },
  { type: 'my_assignments', label: 'My Assignments', minW: 4, minH: 3 },
];

const DashboardCustomizer: React.FC<DashboardCustomizerProps> = ({
  editMode = false,
  onEditModeChange,
}) => {
  const [widgets, setWidgets] = useState<WidgetConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isEditMode, setIsEditMode] = useState(editMode);
  const [showAddMenu, setShowAddMenu] = useState(false);

  useEffect(() => {
    fetchDashboardConfig();
  }, []);

  useEffect(() => {
    setIsEditMode(editMode);
  }, [editMode]);

  const fetchDashboardConfig = async () => {
    try {
      const response = await fetch('/api/dashboard/widgets', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
      });
      const data = await response.json();
      setWidgets(data.widgets || []);
    } catch (error) {
      console.error('Failed to fetch dashboard config:', error);
    } finally {
      setLoading(false);
    }
  };

  const saveDashboardConfig = async () => {
    setSaving(true);
    try {
      await fetch('/api/dashboard/widgets', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify({ widgets }),
      });
    } catch (error) {
      console.error('Failed to save dashboard config:', error);
    } finally {
      setSaving(false);
    }
  };

  interface LayoutItem {
    i: string;
    x: number;
    y: number;
    w: number;
    h: number;
  }

  const handleLayoutChange = (layout: LayoutItem[]) => {
    if (!isEditMode) return;

    const updatedWidgets = widgets.map((widget) => {
      const layoutItem = layout.find((l) => l.i === widget.id);
      if (layoutItem) {
        return {
          ...widget,
          x: layoutItem.x,
          y: layoutItem.y,
          w: layoutItem.w,
          h: layoutItem.h,
        };
      }
      return widget;
    });
    setWidgets(updatedWidgets);
  };

  const addWidget = (type: string) => {
    const typeInfo = WIDGET_TYPES.find((t) => t.type === type);
    if (!typeInfo) return;

    const newWidget: WidgetConfig = {
      id: `${type}_${Date.now()}`,
      widget_type: type,
      x: 0,
      y: Infinity,
      w: typeInfo.minW,
      h: typeInfo.minH,
    };

    setWidgets([...widgets, newWidget]);
    setShowAddMenu(false);
  };

  const removeWidget = (id: string) => {
    setWidgets(widgets.filter((w) => w.id !== id));
  };

  const toggleEditMode = () => {
    const newEditMode = !isEditMode;
    setIsEditMode(newEditMode);
    if (onEditModeChange) {
      onEditModeChange(newEditMode);
    }
  };

  const renderWidget = (widget: WidgetConfig) => {
    const commonProps = {
      onRemove: isEditMode ? () => removeWidget(widget.id) : undefined,
    };

    switch (widget.widget_type) {
      case 'recent_scans':
        return <RecentScansWidget {...commonProps} />;
      case 'vulnerability_summary':
        return <VulnerabilitySummaryWidget {...commonProps} />;
      case 'compliance_scores':
        return <ComplianceScoresWidget {...commonProps} />;
      case 'scan_activity_chart':
        return <ScanActivityWidget {...commonProps} />;
      case 'top_risky_hosts':
        return <TopRiskyHostsWidget {...commonProps} />;
      case 'critical_vulns':
        return <CriticalVulnsWidget {...commonProps} />;
      case 'upcoming_scheduled_scans':
        return <UpcomingScansWidget {...commonProps} />;
      case 'threat_intel':
        return <ThreatIntelWidget {...commonProps} />;
      case 'my_assignments':
        return <MyAssignmentsWidget {...commonProps} />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading dashboard...</div>
      </div>
    );
  }

  const layout = widgets.map((w) => ({
    i: w.id,
    x: w.x,
    y: w.y,
    w: w.w,
    h: w.h,
  }));

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={toggleEditMode}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              isEditMode
                ? 'bg-primary text-white'
                : 'bg-dark-surface text-slate-300 hover:text-white border border-dark-border'
            }`}
          >
            <LayoutIcon className="h-4 w-4" />
            {isEditMode ? 'Exit Edit Mode' : 'Customize Dashboard'}
          </button>

          {isEditMode && (
            <>
              <div className="relative">
                <button
                  onClick={() => setShowAddMenu(!showAddMenu)}
                  className="flex items-center gap-2 px-4 py-2 bg-dark-surface text-slate-300 hover:text-white border border-dark-border rounded-lg transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  Add Widget
                </button>

                {showAddMenu && (
                  <>
                    <div
                      className="fixed inset-0 z-40"
                      onClick={() => setShowAddMenu(false)}
                    />
                    <div className="absolute top-full mt-2 left-0 bg-dark-surface border border-dark-border rounded-lg shadow-xl z-50 min-w-[200px]">
                      {WIDGET_TYPES.map((type) => (
                        <button
                          key={type.type}
                          onClick={() => addWidget(type.type)}
                          className="w-full text-left px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-dark-hover transition-colors first:rounded-t-lg last:rounded-b-lg"
                        >
                          {type.label}
                        </button>
                      ))}
                    </div>
                  </>
                )}
              </div>

              <button
                onClick={saveDashboardConfig}
                disabled={saving}
                className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="h-4 w-4" />
                {saving ? 'Saving...' : 'Save Layout'}
              </button>
            </>
          )}
        </div>

        {isEditMode && (
          <div className="text-sm text-slate-400">
            Drag widgets to reposition, resize from corners
          </div>
        )}
      </div>

      {/* Grid Layout */}
      <GridLayout
        className="layout"
        layout={layout}
        cols={12}
        rowHeight={100}
        width={1200}
        isDraggable={isEditMode}
        isResizable={isEditMode}
        onLayoutChange={handleLayoutChange}
        draggableHandle=".drag-handle"
      >
        {widgets.map((widget) => (
          <div key={widget.id} className={isEditMode ? 'cursor-move' : ''}>
            {renderWidget(widget)}
          </div>
        ))}
      </GridLayout>

      {widgets.length === 0 && (
        <div className="text-center py-12 text-slate-400">
          <LayoutIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>No widgets added yet</p>
          {isEditMode && (
            <button
              onClick={() => setShowAddMenu(true)}
              className="mt-4 text-primary hover:underline"
            >
              Add your first widget
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default DashboardCustomizer;
