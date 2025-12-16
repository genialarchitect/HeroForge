import React, { useMemo, useState } from 'react';
import Layout from '../components/layout/Layout';
import ScanForm from '../components/scan/ScanForm';
import ScanList from '../components/scan/ScanList';
import ScanProgressCard from '../components/scan/ScanProgressCard';
import ActiveScansWidget from '../components/scan/ActiveScansWidget';
import ActivityFeed from '../components/scan/ActivityFeed';
import ResultsViewer from '../components/results/ResultsViewer';
import StatsOverview from '../components/dashboard/StatsOverview';
import VulnerabilityChart from '../components/charts/VulnerabilityChart';
import PortDistributionChart from '../components/charts/PortDistributionChart';
import AnalyticsDashboard from '../components/analytics/AnalyticsDashboard';
import { useScanStore } from '../store/scanStore';
import { useKeyboardShortcuts, formatShortcut } from '../hooks/useKeyboardShortcuts';
import { Keyboard, LayoutDashboard, BarChart3 } from 'lucide-react';

type TabId = 'scans' | 'analytics';

const DashboardPage: React.FC = () => {
  const { activeScan, results, setActiveScan, scans } = useScanStore();
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [activeTab, setActiveTab] = useState<TabId>('scans');

  // Handle scan selection from ActiveScansWidget
  const handleScanSelect = (scanId: string) => {
    const selectedScan = scans.find((s) => s.id === scanId);
    if (selectedScan) {
      setActiveScan(selectedScan);
    }
  };

  // Get hosts for active scan or all hosts if no active scan
  const displayHosts = useMemo(() => {
    if (activeScan && results.has(activeScan.id)) {
      return results.get(activeScan.id) || [];
    }
    // Aggregate all hosts from all scans for overview
    return Array.from(results.values()).flat();
  }, [activeScan, results]);

  // Keyboard shortcuts
  const shortcuts = [
    {
      key: 'f',
      ctrl: true,
      action: () => {
        // Focus search input (will be implemented in ResultsViewer)
        const searchInput = document.querySelector('input[placeholder*="Search"]') as HTMLInputElement;
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      },
      description: 'Focus search',
    },
    {
      key: 'k',
      ctrl: true,
      action: () => setShowShortcuts(!showShortcuts),
      description: 'Show keyboard shortcuts',
    },
    {
      key: 'Escape',
      action: () => setShowShortcuts(false),
      description: 'Close modals',
    },
  ];

  useKeyboardShortcuts({ shortcuts });

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">Network Triage Dashboard</h2>
            <p className="text-slate-400">Create scans, monitor progress, and analyze results in real-time</p>
          </div>
          <button
            onClick={() => setShowShortcuts(true)}
            className="flex items-center gap-2 px-3 py-2 text-sm text-slate-400 hover:text-white transition-colors border border-dark-border hover:border-primary rounded-lg"
          >
            <Keyboard className="h-4 w-4" />
            Shortcuts
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-dark-border pb-2">
          <button
            onClick={() => setActiveTab('scans')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === 'scans'
                ? 'bg-dark-surface text-primary border-b-2 border-primary'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
          >
            <LayoutDashboard className="h-4 w-4" />
            Scans
          </button>
          <button
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${
              activeTab === 'analytics'
                ? 'bg-dark-surface text-primary border-b-2 border-primary'
                : 'text-slate-400 hover:text-white hover:bg-dark-hover'
            }`}
          >
            <BarChart3 className="h-4 w-4" />
            Analytics
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'scans' && (
          <>
            {/* Statistics Overview - Full Width */}
            <StatsOverview />

            {/* Active Scans Widget - Full Width */}
            <ActiveScansWidget onScanSelect={handleScanSelect} />

            {/* Main Grid Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Column: Scan Form + Scan List */}
              <div className="space-y-6">
                <ScanForm />
                <ScanList />
              </div>

              {/* Right Column: Progress, Charts, and Results */}
              <div className="lg:col-span-2 space-y-6">
                {/* Enhanced Scan Progress Card */}
                <ScanProgressCard scanId={activeScan?.id || null} />

                {/* Activity Feed - Show for running scans */}
                {activeScan?.status === 'running' && (
                  <ActivityFeed scanId={activeScan.id} />
                )}

                {/* Charts Row */}
                {displayHosts.length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <VulnerabilityChart hosts={displayHosts} />
                    <PortDistributionChart hosts={displayHosts} />
                  </div>
                )}

                {/* Results Viewer */}
                <ResultsViewer />
              </div>
            </div>
          </>
        )}

        {activeTab === 'analytics' && (
          <AnalyticsDashboard />
        )}

        {/* Keyboard Shortcuts Modal */}
        {showShortcuts && (
          <>
            <div
              className="fixed inset-0 bg-black/50 z-40 animate-fadeIn"
              onClick={() => setShowShortcuts(false)}
            />
            <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 bg-dark-surface border border-dark-border rounded-lg shadow-2xl p-6 w-full max-w-md animate-fadeIn">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                  <Keyboard className="h-5 w-5 text-primary" />
                  Keyboard Shortcuts
                </h3>
                <button
                  onClick={() => setShowShortcuts(false)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="space-y-2">
                {shortcuts.map((shortcut, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between py-2 px-3 bg-dark-bg rounded border border-dark-border"
                  >
                    <span className="text-sm text-slate-300">{shortcut.description}</span>
                    <kbd className="px-2 py-1 bg-dark-surface border border-dark-border rounded text-xs font-mono text-primary">
                      {formatShortcut(shortcut)}
                    </kbd>
                  </div>
                ))}
              </div>

              <p className="text-xs text-slate-500 mt-4 text-center">
                Press <kbd className="px-1 py-0.5 bg-dark-surface border border-dark-border rounded text-xs font-mono">Esc</kbd> to close
              </p>
            </div>
          </>
        )}
      </div>
    </Layout>
  );
};

export default DashboardPage;
