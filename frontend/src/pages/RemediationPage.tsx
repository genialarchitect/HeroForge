import React, { useState, useEffect } from 'react';
import Header from '../components/layout/Header';
import RemediationBoard from '../components/vulnerabilities/RemediationBoard';
import VulnerabilityDetail from '../components/vulnerabilities/VulnerabilityDetail';
import { scanAPI, vulnerabilityAPI } from '../services/api';
import type { ScanResult, VulnerabilityStats } from '../types';

const RemediationPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | undefined>();
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
  const [stats, setStats] = useState<VulnerabilityStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      loadStats();
    }
  }, [selectedScanId]);

  const loadScans = async () => {
    try {
      setLoading(true);
      const response = await scanAPI.list();
      // Filter to only completed scans
      const completedScans = response.data.filter((s) => s.status === 'completed');
      setScans(completedScans);
      if (completedScans.length > 0 && !selectedScanId) {
        setSelectedScanId(completedScans[0].id);
      }
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    if (!selectedScanId) return;
    try {
      const response = await vulnerabilityAPI.getStats(selectedScanId);
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const handleVulnerabilityClick = (vulnId: string) => {
    setSelectedVulnId(vulnId);
  };

  const handleDetailClose = () => {
    setSelectedVulnId(null);
  };

  const handleDetailUpdate = () => {
    loadStats();
  };

  return (
    <div className="min-h-screen bg-gray-950">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white">Remediation Workflow</h1>
          <p className="mt-2 text-gray-400">
            Track and manage vulnerability remediation progress with a Kanban-style board
          </p>
        </div>

        {/* Scan Selector and Stats */}
        <div className="bg-gray-900 rounded-lg p-6 mb-6 border border-gray-800">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Select Scan
              </label>
              <select
                value={selectedScanId || ''}
                onChange={(e) => setSelectedScanId(e.target.value || undefined)}
                className="w-full md:w-96 rounded-md bg-gray-800 border-gray-700 text-white shadow-sm focus:border-blue-500 focus:ring-blue-500"
                disabled={loading}
              >
                <option value="">Select a scan...</option>
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.name} - {new Date(scan.created_at).toLocaleDateString()}
                  </option>
                ))}
              </select>
            </div>

            {/* Stats Summary */}
            {stats && (
              <div className="flex flex-wrap gap-4">
                <div className="bg-gray-800 rounded-lg px-4 py-2 text-center">
                  <div className="text-2xl font-bold text-white">{stats.total}</div>
                  <div className="text-xs text-gray-400">Total</div>
                </div>
                <div className="bg-red-900/30 rounded-lg px-4 py-2 text-center border border-red-800">
                  <div className="text-2xl font-bold text-red-400">{stats.open}</div>
                  <div className="text-xs text-gray-400">Open</div>
                </div>
                <div className="bg-yellow-900/30 rounded-lg px-4 py-2 text-center border border-yellow-800">
                  <div className="text-2xl font-bold text-yellow-400">{stats.in_progress}</div>
                  <div className="text-xs text-gray-400">In Progress</div>
                </div>
                <div className="bg-green-900/30 rounded-lg px-4 py-2 text-center border border-green-800">
                  <div className="text-2xl font-bold text-green-400">{stats.resolved}</div>
                  <div className="text-xs text-gray-400">Resolved</div>
                </div>
              </div>
            )}
          </div>

          {/* Severity Breakdown */}
          {stats && (
            <div className="mt-4 pt-4 border-t border-gray-800">
              <div className="text-sm text-gray-400 mb-2">By Severity</div>
              <div className="flex gap-4">
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded bg-red-500"></span>
                  <span className="text-gray-300">Critical: {stats.critical}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded bg-orange-500"></span>
                  <span className="text-gray-300">High: {stats.high}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded bg-yellow-500"></span>
                  <span className="text-gray-300">Medium: {stats.medium}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded bg-blue-500"></span>
                  <span className="text-gray-300">Low: {stats.low}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Remediation Board */}
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          {loading ? (
            <div className="flex justify-center items-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>
          ) : scans.length === 0 ? (
            <div className="text-center py-12 text-gray-400">
              <p className="text-lg mb-2">No completed scans found</p>
              <p className="text-sm">Run a scan with vulnerability detection enabled to see results here</p>
            </div>
          ) : (
            <RemediationBoard
              scanId={selectedScanId}
              onVulnerabilityClick={handleVulnerabilityClick}
            />
          )}
        </div>
      </main>

      {/* Vulnerability Detail Modal */}
      {selectedVulnId && (
        <VulnerabilityDetail
          vulnerabilityId={selectedVulnId}
          onClose={handleDetailClose}
          onUpdate={handleDetailUpdate}
        />
      )}
    </div>
  );
};

export default RemediationPage;
