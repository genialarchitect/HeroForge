import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import Layout from '../components/layout/Layout';
import Button from '../components/ui/Button';
import WebAppScanForm from '../components/webapp/WebAppScanForm';
import WebAppResults from '../components/webapp/WebAppResults';
import { EngagementRequiredBanner } from '../components/engagement';
import { useRequireEngagement } from '../hooks/useRequireEngagement';

const WebAppScanPage: React.FC = () => {
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const { hasEngagement } = useRequireEngagement();

  const handleScanSuccess = (scanId: string) => {
    setCurrentScanId(scanId);
  };

  const handleNewScan = () => {
    setCurrentScanId(null);
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold text-white">Web Application Scanner</h1>
          </div>
          <p className="text-slate-400">
            Perform comprehensive security testing on web applications
          </p>
        </div>

        <EngagementRequiredBanner toolName="Web Application Scanner" />

        {!currentScanId ? (
          hasEngagement ? (
            <WebAppScanForm onSuccess={handleScanSuccess} />
          ) : (
            <div className="bg-gray-800 rounded-lg p-8 text-center text-gray-400">
              <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Select an engagement above to start scanning</p>
            </div>
          )
        ) : (
          <div className="space-y-6">
            <div className="flex justify-end">
              <Button onClick={handleNewScan}>
                New Scan
              </Button>
            </div>
            <WebAppResults scanId={currentScanId} />
          </div>
        )}
      </div>
    </Layout>
  );
};

export default WebAppScanPage;
