import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import WebAppScanForm from '../components/webapp/WebAppScanForm';
import WebAppResults from '../components/webapp/WebAppResults';

const WebAppScanPage: React.FC = () => {
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  const handleScanSuccess = (scanId: string) => {
    setCurrentScanId(scanId);
  };

  const handleNewScan = () => {
    setCurrentScanId(null);
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-purple-600" />
            <h1 className="text-3xl font-bold text-gray-900">Web Application Scanner</h1>
          </div>
          <p className="text-gray-600">
            Perform comprehensive security testing on web applications
          </p>
        </div>

        {!currentScanId ? (
          <WebAppScanForm onSuccess={handleScanSuccess} />
        ) : (
          <div className="space-y-6">
            <div className="flex justify-end">
              <button
                onClick={handleNewScan}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
              >
                New Scan
              </button>
            </div>
            <WebAppResults scanId={currentScanId} />
          </div>
        )}
      </div>
    </div>
  );
};

export default WebAppScanPage;
