import React from 'react';
import Layout from '../components/layout/Layout';
import ScanComparison from '../components/compare/ScanComparison';
import { GitCompare } from 'lucide-react';

const ScanComparisonPage: React.FC = () => {
  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <GitCompare className="h-8 w-8 text-primary" />
            Scan Comparison Dashboard
          </h1>
          <p className="mt-2 text-gray-600 dark:text-slate-400">
            Compare two scans to identify changes in hosts, ports, services, and vulnerabilities over time
          </p>
        </div>

        {/* Comparison Component */}
        <ScanComparison />
      </div>
    </Layout>
  );
};

export default ScanComparisonPage;
