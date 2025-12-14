import React, { useState } from 'react';
import { Copy, ChevronDown, ChevronUp, Terminal } from 'lucide-react';
import { toast } from 'react-toastify';

interface ServiceBannerProps {
  banner: string;
  port: number;
  service?: string;
}

const ServiceBanner: React.FC<ServiceBannerProps> = ({ banner, service }) => {
  const [expanded, setExpanded] = useState(false);

  const handleCopyBanner = () => {
    navigator.clipboard.writeText(banner);
    toast.success('Service banner copied to clipboard');
  };

  // Truncate long banners
  const isLong = banner.length > 100;
  const displayBanner = expanded || !isLong ? banner : banner.substring(0, 100) + '...';

  return (
    <div className="bg-dark-bg border border-dark-border rounded-lg p-3 mt-2">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-green-400" />
          <span className="text-xs font-semibold text-slate-300">
            Service Banner {service && `(${service})`}
          </span>
        </div>
        <button
          onClick={handleCopyBanner}
          className="text-slate-400 hover:text-white transition-colors p-1 rounded hover:bg-dark-surface"
          title="Copy banner"
        >
          <Copy className="h-3 w-3" />
        </button>
      </div>

      <pre className="bg-slate-900 rounded p-2 overflow-x-auto">
        <code className="text-xs text-green-400 font-mono whitespace-pre-wrap break-all">
          {displayBanner}
        </code>
      </pre>

      {isLong && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 text-xs text-primary hover:text-primary-light transition-colors mt-2"
        >
          {expanded ? (
            <>
              Show less <ChevronUp className="h-3 w-3" />
            </>
          ) : (
            <>
              Show full banner <ChevronDown className="h-3 w-3" />
            </>
          )}
        </button>
      )}
    </div>
  );
};

export default ServiceBanner;
