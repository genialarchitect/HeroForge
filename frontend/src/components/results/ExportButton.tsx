import React, { useState } from 'react';
import { Download, FileJson, FileText, Code, FileType } from 'lucide-react';
import { HostInfo } from '../../types';
import Button from '../ui/Button';
import { toast } from 'react-toastify';
import { format } from 'date-fns';
import axios from 'axios';

interface ExportButtonProps {
  hosts: HostInfo[];
  scanName?: string;
  scanId?: string;
  disabled?: boolean;
}

type ExportFormat = 'json' | 'csv' | 'html' | 'markdown';

const ExportButton: React.FC<ExportButtonProps> = ({ hosts, scanName = 'scan', scanId, disabled = false }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const exportAsJSON = () => {
    const data = {
      scan: scanName,
      exportedAt: new Date().toISOString(),
      totalHosts: hosts.length,
      hosts: hosts.map(host => ({
        ip: host.target.ip,
        hostname: host.target.hostname,
        isAlive: host.is_alive,
        osGuess: host.os_guess,
        ports: host.ports.map(port => ({
          port: port.port,
          protocol: port.protocol,
          state: port.state,
          service: port.service,
        })),
        vulnerabilities: host.vulnerabilities,
      })),
    };

    downloadFile(
      JSON.stringify(data, null, 2),
      `${scanName}_${format(new Date(), 'yyyy-MM-dd_HHmmss')}.json`,
      'application/json'
    );
    toast.success('Exported as JSON');
  };

  const exportAsCSV = () => {
    // CSV headers
    let csv = 'IP,Hostname,Alive,OS,Ports,Vulnerabilities,Critical,High,Medium,Low\n';

    // Add rows
    hosts.forEach(host => {
      const ports = host.ports.filter(p => p.state === 'Open').map(p => p.port).join(';');
      const vulnCounts = {
        Critical: host.vulnerabilities.filter(v => v.severity === 'Critical').length,
        High: host.vulnerabilities.filter(v => v.severity === 'High').length,
        Medium: host.vulnerabilities.filter(v => v.severity === 'Medium').length,
        Low: host.vulnerabilities.filter(v => v.severity === 'Low').length,
      };

      csv += `"${host.target.ip}",`;
      csv += `"${host.target.hostname || ''}",`;
      csv += `${host.is_alive},`;
      csv += `"${host.os_guess?.os_family || ''}",`;
      csv += `"${ports}",`;
      csv += `${host.vulnerabilities.length},`;
      csv += `${vulnCounts.Critical},`;
      csv += `${vulnCounts.High},`;
      csv += `${vulnCounts.Medium},`;
      csv += `${vulnCounts.Low}\n`;
    });

    downloadFile(
      csv,
      `${scanName}_${format(new Date(), 'yyyy-MM-dd_HHmmss')}.csv`,
      'text/csv'
    );
    toast.success('Exported as CSV');
  };

  const exportAsHTML = () => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeroForge Scan Report - ${scanName}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #3b82f6; margin-bottom: 0.5rem; }
    .meta { color: #94a3b8; margin-bottom: 2rem; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 1.5rem;
    }
    .card h3 { color: #cbd5e1; font-size: 0.875rem; margin-bottom: 0.5rem; }
    .card .value { font-size: 2rem; font-weight: bold; }
    .host {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
    }
    .host-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid #334155;
    }
    .host-ip { font-family: monospace; font-size: 1.25rem; color: #3b82f6; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
    .section { margin-top: 1rem; }
    .section h4 { color: #cbd5e1; margin-bottom: 0.5rem; font-size: 0.875rem; }
    .ports { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 0.5rem; }
    .port {
      background: #0f172a;
      padding: 0.5rem;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.875rem;
    }
    .vuln {
      background: rgba(239, 68, 68, 0.1);
      border-left: 4px solid #ef4444;
      padding: 1rem;
      margin-bottom: 0.5rem;
      border-radius: 4px;
    }
    .vuln-title { color: #fff; font-weight: 600; margin-bottom: 0.25rem; }
    .vuln-cve { color: #3b82f6; font-family: monospace; font-size: 0.875rem; }
    @media print {
      body { background: white; color: black; }
      .card, .host { border-color: #ccc; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ HeroForge Scan Report</h1>
    <p class="meta">
      Scan: ${scanName} |
      Generated: ${format(new Date(), 'PPpp')} |
      Hosts: ${hosts.length}
    </p>

    <div class="summary">
      <div class="card">
        <h3>Total Hosts</h3>
        <div class="value" style="color: #3b82f6;">${hosts.length}</div>
      </div>
      <div class="card">
        <h3>Open Ports</h3>
        <div class="value" style="color: #22c55e;">
          ${hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'Open').length, 0)}
        </div>
      </div>
      <div class="card">
        <h3>Total Vulnerabilities</h3>
        <div class="value" style="color: #eab308;">
          ${hosts.reduce((sum, h) => sum + h.vulnerabilities.length, 0)}
        </div>
      </div>
      <div class="card">
        <h3>Critical Findings</h3>
        <div class="value" style="color: #ef4444;">
          ${hosts.reduce((sum, h) => sum + h.vulnerabilities.filter(v => v.severity === 'Critical').length, 0)}
        </div>
      </div>
    </div>

    <h2 style="color: #cbd5e1; margin-bottom: 1rem;">Discovered Hosts</h2>
    ${hosts.map(host => `
      <div class="host">
        <div class="host-header">
          <div>
            <div class="host-ip">${host.target.ip}</div>
            ${host.target.hostname ? `<div style="color: #94a3b8; font-size: 0.875rem;">${host.target.hostname}</div>` : ''}
          </div>
          <div>
            ${host.vulnerabilities.length > 0 ? `<span class="badge badge-critical">${host.vulnerabilities.length} vulnerabilities</span>` : ''}
          </div>
        </div>

        ${host.os_guess ? `
          <div class="section">
            <h4>OS Detection</h4>
            <p style="color: #94a3b8; font-size: 0.875rem;">
              ${host.os_guess.os_family} ${host.os_guess.os_version || ''} (${host.os_guess.confidence}% confidence)
            </p>
          </div>
        ` : ''}

        ${host.ports.filter(p => p.state === 'Open').length > 0 ? `
          <div class="section">
            <h4>Open Ports (${host.ports.filter(p => p.state === 'Open').length})</h4>
            <div class="ports">
              ${host.ports.filter(p => p.state === 'Open').map(port => `
                <div class="port">
                  <strong>${port.port}/${port.protocol}</strong><br>
                  ${port.service ? `<span style="color: #94a3b8;">${port.service.name} ${port.service.version || ''}</span>` : ''}
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        ${host.vulnerabilities.length > 0 ? `
          <div class="section">
            <h4>Vulnerabilities (${host.vulnerabilities.length})</h4>
            ${host.vulnerabilities.map(vuln => `
              <div class="vuln">
                <div class="vuln-title">${vuln.title}</div>
                ${vuln.cve_id ? `<div class="vuln-cve">${vuln.cve_id}</div>` : ''}
                <span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    `).join('')}

    <footer style="margin-top: 2rem; padding-top: 2rem; border-top: 1px solid #334155; text-align: center; color: #64748b;">
      <p>Generated by HeroForge - Network Reconnaissance Tool</p>
      <p style="font-size: 0.875rem;">For authorized security testing only</p>
    </footer>
  </div>
</body>
</html>`;

    downloadFile(
      html,
      `${scanName}_${format(new Date(), 'yyyy-MM-dd_HHmmss')}.html`,
      'text/html'
    );
    toast.success('Exported as HTML report');
  };

  const exportAsMarkdown = async () => {
    if (!scanId) {
      toast.error('Scan ID required for Markdown export');
      return;
    }

    setIsExporting(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/scans/${scanId}/export/markdown`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        responseType: 'blob',
      });

      // Get filename from Content-Disposition header or use default
      const contentDisposition = response.headers['content-disposition'];
      let filename = `${scanName}_${format(new Date(), 'yyyy-MM-dd_HHmmss')}.md`;
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?([^";\n]+)"?/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      toast.success('Exported as Markdown');
    } catch (error) {
      console.error('Markdown export failed:', error);
      toast.error('Failed to export as Markdown');
    } finally {
      setIsExporting(false);
    }
  };

  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleExport = (format: ExportFormat) => {
    setIsOpen(false);

    if (hosts.length === 0) {
      toast.error('No results to export');
      return;
    }

    switch (format) {
      case 'json':
        exportAsJSON();
        break;
      case 'csv':
        exportAsCSV();
        break;
      case 'html':
        exportAsHTML();
        break;
      case 'markdown':
        exportAsMarkdown();
        break;
    }
  };

  return (
    <div className="relative">
      <Button
        onClick={() => setIsOpen(!isOpen)}
        disabled={disabled || hosts.length === 0}
        variant="secondary"
      >
        <Download className="h-4 w-4 mr-2" />
        Export Results
      </Button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute right-0 mt-2 w-56 bg-dark-surface border border-dark-border rounded-lg shadow-xl z-20 overflow-hidden">
            <div className="p-2">
              <button
                onClick={() => handleExport('json')}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover rounded transition-colors"
              >
                <FileJson className="h-4 w-4 text-blue-400" />
                <div className="text-left">
                  <div className="font-medium">JSON</div>
                  <div className="text-xs text-slate-500">Full data export</div>
                </div>
              </button>

              <button
                onClick={() => handleExport('csv')}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover rounded transition-colors"
              >
                <FileText className="h-4 w-4 text-green-400" />
                <div className="text-left">
                  <div className="font-medium">CSV</div>
                  <div className="text-xs text-slate-500">Spreadsheet format</div>
                </div>
              </button>

              <button
                onClick={() => handleExport('html')}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover rounded transition-colors"
              >
                <Code className="h-4 w-4 text-purple-400" />
                <div className="text-left">
                  <div className="font-medium">HTML</div>
                  <div className="text-xs text-slate-500">Printable report</div>
                </div>
              </button>

              <button
                onClick={() => handleExport('markdown')}
                disabled={!scanId || isExporting}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm text-slate-300 hover:bg-dark-hover rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <FileType className="h-4 w-4 text-cyan-400" />
                <div className="text-left">
                  <div className="font-medium">Markdown</div>
                  <div className="text-xs text-slate-500">GitHub-flavored MD</div>
                </div>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default ExportButton;
