import React, { useState } from 'react';
import { Check, Copy, FileCode } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
  description?: string;
  filename?: string;
  showLineNumbers?: boolean;
  className?: string;
}

const languageColors: Record<string, string> = {
  bash: 'text-green-400',
  sh: 'text-green-400',
  shell: 'text-green-400',
  powershell: 'text-blue-400',
  ps1: 'text-blue-400',
  python: 'text-yellow-400',
  py: 'text-yellow-400',
  javascript: 'text-yellow-300',
  js: 'text-yellow-300',
  typescript: 'text-blue-300',
  ts: 'text-blue-300',
  terraform: 'text-purple-400',
  tf: 'text-purple-400',
  hcl: 'text-purple-400',
  yaml: 'text-red-400',
  yml: 'text-red-400',
  json: 'text-orange-400',
  sql: 'text-cyan-400',
  rust: 'text-orange-500',
  go: 'text-cyan-300',
  dockerfile: 'text-blue-500',
  nginx: 'text-green-500',
  apache: 'text-red-500',
};

const languageLabels: Record<string, string> = {
  bash: 'Bash',
  sh: 'Shell',
  shell: 'Shell',
  powershell: 'PowerShell',
  ps1: 'PowerShell',
  python: 'Python',
  py: 'Python',
  javascript: 'JavaScript',
  js: 'JavaScript',
  typescript: 'TypeScript',
  ts: 'TypeScript',
  terraform: 'Terraform',
  tf: 'Terraform',
  hcl: 'HCL',
  yaml: 'YAML',
  yml: 'YAML',
  json: 'JSON',
  sql: 'SQL',
  rust: 'Rust',
  go: 'Go',
  dockerfile: 'Dockerfile',
  nginx: 'Nginx',
  apache: 'Apache',
};

const CodeBlock: React.FC<CodeBlockProps> = ({
  code,
  language = 'bash',
  title,
  description,
  filename,
  showLineNumbers = true,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const lines = code.split('\n');
  const langColor = languageColors[language.toLowerCase()] || 'text-gray-400';
  const langLabel = languageLabels[language.toLowerCase()] || language.toUpperCase();

  return (
    <div className={`rounded-lg overflow-hidden bg-gray-900 border border-gray-700 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <FileCode className={`h-4 w-4 ${langColor}`} />
          <div className="flex flex-col">
            {title && <span className="text-sm font-medium text-white">{title}</span>}
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span className={langColor}>{langLabel}</span>
              {filename && (
                <>
                  <span>•</span>
                  <span className="font-mono">{filename}</span>
                </>
              )}
            </div>
          </div>
        </div>
        <button
          onClick={handleCopy}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all ${
            copied
              ? 'bg-green-600/20 text-green-400'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600 hover:text-white'
          }`}
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              Copy
            </>
          )}
        </button>
      </div>

      {/* Description */}
      {description && (
        <div className="px-4 py-2 bg-gray-800/50 border-b border-gray-700">
          <p className="text-sm text-gray-400">{description}</p>
        </div>
      )}

      {/* Code */}
      <div className="overflow-x-auto">
        <pre className="p-4 text-sm">
          <code className="font-mono">
            {lines.map((line, index) => (
              <div key={index} className="flex">
                {showLineNumbers && (
                  <span className="select-none text-gray-600 w-8 text-right pr-4 flex-shrink-0">
                    {index + 1}
                  </span>
                )}
                <span className="text-gray-100 whitespace-pre">{line || ' '}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
};

export default CodeBlock;
