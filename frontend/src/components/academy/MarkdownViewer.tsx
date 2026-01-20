import React, { useEffect, useRef } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeExample {
  language: string;
  code: string;
}

interface MarkdownViewerProps {
  content: string;
  codeExamples?: CodeExample[];
}

// Simple markdown parser for basic formatting
function parseMarkdown(text: string): string {
  let html = text;

  // Escape HTML entities
  html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Headers
  html = html.replace(/^### (.*$)/gm, '<h3 class="text-xl font-bold text-white mt-6 mb-3">$1</h3>');
  html = html.replace(/^## (.*$)/gm, '<h2 class="text-2xl font-bold text-white mt-8 mb-4">$1</h2>');
  html = html.replace(/^# (.*$)/gm, '<h1 class="text-3xl font-bold text-white mt-8 mb-4">$1</h1>');

  // Bold and italic
  html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>');
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

  // Code blocks (triple backticks)
  html = html.replace(
    /```(\w*)\n([\s\S]*?)```/g,
    '<pre class="code-block" data-language="$1"><code>$2</code></pre>'
  );

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="bg-gray-800 text-cyan-400 px-1.5 py-0.5 rounded text-sm">$1</code>');

  // Links
  html = html.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:text-cyan-300 underline">$1</a>'
  );

  // Unordered lists
  html = html.replace(/^\s*[-*] (.*$)/gm, '<li class="ml-4">$1</li>');
  html = html.replace(/(<li.*<\/li>\n?)+/g, '<ul class="list-disc list-inside space-y-1 my-4">$&</ul>');

  // Ordered lists
  html = html.replace(/^\s*\d+\. (.*$)/gm, '<li class="ml-4">$1</li>');

  // Blockquotes
  html = html.replace(
    /^> (.*$)/gm,
    '<blockquote class="border-l-4 border-cyan-500 pl-4 py-2 my-4 text-gray-300 italic">$1</blockquote>'
  );

  // Horizontal rules
  html = html.replace(/^---$/gm, '<hr class="border-gray-700 my-6" />');

  // Paragraphs (double newline)
  html = html.replace(/\n\n/g, '</p><p class="my-4 text-gray-300 leading-relaxed">');

  // Single newlines to line breaks
  html = html.replace(/\n/g, '<br />');

  // Wrap in paragraph if not already
  if (!html.startsWith('<')) {
    html = '<p class="my-4 text-gray-300 leading-relaxed">' + html + '</p>';
  }

  return html;
}

// Get syntax highlighting classes for a language
function getLanguageClass(language: string): string {
  const langMap: Record<string, string> = {
    javascript: 'language-javascript',
    typescript: 'language-typescript',
    js: 'language-javascript',
    ts: 'language-typescript',
    python: 'language-python',
    py: 'language-python',
    rust: 'language-rust',
    go: 'language-go',
    bash: 'language-bash',
    shell: 'language-bash',
    sh: 'language-bash',
    sql: 'language-sql',
    json: 'language-json',
    yaml: 'language-yaml',
    yml: 'language-yaml',
    html: 'language-html',
    css: 'language-css',
    c: 'language-c',
    cpp: 'language-cpp',
    java: 'language-java',
    ruby: 'language-ruby',
    php: 'language-php',
  };
  return langMap[language.toLowerCase()] || 'language-plaintext';
}

// Code block with copy button
const CodeBlock: React.FC<{ code: string; language: string }> = ({ code, language }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="relative group my-4">
      {/* Language badge */}
      {language && (
        <span className="absolute top-2 left-3 text-xs text-gray-500 uppercase">
          {language}
        </span>
      )}

      {/* Copy button */}
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 p-2 rounded bg-gray-700 text-gray-400 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity"
        title="Copy code"
      >
        {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
      </button>

      {/* Code content */}
      <pre
        className={`bg-gray-900 border border-gray-700 rounded-lg p-4 pt-8 overflow-x-auto ${getLanguageClass(language)}`}
      >
        <code className="text-sm text-gray-300 font-mono">{code}</code>
      </pre>
    </div>
  );
};

const MarkdownViewer: React.FC<MarkdownViewerProps> = ({ content, codeExamples }) => {
  const contentRef = useRef<HTMLDivElement>(null);

  // Process code blocks after rendering
  useEffect(() => {
    if (!contentRef.current) return;

    // Find all pre.code-block elements and enhance them
    const codeBlocks = contentRef.current.querySelectorAll('pre.code-block');
    codeBlocks.forEach((block) => {
      const pre = block as HTMLPreElement;
      const language = pre.dataset.language || '';
      const code = pre.querySelector('code')?.textContent || '';

      // Create wrapper div
      const wrapper = document.createElement('div');
      wrapper.className = 'relative group my-4';

      // Language badge
      if (language) {
        const badge = document.createElement('span');
        badge.className = 'absolute top-2 left-3 text-xs text-gray-500 uppercase';
        badge.textContent = language;
        wrapper.appendChild(badge);
      }

      // Copy button
      const button = document.createElement('button');
      button.className =
        'absolute top-2 right-2 p-2 rounded bg-gray-700 text-gray-400 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity';
      button.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>';
      button.onclick = async () => {
        try {
          await navigator.clipboard.writeText(code);
          button.innerHTML = '<svg class="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
          setTimeout(() => {
            button.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>';
          }, 2000);
        } catch (err) {
          console.error('Failed to copy:', err);
        }
      };
      wrapper.appendChild(button);

      // Style the pre element
      pre.className = `bg-gray-900 border border-gray-700 rounded-lg p-4 pt-8 overflow-x-auto ${getLanguageClass(language)}`;
      const codeEl = pre.querySelector('code');
      if (codeEl) {
        codeEl.className = 'text-sm text-gray-300 font-mono';
      }

      // Wrap the pre
      pre.parentNode?.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);
    });
  }, [content]);

  const parsedContent = parseMarkdown(content);

  return (
    <div className="markdown-viewer">
      {/* Main markdown content */}
      <div
        ref={contentRef}
        className="prose prose-invert max-w-none"
        dangerouslySetInnerHTML={{ __html: parsedContent }}
      />

      {/* Additional code examples */}
      {codeExamples && codeExamples.length > 0 && (
        <div className="mt-8">
          <h3 className="text-xl font-bold text-white mb-4">Code Examples</h3>
          <div className="space-y-4">
            {codeExamples.map((example, index) => (
              <CodeBlock key={index} code={example.code} language={example.language} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default MarkdownViewer;
