import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { chatAPI, ChatMessageResponse } from '../services/chatApi';
import { useCopilotStore, CopilotContext } from '../store/copilotStore';
import { Sparkles, MessageSquare } from 'lucide-react';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  type?: 'text' | 'code' | 'vulnerability' | 'report';
  isStreaming?: boolean;
}

interface QuickAction {
  id: string;
  label: string;
  icon: string;
  prompt: string;
  description: string;
}

const quickActions: QuickAction[] = [
  {
    id: 'explain-vuln',
    label: 'Explain Vulnerability',
    icon: '🔍',
    prompt: 'Explain the vulnerability CVE-',
    description: 'Get a plain-English explanation of any CVE'
  },
  {
    id: 'attack-path',
    label: 'Attack Path Analysis',
    icon: '🎯',
    prompt: 'Analyze the attack path for compromising ',
    description: 'Understand how an attacker could exploit vulnerabilities'
  },
  {
    id: 'remediation',
    label: 'Remediation Script',
    icon: '🔧',
    prompt: 'Generate a remediation script for ',
    description: 'Auto-generate fix scripts for common issues'
  },
  {
    id: 'executive-summary',
    label: 'Executive Summary',
    icon: '📊',
    prompt: 'Write an executive summary for the latest scan results',
    description: 'Draft professional summaries for stakeholders'
  },
  {
    id: 'risk-priority',
    label: 'Risk Prioritization',
    icon: '⚡',
    prompt: 'Prioritize the vulnerabilities from my last scan by business risk',
    description: 'AI-ranked vulnerability list based on context'
  },
  {
    id: 'threat-brief',
    label: 'Threat Briefing',
    icon: '📰',
    prompt: 'Give me a threat briefing for today',
    description: 'Daily AI-generated threat summary'
  }
];

interface AICopilotPanelProps {
  isOpen?: boolean;
  onClose?: () => void;
  context?: CopilotContext;
}

const AICopilotPanel: React.FC<AICopilotPanelProps> = ({
  isOpen: propIsOpen,
  onClose: propOnClose,
  context: propContext
}) => {
  // Use store if no props provided (for global usage)
  const store = useCopilotStore();
  const isOpen = propIsOpen ?? store.isOpen;
  const onClose = propOnClose ?? store.close;
  const context = propContext ?? store.context;

  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'assistant',
      content: "Hello! I'm your AI Security Copilot. I can help you understand vulnerabilities, analyze attack paths, generate remediation scripts, and write reports. How can I assist you today?",
      timestamp: new Date(),
      type: 'text'
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(true);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Handle initial prompt from context
  useEffect(() => {
    if (context?.initialPrompt && isOpen) {
      setInput(context.initialPrompt);
      // Clear the initial prompt from context
      store.setContext({ ...context, initialPrompt: undefined });
    }
  }, [context?.initialPrompt, isOpen, store, context]);

  // Load conversation history on mount
  useEffect(() => {
    const loadHistory = async () => {
      if (conversationId) {
        try {
          const history = await chatAPI.getMessages(conversationId);
          if (history.length > 0) {
            const loadedMessages: Message[] = history.map((msg: ChatMessageResponse) => ({
              id: msg.id,
              role: msg.role,
              content: msg.content,
              timestamp: new Date(msg.created_at),
              type: msg.content.includes('```') ? 'code' : 'text'
            }));
            setMessages(loadedMessages);
            setShowQuickActions(false);
          }
        } catch (error) {
          console.debug('Could not load conversation history:', error);
        }
      }
    };
    loadHistory();
  }, [conversationId]);

  const buildPageContext = useCallback((): string | null => {
    if (!context) return null;

    const parts: string[] = [];
    if (context.scanId) parts.push(`Currently viewing scan: ${context.scanId}`);
    if (context.vulnerabilityId) parts.push(`Currently viewing vulnerability: ${context.vulnerabilityId}`);
    if (context.assetId) parts.push(`Currently viewing asset: ${context.assetId}`);
    if (context.pageContext) parts.push(context.pageContext);

    return parts.length > 0 ? parts.join('. ') : null;
  }, [context]);

  const handleSend = async () => {
    if (!input.trim() || isLoading || isStreaming) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
      type: 'text'
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    setIsStreaming(false);
    setShowQuickActions(false);

    // Create a placeholder message for streaming
    const assistantMessageId = (Date.now() + 1).toString();
    const assistantMessage: Message = {
      id: assistantMessageId,
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      type: 'text',
      isStreaming: true
    };
    setMessages(prev => [...prev, assistantMessage]);

    const pageContext = buildPageContext();

    try {
      await chatAPI.sendMessage(
        userMessage.content,
        conversationId,
        pageContext,
        // onChunk
        (chunk: string) => {
          setIsLoading(false);
          setIsStreaming(true);
          setMessages(prev => prev.map(msg =>
            msg.id === assistantMessageId
              ? { ...msg, content: msg.content + chunk }
              : msg
          ));
        },
        // onConversationId
        (id: string) => {
          setConversationId(id);
          store.setConversationId(id);
        },
        // onComplete
        (_tokensUsed: number) => {
          setIsLoading(false);
          setIsStreaming(false);
          setMessages(prev => prev.map(msg =>
            msg.id === assistantMessageId
              ? { ...msg, isStreaming: false, type: msg.content.includes('```') ? 'code' : 'text' }
              : msg
          ));
        },
        // onError
        (error: string) => {
          setIsLoading(false);
          setIsStreaming(false);
          setMessages(prev => prev.map(msg =>
            msg.id === assistantMessageId
              ? { ...msg, content: `Error: ${error}. Please try again.`, isStreaming: false }
              : msg
          ));
        }
      );
    } catch (error) {
      setIsLoading(false);
      setIsStreaming(false);
      setMessages(prev => prev.map(msg =>
        msg.id === assistantMessageId
          ? { ...msg, content: 'An error occurred. Please try again.', isStreaming: false }
          : msg
      ));
    }
  };

  const handleQuickAction = (action: QuickAction) => {
    // Build context-aware prompt
    let prompt = action.prompt;

    if (context?.vulnerabilityId && action.id === 'explain-vuln') {
      prompt = `Explain the vulnerability ${context.vulnerabilityId}`;
    } else if (context?.scanId && action.id === 'executive-summary') {
      prompt = `Write an executive summary for scan ${context.scanId}`;
    } else if (context?.scanId && action.id === 'risk-priority') {
      prompt = `Prioritize the vulnerabilities from scan ${context.scanId} by business risk`;
    }

    setInput(prompt);
    setShowQuickActions(false);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = async () => {
    // Delete conversation if exists
    if (conversationId) {
      try {
        await chatAPI.deleteConversation(conversationId);
      } catch (error) {
        console.debug('Could not delete conversation:', error);
      }
    }

    setConversationId(null);
    store.setConversationId(null);
    setMessages([{
      id: '1',
      role: 'assistant',
      content: "Chat cleared. How can I help you with your security assessment?",
      timestamp: new Date(),
      type: 'text'
    }]);
    setShowQuickActions(true);
  };

  const renderMarkdown = (content: string) => {
    return content.split('\n').map((line, i) => {
      if (line.startsWith('```')) {
        return null;
      }
      if (line.startsWith('## ')) {
        return <h3 key={i} className="text-lg font-bold mt-2 mb-1">{line.replace(/^##\s*/, '')}</h3>;
      }
      if (line.startsWith('### ')) {
        return <h4 key={i} className="text-base font-semibold mt-2 mb-1">{line.replace(/^###\s*/, '')}</h4>;
      }
      if (line.startsWith('**') && line.endsWith('**')) {
        return <p key={i} className="font-bold">{line.replace(/\*\*/g, '')}</p>;
      }
      if (line.startsWith('|')) {
        return <p key={i} className="font-mono text-xs">{line}</p>;
      }
      if (line.startsWith('- ') || line.startsWith('* ')) {
        return <p key={i} className="ml-4">• {line.slice(2)}</p>;
      }
      if (line.match(/^\d+\.\s/)) {
        return <p key={i} className="ml-4">{line}</p>;
      }
      return line ? <p key={i}>{line}</p> : <br key={i} />;
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[450px] bg-gray-900 border-l border-gray-700 shadow-2xl z-50 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-700 bg-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <Sparkles className="h-5 w-5 text-white" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">AI Copilot</h2>
            <p className="text-xs text-gray-400">Powered by Claude</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={clearChat}
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
            title="Clear chat"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
            title="Close (Cmd+K)"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      {/* Context Banner */}
      {context && (context.scanId || context.vulnerabilityId || context.assetId) && (
        <div className="px-4 py-2 bg-blue-900/30 border-b border-blue-800/50">
          <p className="text-sm text-blue-300">
            <span className="font-medium">Context: </span>
            {context.scanId && `Scan #${context.scanId}`}
            {context.vulnerabilityId && `Vulnerability ${context.vulnerabilityId}`}
            {context.assetId && `Asset ${context.assetId}`}
          </p>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[85%] rounded-lg p-3 ${
                message.role === 'user'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-100'
              }`}
            >
              <div className="prose prose-invert prose-sm max-w-none">
                {renderMarkdown(message.content)}
                {message.isStreaming && (
                  <span className="inline-block w-2 h-4 bg-blue-400 animate-pulse ml-1" />
                )}
              </div>
              <p className="text-xs opacity-50 mt-2">
                {message.timestamp.toLocaleTimeString()}
              </p>
            </div>
          </div>
        ))}

        {isLoading && !isStreaming && (
          <div className="flex justify-start">
            <div className="bg-gray-800 rounded-lg p-3">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions */}
      {showQuickActions && (
        <div className="p-4 border-t border-gray-700 bg-gray-800/50">
          <p className="text-sm text-gray-400 mb-3">Quick Actions:</p>
          <div className="grid grid-cols-2 gap-2">
            {quickActions.map((action) => (
              <button
                key={action.id}
                onClick={() => handleQuickAction(action)}
                className="flex items-center gap-2 p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors text-left"
              >
                <span className="text-lg">{action.icon}</span>
                <div>
                  <p className="text-sm font-medium text-white">{action.label}</p>
                  <p className="text-xs text-gray-400 line-clamp-1">{action.description}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Keyboard shortcut hint */}
      <div className="px-4 py-2 border-t border-gray-700 bg-gray-800/30">
        <p className="text-xs text-gray-500 text-center">
          Press <kbd className="px-1.5 py-0.5 bg-gray-700 rounded text-gray-300">Cmd</kbd> + <kbd className="px-1.5 py-0.5 bg-gray-700 rounded text-gray-300">K</kbd> to toggle
        </p>
      </div>

      {/* Input */}
      <div className="p-4 border-t border-gray-700 bg-gray-800">
        <div className="flex items-end gap-2">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask me anything about your security posture..."
            className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
            rows={2}
            disabled={isLoading || isStreaming}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading || isStreaming}
            className="px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Press Enter to send, Shift+Enter for new line
        </p>
      </div>
    </div>
  );
};

export default AICopilotPanel;
