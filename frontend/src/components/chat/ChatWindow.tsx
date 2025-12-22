import React, { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { useChatStore } from '../../store/chatStore';
import { chatAPI } from '../../services/chatApi';
import ChatMessage from './ChatMessage';
import ChatInput from './ChatInput';
import { AlertCircle, Sparkles } from 'lucide-react';

const ChatWindow: React.FC = () => {
  const location = useLocation();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const {
    messages,
    conversationId,
    isLoading,
    error,
    addMessage,
    appendToLastMessage,
    finalizeLastMessage,
    setLoading,
    setError,
    setConversationId,
  } = useChatStore();

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = async (content: string) => {
    // Add user message
    const userMessage = {
      id: crypto.randomUUID(),
      role: 'user' as const,
      content,
      timestamp: new Date().toISOString(),
    };
    addMessage(userMessage);

    // Add placeholder assistant message
    const assistantMessage = {
      id: crypto.randomUUID(),
      role: 'assistant' as const,
      content: '',
      timestamp: new Date().toISOString(),
      isStreaming: true,
    };
    addMessage(assistantMessage);

    setLoading(true);
    setError(null);

    try {
      await chatAPI.sendMessage(
        content,
        conversationId,
        location.pathname,
        // onChunk
        (chunk) => {
          appendToLastMessage(chunk);
        },
        // onConversationId
        (id) => {
          setConversationId(id);
        },
        // onComplete
        () => {
          finalizeLastMessage();
          setLoading(false);
        },
        // onError
        (errorMsg) => {
          setError(errorMsg);
          // Remove the empty assistant message on error
          finalizeLastMessage();
          setLoading(false);
        }
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center mb-4">
              <Sparkles className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-lg font-medium text-white mb-2">
              HeroForge AI Assistant
            </h3>
            <p className="text-sm text-gray-400 max-w-xs">
              I have access to your security data and can help you understand
              vulnerabilities, plan scans, and navigate the platform.
            </p>
            <div className="mt-4 space-y-2 text-xs text-gray-500">
              <p>Try asking:</p>
              <ul className="space-y-1">
                <li>"What are my most critical vulnerabilities?"</li>
                <li>"How do I start a new scan?"</li>
                <li>"Explain CVE-2024-1234 to me"</li>
              </ul>
            </div>
          </div>
        ) : (
          <>
            {messages.map((message) => (
              <ChatMessage key={message.id} message={message} />
            ))}
          </>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Error Display */}
      {error && (
        <div className="mx-4 mb-2 p-2 bg-red-900/50 border border-red-700 rounded-lg flex items-center gap-2 text-sm text-red-300">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Input Area */}
      <div className="p-4 border-t border-gray-700">
        <ChatInput onSend={handleSendMessage} isLoading={isLoading} />
      </div>
    </div>
  );
};

export default ChatWindow;
