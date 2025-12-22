import React from 'react';
import { MessageCircle, X, Minus, Plus, Trash2, RotateCcw } from 'lucide-react';
import { useChatStore } from '../../store/chatStore';
import { useAuthStore } from '../../store/authStore';
import ChatWindow from './ChatWindow';

const ChatWidget: React.FC = () => {
  const {
    isOpen,
    isMinimized,
    messages,
    setOpen,
    setMinimized,
    startNewConversation,
  } = useChatStore();

  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  // Don't render if not authenticated
  if (!isAuthenticated) return null;

  const handleClose = () => {
    setOpen(false);
    setMinimized(false);
  };

  const handleMinimize = () => {
    setMinimized(true);
  };

  const handleMaximize = () => {
    setMinimized(false);
  };

  const handleNewChat = () => {
    startNewConversation();
  };

  // Floating button when closed or minimized
  if (!isOpen || isMinimized) {
    return (
      <div className="fixed bottom-4 right-4 z-50">
        <button
          onClick={() => {
            setOpen(true);
            setMinimized(false);
          }}
          className="group relative w-14 h-14 bg-gradient-to-br from-purple-600 to-indigo-600
                     hover:from-purple-500 hover:to-indigo-500
                     text-white rounded-full shadow-lg
                     flex items-center justify-center transition-all duration-200
                     hover:scale-105 hover:shadow-xl"
          aria-label="Open Zeus AI Assistant"
        >
          <MessageCircle className="w-6 h-6" />
          {messages.length > 0 && (
            <span className="absolute -top-1 -right-1 w-5 h-5 bg-cyan-500 rounded-full
                           text-xs font-medium flex items-center justify-center">
              {messages.length > 99 ? '99+' : messages.length}
            </span>
          )}
          {/* Tooltip */}
          <span className="absolute bottom-full right-0 mb-2 px-2 py-1 bg-gray-800 text-white
                         text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity
                         whitespace-nowrap pointer-events-none">
            Zeus
          </span>
        </button>
      </div>
    );
  }

  // Expanded chat window
  return (
    <div className="fixed bottom-4 right-4 z-50">
      <div className="w-96 h-[500px] bg-gray-800 border border-gray-700
                      rounded-lg shadow-2xl flex flex-col overflow-hidden
                      animate-in slide-in-from-bottom-4 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3
                        bg-gradient-to-r from-purple-600 to-indigo-600">
          <div className="flex items-center gap-2">
            <MessageCircle className="w-5 h-5 text-white" />
            <span className="font-medium text-white">Zeus</span>
          </div>
          <div className="flex items-center gap-1">
            {/* New Chat Button */}
            <button
              onClick={handleNewChat}
              className="p-1.5 text-white/80 hover:text-white hover:bg-white/10 rounded
                         transition-colors"
              title="New conversation"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
            {/* Minimize Button */}
            <button
              onClick={handleMinimize}
              className="p-1.5 text-white/80 hover:text-white hover:bg-white/10 rounded
                         transition-colors"
              title="Minimize"
            >
              <Minus className="w-4 h-4" />
            </button>
            {/* Close Button */}
            <button
              onClick={handleClose}
              className="p-1.5 text-white/80 hover:text-white hover:bg-white/10 rounded
                         transition-colors"
              title="Close"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Chat Window */}
        <ChatWindow />
      </div>
    </div>
  );
};

export default ChatWidget;
