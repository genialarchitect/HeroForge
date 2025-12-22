import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  isStreaming?: boolean;
}

interface ChatState {
  isOpen: boolean;
  isMinimized: boolean;
  isLoading: boolean;
  messages: ChatMessage[];
  conversationId: string | null;
  error: string | null;

  // Actions
  setOpen: (open: boolean) => void;
  setMinimized: (minimized: boolean) => void;
  toggle: () => void;
  addMessage: (message: ChatMessage) => void;
  appendToLastMessage: (content: string) => void;
  finalizeLastMessage: () => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  clearMessages: () => void;
  setConversationId: (id: string | null) => void;
  startNewConversation: () => void;
}

export const useChatStore = create<ChatState>()(
  persist(
    (set, get) => ({
      isOpen: false,
      isMinimized: false,
      isLoading: false,
      messages: [],
      conversationId: null,
      error: null,

      setOpen: (open) => set({ isOpen: open }),

      setMinimized: (minimized) => set({ isMinimized: minimized }),

      toggle: () => {
        const state = get();
        if (state.isOpen && !state.isMinimized) {
          set({ isMinimized: true });
        } else {
          set({ isOpen: true, isMinimized: false });
        }
      },

      addMessage: (message) => set((state) => ({
        messages: [...state.messages, message],
        error: null,
      })),

      appendToLastMessage: (content) => set((state) => {
        const messages = [...state.messages];
        const lastIndex = messages.length - 1;
        if (lastIndex >= 0 && messages[lastIndex].role === 'assistant') {
          messages[lastIndex] = {
            ...messages[lastIndex],
            content: messages[lastIndex].content + content,
          };
        }
        return { messages };
      }),

      finalizeLastMessage: () => set((state) => {
        const messages = [...state.messages];
        const lastIndex = messages.length - 1;
        if (lastIndex >= 0 && messages[lastIndex].isStreaming) {
          messages[lastIndex] = {
            ...messages[lastIndex],
            isStreaming: false,
          };
        }
        return { messages };
      }),

      setLoading: (isLoading) => set({ isLoading }),

      setError: (error) => set({ error }),

      clearMessages: () => set({ messages: [], conversationId: null, error: null }),

      setConversationId: (id) => set({ conversationId: id }),

      startNewConversation: () => set({
        messages: [],
        conversationId: null,
        error: null,
        isLoading: false,
      }),
    }),
    {
      name: 'heroforge-chat',
      partialize: (state) => ({
        messages: state.messages.slice(-50), // Keep last 50 messages
        conversationId: state.conversationId,
      }),
    }
  )
);
