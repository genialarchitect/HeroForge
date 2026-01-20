import { create } from 'zustand';

export interface CopilotContext {
  scanId?: string;
  vulnerabilityId?: string;
  assetId?: string;
  pageContext?: string;
  initialPrompt?: string;
}

interface CopilotState {
  isOpen: boolean;
  context: CopilotContext | null;
  conversationId: string | null;

  // Actions
  open: (context?: CopilotContext) => void;
  close: () => void;
  toggle: () => void;
  setContext: (context: CopilotContext | null) => void;
  setConversationId: (id: string | null) => void;
  openWithPrompt: (prompt: string, context?: CopilotContext) => void;
}

export const useCopilotStore = create<CopilotState>()((set, get) => ({
  isOpen: false,
  context: null,
  conversationId: null,

  open: (context?: CopilotContext) => {
    set({
      isOpen: true,
      context: context || null,
    });
  },

  close: () => {
    set({
      isOpen: false,
      // Keep context for when reopening
    });
  },

  toggle: () => {
    const { isOpen } = get();
    set({ isOpen: !isOpen });
  },

  setContext: (context: CopilotContext | null) => {
    set({ context });
  },

  setConversationId: (id: string | null) => {
    set({ conversationId: id });
  },

  openWithPrompt: (prompt: string, context?: CopilotContext) => {
    set({
      isOpen: true,
      context: {
        ...context,
        initialPrompt: prompt,
      },
    });
  },
}));
