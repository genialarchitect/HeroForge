/**
 * Chat API service with SSE streaming support
 */

const API_BASE = '/api';

export interface ChatSSEEvent {
  type: 'content' | 'done' | 'error';
  content?: string;
  conversation_id?: string;
  tokens_used?: number;
  error?: string;
}

export interface ConversationSummary {
  id: string;
  title: string | null;
  last_message: string | null;
  message_count: number;
  created_at: string;
  updated_at: string;
}

export interface ChatMessageResponse {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
  tokens_used: number | null;
}

export const chatAPI = {
  /**
   * Send a message and stream the response
   */
  sendMessage: async (
    message: string,
    conversationId: string | null,
    pageContext: string | null,
    onChunk: (chunk: string) => void,
    onConversationId: (id: string) => void,
    onComplete: (tokensUsed: number) => void,
    onError: (error: string) => void
  ): Promise<void> => {
    const token = localStorage.getItem('token');

    if (!token) {
      onError('Not authenticated');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          message,
          conversation_id: conversationId,
          page_context: pageContext,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Chat request failed: ${response.status}`);
      }

      // Handle SSE stream
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('Response body is not readable');
      }

      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Process complete SSE events
        const lines = buffer.split('\n');
        buffer = lines.pop() || ''; // Keep incomplete line in buffer

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (!data) continue;

            try {
              const event: ChatSSEEvent = JSON.parse(data);

              if (event.type === 'content' && event.content) {
                onChunk(event.content);
                if (event.conversation_id) {
                  onConversationId(event.conversation_id);
                }
              } else if (event.type === 'done') {
                if (event.conversation_id) {
                  onConversationId(event.conversation_id);
                }
                onComplete(event.tokens_used || 0);
                return;
              } else if (event.type === 'error' && event.error) {
                onError(event.error);
                return;
              }
            } catch {
              // Not JSON, might be plain text
              console.debug('Non-JSON SSE data:', data);
            }
          }
        }
      }

      // Stream ended without done event
      onComplete(0);
    } catch (error) {
      onError(error instanceof Error ? error.message : 'Failed to send message');
    }
  },

  /**
   * Get list of conversations
   */
  getConversations: async (): Promise<ConversationSummary[]> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/chat/conversations`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch conversations');
    }

    const data = await response.json();
    return data.conversations;
  },

  /**
   * Get messages for a conversation
   */
  getMessages: async (conversationId: string): Promise<ChatMessageResponse[]> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/chat/conversations/${conversationId}/messages`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch messages');
    }

    const data = await response.json();
    return data.messages;
  },

  /**
   * Delete a conversation
   */
  deleteConversation: async (conversationId: string): Promise<void> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/chat/conversations/${conversationId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to delete conversation');
    }
  },

  /**
   * Create a new conversation
   */
  createConversation: async (): Promise<string> => {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API_BASE}/chat/conversations`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to create conversation');
    }

    const data = await response.json();
    return data.id;
  },
};

export default chatAPI;
