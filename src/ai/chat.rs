//! AI Chat Client
//!
//! Provides streaming and non-streaming chat completions via the configured LLM provider.
//! Supports multiple backends including Anthropic Claude and Ollama.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::ai::chat::{ChatClient, ChatMessage};
//!
//! let client = ChatClient::new().await?;
//!
//! // Non-streaming
//! let (response, tokens) = client.get_response("You are helpful.", messages).await?;
//!
//! // Streaming
//! let stream = client.stream_response("You are helpful.", messages).await?;
//! while let Some(chunk) = stream.next().await {
//!     match chunk {
//!         ChatStreamChunk::Content(text) => print!("{}", text),
//!         ChatStreamChunk::Done { .. } => break,
//!         ChatStreamChunk::Error(e) => eprintln!("Error: {}", e),
//!     }
//! }
//! ```

use anyhow::{anyhow, Result};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

use super::providers::{
    BoxedProvider, LLMRequest, LLMMessage, MessageRole, StreamChunk,
    get_provider, LLMConfig, LLMError,
};

/// Message for chat API (backwards compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }
}

impl From<ChatMessage> for LLMMessage {
    fn from(msg: ChatMessage) -> Self {
        let role = match msg.role.as_str() {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            "system" => MessageRole::System,
            _ => MessageRole::User, // Default to user for unknown roles
        };
        LLMMessage {
            role,
            content: msg.content,
        }
    }
}

impl From<LLMMessage> for ChatMessage {
    fn from(msg: LLMMessage) -> Self {
        Self {
            role: msg.role.to_string(),
            content: msg.content,
        }
    }
}

/// Stream chunk from chat (backwards compatible)
#[derive(Debug, Clone)]
pub enum ChatStreamChunk {
    /// Text content chunk
    Content(String),
    /// Stream completed with token usage
    Done { input_tokens: u32, output_tokens: u32 },
    /// Error occurred
    Error(String),
}

impl From<StreamChunk> for ChatStreamChunk {
    fn from(chunk: StreamChunk) -> Self {
        match chunk {
            StreamChunk::Content(text) => ChatStreamChunk::Content(text),
            StreamChunk::Done(usage) => ChatStreamChunk::Done {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
            },
            StreamChunk::Error(e) => ChatStreamChunk::Error(e),
        }
    }
}

/// Chat client using the configured LLM provider
pub struct ChatClient {
    provider: BoxedProvider,
}

impl ChatClient {
    /// Create a new chat client with the default configured provider
    pub async fn new() -> Result<Self> {
        let provider = get_provider(None).await
            .map_err(|e| anyhow!("Failed to initialize chat provider: {}", e))?;

        Ok(Self { provider })
    }

    /// Create chat client with custom configuration
    pub async fn with_config(config: &LLMConfig) -> Result<Self> {
        let provider = get_provider(Some(config)).await
            .map_err(|e| anyhow!("Failed to initialize chat provider: {}", e))?;

        Ok(Self { provider })
    }

    /// Create chat client with a specific provider
    pub fn with_provider(provider: BoxedProvider) -> Self {
        Self { provider }
    }

    /// Check if the chat client is configured and available
    pub fn is_configured() -> bool {
        // Check if any LLM provider is configured
        std::env::var("ANTHROPIC_API_KEY").is_ok() ||
        std::env::var("OLLAMA_BASE_URL").is_ok() ||
        std::env::var("OPENAI_API_KEY").is_ok()
    }

    /// Get the provider name
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Get the model being used
    pub fn model(&self) -> &str {
        self.provider.default_model()
    }

    /// Stream a response from the LLM
    pub async fn stream_response(
        &self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<Pin<Box<dyn Stream<Item = ChatStreamChunk> + Send>>> {
        let llm_messages: Vec<LLMMessage> = messages.into_iter().map(|m| m.into()).collect();

        let request = LLMRequest::new()
            .with_system_prompt(system_prompt)
            .with_streaming(true)
            .with_max_tokens(4096);

        // Add messages to request
        let request = llm_messages.into_iter().fold(request, |req, msg| {
            req.with_message(msg)
        });

        let stream = self.provider.stream(request).await
            .map_err(|e| self.map_error(e))?;

        // Convert StreamChunk to ChatStreamChunk
        use futures::StreamExt;
        let converted_stream = stream.map(|chunk| ChatStreamChunk::from(chunk));

        Ok(Box::pin(converted_stream))
    }

    /// Non-streaming response (for simple queries)
    pub async fn get_response(
        &self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<(String, u32)> {
        let llm_messages: Vec<LLMMessage> = messages.into_iter().map(|m| m.into()).collect();

        let request = LLMRequest::new()
            .with_system_prompt(system_prompt)
            .with_streaming(false)
            .with_max_tokens(4096);

        // Add messages to request
        let request = llm_messages.into_iter().fold(request, |req, msg| {
            req.with_message(msg)
        });

        let response = self.provider.complete(request).await
            .map_err(|e| self.map_error(e))?;

        let total_tokens = response.usage.total();

        Ok((response.content, total_tokens))
    }

    /// Map LLM errors to anyhow errors
    fn map_error(&self, error: LLMError) -> anyhow::Error {
        match error {
            LLMError::NotConfigured(msg) => anyhow!("Chat provider not configured: {}", msg),
            LLMError::ApiError { status, message } => anyhow!("Chat API error {}: {}", status, message),
            LLMError::RateLimited { retry_after_secs } => {
                if let Some(secs) = retry_after_secs {
                    anyhow!("Rate limited, retry after {} seconds", secs)
                } else {
                    anyhow!("Rate limited, try again later")
                }
            }
            LLMError::ModelNotFound(model) => anyhow!("Model not found: {}", model),
            LLMError::Unavailable(msg) => anyhow!("Chat provider unavailable: {}", msg),
            LLMError::NetworkError(msg) => anyhow!("Network error: {}", msg),
            LLMError::ParseError(msg) => anyhow!("Parse error: {}", msg),
            LLMError::StreamError(msg) => anyhow!("Stream error: {}", msg),
            LLMError::ContextLengthExceeded { used, max } => {
                anyhow!("Context length exceeded: {} > {} tokens", used, max)
            }
        }
    }
}

/// Legacy Claude client for backwards compatibility
///
/// This struct provides the original ClaudeClient API for code that
/// hasn't been updated to use the new ChatClient. New code should
/// use ChatClient instead.
pub struct ClaudeClient {
    inner: Option<ChatClient>,
}

impl ClaudeClient {
    /// Create a new Claude client
    ///
    /// Note: This is async internally but the struct is created synchronously
    /// for backwards compatibility. Actual provider initialization happens
    /// on first use.
    pub fn new() -> Result<Self> {
        // Check if Anthropic is configured
        if std::env::var("ANTHROPIC_API_KEY").is_err() {
            return Err(anyhow!("ANTHROPIC_API_KEY environment variable not set"));
        }

        // We'll initialize the inner client lazily
        Ok(Self { inner: None })
    }

    /// Check if Claude API is configured
    pub fn is_configured() -> bool {
        std::env::var("ANTHROPIC_API_KEY").is_ok()
    }

    /// Ensure the inner client is initialized
    async fn ensure_initialized(&mut self) -> Result<&ChatClient> {
        if self.inner.is_none() {
            // Create a config that forces Anthropic
            let mut config = LLMConfig::from_env();
            config.provider = super::providers::LLMProviderType::Anthropic;

            let client = ChatClient::with_config(&config).await?;
            self.inner = Some(client);
        }
        Ok(self.inner.as_ref().unwrap())
    }

    /// Stream a response from Claude
    pub async fn stream_response(
        &mut self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<Pin<Box<dyn Stream<Item = ChatStreamChunk> + Send>>> {
        let client = self.ensure_initialized().await?;
        client.stream_response(system_prompt, messages).await
    }

    /// Non-streaming response from Claude
    pub async fn get_response(
        &mut self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<(String, u32)> {
        let client = self.ensure_initialized().await?;
        client.get_response(system_prompt, messages).await
    }
}

impl Default for ClaudeClient {
    fn default() -> Self {
        Self::new().expect("Failed to create Claude client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_user() {
        let msg = ChatMessage::user("Hello");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello");
    }

    #[test]
    fn test_chat_message_to_llm_message() {
        let chat_msg = ChatMessage::user("Test");
        let llm_msg: LLMMessage = chat_msg.into();
        assert_eq!(llm_msg.role, MessageRole::User);
        assert_eq!(llm_msg.content, "Test");
    }

    #[test]
    fn test_stream_chunk_conversion() {
        use super::super::providers::TokenUsage;

        let content_chunk = StreamChunk::Content("Hello".to_string());
        let chat_chunk: ChatStreamChunk = content_chunk.into();
        match chat_chunk {
            ChatStreamChunk::Content(text) => assert_eq!(text, "Hello"),
            _ => panic!("Expected Content chunk"),
        }

        let done_chunk = StreamChunk::Done(TokenUsage {
            input_tokens: 10,
            output_tokens: 20,
        });
        let chat_chunk: ChatStreamChunk = done_chunk.into();
        match chat_chunk {
            ChatStreamChunk::Done { input_tokens, output_tokens } => {
                assert_eq!(input_tokens, 10);
                assert_eq!(output_tokens, 20);
            }
            _ => panic!("Expected Done chunk"),
        }
    }
}
