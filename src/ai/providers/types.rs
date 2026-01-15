//! Shared types for LLM providers
//!
//! Provider-agnostic types for request/response handling across different LLM backends.

use serde::{Deserialize, Serialize};

/// Role in a conversation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::User => write!(f, "user"),
            MessageRole::Assistant => write!(f, "assistant"),
            MessageRole::System => write!(f, "system"),
        }
    }
}

/// A message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMMessage {
    pub role: MessageRole,
    pub content: String,
}

impl LLMMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: content.into(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.into(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: content.into(),
        }
    }
}

/// Request to an LLM provider
#[derive(Debug, Clone)]
pub struct LLMRequest {
    /// System prompt (instructions for the model)
    pub system_prompt: Option<String>,
    /// Conversation messages
    pub messages: Vec<LLMMessage>,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Temperature (0.0-1.0, higher = more creative)
    pub temperature: Option<f32>,
    /// Whether to stream the response
    pub stream: bool,
    /// Optional model override (uses provider default if None)
    pub model: Option<String>,
}

impl Default for LLMRequest {
    fn default() -> Self {
        Self {
            system_prompt: None,
            messages: Vec::new(),
            max_tokens: 4096,
            temperature: None,
            stream: false,
            model: None,
        }
    }
}

impl LLMRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    pub fn with_message(mut self, message: LLMMessage) -> Self {
        self.messages.push(message);
        self
    }

    pub fn with_user_message(mut self, content: impl Into<String>) -> Self {
        self.messages.push(LLMMessage::user(content));
        self
    }

    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = tokens;
        self
    }

    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp);
        self
    }

    pub fn with_streaming(mut self, stream: bool) -> Self {
        self.stream = stream;
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

/// Response from an LLM provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    /// Generated text content
    pub content: String,
    /// Model used for generation
    pub model: String,
    /// Token usage statistics
    pub usage: TokenUsage,
    /// Provider-specific metadata
    pub metadata: Option<serde_json::Value>,
}

/// Token usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

impl TokenUsage {
    pub fn total(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }
}

/// Streaming chunk from an LLM provider
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Text content chunk
    Content(String),
    /// Stream completed with usage statistics
    Done(TokenUsage),
    /// Error occurred during streaming
    Error(String),
}

/// LLM provider type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LLMProviderType {
    Anthropic,
    Ollama,
    OpenAI,
}

impl std::fmt::Display for LLMProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMProviderType::Anthropic => write!(f, "anthropic"),
            LLMProviderType::Ollama => write!(f, "ollama"),
            LLMProviderType::OpenAI => write!(f, "openai"),
        }
    }
}

impl std::str::FromStr for LLMProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" => Ok(LLMProviderType::Anthropic),
            "ollama" => Ok(LLMProviderType::Ollama),
            "openai" | "gpt" => Ok(LLMProviderType::OpenAI),
            _ => Err(format!("Unknown LLM provider: {}", s)),
        }
    }
}

/// Provider capabilities
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// Supports streaming responses
    pub streaming: bool,
    /// Supports system prompts
    pub system_prompts: bool,
    /// Supports function/tool calling
    pub function_calling: bool,
    /// Supports vision/image input
    pub vision: bool,
    /// Maximum context window size
    pub max_context_tokens: u32,
}

/// Error types specific to LLM operations
#[derive(Debug, thiserror::Error)]
pub enum LLMError {
    #[error("Provider not configured: {0}")]
    NotConfigured(String),

    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Rate limited: retry after {retry_after_secs:?} seconds")]
    RateLimited { retry_after_secs: Option<u64> },

    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Context length exceeded: {used} > {max}")]
    ContextLengthExceeded { used: u32, max: u32 },

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Provider unavailable: {0}")]
    Unavailable(String),
}

impl From<reqwest::Error> for LLMError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            LLMError::NetworkError("Request timed out".to_string())
        } else if err.is_connect() {
            LLMError::NetworkError("Connection failed".to_string())
        } else {
            LLMError::NetworkError(err.to_string())
        }
    }
}
