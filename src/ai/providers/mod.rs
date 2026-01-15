//! LLM Provider Abstraction Layer
//!
//! This module provides a unified interface for interacting with different LLM providers
//! (Anthropic Claude, Ollama, OpenAI). Organizations can configure their preferred provider
//! and switch between them without changing application code.
//!
//! # Supported Providers
//!
//! - **Anthropic (Claude)**: Cloud-based, requires API key
//! - **Ollama**: Self-hosted, runs locally, no API key required
//! - **OpenAI**: Cloud-based, requires API key (planned)
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::ai::providers::{LLMProvider, get_provider, LLMRequest};
//!
//! // Get the configured provider (from environment or database)
//! let provider = get_provider(None).await?;
//!
//! // Build a request
//! let request = LLMRequest::new()
//!     .with_system_prompt("You are a helpful assistant.")
//!     .with_user_message("Hello!");
//!
//! // Get a response
//! let response = provider.complete(request).await?;
//! println!("Response: {}", response.content);
//! ```

pub mod types;
pub mod anthropic;
pub mod ollama;
pub mod config;

pub use types::*;
pub use anthropic::AnthropicProvider;
pub use ollama::OllamaProvider;
pub use config::{LLMConfig, get_config, get_provider, get_provider_for_org};

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;
use std::sync::Arc;

/// Trait defining the interface for LLM providers
///
/// All LLM providers (Anthropic, Ollama, OpenAI) implement this trait,
/// allowing seamless switching between providers.
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Get the provider name
    fn name(&self) -> &str;

    /// Get the provider type
    fn provider_type(&self) -> LLMProviderType;

    /// Get the default model for this provider
    fn default_model(&self) -> &str;

    /// Get provider capabilities
    fn capabilities(&self) -> ProviderCapabilities;

    /// Check if the provider is available and configured
    async fn is_available(&self) -> bool;

    /// Get a non-streaming completion
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse, LLMError>;

    /// Get a streaming completion
    ///
    /// Returns a stream of `StreamChunk` items. The stream will end with
    /// either `StreamChunk::Done` or `StreamChunk::Error`.
    async fn stream(&self, request: LLMRequest) -> Result<BoxStream<'static, StreamChunk>, LLMError>;

    /// List available models for this provider
    async fn list_models(&self) -> Result<Vec<String>, LLMError>;
}

/// A boxed provider for dynamic dispatch
pub type BoxedProvider = Arc<dyn LLMProvider>;

/// Status information for a provider
#[derive(Debug, Clone)]
pub struct ProviderStatus {
    pub provider_type: LLMProviderType,
    pub name: String,
    pub model: String,
    pub available: bool,
    pub capabilities: ProviderCapabilities,
}

/// Get status of all providers
pub async fn get_all_provider_status(config: &LLMConfig) -> Vec<ProviderStatus> {
    let mut statuses = Vec::new();

    // Check Anthropic
    let anthropic_available = config.anthropic_api_key.is_some()
        || std::env::var("ANTHROPIC_API_KEY").is_ok();
    let anthropic_model = config.anthropic_model.clone()
        .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());
    statuses.push(ProviderStatus {
        provider_type: LLMProviderType::Anthropic,
        name: "Anthropic Claude".to_string(),
        model: anthropic_model,
        available: anthropic_available,
        capabilities: ProviderCapabilities {
            streaming: true,
            function_calling: true,
            vision: true,
            max_context_tokens: 200000,
            system_prompts: true,
        },
    });

    // Check Ollama
    let ollama_base_url = config.ollama_base_url.clone()
        .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
        .unwrap_or_else(|| "http://localhost:11434".to_string());
    let ollama_model = config.ollama_model.clone()
        .or_else(|| std::env::var("OLLAMA_MODEL").ok())
        .unwrap_or_else(|| "llama3:8b".to_string());

    // Try to check if Ollama is actually running
    let ollama_available = check_ollama_availability(&ollama_base_url).await;

    statuses.push(ProviderStatus {
        provider_type: LLMProviderType::Ollama,
        name: "Ollama".to_string(),
        model: ollama_model,
        available: ollama_available,
        capabilities: ProviderCapabilities {
            streaming: true,
            function_calling: false,
            vision: false,
            max_context_tokens: 128000,
            system_prompts: true,
        },
    });

    // Check OpenAI
    let openai_available = config.openai_api_key.is_some()
        || std::env::var("OPENAI_API_KEY").is_ok();
    let openai_model = config.openai_model.clone()
        .unwrap_or_else(|| "gpt-4-turbo".to_string());
    statuses.push(ProviderStatus {
        provider_type: LLMProviderType::OpenAI,
        name: "OpenAI".to_string(),
        model: openai_model,
        available: openai_available,
        capabilities: ProviderCapabilities {
            streaming: true,
            function_calling: true,
            vision: true,
            max_context_tokens: 128000,
            system_prompts: true,
        },
    });

    statuses
}

/// Check if Ollama is available by hitting its API
async fn check_ollama_availability(base_url: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .ok();

    if let Some(client) = client {
        let url = format!("{}/api/tags", base_url);
        match client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    } else {
        false
    }
}

/// Create a provider instance based on type
pub fn create_provider(provider_type: LLMProviderType, config: &LLMConfig) -> Result<BoxedProvider, LLMError> {
    match provider_type {
        LLMProviderType::Anthropic => {
            let api_key = config.anthropic_api_key.clone()
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .ok_or_else(|| LLMError::NotConfigured("ANTHROPIC_API_KEY not set".to_string()))?;

            let model = config.anthropic_model.clone()
                .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());

            Ok(Arc::new(AnthropicProvider::new(api_key, model)))
        }
        LLMProviderType::Ollama => {
            let base_url = config.ollama_base_url.clone()
                .or_else(|| std::env::var("OLLAMA_BASE_URL").ok())
                .unwrap_or_else(|| "http://localhost:11434".to_string());

            let model = config.ollama_model.clone()
                .or_else(|| std::env::var("OLLAMA_MODEL").ok())
                .unwrap_or_else(|| "llama3:8b".to_string());

            Ok(Arc::new(OllamaProvider::new(base_url, model)))
        }
        LLMProviderType::OpenAI => {
            // OpenAI provider planned for future implementation
            Err(LLMError::NotConfigured("OpenAI provider not yet implemented".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_display() {
        assert_eq!(LLMProviderType::Anthropic.to_string(), "anthropic");
        assert_eq!(LLMProviderType::Ollama.to_string(), "ollama");
        assert_eq!(LLMProviderType::OpenAI.to_string(), "openai");
    }

    #[test]
    fn test_provider_type_from_str() {
        assert_eq!("anthropic".parse::<LLMProviderType>().unwrap(), LLMProviderType::Anthropic);
        assert_eq!("claude".parse::<LLMProviderType>().unwrap(), LLMProviderType::Anthropic);
        assert_eq!("ollama".parse::<LLMProviderType>().unwrap(), LLMProviderType::Ollama);
        assert_eq!("openai".parse::<LLMProviderType>().unwrap(), LLMProviderType::OpenAI);
        assert_eq!("gpt".parse::<LLMProviderType>().unwrap(), LLMProviderType::OpenAI);
    }

    #[test]
    fn test_llm_request_builder() {
        let request = LLMRequest::new()
            .with_system_prompt("You are helpful.")
            .with_user_message("Hello")
            .with_max_tokens(1024)
            .with_temperature(0.7);

        assert_eq!(request.system_prompt, Some("You are helpful.".to_string()));
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.max_tokens, 1024);
        assert_eq!(request.temperature, Some(0.7));
    }

    #[test]
    fn test_token_usage() {
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
        };
        assert_eq!(usage.total(), 150);
    }
}
