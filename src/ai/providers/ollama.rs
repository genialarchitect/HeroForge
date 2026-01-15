//! Ollama LLM Provider
//!
//! Implementation of the LLM provider trait for Ollama (self-hosted LLM server).
//! Ollama provides local inference with models like Llama, Mistral, CodeLlama, etc.
//!
//! # Configuration
//!
//! - `OLLAMA_BASE_URL`: Base URL for Ollama API (default: http://localhost:11434)
//! - `OLLAMA_MODEL`: Default model to use (default: llama3:8b)
//!
//! # Recommended Models
//!
//! | Use Case | Model | VRAM |
//! |----------|-------|------|
//! | General chat | llama3:8b | 8GB |
//! | Better quality | llama3:70b | 80GB+ |
//! | Code/security | codellama:34b | 40GB |
//! | Quick analysis | mistral:7b | 8GB |

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{
    LLMProvider, LLMProviderType, LLMRequest, LLMResponse, LLMError,
    ProviderCapabilities, StreamChunk, TokenUsage, MessageRole,
};

/// Ollama provider for self-hosted LLM inference
pub struct OllamaProvider {
    client: Client,
    base_url: String,
    model: String,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(base_url: String, model: String) -> Self {
        // Ensure base_url doesn't have trailing slash
        let base_url = base_url.trim_end_matches('/').to_string();

        Self {
            client: Client::new(),
            base_url,
            model,
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        let base_url = std::env::var("OLLAMA_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());

        let model = std::env::var("OLLAMA_MODEL")
            .unwrap_or_else(|_| "llama3:8b".to_string());

        Self::new(base_url, model)
    }

    /// Check if Ollama is running
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        self.client.get(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false)
    }
}

// Ollama API request/response structures
#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Debug, Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    model: String,
    message: OllamaResponseMessage,
    done: bool,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaResponseMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OllamaStreamChunk {
    model: String,
    message: OllamaResponseMessage,
    done: bool,
    #[serde(default)]
    prompt_eval_count: Option<u32>,
    #[serde(default)]
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelInfo>,
}

#[derive(Debug, Deserialize)]
struct OllamaModelInfo {
    name: String,
    #[allow(dead_code)]
    size: u64,
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    fn name(&self) -> &str {
        "Ollama"
    }

    fn provider_type(&self) -> LLMProviderType {
        LLMProviderType::Ollama
    }

    fn default_model(&self) -> &str {
        &self.model
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            streaming: true,
            system_prompts: true,
            function_calling: false, // Not all Ollama models support this
            vision: false, // Depends on model
            max_context_tokens: 32_768, // Varies by model, conservative default
        }
    }

    async fn is_available(&self) -> bool {
        self.health_check().await
    }

    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());
        let url = format!("{}/api/chat", self.base_url);

        // Convert messages to Ollama format
        // Ollama handles system prompts as a system message in the messages array
        let mut messages: Vec<OllamaMessage> = Vec::new();

        // Add system prompt as first message if present
        if let Some(system) = &request.system_prompt {
            messages.push(OllamaMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }

        // Add conversation messages
        for msg in request.messages {
            messages.push(OllamaMessage {
                role: msg.role.to_string(),
                content: msg.content,
            });
        }

        let api_request = OllamaRequest {
            model: model.clone(),
            messages,
            stream: false,
            options: Some(OllamaOptions {
                num_predict: Some(request.max_tokens),
                temperature: request.temperature,
            }),
        };

        let response = self.client
            .post(&url)
            .json(&api_request)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    LLMError::Unavailable(format!("Cannot connect to Ollama at {}", self.base_url))
                } else {
                    LLMError::from(e)
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            if error_text.contains("model") && error_text.contains("not found") {
                return Err(LLMError::ModelNotFound(model));
            }

            return Err(LLMError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let api_response: OllamaResponse = response.json().await
            .map_err(|e| LLMError::ParseError(e.to_string()))?;

        Ok(LLMResponse {
            content: api_response.message.content,
            model: api_response.model,
            usage: TokenUsage {
                input_tokens: api_response.prompt_eval_count.unwrap_or(0),
                output_tokens: api_response.eval_count.unwrap_or(0),
            },
            metadata: None,
        })
    }

    async fn stream(&self, request: LLMRequest) -> Result<BoxStream<'static, StreamChunk>, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());
        let url = format!("{}/api/chat", self.base_url);

        // Convert messages to Ollama format
        let mut messages: Vec<OllamaMessage> = Vec::new();

        if let Some(system) = &request.system_prompt {
            messages.push(OllamaMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }

        for msg in request.messages {
            messages.push(OllamaMessage {
                role: msg.role.to_string(),
                content: msg.content,
            });
        }

        let api_request = OllamaRequest {
            model: model.clone(),
            messages,
            stream: true,
            options: Some(OllamaOptions {
                num_predict: Some(request.max_tokens),
                temperature: request.temperature,
            }),
        };

        let response = self.client
            .post(&url)
            .json(&api_request)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    LLMError::Unavailable(format!("Cannot connect to Ollama at {}", self.base_url))
                } else {
                    LLMError::from(e)
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            if error_text.contains("model") && error_text.contains("not found") {
                return Err(LLMError::ModelNotFound(model));
            }

            return Err(LLMError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        // Create channel for streaming
        let (tx, rx) = mpsc::channel::<StreamChunk>(100);

        // Spawn task to process NDJSON stream
        // Ollama streams newline-delimited JSON (not SSE)
        let bytes_stream = response.bytes_stream();
        tokio::spawn(async move {
            let mut buffer = String::new();
            let mut input_tokens = 0u32;
            let mut output_tokens = 0u32;

            let mut stream = bytes_stream;
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        buffer.push_str(&String::from_utf8_lossy(&bytes));

                        // Process complete JSON lines
                        while let Some(newline_pos) = buffer.find('\n') {
                            let line = buffer[..newline_pos].trim().to_string();
                            buffer = buffer[newline_pos + 1..].to_string();

                            if line.is_empty() {
                                continue;
                            }

                            match serde_json::from_str::<OllamaStreamChunk>(&line) {
                                Ok(chunk) => {
                                    // Send content if present
                                    if !chunk.message.content.is_empty() {
                                        let _ = tx.send(StreamChunk::Content(chunk.message.content)).await;
                                    }

                                    // Update token counts
                                    if let Some(prompt_count) = chunk.prompt_eval_count {
                                        input_tokens = prompt_count;
                                    }
                                    if let Some(eval_count) = chunk.eval_count {
                                        output_tokens = eval_count;
                                    }

                                    // Check if done
                                    if chunk.done {
                                        let _ = tx.send(StreamChunk::Done(TokenUsage {
                                            input_tokens,
                                            output_tokens,
                                        })).await;
                                        return;
                                    }
                                }
                                Err(e) => {
                                    log::debug!("Failed to parse Ollama chunk: {} - {}", e, line);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(StreamChunk::Error(format!("Stream error: {}", e))).await;
                        return;
                    }
                }
            }

            // Stream ended naturally
            let _ = tx.send(StreamChunk::Done(TokenUsage {
                input_tokens,
                output_tokens,
            })).await;
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn list_models(&self) -> Result<Vec<String>, LLMError> {
        let url = format!("{}/api/tags", self.base_url);

        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    LLMError::Unavailable(format!("Cannot connect to Ollama at {}", self.base_url))
                } else {
                    LLMError::from(e)
                }
            })?;

        if !response.status().is_success() {
            return Err(LLMError::ApiError {
                status: response.status().as_u16(),
                message: response.text().await.unwrap_or_default(),
            });
        }

        let tags_response: OllamaTagsResponse = response.json().await
            .map_err(|e| LLMError::ParseError(e.to_string()))?;

        Ok(tags_response.models.into_iter().map(|m| m.name).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_name() {
        let provider = OllamaProvider::new(
            "http://localhost:11434".to_string(),
            "llama3:8b".to_string(),
        );
        assert_eq!(provider.name(), "Ollama");
        assert_eq!(provider.provider_type(), LLMProviderType::Ollama);
    }

    #[test]
    fn test_default_model() {
        let provider = OllamaProvider::new(
            "http://localhost:11434".to_string(),
            "mistral:7b".to_string(),
        );
        assert_eq!(provider.default_model(), "mistral:7b");
    }

    #[test]
    fn test_url_trailing_slash() {
        let provider = OllamaProvider::new(
            "http://localhost:11434/".to_string(),
            "llama3:8b".to_string(),
        );
        assert_eq!(provider.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_capabilities() {
        let provider = OllamaProvider::from_env();
        let caps = provider.capabilities();
        assert!(caps.streaming);
        assert!(caps.system_prompts);
        assert!(!caps.function_calling); // Conservative default
    }
}
