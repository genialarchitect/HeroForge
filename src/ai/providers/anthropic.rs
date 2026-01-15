//! Anthropic Claude LLM Provider
//!
//! Implementation of the LLM provider trait for Anthropic's Claude API.

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

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic Claude provider
pub struct AnthropicProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, LLMError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| LLMError::NotConfigured("ANTHROPIC_API_KEY not set".to_string()))?;

        let model = std::env::var("CLAUDE_MODEL")
            .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string());

        Ok(Self::new(api_key, model))
    }
}

// Anthropic API request/response structures
#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
    model: String,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

// Streaming event types
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: MessageInfo },
    #[serde(rename = "content_block_start")]
    ContentBlockStart { index: u32, content_block: ContentBlockInfo },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: u32, delta: Delta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: u32 },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: MessageDeltaInfo, usage: Option<StreamUsage> },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "error")]
    Error { error: ErrorInfo },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MessageInfo {
    id: String,
    model: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ContentBlockInfo {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Delta {
    #[serde(rename = "type")]
    delta_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct MessageDeltaInfo {
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StreamUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ErrorInfo {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "Anthropic Claude"
    }

    fn provider_type(&self) -> LLMProviderType {
        LLMProviderType::Anthropic
    }

    fn default_model(&self) -> &str {
        &self.model
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            streaming: true,
            system_prompts: true,
            function_calling: true,
            vision: true,
            max_context_tokens: 200_000, // Claude 3+ supports 200k context
        }
    }

    async fn is_available(&self) -> bool {
        // Quick health check - just verify we can reach the API
        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "model": &self.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}]
            }))
            .send()
            .await;

        match response {
            Ok(resp) => resp.status().is_success() || resp.status().as_u16() == 400,
            Err(_) => false,
        }
    }

    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());

        // Convert messages to Anthropic format
        let messages: Vec<AnthropicMessage> = request.messages
            .into_iter()
            .filter(|m| m.role != MessageRole::System) // System messages handled separately
            .map(|m| AnthropicMessage {
                role: m.role.to_string(),
                content: m.content,
            })
            .collect();

        let api_request = AnthropicRequest {
            model: model.clone(),
            max_tokens: request.max_tokens,
            system: request.system_prompt,
            messages,
            temperature: request.temperature,
            stream: false,
        };

        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&api_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                return Err(LLMError::RateLimited { retry_after_secs: None });
            }

            return Err(LLMError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let api_response: AnthropicResponse = response.json().await
            .map_err(|e| LLMError::ParseError(e.to_string()))?;

        let content = api_response.content
            .into_iter()
            .map(|c| c.text)
            .collect::<Vec<_>>()
            .join("");

        Ok(LLMResponse {
            content,
            model: api_response.model,
            usage: TokenUsage {
                input_tokens: api_response.usage.input_tokens,
                output_tokens: api_response.usage.output_tokens,
            },
            metadata: None,
        })
    }

    async fn stream(&self, request: LLMRequest) -> Result<BoxStream<'static, StreamChunk>, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());

        // Convert messages to Anthropic format
        let messages: Vec<AnthropicMessage> = request.messages
            .into_iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| AnthropicMessage {
                role: m.role.to_string(),
                content: m.content,
            })
            .collect();

        let api_request = AnthropicRequest {
            model,
            max_tokens: request.max_tokens,
            system: request.system_prompt,
            messages,
            temperature: request.temperature,
            stream: true,
        };

        let response = self.client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&api_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                return Err(LLMError::RateLimited { retry_after_secs: None });
            }

            return Err(LLMError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        // Create channel for streaming
        let (tx, rx) = mpsc::channel::<StreamChunk>(100);

        // Spawn task to process SSE stream
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

                        // Process complete SSE events
                        while let Some(event_end) = buffer.find("\n\n") {
                            let event_str = buffer[..event_end].to_string();
                            buffer = buffer[event_end + 2..].to_string();

                            // Parse SSE event
                            for line in event_str.lines() {
                                if let Some(data) = line.strip_prefix("data: ") {
                                    if data == "[DONE]" {
                                        let _ = tx.send(StreamChunk::Done(TokenUsage {
                                            input_tokens,
                                            output_tokens,
                                        })).await;
                                        return;
                                    }

                                    match serde_json::from_str::<StreamEvent>(data) {
                                        Ok(event) => match event {
                                            StreamEvent::ContentBlockDelta { delta, .. } => {
                                                if let Some(text) = delta.text {
                                                    let _ = tx.send(StreamChunk::Content(text)).await;
                                                }
                                            }
                                            StreamEvent::MessageDelta { usage, .. } => {
                                                if let Some(u) = usage {
                                                    input_tokens = u.input_tokens.unwrap_or(input_tokens);
                                                    output_tokens = u.output_tokens.unwrap_or(output_tokens);
                                                }
                                            }
                                            StreamEvent::MessageStop => {
                                                let _ = tx.send(StreamChunk::Done(TokenUsage {
                                                    input_tokens,
                                                    output_tokens,
                                                })).await;
                                                return;
                                            }
                                            StreamEvent::Error { error } => {
                                                let _ = tx.send(StreamChunk::Error(error.message)).await;
                                                return;
                                            }
                                            _ => {}
                                        },
                                        Err(e) => {
                                            log::debug!("Failed to parse SSE event: {} - {}", e, data);
                                        }
                                    }
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
        // Anthropic doesn't have a models list endpoint, return known models
        Ok(vec![
            "claude-opus-4-20250514".to_string(),
            "claude-sonnet-4-20250514".to_string(),
            "claude-3-5-sonnet-20241022".to_string(),
            "claude-3-5-haiku-20241022".to_string(),
            "claude-3-opus-20240229".to_string(),
            "claude-3-sonnet-20240229".to_string(),
            "claude-3-haiku-20240307".to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_name() {
        let provider = AnthropicProvider::new(
            "test-key".to_string(),
            "claude-sonnet-4-20250514".to_string(),
        );
        assert_eq!(provider.name(), "Anthropic Claude");
        assert_eq!(provider.provider_type(), LLMProviderType::Anthropic);
    }

    #[test]
    fn test_capabilities() {
        let provider = AnthropicProvider::new(
            "test-key".to_string(),
            "claude-sonnet-4-20250514".to_string(),
        );
        let caps = provider.capabilities();
        assert!(caps.streaming);
        assert!(caps.system_prompts);
        assert!(caps.vision);
        assert_eq!(caps.max_context_tokens, 200_000);
    }
}
