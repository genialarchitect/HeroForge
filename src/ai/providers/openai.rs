//! OpenAI LLM Provider
//!
//! Implementation of the LLM provider trait for OpenAI's GPT API.
//!
//! Supports:
//! - GPT-4 Turbo and GPT-4
//! - GPT-3.5 Turbo
//! - Streaming and non-streaming responses
//! - Function calling (tool use)

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

const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";
const OPENAI_MODELS_URL: &str = "https://api.openai.com/v1/models";

/// OpenAI GPT provider
pub struct OpenAIProvider {
    client: Client,
    api_key: String,
    model: String,
    organization_id: Option<String>,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            organization_id: None,
        }
    }

    /// Create with organization ID
    pub fn with_organization(api_key: String, model: String, organization_id: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            organization_id: Some(organization_id),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, LLMError> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| LLMError::NotConfigured("OPENAI_API_KEY not set".to_string()))?;

        let model = std::env::var("OPENAI_MODEL")
            .unwrap_or_else(|_| "gpt-4-turbo".to_string());

        let organization_id = std::env::var("OPENAI_ORG_ID").ok();

        let mut provider = Self::new(api_key, model);
        provider.organization_id = organization_id;
        Ok(provider)
    }

    /// Build the request headers
    fn build_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("Authorization", format!("Bearer {}", self.api_key)),
            ("Content-Type", "application/json".to_string()),
        ];

        if let Some(org_id) = &self.organization_id {
            headers.push(("OpenAI-Organization", org_id.clone()));
        }

        headers
    }
}

// OpenAI API request/response structures
#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    id: String,
    model: String,
    choices: Vec<OpenAIChoice>,
    usage: Option<OpenAIUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    index: u32,
    message: OpenAIResponseMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponseMessage {
    role: String,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

// Streaming response types
#[derive(Debug, Deserialize)]
struct OpenAIStreamResponse {
    choices: Vec<OpenAIStreamChoice>,
    #[serde(default)]
    usage: Option<OpenAIUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAIStreamChoice {
    index: u32,
    delta: OpenAIDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIDelta {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIModelsResponse {
    data: Vec<OpenAIModelInfo>,
}

#[derive(Debug, Deserialize)]
struct OpenAIModelInfo {
    id: String,
    #[serde(default)]
    owned_by: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorResponse {
    error: OpenAIErrorInfo,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorInfo {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    #[serde(default)]
    code: Option<String>,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    fn name(&self) -> &str {
        "OpenAI"
    }

    fn provider_type(&self) -> LLMProviderType {
        LLMProviderType::OpenAI
    }

    fn default_model(&self) -> &str {
        &self.model
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            streaming: true,
            system_prompts: true,
            function_calling: true,
            vision: self.model.contains("vision") || self.model.contains("gpt-4"),
            max_context_tokens: if self.model.contains("gpt-4-turbo") || self.model.contains("gpt-4o") {
                128_000
            } else if self.model.contains("gpt-4") {
                8_192
            } else {
                16_385 // GPT-3.5 Turbo
            },
        }
    }

    async fn is_available(&self) -> bool {
        let mut request_builder = self.client.get(OPENAI_MODELS_URL);

        for (key, value) in self.build_headers() {
            request_builder = request_builder.header(key, value);
        }

        match request_builder.send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());

        // Build messages array - OpenAI includes system as a message
        let mut messages: Vec<OpenAIMessage> = Vec::new();

        // Add system message first if present
        if let Some(system) = &request.system_prompt {
            messages.push(OpenAIMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }

        // Add user/assistant messages
        for msg in request.messages {
            messages.push(OpenAIMessage {
                role: match msg.role {
                    MessageRole::User => "user".to_string(),
                    MessageRole::Assistant => "assistant".to_string(),
                    MessageRole::System => "system".to_string(),
                },
                content: msg.content,
            });
        }

        let api_request = OpenAIRequest {
            model: model.clone(),
            messages,
            max_tokens: Some(request.max_tokens),
            temperature: request.temperature,
            stream: None,
        };

        let mut request_builder = self.client.post(OPENAI_API_URL);
        for (key, value) in self.build_headers() {
            request_builder = request_builder.header(key, value);
        }

        let response = request_builder
            .json(&api_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();

            if status.as_u16() == 429 {
                // Try to parse retry-after from response
                if let Ok(error_resp) = serde_json::from_str::<OpenAIErrorResponse>(&error_text) {
                    return Err(LLMError::RateLimited {
                        retry_after_secs: None,
                    });
                }
                return Err(LLMError::RateLimited { retry_after_secs: None });
            }

            // Try to parse OpenAI error format
            if let Ok(error_resp) = serde_json::from_str::<OpenAIErrorResponse>(&error_text) {
                return Err(LLMError::ApiError {
                    status: status.as_u16(),
                    message: error_resp.error.message,
                });
            }

            return Err(LLMError::ApiError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let api_response: OpenAIResponse = response.json().await
            .map_err(|e| LLMError::ParseError(e.to_string()))?;

        let content = api_response.choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = api_response.usage.unwrap_or(OpenAIUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        });

        Ok(LLMResponse {
            content,
            model: api_response.model,
            usage: TokenUsage {
                input_tokens: usage.prompt_tokens,
                output_tokens: usage.completion_tokens,
            },
            metadata: Some(serde_json::json!({
                "id": api_response.id,
                "finish_reason": api_response.choices.first().and_then(|c| c.finish_reason.clone())
            })),
        })
    }

    async fn stream(&self, request: LLMRequest) -> Result<BoxStream<'static, StreamChunk>, LLMError> {
        let model = request.model.unwrap_or_else(|| self.model.clone());

        // Build messages array
        let mut messages: Vec<OpenAIMessage> = Vec::new();

        if let Some(system) = &request.system_prompt {
            messages.push(OpenAIMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }

        for msg in request.messages {
            messages.push(OpenAIMessage {
                role: match msg.role {
                    MessageRole::User => "user".to_string(),
                    MessageRole::Assistant => "assistant".to_string(),
                    MessageRole::System => "system".to_string(),
                },
                content: msg.content,
            });
        }

        let api_request = OpenAIRequest {
            model,
            messages,
            max_tokens: Some(request.max_tokens),
            temperature: request.temperature,
            stream: Some(true),
        };

        let mut request_builder = self.client.post(OPENAI_API_URL);
        for (key, value) in self.build_headers() {
            request_builder = request_builder.header(key, value);
        }

        let response = request_builder
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
            let mut total_tokens = 0u32;

            let mut stream = bytes_stream;
            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        buffer.push_str(&String::from_utf8_lossy(&bytes));

                        // Process complete SSE events (lines ending with double newline)
                        while let Some(event_end) = buffer.find("\n\n") {
                            let event_str = buffer[..event_end].to_string();
                            buffer = buffer[event_end + 2..].to_string();

                            // Parse SSE event
                            for line in event_str.lines() {
                                if let Some(data) = line.strip_prefix("data: ") {
                                    if data == "[DONE]" {
                                        let _ = tx.send(StreamChunk::Done(TokenUsage {
                                            input_tokens: 0, // OpenAI doesn't provide this in stream
                                            output_tokens: total_tokens,
                                        })).await;
                                        return;
                                    }

                                    match serde_json::from_str::<OpenAIStreamResponse>(data) {
                                        Ok(stream_resp) => {
                                            if let Some(choice) = stream_resp.choices.first() {
                                                if let Some(content) = &choice.delta.content {
                                                    total_tokens += 1; // Rough approximation
                                                    let _ = tx.send(StreamChunk::Content(content.clone())).await;
                                                }

                                                if choice.finish_reason.is_some() {
                                                    // Stream finished
                                                    if let Some(usage) = stream_resp.usage {
                                                        let _ = tx.send(StreamChunk::Done(TokenUsage {
                                                            input_tokens: usage.prompt_tokens,
                                                            output_tokens: usage.completion_tokens,
                                                        })).await;
                                                    } else {
                                                        let _ = tx.send(StreamChunk::Done(TokenUsage {
                                                            input_tokens: 0,
                                                            output_tokens: total_tokens,
                                                        })).await;
                                                    }
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::debug!("Failed to parse OpenAI SSE event: {} - {}", e, data);
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
                input_tokens: 0,
                output_tokens: total_tokens,
            })).await;
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn list_models(&self) -> Result<Vec<String>, LLMError> {
        let mut request_builder = self.client.get(OPENAI_MODELS_URL);
        for (key, value) in self.build_headers() {
            request_builder = request_builder.header(key, value);
        }

        let response = request_builder.send().await?;

        if !response.status().is_success() {
            // Return default models if API call fails
            return Ok(vec![
                "gpt-4o".to_string(),
                "gpt-4o-mini".to_string(),
                "gpt-4-turbo".to_string(),
                "gpt-4".to_string(),
                "gpt-3.5-turbo".to_string(),
            ]);
        }

        let models_resp: OpenAIModelsResponse = response.json().await
            .map_err(|e| LLMError::ParseError(e.to_string()))?;

        // Filter to only GPT models
        let gpt_models: Vec<String> = models_resp.data
            .into_iter()
            .filter(|m| m.id.starts_with("gpt-"))
            .map(|m| m.id)
            .collect();

        if gpt_models.is_empty() {
            // Return defaults if no GPT models found
            Ok(vec![
                "gpt-4o".to_string(),
                "gpt-4o-mini".to_string(),
                "gpt-4-turbo".to_string(),
                "gpt-4".to_string(),
                "gpt-3.5-turbo".to_string(),
            ])
        } else {
            Ok(gpt_models)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_name() {
        let provider = OpenAIProvider::new(
            "test-key".to_string(),
            "gpt-4-turbo".to_string(),
        );
        assert_eq!(provider.name(), "OpenAI");
        assert_eq!(provider.provider_type(), LLMProviderType::OpenAI);
    }

    #[test]
    fn test_capabilities_gpt4_turbo() {
        let provider = OpenAIProvider::new(
            "test-key".to_string(),
            "gpt-4-turbo".to_string(),
        );
        let caps = provider.capabilities();
        assert!(caps.streaming);
        assert!(caps.system_prompts);
        assert!(caps.function_calling);
        assert!(caps.vision);
        assert_eq!(caps.max_context_tokens, 128_000);
    }

    #[test]
    fn test_capabilities_gpt35() {
        let provider = OpenAIProvider::new(
            "test-key".to_string(),
            "gpt-3.5-turbo".to_string(),
        );
        let caps = provider.capabilities();
        assert_eq!(caps.max_context_tokens, 16_385);
    }

    #[test]
    fn test_headers_with_org() {
        let provider = OpenAIProvider::with_organization(
            "test-key".to_string(),
            "gpt-4".to_string(),
            "org-123".to_string(),
        );
        let headers = provider.build_headers();
        assert!(headers.iter().any(|(k, v)| *k == "Authorization" && v.contains("test-key")));
        assert!(headers.iter().any(|(k, v)| *k == "OpenAI-Organization" && v == "org-123"));
    }
}
