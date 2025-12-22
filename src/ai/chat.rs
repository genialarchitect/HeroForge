//! Claude API Client for AI Chat
//!
//! Provides streaming chat completions via the Anthropic Claude API.

use anyhow::{anyhow, Result};
use futures::stream::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::sync::mpsc;

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Message for Claude API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Claude API request
#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ChatMessage>,
    stream: bool,
}

/// Claude streaming event types
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
enum StreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: MessageInfo },
    #[serde(rename = "content_block_start")]
    ContentBlockStart { index: u32, content_block: ContentBlock },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: u32, delta: Delta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: u32 },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: MessageDelta, usage: Option<Usage> },
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
struct ContentBlock {
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
struct MessageDelta {
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Usage {
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

/// Stream chunk from Claude
#[derive(Debug, Clone)]
pub enum ChatStreamChunk {
    /// Text content chunk
    Content(String),
    /// Stream completed with token usage
    Done { input_tokens: u32, output_tokens: u32 },
    /// Error occurred
    Error(String),
}

/// Claude API client
pub struct ClaudeClient {
    client: Client,
    api_key: String,
    model: String,
}

impl ClaudeClient {
    /// Create a new Claude client
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY environment variable not set"))?;

        let model = std::env::var("CLAUDE_MODEL")
            .unwrap_or_else(|_| "claude-sonnet-4-20250514".to_string());

        Ok(Self {
            client: Client::new(),
            api_key,
            model,
        })
    }

    /// Check if Claude API is configured
    pub fn is_configured() -> bool {
        std::env::var("ANTHROPIC_API_KEY").is_ok()
    }

    /// Stream a response from Claude
    pub async fn stream_response(
        &self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<Pin<Box<dyn Stream<Item = ChatStreamChunk> + Send>>> {
        let request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens: 4096,
            system: system_prompt.to_string(),
            messages,
            stream: true,
        };

        let response = self
            .client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Claude API error {}: {}", status, body));
        }

        // Create a channel for streaming
        let (tx, rx) = mpsc::channel::<ChatStreamChunk>(100);

        // Spawn task to read SSE stream
        let bytes_stream = response.bytes_stream();
        tokio::spawn(async move {
            use futures::StreamExt;

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
                                        let _ = tx
                                            .send(ChatStreamChunk::Done {
                                                input_tokens,
                                                output_tokens,
                                            })
                                            .await;
                                        return;
                                    }

                                    match serde_json::from_str::<StreamEvent>(data) {
                                        Ok(event) => match event {
                                            StreamEvent::ContentBlockDelta { delta, .. } => {
                                                if let Some(text) = delta.text {
                                                    let _ = tx
                                                        .send(ChatStreamChunk::Content(text))
                                                        .await;
                                                }
                                            }
                                            StreamEvent::MessageDelta { usage, .. } => {
                                                if let Some(u) = usage {
                                                    input_tokens = u.input_tokens.unwrap_or(0);
                                                    output_tokens = u.output_tokens.unwrap_or(0);
                                                }
                                            }
                                            StreamEvent::MessageStop => {
                                                let _ = tx
                                                    .send(ChatStreamChunk::Done {
                                                        input_tokens,
                                                        output_tokens,
                                                    })
                                                    .await;
                                                return;
                                            }
                                            StreamEvent::Error { error } => {
                                                let _ = tx
                                                    .send(ChatStreamChunk::Error(error.message))
                                                    .await;
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
                        let _ = tx
                            .send(ChatStreamChunk::Error(format!("Stream error: {}", e)))
                            .await;
                        return;
                    }
                }
            }

            // Stream ended
            let _ = tx
                .send(ChatStreamChunk::Done {
                    input_tokens,
                    output_tokens,
                })
                .await;
        });

        // Convert receiver to stream
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    /// Non-streaming response (for simple queries)
    pub async fn get_response(
        &self,
        system_prompt: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<(String, u32)> {
        let request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens: 4096,
            system: system_prompt.to_string(),
            messages,
            stream: false,
        };

        let response = self
            .client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Claude API error {}: {}", status, body));
        }

        #[derive(Deserialize)]
        struct NonStreamResponse {
            content: Vec<ContentItem>,
            usage: ResponseUsage,
        }

        #[derive(Deserialize)]
        struct ContentItem {
            text: String,
        }

        #[derive(Deserialize)]
        struct ResponseUsage {
            input_tokens: u32,
            output_tokens: u32,
        }

        let resp: NonStreamResponse = response.json().await?;
        let text = resp
            .content
            .into_iter()
            .map(|c| c.text)
            .collect::<Vec<_>>()
            .join("");
        let total_tokens = resp.usage.input_tokens + resp.usage.output_tokens;

        Ok((text, total_tokens))
    }
}

impl Default for ClaudeClient {
    fn default() -> Self {
        Self::new().expect("Failed to create Claude client")
    }
}
