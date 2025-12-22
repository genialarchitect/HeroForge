//! Chat API endpoints
//!
//! Provides REST API endpoints for AI chat functionality with streaming responses.

use actix_web::{web, HttpResponse, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::ai::chat::{ChatMessage, ChatStreamChunk, ClaudeClient};
use crate::ai::context::ContextBuilder;
use crate::db;
use crate::web::auth;
use crate::web::error::{ApiError, ApiErrorKind};

/// Request to send a chat message
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub message: String,
    pub conversation_id: Option<String>,
    pub page_context: Option<String>,
}

/// Response for chat metadata
#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub conversation_id: String,
    pub message_id: String,
}

/// Conversation summary for listing
#[derive(Debug, Serialize)]
pub struct ConversationSummary {
    pub id: String,
    pub title: Option<String>,
    pub last_message: Option<String>,
    pub message_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// POST /api/chat
/// Stream a chat response via Server-Sent Events
pub async fn chat(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<ChatRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    // Check if Claude API is configured
    if !ClaudeClient::is_configured() {
        return Err(ApiError::new(
            ApiErrorKind::BadRequest("AI chat is not configured. Please set ANTHROPIC_API_KEY.".to_string()),
            "AI chat is not configured".to_string(),
        ));
    }

    // Rate limiting: max 20 messages per minute
    let recent_count = db::chat::count_recent_user_messages(pool.get_ref(), user_id, 60)
        .await
        .unwrap_or(0);

    if recent_count >= 20 {
        return Err(ApiError::new(
            ApiErrorKind::BadRequest("Rate limit exceeded. Please wait before sending more messages.".to_string()),
            "Rate limit exceeded".to_string(),
        ));
    }

    // Get or create conversation
    let conversation_id = match &body.conversation_id {
        Some(id) => {
            // Verify user owns this conversation
            if !db::chat::user_owns_conversation(pool.get_ref(), id, user_id)
                .await
                .unwrap_or(false)
            {
                return Err(ApiError::new(
                    ApiErrorKind::Forbidden(String::new()),
                    "Not authorized to access this conversation".to_string(),
                ));
            }
            id.clone()
        }
        None => db::chat::create_conversation(pool.get_ref(), user_id)
            .await
            .map_err(|e| {
                ApiError::new(
                    ApiErrorKind::InternalError(e.to_string()),
                    "Failed to create conversation".to_string(),
                )
            })?,
    };

    // Save user message
    let _user_message_id = db::chat::save_message(
        pool.get_ref(),
        &conversation_id,
        "user",
        &body.message,
        None,
        None,
    )
    .await
    .map_err(|e| {
        ApiError::new(
            ApiErrorKind::InternalError(e.to_string()),
            "Failed to save message".to_string(),
        )
    })?;

    // Build context
    let context_builder = ContextBuilder::new(pool.get_ref().clone());
    let context = context_builder
        .build_context(user_id, body.page_context.as_deref())
        .await;
    let system_prompt = ContextBuilder::build_system_prompt(&context);

    // Get conversation history (last 10 messages for context)
    let history = db::chat::get_messages(pool.get_ref(), &conversation_id, 10)
        .await
        .unwrap_or_default();

    // Convert to Claude message format
    let mut messages: Vec<ChatMessage> = history
        .iter()
        .map(|m| ChatMessage {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect();

    // Add current message if not already in history
    if messages.last().map(|m| m.content.as_str()) != Some(&body.message) {
        messages.push(ChatMessage {
            role: "user".to_string(),
            content: body.message.clone(),
        });
    }

    // Create Claude client and stream response
    let claude = ClaudeClient::new().map_err(|e| {
        ApiError::new(
            ApiErrorKind::InternalError(e.to_string()),
            "Failed to initialize AI client".to_string(),
        )
    })?;

    let stream = claude.stream_response(&system_prompt, messages).await.map_err(|e| {
        ApiError::new(
            ApiErrorKind::InternalError(e.to_string()),
            "Failed to start AI response".to_string(),
        )
    })?;

    // Clone values needed in the streaming closure
    let pool_clone = pool.get_ref().clone();
    let conversation_id_clone = conversation_id.clone();

    // Collect response for saving
    let (tx, rx) = tokio::sync::mpsc::channel::<web::Bytes>(100);

    // Spawn task to process stream and collect full response
    tokio::spawn(async move {
        let mut full_response = String::new();
        let mut tokens_used = 0i32;

        let mut stream = std::pin::pin!(stream);

        while let Some(chunk) = stream.next().await {
            match chunk {
                ChatStreamChunk::Content(text) => {
                    full_response.push_str(&text);

                    // Send SSE event
                    let event = serde_json::json!({
                        "type": "content",
                        "content": text,
                        "conversation_id": conversation_id_clone,
                    });
                    let sse = format!("data: {}\n\n", event);
                    let _ = tx.send(web::Bytes::from(sse)).await;
                }
                ChatStreamChunk::Done {
                    input_tokens,
                    output_tokens,
                } => {
                    tokens_used = (input_tokens + output_tokens) as i32;

                    // Send done event
                    let event = serde_json::json!({
                        "type": "done",
                        "conversation_id": conversation_id_clone,
                        "tokens_used": tokens_used,
                    });
                    let sse = format!("data: {}\n\n", event);
                    let _ = tx.send(web::Bytes::from(sse)).await;

                    break;
                }
                ChatStreamChunk::Error(err) => {
                    let event = serde_json::json!({
                        "type": "error",
                        "error": err,
                    });
                    let sse = format!("data: {}\n\n", event);
                    let _ = tx.send(web::Bytes::from(sse)).await;
                    break;
                }
            }
        }

        // Save assistant response if we got one
        if !full_response.is_empty() {
            let _ = db::chat::save_message(
                &pool_clone,
                &conversation_id_clone,
                "assistant",
                &full_response,
                None,
                Some(tokens_used),
            )
            .await;

            // Update conversation title if this is the first exchange
            if let Ok(count) = db::chat::count_messages(&pool_clone, &conversation_id_clone).await {
                if count <= 2 {
                    // Generate a title from the first user message (truncate to 50 chars)
                    if let Ok(messages) = db::chat::get_messages(&pool_clone, &conversation_id_clone, 1).await {
                        if let Some(first_msg) = messages.first() {
                            let title = if first_msg.content.len() > 50 {
                                format!("{}...", &first_msg.content[..47])
                            } else {
                                first_msg.content.clone()
                            };
                            let _ = db::chat::update_conversation_title(
                                &pool_clone,
                                &conversation_id_clone,
                                &title,
                            )
                            .await;
                        }
                    }
                }
            }
        }
    });

    // Convert receiver to streaming response
    let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .streaming(body_stream.map(Ok::<_, actix_web::Error>)))
}

/// GET /api/chat/conversations
/// List user's conversations
pub async fn list_conversations(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let conversations = db::chat::get_user_conversations(pool.get_ref(), user_id, 50)
        .await
        .map_err(|e| {
            ApiError::new(
                ApiErrorKind::InternalError(e.to_string()),
                "Failed to fetch conversations".to_string(),
            )
        })?;

    let mut summaries = Vec::new();
    for conv in conversations {
        let last_message = db::chat::get_last_message(pool.get_ref(), &conv.id)
            .await
            .ok()
            .flatten()
            .map(|m| {
                if m.content.len() > 100 {
                    format!("{}...", &m.content[..97])
                } else {
                    m.content
                }
            });

        let message_count = db::chat::count_messages(pool.get_ref(), &conv.id)
            .await
            .unwrap_or(0);

        summaries.push(ConversationSummary {
            id: conv.id,
            title: conv.title,
            last_message,
            message_count,
            created_at: conv.created_at.to_rfc3339(),
            updated_at: conv.updated_at.to_rfc3339(),
        });
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "conversations": summaries
    })))
}

/// GET /api/chat/conversations/{id}/messages
/// Get messages for a conversation
pub async fn get_messages(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let conversation_id = path.into_inner();

    // Verify ownership
    if !db::chat::user_owns_conversation(pool.get_ref(), &conversation_id, user_id)
        .await
        .unwrap_or(false)
    {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "Not authorized to access this conversation".to_string(),
        ));
    }

    let messages = db::chat::get_all_messages(pool.get_ref(), &conversation_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ApiErrorKind::InternalError(e.to_string()),
                "Failed to fetch messages".to_string(),
            )
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "conversation_id": conversation_id,
        "messages": messages
    })))
}

/// DELETE /api/chat/conversations/{id}
/// Delete a conversation
pub async fn delete_conversation(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let conversation_id = path.into_inner();

    // Verify ownership
    if !db::chat::user_owns_conversation(pool.get_ref(), &conversation_id, user_id)
        .await
        .unwrap_or(false)
    {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "Not authorized to access this conversation".to_string(),
        ));
    }

    db::chat::delete_conversation(pool.get_ref(), &conversation_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ApiErrorKind::InternalError(e.to_string()),
                "Failed to delete conversation".to_string(),
            )
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Conversation deleted"
    })))
}

/// POST /api/chat/conversations
/// Create a new conversation
pub async fn create_conversation(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let id = db::chat::create_conversation(pool.get_ref(), user_id)
        .await
        .map_err(|e| {
            ApiError::new(
                ApiErrorKind::InternalError(e.to_string()),
                "Failed to create conversation".to_string(),
            )
        })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Conversation created"
    })))
}

/// Configure chat routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/chat")
            .route("", web::post().to(chat))
            .route("/conversations", web::get().to(list_conversations))
            .route("/conversations", web::post().to(create_conversation))
            .route("/conversations/{id}/messages", web::get().to(get_messages))
            .route("/conversations/{id}", web::delete().to(delete_conversation)),
    );
}
