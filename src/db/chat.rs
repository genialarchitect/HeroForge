//! Database operations for AI Chat

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::FromRow;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatConversation {
    pub id: String,
    pub user_id: String,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub role: String,  // "user" or "assistant"
    pub content: String,
    pub context_summary: Option<String>,
    pub tokens_used: Option<i32>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Row Types for query_as
// ============================================================================

#[derive(Debug, FromRow)]
struct ConversationRow {
    id: String,
    user_id: String,
    title: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<ConversationRow> for ChatConversation {
    fn from(row: ConversationRow) -> Self {
        ChatConversation {
            id: row.id,
            user_id: row.user_id,
            title: row.title,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, FromRow)]
struct MessageRow {
    id: String,
    conversation_id: String,
    role: String,
    content: String,
    context_summary: Option<String>,
    tokens_used: Option<i32>,
    created_at: String,
}

impl From<MessageRow> for ChatMessage {
    fn from(row: MessageRow) -> Self {
        ChatMessage {
            id: row.id,
            conversation_id: row.conversation_id,
            role: row.role,
            content: row.content,
            context_summary: row.context_summary,
            tokens_used: row.tokens_used,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

// ============================================================================
// Conversation Operations
// ============================================================================

/// Create a new conversation
pub async fn create_conversation(pool: &SqlitePool, user_id: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO chat_conversations (id, user_id, title, created_at, updated_at)
        VALUES (?, ?, NULL, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a conversation by ID
pub async fn get_conversation(pool: &SqlitePool, id: &str) -> Result<Option<ChatConversation>> {
    let row = sqlx::query_as::<_, ConversationRow>(
        "SELECT id, user_id, title, created_at, updated_at FROM chat_conversations WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(ChatConversation::from))
}

/// Get conversations for a user (most recent first)
pub async fn get_user_conversations(
    pool: &SqlitePool,
    user_id: &str,
    limit: i32,
) -> Result<Vec<ChatConversation>> {
    let rows = sqlx::query_as::<_, ConversationRow>(
        r#"
        SELECT id, user_id, title, created_at, updated_at
        FROM chat_conversations
        WHERE user_id = ?
        ORDER BY updated_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(ChatConversation::from).collect())
}

/// Update conversation title
pub async fn update_conversation_title(
    pool: &SqlitePool,
    id: &str,
    title: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE chat_conversations SET title = ?, updated_at = ? WHERE id = ?",
    )
    .bind(title)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update conversation timestamp
pub async fn touch_conversation(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE chat_conversations SET updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a conversation and all its messages
pub async fn delete_conversation(pool: &SqlitePool, id: &str) -> Result<()> {
    // Messages will be cascade deleted due to foreign key
    sqlx::query("DELETE FROM chat_conversations WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Check if user owns conversation
pub async fn user_owns_conversation(
    pool: &SqlitePool,
    conversation_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM chat_conversations WHERE id = ? AND user_id = ?",
    )
    .bind(conversation_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(result > 0)
}

// ============================================================================
// Message Operations
// ============================================================================

/// Save a message to a conversation
pub async fn save_message(
    pool: &SqlitePool,
    conversation_id: &str,
    role: &str,
    content: &str,
    context_summary: Option<&str>,
    tokens_used: Option<i32>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO chat_messages (id, conversation_id, role, content, context_summary, tokens_used, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(conversation_id)
    .bind(role)
    .bind(content)
    .bind(context_summary)
    .bind(tokens_used)
    .bind(&now)
    .execute(pool)
    .await?;

    // Update conversation timestamp
    touch_conversation(pool, conversation_id).await?;

    Ok(id)
}

/// Get messages for a conversation (in chronological order)
pub async fn get_messages(
    pool: &SqlitePool,
    conversation_id: &str,
    limit: i32,
) -> Result<Vec<ChatMessage>> {
    let rows = sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT id, conversation_id, role, content, context_summary, tokens_used, created_at
        FROM chat_messages
        WHERE conversation_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        "#,
    )
    .bind(conversation_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    // Reverse to get chronological order
    let mut messages: Vec<ChatMessage> = rows.into_iter().map(ChatMessage::from).collect();
    messages.reverse();
    Ok(messages)
}

/// Get all messages for a conversation (no limit)
pub async fn get_all_messages(
    pool: &SqlitePool,
    conversation_id: &str,
) -> Result<Vec<ChatMessage>> {
    let rows = sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT id, conversation_id, role, content, context_summary, tokens_used, created_at
        FROM chat_messages
        WHERE conversation_id = ?
        ORDER BY created_at ASC
        "#,
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(ChatMessage::from).collect())
}

/// Get the last message in a conversation
pub async fn get_last_message(
    pool: &SqlitePool,
    conversation_id: &str,
) -> Result<Option<ChatMessage>> {
    let row = sqlx::query_as::<_, MessageRow>(
        r#"
        SELECT id, conversation_id, role, content, context_summary, tokens_used, created_at
        FROM chat_messages
        WHERE conversation_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(conversation_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(ChatMessage::from))
}

/// Count messages in a conversation
pub async fn count_messages(pool: &SqlitePool, conversation_id: &str) -> Result<i32> {
    let count = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM chat_messages WHERE conversation_id = ?",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Get total tokens used in a conversation
pub async fn get_total_tokens(pool: &SqlitePool, conversation_id: &str) -> Result<i32> {
    let total = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT SUM(tokens_used) FROM chat_messages WHERE conversation_id = ?",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await?;

    Ok(total.unwrap_or(0) as i32)
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Count messages from a user in the last N seconds
pub async fn count_recent_user_messages(
    pool: &SqlitePool,
    user_id: &str,
    seconds: i64,
) -> Result<i32> {
    let since = (Utc::now() - chrono::Duration::seconds(seconds)).to_rfc3339();

    let count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COUNT(*)
        FROM chat_messages m
        JOIN chat_conversations c ON m.conversation_id = c.id
        WHERE c.user_id = ? AND m.role = 'user' AND m.created_at > ?
        "#,
    )
    .bind(user_id)
    .bind(&since)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

// ============================================================================
// Cleanup
// ============================================================================

/// Delete old conversations (older than N days)
pub async fn cleanup_old_conversations(pool: &SqlitePool, days: i64) -> Result<i32> {
    let cutoff = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();

    let result = sqlx::query("DELETE FROM chat_conversations WHERE updated_at < ?")
        .bind(&cutoff)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() as i32)
}
