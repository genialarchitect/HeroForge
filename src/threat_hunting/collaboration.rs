use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;
use chrono::Utc;

use super::types::HuntNotebook;

/// Create a new hunt notebook
#[allow(dead_code)]
pub async fn create_notebook(
    pool: &SqlitePool,
    name: String,
    user_id: Option<String>,
) -> Result<HuntNotebook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let content = serde_json::json!({
        "cells": []
    });
    let shared_with = Vec::new();

    sqlx::query(
        "INSERT INTO hunt_notebooks (id, name, content, shared_with, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&name)
    .bind(content.to_string())
    .bind(serde_json::to_string(&shared_with)?)
    .bind(&user_id)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(HuntNotebook {
        id,
        name,
        content,
        shared_with,
        created_by: user_id,
        created_at: now,
        updated_at: now,
    })
}

/// Get notebook by ID
#[allow(dead_code)]
pub async fn get_notebook(pool: &SqlitePool, id: &str) -> Result<Option<HuntNotebook>> {
    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String)>(
        "SELECT id, name, content, shared_with, created_by, created_at, updated_at
         FROM hunt_notebooks
         WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    if let Some((id, name, content, shared_with, created_by, created_at, updated_at)) = row {
        Ok(Some(HuntNotebook {
            id,
            name,
            content: serde_json::from_str(&content)?,
            shared_with: serde_json::from_str(&shared_with)?,
            created_by,
            created_at: created_at.parse()?,
            updated_at: updated_at.parse()?,
        }))
    } else {
        Ok(None)
    }
}

/// List notebooks accessible to a user
#[allow(dead_code)]
pub async fn list_notebooks(pool: &SqlitePool, user_id: &str) -> Result<Vec<HuntNotebook>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, Option<String>, String, String)>(
        "SELECT id, name, content, shared_with, created_by, created_at, updated_at
         FROM hunt_notebooks
         WHERE created_by = ? OR shared_with LIKE ?
         ORDER BY updated_at DESC"
    )
    .bind(user_id)
    .bind(format!("%{}%", user_id))
    .fetch_all(pool)
    .await?;

    let mut notebooks = Vec::new();
    for (id, name, content, shared_with, created_by, created_at, updated_at) in rows {
        notebooks.push(HuntNotebook {
            id,
            name,
            content: serde_json::from_str(&content)?,
            shared_with: serde_json::from_str(&shared_with)?,
            created_by,
            created_at: created_at.parse()?,
            updated_at: updated_at.parse()?,
        });
    }

    Ok(notebooks)
}

/// Share notebook with other users
#[allow(dead_code)]
pub async fn share_notebook(
    pool: &SqlitePool,
    notebook_id: &str,
    user_ids: Vec<String>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE hunt_notebooks
         SET shared_with = ?, updated_at = ?
         WHERE id = ?"
    )
    .bind(serde_json::to_string(&user_ids)?)
    .bind(now.to_rfc3339())
    .bind(notebook_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update notebook content
#[allow(dead_code)]
pub async fn update_notebook_content(
    pool: &SqlitePool,
    notebook_id: &str,
    content: serde_json::Value,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE hunt_notebooks
         SET content = ?, updated_at = ?
         WHERE id = ?"
    )
    .bind(content.to_string())
    .bind(now.to_rfc3339())
    .bind(notebook_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Hunt team workspace
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntWorkspace {
    pub id: String,
    pub name: String,
    pub team_members: Vec<String>,
    pub notebooks: Vec<String>,
    pub hypotheses: Vec<String>,
}

/// Create a team workspace
#[allow(dead_code)]
pub fn create_workspace(name: String, team_members: Vec<String>) -> HuntWorkspace {
    HuntWorkspace {
        id: Uuid::new_v4().to_string(),
        name,
        team_members,
        notebooks: Vec::new(),
        hypotheses: Vec::new(),
    }
}

/// Peer review for hunt hypothesis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HuntReview {
    pub id: String,
    pub hypothesis_id: String,
    pub reviewer_id: String,
    pub status: ReviewStatus,
    pub comments: String,
    pub reviewed_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewStatus {
    Approved,
    ChangesRequested,
    Rejected,
}

/// Submit a peer review
#[allow(dead_code)]
pub fn create_review(
    hypothesis_id: String,
    reviewer_id: String,
    status: ReviewStatus,
    comments: String,
) -> HuntReview {
    HuntReview {
        id: Uuid::new_v4().to_string(),
        hypothesis_id,
        reviewer_id,
        status,
        comments,
        reviewed_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_creation() {
        let workspace = create_workspace(
            "Red Team Hunt".to_string(),
            vec!["user1".to_string(), "user2".to_string()],
        );

        assert_eq!(workspace.name, "Red Team Hunt");
        assert_eq!(workspace.team_members.len(), 2);
    }

    #[test]
    fn test_review_creation() {
        let review = create_review(
            "hyp1".to_string(),
            "reviewer1".to_string(),
            ReviewStatus::Approved,
            "Looks good!".to_string(),
        );

        assert_eq!(review.hypothesis_id, "hyp1");
        matches!(review.status, ReviewStatus::Approved);
    }
}
