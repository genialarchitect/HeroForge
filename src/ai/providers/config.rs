//! LLM Provider Configuration
//!
//! Handles provider selection and configuration from environment variables,
//! database settings, or per-organization configuration.
//!
//! # Configuration Hierarchy
//!
//! 1. Per-organization database settings (highest priority)
//! 2. Environment variables
//! 3. Default values
//!
//! # Environment Variables
//!
//! - `LLM_PROVIDER`: Provider type (anthropic, ollama, openai)
//! - `ANTHROPIC_API_KEY`: API key for Anthropic Claude
//! - `CLAUDE_MODEL`: Model name for Claude (default: claude-sonnet-4-20250514)
//! - `OLLAMA_BASE_URL`: Base URL for Ollama (default: http://localhost:11434)
//! - `OLLAMA_MODEL`: Model name for Ollama (default: llama3:8b)
//! - `OPENAI_API_KEY`: API key for OpenAI (future)
//! - `LLM_FALLBACK_PROVIDER`: Fallback provider if primary fails

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

use super::{BoxedProvider, LLMProviderType, LLMError, create_provider};

/// LLM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    /// Primary provider type
    pub provider: LLMProviderType,

    /// Fallback provider (used if primary fails)
    pub fallback_provider: Option<LLMProviderType>,

    /// Anthropic settings
    pub anthropic_api_key: Option<String>,
    pub anthropic_model: Option<String>,

    /// Ollama settings
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,

    /// OpenAI settings (future)
    pub openai_api_key: Option<String>,
    pub openai_model: Option<String>,
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            provider: LLMProviderType::Anthropic,
            fallback_provider: None,
            anthropic_api_key: None,
            anthropic_model: Some("claude-sonnet-4-20250514".to_string()),
            ollama_base_url: Some("http://localhost:11434".to_string()),
            ollama_model: Some("llama3:8b".to_string()),
            openai_api_key: None,
            openai_model: Some("gpt-4-turbo".to_string()),
        }
    }
}

impl LLMConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let provider = std::env::var("LLM_PROVIDER")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LLMProviderType::Anthropic);

        let fallback_provider = std::env::var("LLM_FALLBACK_PROVIDER")
            .ok()
            .and_then(|s| s.parse().ok());

        Self {
            provider,
            fallback_provider,
            anthropic_api_key: std::env::var("ANTHROPIC_API_KEY").ok(),
            anthropic_model: std::env::var("CLAUDE_MODEL").ok(),
            ollama_base_url: std::env::var("OLLAMA_BASE_URL").ok(),
            ollama_model: std::env::var("OLLAMA_MODEL").ok(),
            openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
            openai_model: std::env::var("OPENAI_MODEL").ok(),
        }
    }

    /// Check if the configured provider is available
    pub fn is_provider_configured(&self) -> bool {
        match self.provider {
            LLMProviderType::Anthropic => {
                self.anthropic_api_key.is_some() ||
                std::env::var("ANTHROPIC_API_KEY").is_ok()
            }
            LLMProviderType::Ollama => true, // Ollama doesn't require API key
            LLMProviderType::OpenAI => {
                self.openai_api_key.is_some() ||
                std::env::var("OPENAI_API_KEY").is_ok()
            }
        }
    }
}

/// Get the current LLM configuration
pub fn get_config() -> LLMConfig {
    LLMConfig::from_env()
}

/// Get a provider instance using environment configuration
pub async fn get_provider(config: Option<&LLMConfig>) -> Result<BoxedProvider, LLMError> {
    let config = config.cloned().unwrap_or_else(LLMConfig::from_env);

    // Try primary provider
    match create_provider(config.provider, &config) {
        Ok(provider) => {
            // Verify it's available
            if provider.is_available().await {
                return Ok(provider);
            }

            // Try fallback if primary is unavailable
            if let Some(fallback) = config.fallback_provider {
                log::warn!(
                    "Primary LLM provider {} unavailable, trying fallback {}",
                    config.provider,
                    fallback
                );
                return create_provider(fallback, &config);
            }

            // Return primary anyway, let caller handle errors
            Ok(provider)
        }
        Err(e) => {
            // Try fallback on configuration error
            if let Some(fallback) = config.fallback_provider {
                log::warn!(
                    "Primary LLM provider {} failed: {}, trying fallback {}",
                    config.provider,
                    e,
                    fallback
                );
                return create_provider(fallback, &config);
            }
            Err(e)
        }
    }
}

/// Get a provider instance for a specific organization
///
/// Looks up organization-specific LLM settings in the database,
/// falling back to environment configuration if not found.
pub async fn get_provider_for_org(
    pool: &SqlitePool,
    org_id: &str,
) -> Result<BoxedProvider, LLMError> {
    // Try to load org-specific configuration from database
    let org_config = load_org_llm_config(pool, org_id).await;

    match org_config {
        Ok(Some(config)) => {
            log::debug!("Using org-specific LLM config for {}: {:?}", org_id, config.provider);
            get_provider(Some(&config)).await
        }
        Ok(None) => {
            log::debug!("No org-specific LLM config for {}, using environment", org_id);
            get_provider(None).await
        }
        Err(e) => {
            log::warn!("Failed to load org LLM config for {}: {}, using environment", org_id, e);
            get_provider(None).await
        }
    }
}

/// Load organization-specific LLM configuration from database
async fn load_org_llm_config(
    pool: &SqlitePool,
    org_id: &str,
) -> Result<Option<LLMConfig>, sqlx::Error> {
    // Query the settings table for org-specific LLM configuration
    let result: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT value FROM settings
        WHERE organization_id = ? AND key = 'llm_config'
        "#
    )
    .bind(org_id)
    .fetch_optional(pool)
    .await?;

    match result {
        Some((json,)) => {
            match serde_json::from_str::<LLMConfig>(&json) {
                Ok(config) => Ok(Some(config)),
                Err(e) => {
                    log::warn!("Failed to parse org LLM config: {}", e);
                    Ok(None)
                }
            }
        }
        None => Ok(None),
    }
}

/// Save organization-specific LLM configuration to database
pub async fn save_org_llm_config(
    pool: &SqlitePool,
    org_id: &str,
    config: &LLMConfig,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(config)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

    sqlx::query(
        r#"
        INSERT INTO settings (organization_id, key, value, updated_at)
        VALUES (?, 'llm_config', ?, datetime('now'))
        ON CONFLICT (organization_id, key) DO UPDATE SET
            value = excluded.value,
            updated_at = datetime('now')
        "#
    )
    .bind(org_id)
    .bind(&json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Provider with automatic fallback support
pub struct FallbackProvider {
    primary: BoxedProvider,
    fallback: Option<BoxedProvider>,
}

impl FallbackProvider {
    pub fn new(primary: BoxedProvider, fallback: Option<BoxedProvider>) -> Self {
        Self { primary, fallback }
    }

    /// Get the active provider (primary if available, fallback otherwise)
    pub async fn get_active(&self) -> &BoxedProvider {
        if self.primary.is_available().await {
            &self.primary
        } else if let Some(ref fallback) = self.fallback {
            log::warn!("Primary LLM provider unavailable, using fallback");
            fallback
        } else {
            &self.primary
        }
    }
}

/// LLM provider status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub provider_type: LLMProviderType,
    pub name: String,
    pub model: String,
    pub available: bool,
    pub capabilities: ProviderCapabilitiesInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilitiesInfo {
    pub streaming: bool,
    pub system_prompts: bool,
    pub function_calling: bool,
    pub vision: bool,
    pub max_context_tokens: u32,
}

/// Get status of all configured providers
pub async fn get_all_provider_status(config: &LLMConfig) -> Vec<ProviderStatus> {
    let mut statuses = Vec::new();

    // Check Anthropic
    if config.anthropic_api_key.is_some() || std::env::var("ANTHROPIC_API_KEY").is_ok() {
        if let Ok(provider) = create_provider(LLMProviderType::Anthropic, config) {
            let caps = provider.capabilities();
            statuses.push(ProviderStatus {
                provider_type: LLMProviderType::Anthropic,
                name: provider.name().to_string(),
                model: provider.default_model().to_string(),
                available: provider.is_available().await,
                capabilities: ProviderCapabilitiesInfo {
                    streaming: caps.streaming,
                    system_prompts: caps.system_prompts,
                    function_calling: caps.function_calling,
                    vision: caps.vision,
                    max_context_tokens: caps.max_context_tokens,
                },
            });
        }
    }

    // Check Ollama
    if let Ok(provider) = create_provider(LLMProviderType::Ollama, config) {
        let caps = provider.capabilities();
        statuses.push(ProviderStatus {
            provider_type: LLMProviderType::Ollama,
            name: provider.name().to_string(),
            model: provider.default_model().to_string(),
            available: provider.is_available().await,
            capabilities: ProviderCapabilitiesInfo {
                streaming: caps.streaming,
                system_prompts: caps.system_prompts,
                function_calling: caps.function_calling,
                vision: caps.vision,
                max_context_tokens: caps.max_context_tokens,
            },
        });
    }

    statuses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        // Test default provider
        let config = LLMConfig::from_env();
        // Default is Anthropic if LLM_PROVIDER not set
        assert!(matches!(config.provider, LLMProviderType::Anthropic | LLMProviderType::Ollama));
    }

    #[test]
    fn test_config_default() {
        let config = LLMConfig::default();
        assert_eq!(config.provider, LLMProviderType::Anthropic);
        assert_eq!(config.anthropic_model, Some("claude-sonnet-4-20250514".to_string()));
        assert_eq!(config.ollama_base_url, Some("http://localhost:11434".to_string()));
    }

    #[test]
    fn test_provider_configured_check() {
        let mut config = LLMConfig::default();
        config.provider = LLMProviderType::Ollama;
        assert!(config.is_provider_configured()); // Ollama doesn't need API key

        config.provider = LLMProviderType::Anthropic;
        config.anthropic_api_key = None;
        // Will check env var, may or may not be configured
    }
}
