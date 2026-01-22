//! AI Configuration API
//!
//! Provides endpoints for managing LLM provider settings per user/organization.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::ai::providers::{
    get_provider, LLMConfig, LLMProviderType, get_all_provider_status,
};
use crate::web::auth::Claims;

/// AI Configuration response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AiConfigurationResponse {
    pub provider: String,
    pub model: String,
    pub ollama_base_url: Option<String>,
    pub has_anthropic_key: bool,
    pub has_openai_key: bool,
    pub fallback_provider: Option<String>,
    pub auto_reports: bool,
    pub auto_remediation: bool,
    pub updated_at: Option<String>,
}

/// Update AI Configuration request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAiConfigurationRequest {
    pub provider: String,
    pub model: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,
    pub fallback_provider: Option<String>,
    pub auto_reports: Option<bool>,
    pub auto_remediation: Option<bool>,
}

/// Provider status response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProviderStatusResponse {
    pub provider: String,
    pub name: String,
    pub model: String,
    pub available: bool,
    pub streaming: bool,
    pub max_context_tokens: u32,
}

/// Test connection response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
    pub provider: String,
    pub model: String,
    pub response_time_ms: Option<u64>,
}

/// Available models response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AvailableModelsResponse {
    pub anthropic: Vec<ModelInfo>,
    pub ollama: Vec<ModelInfo>,
    pub openai: Vec<ModelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Configure AI configuration routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ai-settings")
            .route("", web::get().to(get_configuration))
            .route("", web::put().to(update_configuration))
            .route("/test", web::post().to(test_connection))
            .route("/providers", web::get().to(get_providers_status))
            .route("/models", web::get().to(get_available_models))
    );
}

/// Get current AI configuration
#[utoipa::path(
    get,
    path = "/api/ai-settings",
    tag = "AI Configuration",
    responses(
        (status = 200, description = "AI configuration retrieved", body = AiConfigurationResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_configuration(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Try to load user-specific configuration from database
    let db_config = load_user_ai_config(&pool, user_id).await;

    // Build response from database config or environment defaults
    let config = match db_config {
        Ok(Some(cfg)) => cfg,
        _ => {
            // Fall back to environment configuration
            let env_config = LLMConfig::from_env();
            AiConfigurationResponse {
                provider: env_config.provider.to_string(),
                model: env_config.anthropic_model
                    .or(env_config.ollama_model)
                    .unwrap_or_else(|| "claude-sonnet-4-20250514".to_string()),
                ollama_base_url: env_config.ollama_base_url,
                has_anthropic_key: env_config.anthropic_api_key.is_some()
                    || std::env::var("ANTHROPIC_API_KEY").is_ok(),
                has_openai_key: env_config.openai_api_key.is_some()
                    || std::env::var("OPENAI_API_KEY").is_ok(),
                fallback_provider: env_config.fallback_provider.map(|p| p.to_string()),
                auto_reports: false,
                auto_remediation: true,
                updated_at: None,
            }
        }
    };

    Ok(HttpResponse::Ok().json(config))
}

/// Update AI configuration
#[utoipa::path(
    put,
    path = "/api/ai-settings",
    tag = "AI Configuration",
    request_body = UpdateAiConfigurationRequest,
    responses(
        (status = 200, description = "AI configuration updated", body = AiConfigurationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_configuration(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<UpdateAiConfigurationRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Validate provider
    let provider: LLMProviderType = body.provider.parse()
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid provider"))?;

    // Validate fallback provider if specified
    let fallback_provider = if let Some(ref fp) = body.fallback_provider {
        Some(fp.parse::<LLMProviderType>()
            .map_err(|_| actix_web::error::ErrorBadRequest("Invalid fallback provider"))?)
    } else {
        None
    };

    let now = Utc::now().to_rfc3339();

    // Upsert configuration
    let result = sqlx::query(
        r#"
        INSERT INTO ai_user_config (
            user_id, provider, model, anthropic_api_key, openai_api_key,
            ollama_base_url, ollama_model, fallback_provider,
            auto_reports, auto_remediation, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (user_id) DO UPDATE SET
            provider = excluded.provider,
            model = COALESCE(excluded.model, ai_user_config.model),
            anthropic_api_key = COALESCE(excluded.anthropic_api_key, ai_user_config.anthropic_api_key),
            openai_api_key = COALESCE(excluded.openai_api_key, ai_user_config.openai_api_key),
            ollama_base_url = COALESCE(excluded.ollama_base_url, ai_user_config.ollama_base_url),
            ollama_model = COALESCE(excluded.ollama_model, ai_user_config.ollama_model),
            fallback_provider = excluded.fallback_provider,
            auto_reports = COALESCE(excluded.auto_reports, ai_user_config.auto_reports),
            auto_remediation = COALESCE(excluded.auto_remediation, ai_user_config.auto_remediation),
            updated_at = excluded.updated_at
        "#
    )
    .bind(user_id)
    .bind(provider.to_string())
    .bind(&body.model)
    .bind(&body.anthropic_api_key)
    .bind(&body.openai_api_key)
    .bind(&body.ollama_base_url)
    .bind(&body.ollama_model)
    .bind(fallback_provider.map(|p| p.to_string()))
    .bind(body.auto_reports)
    .bind(body.auto_remediation)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to save AI configuration: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to save configuration")
    })?;

    log::info!("AI configuration updated for user {}: provider={}", user_id, provider);

    // Return updated configuration
    let config = load_user_ai_config(&pool, user_id)
        .await
        .map_err(|e| {
            log::error!("Failed to load updated configuration: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to load configuration")
        })?
        .unwrap_or_else(|| AiConfigurationResponse {
            provider: provider.to_string(),
            model: body.model.clone().unwrap_or_default(),
            ollama_base_url: body.ollama_base_url.clone(),
            has_anthropic_key: body.anthropic_api_key.is_some(),
            has_openai_key: body.openai_api_key.is_some(),
            fallback_provider: body.fallback_provider.clone(),
            auto_reports: body.auto_reports.unwrap_or(false),
            auto_remediation: body.auto_remediation.unwrap_or(true),
            updated_at: Some(now),
        });

    Ok(HttpResponse::Ok().json(config))
}

/// Test AI connection
#[utoipa::path(
    post,
    path = "/api/ai-settings/test",
    tag = "AI Configuration",
    responses(
        (status = 200, description = "Connection test result", body = TestConnectionResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Load user's configuration
    let config = build_llm_config_for_user(&pool, user_id).await;

    let start = std::time::Instant::now();

    // Try to get a provider and make a simple request
    match get_provider(Some(&config)).await {
        Ok(provider) => {
            // Check if available
            if !provider.is_available().await {
                return Ok(HttpResponse::Ok().json(TestConnectionResponse {
                    success: false,
                    message: format!("{} is not available. Check your configuration.", provider.name()),
                    provider: provider.provider_type().to_string(),
                    model: provider.default_model().to_string(),
                    response_time_ms: None,
                }));
            }

            // Make a simple test request
            use crate::ai::providers::LLMRequest;
            let test_request = LLMRequest::new()
                .with_system_prompt("You are a helpful assistant.")
                .with_user_message("Say 'Connection successful' and nothing else.")
                .with_max_tokens(50);

            match provider.complete(test_request).await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    Ok(HttpResponse::Ok().json(TestConnectionResponse {
                        success: true,
                        message: format!("Connected successfully. Response: {}",
                            response.content.chars().take(100).collect::<String>()),
                        provider: provider.provider_type().to_string(),
                        model: response.model,
                        response_time_ms: Some(elapsed),
                    }))
                }
                Err(e) => {
                    Ok(HttpResponse::Ok().json(TestConnectionResponse {
                        success: false,
                        message: format!("Connection failed: {}", e),
                        provider: provider.provider_type().to_string(),
                        model: provider.default_model().to_string(),
                        response_time_ms: None,
                    }))
                }
            }
        }
        Err(e) => {
            Ok(HttpResponse::Ok().json(TestConnectionResponse {
                success: false,
                message: format!("Failed to initialize provider: {}", e),
                provider: config.provider.to_string(),
                model: "unknown".to_string(),
                response_time_ms: None,
            }))
        }
    }
}

/// Get status of all configured providers
#[utoipa::path(
    get,
    path = "/api/ai-settings/providers",
    tag = "AI Configuration",
    responses(
        (status = 200, description = "Provider status list", body = Vec<ProviderStatusResponse>),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_providers_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Load user's configuration
    let config = build_llm_config_for_user(&pool, user_id).await;

    // Get status of all providers
    let statuses = get_all_provider_status(&config).await;

    let response: Vec<ProviderStatusResponse> = statuses
        .into_iter()
        .map(|s| ProviderStatusResponse {
            provider: s.provider_type.to_string(),
            name: s.name,
            model: s.model,
            available: s.available,
            streaming: s.capabilities.streaming,
            max_context_tokens: s.capabilities.max_context_tokens,
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get available models for each provider
#[utoipa::path(
    get,
    path = "/api/ai-settings/models",
    tag = "AI Configuration",
    responses(
        (status = 200, description = "Available models by provider", body = AvailableModelsResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_available_models(
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    // Return known models for each provider
    let response = AvailableModelsResponse {
        anthropic: vec![
            ModelInfo {
                id: "claude-opus-4-20250514".to_string(),
                name: "Claude Opus 4".to_string(),
                description: Some("Most capable model, best for complex tasks".to_string()),
            },
            ModelInfo {
                id: "claude-sonnet-4-20250514".to_string(),
                name: "Claude Sonnet 4".to_string(),
                description: Some("Balanced performance and speed".to_string()),
            },
            ModelInfo {
                id: "claude-3-5-sonnet-20241022".to_string(),
                name: "Claude 3.5 Sonnet".to_string(),
                description: Some("Previous generation, still excellent".to_string()),
            },
            ModelInfo {
                id: "claude-3-5-haiku-20241022".to_string(),
                name: "Claude 3.5 Haiku".to_string(),
                description: Some("Fast and efficient for simpler tasks".to_string()),
            },
        ],
        ollama: vec![
            ModelInfo {
                id: "llama3:70b".to_string(),
                name: "Llama 3 70B".to_string(),
                description: Some("Large model, best quality (requires 80GB+ VRAM)".to_string()),
            },
            ModelInfo {
                id: "llama3:8b".to_string(),
                name: "Llama 3 8B".to_string(),
                description: Some("Good balance of quality and speed".to_string()),
            },
            ModelInfo {
                id: "mistral:7b".to_string(),
                name: "Mistral 7B".to_string(),
                description: Some("Fast, good for quick analysis".to_string()),
            },
            ModelInfo {
                id: "codellama:34b".to_string(),
                name: "CodeLlama 34B".to_string(),
                description: Some("Specialized for code and security analysis".to_string()),
            },
            ModelInfo {
                id: "deepseek-coder:33b".to_string(),
                name: "DeepSeek Coder 33B".to_string(),
                description: Some("Excellent for code understanding".to_string()),
            },
        ],
        openai: vec![
            ModelInfo {
                id: "gpt-4-turbo".to_string(),
                name: "GPT-4 Turbo".to_string(),
                description: Some("Latest GPT-4 with improved performance".to_string()),
            },
            ModelInfo {
                id: "gpt-4".to_string(),
                name: "GPT-4".to_string(),
                description: Some("Original GPT-4 model".to_string()),
            },
            ModelInfo {
                id: "gpt-3.5-turbo".to_string(),
                name: "GPT-3.5 Turbo".to_string(),
                description: Some("Fast and cost-effective".to_string()),
            },
        ],
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Load user's AI configuration from database
async fn load_user_ai_config(
    pool: &SqlitePool,
    user_id: &str,
) -> anyhow::Result<Option<AiConfigurationResponse>> {
    let result: Option<(
        String,          // provider
        Option<String>,  // model
        Option<String>,  // anthropic_api_key
        Option<String>,  // openai_api_key
        Option<String>,  // ollama_base_url
        Option<String>,  // ollama_model
        Option<String>,  // fallback_provider
        bool,            // auto_reports
        bool,            // auto_remediation
        String,          // updated_at
    )> = sqlx::query_as(
        r#"
        SELECT provider, model, anthropic_api_key, openai_api_key,
               ollama_base_url, ollama_model, fallback_provider,
               auto_reports, auto_remediation, updated_at
        FROM ai_user_config
        WHERE user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|(provider, model, anthropic_key, openai_key, ollama_url, ollama_model, fallback, auto_reports, auto_remediation, updated_at)| {
        // Determine actual model based on provider
        let effective_model = match provider.as_str() {
            "ollama" => ollama_model.or(model).unwrap_or_else(|| "llama3:8b".to_string()),
            "anthropic" => model.unwrap_or_else(|| "claude-sonnet-4-20250514".to_string()),
            "openai" => model.unwrap_or_else(|| "gpt-4-turbo".to_string()),
            _ => model.unwrap_or_default(),
        };

        AiConfigurationResponse {
            provider,
            model: effective_model,
            ollama_base_url: ollama_url,
            has_anthropic_key: anthropic_key.is_some() || std::env::var("ANTHROPIC_API_KEY").is_ok(),
            has_openai_key: openai_key.is_some() || std::env::var("OPENAI_API_KEY").is_ok(),
            fallback_provider: fallback,
            auto_reports,
            auto_remediation,
            updated_at: Some(updated_at),
        }
    }))
}

/// Build LLM config from user's database settings
async fn build_llm_config_for_user(pool: &SqlitePool, user_id: &str) -> LLMConfig {
    let result: Option<(
        String,          // provider
        Option<String>,  // model
        Option<String>,  // anthropic_api_key
        Option<String>,  // openai_api_key
        Option<String>,  // ollama_base_url
        Option<String>,  // ollama_model
        Option<String>,  // fallback_provider
    )> = sqlx::query_as(
        r#"
        SELECT provider, model, anthropic_api_key, openai_api_key,
               ollama_base_url, ollama_model, fallback_provider
        FROM ai_user_config
        WHERE user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match result {
        Some((provider, model, anthropic_key, openai_key, ollama_url, ollama_model, fallback)) => {
            LLMConfig {
                provider: provider.parse().unwrap_or(LLMProviderType::Anthropic),
                fallback_provider: fallback.and_then(|f| f.parse().ok()),
                anthropic_api_key: anthropic_key.or_else(|| std::env::var("ANTHROPIC_API_KEY").ok()),
                anthropic_model: model.clone(),
                ollama_base_url: ollama_url.or_else(|| std::env::var("OLLAMA_BASE_URL").ok()),
                ollama_model: ollama_model.or_else(|| std::env::var("OLLAMA_MODEL").ok()),
                openai_api_key: openai_key.or_else(|| std::env::var("OPENAI_API_KEY").ok()),
                openai_model: model,
                openai_org_id: std::env::var("OPENAI_ORG_ID").ok(),
            }
        }
        None => LLMConfig::from_env(),
    }
}

/// Initialize the AI configuration table
pub async fn init_ai_config_table(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ai_user_config (
            user_id TEXT PRIMARY KEY,
            provider TEXT NOT NULL DEFAULT 'anthropic',
            model TEXT,
            anthropic_api_key TEXT,
            openai_api_key TEXT,
            ollama_base_url TEXT,
            ollama_model TEXT,
            fallback_provider TEXT,
            auto_reports INTEGER NOT NULL DEFAULT 0,
            auto_remediation INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#
    )
    .execute(pool)
    .await?;

    log::info!("AI configuration table initialized");
    Ok(())
}
