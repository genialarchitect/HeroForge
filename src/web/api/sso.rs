#![allow(dead_code)]
//! SSO API Endpoints
//!
//! This module provides REST API endpoints for SSO (SAML/OIDC) authentication management.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db;
use crate::web::auth::sso::{
    self, get_active_sso_providers, get_all_sso_providers, get_provider_presets,
    get_sso_provider, CreateSsoProviderRequest, OidcCallbackParams, ProviderConfig,
    SamlAcsRequest, SsoManager, SsoMetadataResponse, SsoProvider, SsoProviderForLogin,
    SsoProviderResponse, SsoProviderStatus, SsoProviderType, SsoTestResult,
    UpdateMappingsRequest, UpdateSsoProviderRequest,
};
use crate::web::auth::Claims;
use crate::web::error::ApiErrorKind;

/// Get SSO providers available for login (public endpoint)
pub async fn get_sso_providers_for_login(
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiErrorKind> {
    let providers = get_active_sso_providers(pool.get_ref())
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let login_providers: Vec<SsoProviderForLogin> = providers
        .into_iter()
        .map(|p| {
            let provider_type = p.provider_type.parse().unwrap_or(SsoProviderType::Saml);
            SsoProviderForLogin {
                id: p.id,
                name: p.name,
                display_name: p.display_name,
                provider_type,
                icon: p.icon,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(login_providers))
}

/// Get all SSO providers (admin only)
pub async fn list_sso_providers(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let providers = get_all_sso_providers(pool.get_ref())
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let responses: Vec<SsoProviderResponse> = providers
        .into_iter()
        .map(|p| provider_to_response(p, true))
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Get provider presets
pub async fn get_presets(claims: Claims, pool: web::Data<SqlitePool>) -> Result<HttpResponse, ApiErrorKind> {
    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let presets = get_provider_presets();
    Ok(HttpResponse::Ok().json(presets))
}

/// Get single SSO provider
pub async fn get_provider(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let provider = get_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|_| ApiErrorKind::NotFound("Provider not found".to_string()))?;

    Ok(HttpResponse::Ok().json(provider_to_response(provider, true)))
}

/// Create SSO provider
pub async fn create_provider(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateSsoProviderRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let now = Utc::now();
    let id = Uuid::new_v4().to_string();

    let config_json = serde_json::to_string(&body.config)
        .map_err(|e| ApiErrorKind::BadRequest(format!("Invalid config: {}", e)))?;

    let attribute_mappings_json = body
        .attribute_mappings
        .as_ref()
        .map(|m| serde_json::to_string(m).ok())
        .flatten();

    let group_mappings_json = body
        .group_mappings
        .as_ref()
        .map(|m| serde_json::to_string(m).ok())
        .flatten();

    let provider = SsoProvider {
        id: id.clone(),
        name: body.name.clone(),
        display_name: body.display_name.clone(),
        provider_type: body.provider_type.to_string(),
        status: SsoProviderStatus::Disabled.to_string(),
        icon: body.icon.clone(),
        config: config_json,
        attribute_mappings: attribute_mappings_json,
        group_mappings: group_mappings_json,
        jit_provisioning: body.jit_provisioning.unwrap_or(false),
        default_role: body.default_role.clone().unwrap_or_else(|| "user".to_string()),
        update_on_login: body.update_on_login.unwrap_or(false),
        created_at: now,
        updated_at: now,
        last_used_at: None,
    };

    sso::create_sso_provider(pool.get_ref(), &provider)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Log audit
    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "sso_provider_created",
        Some("sso_provider"),
        Some(&id),
        Some(&format!("Created SSO provider: {}", body.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Created().json(provider_to_response(provider, true)))
}

/// Update SSO provider
pub async fn update_provider(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
    body: web::Json<UpdateSsoProviderRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let provider = sso::update_sso_provider(pool.get_ref(), &provider_id, &body)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Log audit
    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "sso_provider_updated",
        Some("sso_provider"),
        Some(&provider_id),
        Some(&format!("Updated SSO provider: {}", provider.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::Ok().json(provider_to_response(provider, true)))
}

/// Delete SSO provider
pub async fn delete_provider(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    // Get provider name for audit log
    let provider = get_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|_| ApiErrorKind::NotFound("Provider not found".to_string()))?;

    sso::delete_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Log audit
    db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "sso_provider_deleted",
        Some("sso_provider"),
        Some(&provider_id),
        Some(&format!("Deleted SSO provider: {}", provider.name)),
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// Get SP metadata for a provider
pub async fn get_provider_metadata(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Verify provider exists
    let provider = get_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|_| ApiErrorKind::NotFound("Provider not found".to_string()))?;

    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url.clone());

    let provider_type: SsoProviderType = provider
        .provider_type
        .parse()
        .unwrap_or(SsoProviderType::Saml);

    let response = match provider_type {
        SsoProviderType::Saml => {
            let metadata_xml = manager.generate_sp_metadata(&provider_id);
            SsoMetadataResponse {
                entity_id: manager.get_sp_entity_id(&provider_id),
                metadata_xml: Some(metadata_xml),
                acs_url: Some(manager.get_acs_url()),
                slo_url: Some(format!("{}/api/sso/logout", base_url)),
                redirect_uri: None,
            }
        }
        SsoProviderType::Oidc => SsoMetadataResponse {
            entity_id: manager.get_sp_entity_id(&provider_id),
            metadata_xml: None,
            acs_url: None,
            slo_url: None,
            redirect_uri: Some(manager.get_oidc_redirect_uri()),
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Download SP metadata XML (for SAML providers)
pub async fn download_metadata_xml(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Verify provider exists and is SAML
    let provider = get_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|_| ApiErrorKind::NotFound("Provider not found".to_string()))?;

    let provider_type: SsoProviderType = provider
        .provider_type
        .parse()
        .unwrap_or(SsoProviderType::Saml);

    if provider_type != SsoProviderType::Saml {
        return Err(ApiErrorKind::BadRequest(
            "Metadata XML only available for SAML providers".to_string(),
        ));
    }

    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url);
    let metadata_xml = manager.generate_sp_metadata(&provider_id);

    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .insert_header(("Content-Disposition", format!("attachment; filename=\"sp-metadata-{}.xml\"", provider_id)))
        .body(metadata_xml))
}

/// Update provider attribute/group mappings
pub async fn update_mappings(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
    body: web::Json<UpdateMappingsRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let updates = UpdateSsoProviderRequest {
        display_name: None,
        icon: None,
        status: None,
        config: None,
        attribute_mappings: body.attribute_mappings.clone(),
        group_mappings: body.group_mappings.clone(),
        jit_provisioning: None,
        default_role: None,
        update_on_login: None,
    };

    let provider = sso::update_sso_provider(pool.get_ref(), &provider_id, &updates)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(provider_to_response(provider, true)))
}

/// Initiate SSO login
pub async fn initiate_login(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url);

    let login_response = manager
        .initiate_login(&provider_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(login_response))
}

/// SAML Assertion Consumer Service (ACS) callback
pub async fn saml_callback(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    form: web::Form<SamlAcsRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url.clone());

    let auth_result = manager
        .process_saml_callback(&form.saml_response, form.relay_state.as_deref())
        .await
        .map_err(|e| ApiErrorKind::Unauthorized(e.to_string()))?;

    // Redirect to frontend with token
    let redirect_url = format!(
        "{}/?token={}",
        base_url,
        urlencoding::encode(&auth_result.token),
    );

    Ok(HttpResponse::Found()
        .insert_header(("Location", redirect_url))
        .finish())
}

/// OIDC callback
pub async fn oidc_callback(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<OidcCallbackParams>,
) -> Result<HttpResponse, ApiErrorKind> {
    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url.clone());

    let auth_result = manager
        .process_oidc_callback(&query)
        .await
        .map_err(|e| ApiErrorKind::Unauthorized(e.to_string()))?;

    // Redirect to frontend with token
    let redirect_url = format!(
        "{}/?token={}",
        base_url,
        urlencoding::encode(&auth_result.token),
    );

    Ok(HttpResponse::Found()
        .insert_header(("Location", redirect_url))
        .finish())
}

/// SSO Single Logout
pub async fn sso_logout(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: HttpRequest,
    body: web::Json<sso::SsoLogoutRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let base_url = get_base_url(&req);
    let manager = SsoManager::new(pool.get_ref().clone(), base_url);

    let logout_url = manager
        .process_logout(&claims.sub, body.logout_from_idp.unwrap_or(false))
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Revoke refresh tokens
    db::revoke_all_user_refresh_tokens(pool.get_ref(), &claims.sub)
        .await
        .ok();

    #[derive(Serialize)]
    struct LogoutResponse {
        success: bool,
        idp_logout_url: Option<String>,
    }

    Ok(HttpResponse::Ok().json(LogoutResponse {
        success: true,
        idp_logout_url: logout_url,
    }))
}

/// Test SSO provider connection
pub async fn test_provider(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
    req: HttpRequest,
) -> Result<HttpResponse, ApiErrorKind> {
    let provider_id = path.into_inner();

    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let provider = get_sso_provider(pool.get_ref(), &provider_id)
        .await
        .map_err(|_| ApiErrorKind::NotFound("Provider not found".to_string()))?;

    let config: ProviderConfig = serde_json::from_str(&provider.config)
        .map_err(|e| ApiErrorKind::InternalError(format!("Invalid config: {}", e)))?;

    let result = match config {
        ProviderConfig::Saml(saml_config) => {
            // Test SAML config by validating certificate
            if saml_config.idp_certificate.is_empty() {
                SsoTestResult {
                    success: false,
                    message: "IdP certificate is not configured".to_string(),
                    details: None,
                }
            } else if saml_config.idp_sso_url.is_empty() {
                SsoTestResult {
                    success: false,
                    message: "IdP SSO URL is not configured".to_string(),
                    details: None,
                }
            } else {
                SsoTestResult {
                    success: true,
                    message: "SAML configuration validated".to_string(),
                    details: Some(serde_json::json!({
                        "idp_entity_id": saml_config.idp_entity_id,
                        "idp_sso_url": saml_config.idp_sso_url,
                        "has_slo": saml_config.idp_slo_url.is_some(),
                    })),
                }
            }
        }
        ProviderConfig::Oidc(oidc_config) => {
            // Test OIDC config by fetching discovery document
            let base_url = get_base_url(&req);
            let mut client = sso::OidcClient::new(oidc_config.clone(), format!("{}/api/sso/callback/oidc", base_url));

            match client.discover().await {
                Ok(()) => SsoTestResult {
                    success: true,
                    message: "OIDC discovery successful".to_string(),
                    details: Some(serde_json::json!({
                        "issuer": oidc_config.issuer_url,
                        "client_id": oidc_config.client_id,
                        "scopes": oidc_config.scopes,
                    })),
                },
                Err(e) => SsoTestResult {
                    success: false,
                    message: format!("OIDC discovery failed: {}", e),
                    details: None,
                },
            }
        }
    };

    Ok(HttpResponse::Ok().json(result))
}

/// Parse IdP metadata (SAML) and return extracted config
#[derive(Debug, Deserialize)]
pub struct ParseMetadataRequest {
    pub metadata_xml: String,
}

pub async fn parse_idp_metadata(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    body: web::Json<ParseMetadataRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    // Check admin permission
    let is_admin = db::has_permission(pool.get_ref(), &claims.sub, "manage_settings")
        .await
        .unwrap_or(false);

    if !is_admin {
        return Err(ApiErrorKind::Forbidden(
            "Admin permission required".to_string(),
        ));
    }

    let config = sso::saml::parse_idp_metadata(&body.metadata_xml)
        .map_err(|e| ApiErrorKind::BadRequest(format!("Failed to parse metadata: {}", e)))?;

    Ok(HttpResponse::Ok().json(ProviderConfig::Saml(config)))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn provider_to_response(provider: SsoProvider, include_config: bool) -> SsoProviderResponse {
    let provider_type = provider.provider_type.parse().unwrap_or(SsoProviderType::Saml);
    let status = match provider.status.as_str() {
        "active" => SsoProviderStatus::Active,
        "disabled" => SsoProviderStatus::Disabled,
        "incomplete" => SsoProviderStatus::Incomplete,
        "error" => SsoProviderStatus::Error,
        _ => SsoProviderStatus::Disabled,
    };

    let (config, attribute_mappings, group_mappings) = if include_config {
        let config = serde_json::from_str(&provider.config).ok();
        let attr_mappings = provider
            .attribute_mappings
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());
        let grp_mappings = provider
            .group_mappings
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());
        (config, attr_mappings, grp_mappings)
    } else {
        (None, None, None)
    };

    SsoProviderResponse {
        id: provider.id,
        name: provider.name,
        display_name: provider.display_name,
        provider_type,
        status,
        icon: provider.icon,
        jit_provisioning: provider.jit_provisioning,
        default_role: provider.default_role,
        update_on_login: provider.update_on_login,
        created_at: provider.created_at,
        updated_at: provider.updated_at,
        last_used_at: provider.last_used_at,
        config,
        attribute_mappings,
        group_mappings,
    }
}

fn get_base_url(req: &HttpRequest) -> String {
    // Try to get from X-Forwarded-Proto and Host headers (behind reverse proxy)
    let scheme = req
        .headers()
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");

    let host = req
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    format!("{}://{}", scheme, host)
}

/// Configure SSO routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/sso")
            // Public endpoints (for login page)
            .route("/providers", web::get().to(get_sso_providers_for_login))
            .route("/login/{provider_id}", web::get().to(initiate_login))
            .route("/callback/saml", web::post().to(saml_callback))
            .route("/callback/oidc", web::get().to(oidc_callback))
            // Admin endpoints (require authentication)
            .route("/admin/providers", web::get().to(list_sso_providers))
            .route("/admin/providers", web::post().to(create_provider))
            .route("/admin/presets", web::get().to(get_presets))
            .route("/admin/parse-metadata", web::post().to(parse_idp_metadata))
            .route("/admin/providers/{id}", web::get().to(get_provider))
            .route("/admin/providers/{id}", web::put().to(update_provider))
            .route("/admin/providers/{id}", web::delete().to(delete_provider))
            .route("/admin/providers/{id}/metadata", web::get().to(get_provider_metadata))
            .route("/admin/providers/{id}/metadata.xml", web::get().to(download_metadata_xml))
            .route("/admin/providers/{id}/mappings", web::put().to(update_mappings))
            .route("/admin/providers/{id}/test", web::post().to(test_provider))
            // Logout (authenticated)
            .route("/logout", web::post().to(sso_logout))
    );
}
