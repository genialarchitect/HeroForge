// Payload Encoding API Endpoints
// REST API for payload encoding, obfuscation, and transformation
//
// These endpoints are for authorized penetration testing - helping red teams
// test security controls including EDR/AV evasion testing during authorized engagements.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::exploitation::encoders::{
    EncoderCategory, EncoderChain,
    EncoderType, EncodingMetadata, EncodingOptions,
    get_encoder, list_encoders,
};
use crate::web::auth::Claims;
use crate::web::error::ApiError;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to encode a payload
#[derive(Debug, Deserialize)]
pub struct EncodePayloadRequest {
    /// Payload to encode (base64 encoded for binary safety)
    pub payload: String,

    /// Whether payload is base64 encoded
    #[serde(default)]
    pub payload_is_base64: bool,

    /// Encoder type to use
    pub encoder_type: EncoderType,

    /// Encoding options
    #[serde(default)]
    pub options: EncodingOptions,

    /// Customer ID for authorization tracking
    pub customer_id: Option<String>,

    /// Asset ID for tracking
    pub asset_id: Option<String>,
}

/// Request to decode a payload
#[derive(Debug, Deserialize)]
pub struct DecodePayloadRequest {
    /// Encoded payload (base64 or hex)
    pub payload: String,

    /// Whether payload is base64 encoded (vs hex)
    #[serde(default)]
    pub payload_is_base64: bool,

    /// Encoder type used
    pub encoder_type: EncoderType,

    /// Decoding options (must include key/iv if required)
    #[serde(default)]
    pub options: EncodingOptions,
}

/// Request to chain multiple encoders
#[derive(Debug, Deserialize)]
pub struct ChainEncodersRequest {
    /// Payload to encode (base64 encoded for binary safety)
    pub payload: String,

    /// Whether payload is base64 encoded
    #[serde(default)]
    pub payload_is_base64: bool,

    /// Encoder chain to apply (in order)
    pub encoders: Vec<EncoderChainItemRequest>,

    /// Customer ID for authorization tracking
    pub customer_id: Option<String>,

    /// Asset ID for tracking
    pub asset_id: Option<String>,
}

/// Single encoder in a chain request
#[derive(Debug, Serialize, Deserialize)]
pub struct EncoderChainItemRequest {
    /// Encoder type
    pub encoder_type: EncoderType,

    /// Options for this encoder
    #[serde(default)]
    pub options: EncodingOptions,
}

/// Response for encoding operations
#[derive(Debug, Serialize)]
pub struct EncodePayloadResponse {
    /// Unique ID for this encoding job
    pub id: String,

    /// Encoded payload (hex encoded)
    pub encoded_payload_hex: String,

    /// Encoded payload (base64 encoded)
    pub encoded_payload_base64: String,

    /// Encoder type used
    pub encoder_type: EncoderType,

    /// Decoder stub code
    pub decoder_stub: Option<String>,

    /// Key used (if any)
    pub key_used: Option<String>,

    /// IV used (if any)
    pub iv_used: Option<String>,

    /// Encoding metadata
    pub metadata: EncodingMetadata,

    /// Created timestamp
    pub created_at: String,
}

/// Response for chain encoding
#[derive(Debug, Serialize)]
pub struct ChainEncodeResponse {
    /// Unique ID for this encoding job
    pub id: String,

    /// Final encoded payload (hex)
    pub final_payload_hex: String,

    /// Final encoded payload (base64)
    pub final_payload_base64: String,

    /// Number of encoders applied
    pub encoders_applied: usize,

    /// Results from each step
    pub steps: Vec<StepResult>,

    /// Combined decoder stub (for all steps)
    pub combined_decoder_stub: Option<String>,

    /// Created timestamp
    pub created_at: String,
}

/// Result from a single encoding step
#[derive(Debug, Serialize)]
pub struct StepResult {
    pub step: usize,
    pub encoder_type: EncoderType,
    pub output_size: usize,
    pub key_used: Option<String>,
    pub iv_used: Option<String>,
}

/// Response for decode operation
#[derive(Debug, Serialize)]
pub struct DecodePayloadResponse {
    /// Decoded payload (hex encoded)
    pub decoded_payload_hex: String,

    /// Decoded payload (base64 encoded)
    pub decoded_payload_base64: String,

    /// Decoded payload as string (if valid UTF-8)
    pub decoded_payload_string: Option<String>,

    /// Size of decoded data
    pub decoded_size: usize,
}

/// Query parameters for listing encoders
#[derive(Debug, Deserialize)]
pub struct ListEncodersQuery {
    /// Filter by category
    pub category: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Encode a payload
pub async fn encode_payload(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<EncodePayloadRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate customer if provided
    if let Some(ref customer_id) = body.customer_id {
        let customer: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM customers WHERE id = ? AND user_id = ?"
        )
        .bind(customer_id)
        .bind(&claims.sub)
        .fetch_optional(pool.get_ref())
        .await?;

        if customer.is_none() {
            return Err(ApiError::bad_request("Customer not found or access denied"));
        }
    }

    // Decode payload
    let payload_bytes = if body.payload_is_base64 {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.payload)
            .map_err(|e| ApiError::bad_request(format!("Invalid base64 payload: {}", e)))?
    } else {
        body.payload.as_bytes().to_vec()
    };

    // Get encoder
    let encoder = get_encoder(&body.encoder_type)
        .map_err(|e| ApiError::bad_request(format!("Invalid encoder: {}", e)))?;

    // Encode
    let result = encoder
        .encode(&payload_bytes, &body.options)
        .map_err(|e| ApiError::internal(format!("Encoding failed: {}", e)))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Store encoding job in database
    let encoder_type_json = serde_json::to_string(&body.encoder_type).unwrap_or_default();
    let options_json = serde_json::to_string(&body.options).unwrap_or_default();
    let metadata_json = serde_json::to_string(&result.metadata).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO encoding_jobs (id, user_id, encoder_type, options, original_size, encoded_size, metadata, customer_id, asset_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&encoder_type_json)
    .bind(&options_json)
    .bind(result.metadata.original_size as i64)
    .bind(result.metadata.encoded_size as i64)
    .bind(&metadata_json)
    .bind(&body.customer_id)
    .bind(&body.asset_id)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    // Create response
    let encoded_hex = hex::encode(&result.encoded_data);
    let encoded_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &result.encoded_data,
    );

    Ok(HttpResponse::Ok().json(EncodePayloadResponse {
        id,
        encoded_payload_hex: encoded_hex,
        encoded_payload_base64: encoded_base64,
        encoder_type: result.encoder_type,
        decoder_stub: result.decoder_stub,
        key_used: result.key_used,
        iv_used: result.iv_used,
        metadata: result.metadata,
        created_at: now.to_rfc3339(),
    }))
}

/// Decode a payload
pub async fn decode_payload(
    _claims: web::ReqData<Claims>,
    body: web::Json<DecodePayloadRequest>,
) -> Result<HttpResponse, ApiError> {
    // Decode input payload
    let payload_bytes = if body.payload_is_base64 {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.payload)
            .map_err(|e| ApiError::bad_request(format!("Invalid base64 payload: {}", e)))?
    } else {
        hex::decode(&body.payload)
            .map_err(|e| ApiError::bad_request(format!("Invalid hex payload: {}", e)))?
    };

    // Get encoder
    let encoder = get_encoder(&body.encoder_type)
        .map_err(|e| ApiError::bad_request(format!("Invalid encoder: {}", e)))?;

    // Decode
    let decoded = encoder
        .decode(&payload_bytes, &body.options)
        .map_err(|e| ApiError::bad_request(format!("Decoding failed: {}", e)))?;

    let decoded_hex = hex::encode(&decoded);
    let decoded_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &decoded,
    );
    let decoded_string = String::from_utf8(decoded.clone()).ok();

    Ok(HttpResponse::Ok().json(DecodePayloadResponse {
        decoded_payload_hex: decoded_hex,
        decoded_payload_base64: decoded_base64,
        decoded_payload_string: decoded_string,
        decoded_size: decoded.len(),
    }))
}

/// Chain multiple encoders
pub async fn chain_encoders(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<ChainEncodersRequest>,
) -> Result<HttpResponse, ApiError> {
    if body.encoders.is_empty() {
        return Err(ApiError::bad_request("At least one encoder required"));
    }

    if body.encoders.len() > 10 {
        return Err(ApiError::bad_request("Maximum 10 encoders in chain"));
    }

    // Validate customer if provided
    if let Some(ref customer_id) = body.customer_id {
        let customer: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM customers WHERE id = ? AND user_id = ?"
        )
        .bind(customer_id)
        .bind(&claims.sub)
        .fetch_optional(pool.get_ref())
        .await?;

        if customer.is_none() {
            return Err(ApiError::bad_request("Customer not found or access denied"));
        }
    }

    // Decode payload
    let payload_bytes = if body.payload_is_base64 {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body.payload)
            .map_err(|e| ApiError::bad_request(format!("Invalid base64 payload: {}", e)))?
    } else {
        body.payload.as_bytes().to_vec()
    };

    // Build encoder chain
    let mut chain = EncoderChain::new();
    for item in &body.encoders {
        chain = chain.add(item.encoder_type.clone(), item.options.clone());
    }

    // Execute chain
    let chain_result = chain
        .execute(&payload_bytes)
        .map_err(|e| ApiError::internal(format!("Chain encoding failed: {}", e)))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Build step results and combined decoder stub
    let mut steps: Vec<StepResult> = Vec::new();
    let mut combined_stub = String::new();

    for (i, step_result) in chain_result.steps.iter().enumerate() {
        steps.push(StepResult {
            step: i + 1,
            encoder_type: step_result.encoder_type.clone(),
            output_size: step_result.encoded_data.len(),
            key_used: step_result.key_used.clone(),
            iv_used: step_result.iv_used.clone(),
        });

        if let Some(ref stub) = step_result.decoder_stub {
            combined_stub.push_str(&format!("# Step {} ({})\n", i + 1, step_result.encoder_type));
            combined_stub.push_str(stub);
            combined_stub.push_str("\n\n");
        }
    }

    // Store in database
    let chain_json = serde_json::to_string(&body.encoders).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO encoding_jobs (id, user_id, encoder_type, options, original_size, encoded_size, metadata, customer_id, asset_id, created_at)
        VALUES (?, ?, 'chain', ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&chain_json)
    .bind(payload_bytes.len() as i64)
    .bind(chain_result.final_data.len() as i64)
    .bind(serde_json::to_string(&steps).unwrap_or_default())
    .bind(&body.customer_id)
    .bind(&body.asset_id)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    let final_hex = hex::encode(&chain_result.final_data);
    let final_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &chain_result.final_data,
    );

    Ok(HttpResponse::Ok().json(ChainEncodeResponse {
        id,
        final_payload_hex: final_hex,
        final_payload_base64: final_base64,
        encoders_applied: chain_result.total_encoders,
        steps,
        combined_decoder_stub: if combined_stub.is_empty() {
            None
        } else {
            Some(combined_stub)
        },
        created_at: now.to_rfc3339(),
    }))
}

/// List available encoders
pub async fn list_available_encoders(
    query: web::Query<ListEncodersQuery>,
) -> Result<HttpResponse, ApiError> {
    let mut encoders = list_encoders();

    // Filter by category if specified
    if let Some(ref category) = query.category {
        let filter_category = match category.to_lowercase().as_str() {
            "xor" => Some(EncoderCategory::Xor),
            "base64" => Some(EncoderCategory::Base64),
            "encryption" | "aes" => Some(EncoderCategory::Encryption),
            "transform" | "custom" => Some(EncoderCategory::Transform),
            _ => None,
        };

        if let Some(cat) = filter_category {
            encoders.retain(|e| e.category == cat);
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "encoders": encoders,
        "total": encoders.len(),
        "categories": [
            {"name": "xor", "description": "XOR-based encoding"},
            {"name": "base64", "description": "Base64 encoding variants"},
            {"name": "encryption", "description": "AES encryption"},
            {"name": "transform", "description": "Custom transformations"}
        ]
    })))
}

/// Get encoding job history
pub async fn list_encoding_jobs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let jobs: Vec<(String, String, i64, i64, String, Option<String>, Option<String>, String)> =
        sqlx::query_as(
            r#"
            SELECT id, encoder_type, original_size, encoded_size, metadata, customer_id, asset_id, created_at
            FROM encoding_jobs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 100
            "#,
        )
        .bind(&claims.sub)
        .fetch_all(pool.get_ref())
        .await?;

    let response: Vec<serde_json::Value> = jobs
        .into_iter()
        .map(
            |(id, encoder_type, original_size, encoded_size, metadata, customer_id, asset_id, created_at)| {
                serde_json::json!({
                    "id": id,
                    "encoder_type": encoder_type,
                    "original_size": original_size,
                    "encoded_size": encoded_size,
                    "size_ratio": if original_size > 0 { encoded_size as f64 / original_size as f64 } else { 1.0 },
                    "metadata": serde_json::from_str::<serde_json::Value>(&metadata).ok(),
                    "customer_id": customer_id,
                    "asset_id": asset_id,
                    "created_at": created_at
                })
            },
        )
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get a specific encoding job
pub async fn get_encoding_job(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    let job: Option<(String, String, String, i64, i64, String, Option<String>, Option<String>, String)> =
        sqlx::query_as(
            r#"
            SELECT id, encoder_type, options, original_size, encoded_size, metadata, customer_id, asset_id, created_at
            FROM encoding_jobs
            WHERE id = ? AND user_id = ?
            "#,
        )
        .bind(&job_id)
        .bind(&claims.sub)
        .fetch_optional(pool.get_ref())
        .await?;

    match job {
        Some((id, encoder_type, options, original_size, encoded_size, metadata, customer_id, asset_id, created_at)) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "id": id,
                "encoder_type": encoder_type,
                "options": serde_json::from_str::<serde_json::Value>(&options).ok(),
                "original_size": original_size,
                "encoded_size": encoded_size,
                "metadata": serde_json::from_str::<serde_json::Value>(&metadata).ok(),
                "customer_id": customer_id,
                "asset_id": asset_id,
                "created_at": created_at
            })))
        }
        None => Err(ApiError::not_found("Encoding job not found")),
    }
}

/// Delete an encoding job
pub async fn delete_encoding_job(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let job_id = path.into_inner();

    let result = sqlx::query("DELETE FROM encoding_jobs WHERE id = ? AND user_id = ?")
        .bind(&job_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Encoding job not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Encoding job deleted"
    })))
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/payloads")
            .route("/encode", web::post().to(encode_payload))
            .route("/decode", web::post().to(decode_payload))
            .route("/chain", web::post().to(chain_encoders))
            .route("/encoders", web::get().to(list_available_encoders))
            .route("/jobs", web::get().to(list_encoding_jobs))
            .route("/jobs/{id}", web::get().to(get_encoding_job))
            .route("/jobs/{id}", web::delete().to(delete_encoding_job)),
    );
}
