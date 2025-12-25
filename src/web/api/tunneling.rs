//! Tunneling API Endpoints
//!
//! Provides REST API endpoints for data exfiltration defense testing
//! using various tunneling protocols (DNS, HTTPS, ICMP).
//!
//! **WARNING**: These endpoints are for authorized security testing only.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::scanner::exploitation::tunneling::{
    self,
    dns::{self, DnsRecordType, DnsTunnelOptions},
    https::{self, HttpsTunnelMethod, HttpsTunnelOptions},
    icmp::{self, IcmpTunnelOptions},
    DecodeRequest, EncodeRequest,
    TunnelConfig, TunnelEncoding, TunnelProtocol, TunnelSession,
};
use crate::web::auth::Claims;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to encode data for DNS tunneling
#[derive(Debug, Deserialize)]
pub struct DnsEncodeRequest {
    /// Data to encode (plaintext or base64)
    pub data: String,
    /// Whether data is base64 encoded
    #[serde(default)]
    pub data_is_base64: bool,
    /// Base domain for DNS queries
    pub domain: String,
    /// DNS record type
    #[serde(default)]
    pub record_type: Option<String>,
    /// Encoding method
    #[serde(default)]
    pub encoding: Option<String>,
    /// Chunk size
    #[serde(default)]
    pub chunk_size: Option<usize>,
}

/// Request to decode DNS tunnel data
#[derive(Debug, Deserialize)]
pub struct DnsDecodeRequest {
    /// Encoded DNS queries
    pub chunks: Vec<String>,
    /// Base domain used
    pub domain: String,
    /// Encoding method used
    #[serde(default)]
    pub encoding: Option<String>,
}

/// Request to encode data for HTTPS tunneling
#[derive(Debug, Deserialize)]
pub struct HttpsEncodeRequest {
    /// Data to encode
    pub data: String,
    /// Whether data is base64 encoded
    #[serde(default)]
    pub data_is_base64: bool,
    /// Target endpoint URL
    pub endpoint: String,
    /// Tunneling method (headers, body, url_params, cookies)
    #[serde(default)]
    pub method: Option<String>,
    /// Encoding method
    #[serde(default)]
    pub encoding: Option<String>,
    /// Chunk size
    #[serde(default)]
    pub chunk_size: Option<usize>,
}

/// Request to encode data for ICMP tunneling
#[derive(Debug, Deserialize)]
pub struct IcmpEncodeRequest {
    /// Data to encode
    pub data: String,
    /// Whether data is base64 encoded
    #[serde(default)]
    pub data_is_base64: bool,
    /// Target IP address
    pub target: String,
    /// ICMP identifier
    #[serde(default)]
    pub identifier: Option<u16>,
    /// Encoding method
    #[serde(default)]
    pub encoding: Option<String>,
    /// Chunk size
    #[serde(default)]
    pub chunk_size: Option<usize>,
}

/// Generic decode request
#[derive(Debug, Deserialize)]
pub struct GenericDecodeRequest {
    /// Encoded chunks
    pub chunks: Vec<String>,
    /// Encoding method used
    #[serde(default)]
    pub encoding: Option<String>,
    /// Protocol-specific options
    #[serde(default)]
    pub options: Option<HashMap<String, serde_json::Value>>,
}

/// Encode response
#[derive(Debug, Serialize)]
pub struct EncodeResponseWrapper {
    pub success: bool,
    pub chunks: Vec<EncodedChunk>,
    pub total_chunks: usize,
    pub original_size: usize,
    pub total_encoded_size: usize,
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Individual encoded chunk
#[derive(Debug, Serialize)]
pub struct EncodedChunk {
    pub payload: String,
    pub original_size: usize,
    pub encoded_size: usize,
    pub protocol_data: serde_json::Value,
}

/// Decode response
#[derive(Debug, Serialize)]
pub struct DecodeResponseWrapper {
    pub success: bool,
    pub data: String,
    pub original_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Session creation request
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub name: String,
    pub protocol: String,
    pub config: serde_json::Value,
}

/// Session response
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub status: String,
    pub stats: SessionStats,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
}

/// Session statistics
#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub successful_transmissions: u64,
    pub failed_transmissions: u64,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Encode data for DNS tunneling
pub async fn dns_encode(
    _claims: Claims,
    body: web::Json<DnsEncodeRequest>,
) -> HttpResponse {
    let encoding = parse_encoding(&body.encoding);
    let record_type = parse_dns_record_type(&body.record_type);

    let options = DnsTunnelOptions {
        domain: body.domain.clone(),
        record_type,
        ..Default::default()
    };

    let request = EncodeRequest {
        data: body.data.clone(),
        data_is_base64: body.data_is_base64,
        encoding: encoding.clone(),
        chunk_size: body.chunk_size,
        options: None,
    };

    match dns::encode_dns_data(&request, &options) {
        Ok(response) => {
            let chunks: Vec<EncodedChunk> = response
                .chunks
                .iter()
                .map(|c| EncodedChunk {
                    payload: c.payload.clone(),
                    original_size: c.original_size,
                    encoded_size: c.encoded_size,
                    protocol_data: c.protocol_data.clone(),
                })
                .collect();

            HttpResponse::Ok().json(EncodeResponseWrapper {
                success: true,
                chunks,
                total_chunks: response.total_chunks,
                original_size: response.original_size,
                total_encoded_size: response.total_encoded_size,
                encoding: format!("{}", response.encoding),
                error: None,
            })
        }
        Err(e) => HttpResponse::BadRequest().json(EncodeResponseWrapper {
            success: false,
            chunks: vec![],
            total_chunks: 0,
            original_size: 0,
            total_encoded_size: 0,
            encoding: format!("{}", encoding),
            error: Some(e.to_string()),
        }),
    }
}

/// Decode DNS tunnel data
pub async fn dns_decode(
    _claims: Claims,
    body: web::Json<DnsDecodeRequest>,
) -> HttpResponse {
    let encoding = parse_encoding(&body.encoding);

    let options = DnsTunnelOptions {
        domain: body.domain.clone(),
        ..Default::default()
    };

    let request = DecodeRequest {
        chunks: body.chunks.clone(),
        encoding: encoding.clone(),
        options: None,
    };

    match dns::decode_dns_data(&request, &options) {
        Ok(response) => HttpResponse::Ok().json(DecodeResponseWrapper {
            success: response.success,
            data: response.data,
            original_size: response.original_size,
            error: response.error,
        }),
        Err(e) => HttpResponse::BadRequest().json(DecodeResponseWrapper {
            success: false,
            data: String::new(),
            original_size: 0,
            error: Some(e.to_string()),
        }),
    }
}

/// Encode data for HTTPS tunneling
pub async fn https_encode(
    _claims: Claims,
    body: web::Json<HttpsEncodeRequest>,
) -> HttpResponse {
    let encoding = parse_encoding(&body.encoding);
    let tunnel_method = parse_https_method(&body.method);

    let options = HttpsTunnelOptions {
        endpoint: body.endpoint.clone(),
        tunnel_method,
        ..Default::default()
    };

    let request = EncodeRequest {
        data: body.data.clone(),
        data_is_base64: body.data_is_base64,
        encoding: encoding.clone(),
        chunk_size: body.chunk_size,
        options: None,
    };

    match https::encode_https_data(&request, &options) {
        Ok(response) => {
            let chunks: Vec<EncodedChunk> = response
                .chunks
                .iter()
                .map(|c| EncodedChunk {
                    payload: c.payload.clone(),
                    original_size: c.original_size,
                    encoded_size: c.encoded_size,
                    protocol_data: c.protocol_data.clone(),
                })
                .collect();

            HttpResponse::Ok().json(EncodeResponseWrapper {
                success: true,
                chunks,
                total_chunks: response.total_chunks,
                original_size: response.original_size,
                total_encoded_size: response.total_encoded_size,
                encoding: format!("{}", response.encoding),
                error: None,
            })
        }
        Err(e) => HttpResponse::BadRequest().json(EncodeResponseWrapper {
            success: false,
            chunks: vec![],
            total_chunks: 0,
            original_size: 0,
            total_encoded_size: 0,
            encoding: format!("{}", encoding),
            error: Some(e.to_string()),
        }),
    }
}

/// Encode data for ICMP tunneling
pub async fn icmp_encode(
    _claims: Claims,
    body: web::Json<IcmpEncodeRequest>,
) -> HttpResponse {
    let encoding = parse_encoding(&body.encoding);

    let options = IcmpTunnelOptions {
        target: body.target.clone(),
        identifier: body.identifier.unwrap_or_else(rand::random),
        ..Default::default()
    };

    let request = EncodeRequest {
        data: body.data.clone(),
        data_is_base64: body.data_is_base64,
        encoding: encoding.clone(),
        chunk_size: body.chunk_size,
        options: None,
    };

    match icmp::encode_icmp_data(&request, &options) {
        Ok(response) => {
            let chunks: Vec<EncodedChunk> = response
                .chunks
                .iter()
                .map(|c| EncodedChunk {
                    payload: c.payload.clone(),
                    original_size: c.original_size,
                    encoded_size: c.encoded_size,
                    protocol_data: c.protocol_data.clone(),
                })
                .collect();

            HttpResponse::Ok().json(EncodeResponseWrapper {
                success: true,
                chunks,
                total_chunks: response.total_chunks,
                original_size: response.original_size,
                total_encoded_size: response.total_encoded_size,
                encoding: format!("{}", response.encoding),
                error: None,
            })
        }
        Err(e) => HttpResponse::BadRequest().json(EncodeResponseWrapper {
            success: false,
            chunks: vec![],
            total_chunks: 0,
            original_size: 0,
            total_encoded_size: 0,
            encoding: format!("{}", encoding),
            error: Some(e.to_string()),
        }),
    }
}

/// Get list of supported tunneling protocols
pub async fn get_protocols(_claims: Claims) -> HttpResponse {
    let protocols = tunneling::get_supported_protocols();

    #[derive(Serialize)]
    struct ProtocolResponse {
        protocol: String,
        name: String,
        description: String,
        supported_encodings: Vec<String>,
        default_chunk_size: usize,
        max_chunk_size: usize,
        supports_encryption: bool,
        options: Vec<OptionInfo>,
    }

    #[derive(Serialize)]
    struct OptionInfo {
        name: String,
        description: String,
        option_type: String,
        default_value: Option<serde_json::Value>,
        required: bool,
    }

    let response: Vec<ProtocolResponse> = protocols
        .into_iter()
        .map(|p| ProtocolResponse {
            protocol: format!("{}", p.protocol),
            name: p.name,
            description: p.description,
            supported_encodings: p.supported_encodings.iter().map(|e| format!("{}", e)).collect(),
            default_chunk_size: p.default_chunk_size,
            max_chunk_size: p.max_chunk_size,
            supports_encryption: p.supports_encryption,
            options: p
                .options
                .into_iter()
                .map(|o| OptionInfo {
                    name: o.name,
                    description: o.description,
                    option_type: o.option_type,
                    default_value: o.default_value,
                    required: o.required,
                })
                .collect(),
        })
        .collect();

    HttpResponse::Ok().json(response)
}

/// Check ICMP capability (requires root/CAP_NET_RAW)
pub async fn check_icmp_capability(_claims: Claims) -> HttpResponse {
    let has_capability = icmp::check_icmp_capability();

    HttpResponse::Ok().json(serde_json::json!({
        "icmp_available": has_capability,
        "message": if has_capability {
            "ICMP tunneling is available (raw socket capability present)"
        } else {
            "ICMP tunneling requires root privileges or CAP_NET_RAW capability"
        }
    }))
}

/// Create a new tunnel session
pub async fn create_session(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateSessionRequest>,
) -> HttpResponse {
    let protocol = match body.protocol.to_lowercase().as_str() {
        "dns" => TunnelProtocol::Dns,
        "https" => TunnelProtocol::Https,
        "icmp" => TunnelProtocol::Icmp,
        "websocket" => TunnelProtocol::WebSocket,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Unknown protocol: {}", body.protocol)
            }));
        }
    };

    let config = TunnelConfig {
        protocol: protocol.clone(),
        ..Default::default()
    };

    let session = TunnelSession::new(&claims.sub, &body.name, config);

    // Store session in database
    let result = sqlx::query(
        r#"
        INSERT INTO tunnel_sessions (id, user_id, name, protocol, status, config, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&session.id)
    .bind(&session.user_id)
    .bind(&session.name)
    .bind(format!("{}", protocol))
    .bind("active")
    .bind(serde_json::to_string(&body.config).unwrap_or_default())
    .bind(session.created_at.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Created().json(SessionResponse {
            id: session.id,
            name: session.name,
            protocol: format!("{}", protocol),
            status: format!("{}", session.status),
            stats: SessionStats {
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                successful_transmissions: 0,
                failed_transmissions: 0,
            },
            created_at: session.created_at.to_rfc3339(),
            started_at: None,
            ended_at: None,
        }),
        Err(e) => {
            log::error!("Failed to create tunnel session: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create session"
            }))
        }
    }
}

/// List tunnel sessions
pub async fn list_sessions(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> HttpResponse {
    let sessions = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        r#"
        SELECT id, name, protocol, status, config, created_at
        FROM tunnel_sessions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await;

    match sessions {
        Ok(rows) => {
            let sessions: Vec<SessionResponse> = rows
                .into_iter()
                .map(|(id, name, protocol, status, _config, created_at)| SessionResponse {
                    id,
                    name,
                    protocol,
                    status,
                    stats: SessionStats {
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        successful_transmissions: 0,
                        failed_transmissions: 0,
                    },
                    created_at,
                    started_at: None,
                    ended_at: None,
                })
                .collect();

            HttpResponse::Ok().json(sessions)
        }
        Err(e) => {
            log::error!("Failed to list tunnel sessions: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list sessions"
            }))
        }
    }
}

/// Get tunnel session by ID
pub async fn get_session(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let session_id = path.into_inner();

    let session = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        r#"
        SELECT id, name, protocol, status, config, created_at
        FROM tunnel_sessions
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await;

    match session {
        Ok(Some((id, name, protocol, status, _config, created_at))) => {
            HttpResponse::Ok().json(SessionResponse {
                id,
                name,
                protocol,
                status,
                stats: SessionStats {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    successful_transmissions: 0,
                    failed_transmissions: 0,
                },
                created_at,
                started_at: None,
                ended_at: None,
            })
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        })),
        Err(e) => {
            log::error!("Failed to get tunnel session: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get session"
            }))
        }
    }
}

/// Delete tunnel session
pub async fn delete_session(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let session_id = path.into_inner();

    let result = sqlx::query(
        r#"
        DELETE FROM tunnel_sessions
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(&session_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Session deleted"
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        })),
        Err(e) => {
            log::error!("Failed to delete tunnel session: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete session"
            }))
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_encoding(encoding: &Option<String>) -> TunnelEncoding {
    match encoding.as_ref().map(|s| s.to_lowercase()).as_deref() {
        Some("base64") => TunnelEncoding::Base64,
        Some("base64url") | Some("base64_url") => TunnelEncoding::Base64Url,
        Some("hex") | Some("hexadecimal") => TunnelEncoding::Hex,
        Some("base32") => TunnelEncoding::Base32,
        Some("none") | Some("raw") => TunnelEncoding::None,
        _ => TunnelEncoding::Base64,
    }
}

fn parse_dns_record_type(record_type: &Option<String>) -> DnsRecordType {
    match record_type.as_ref().map(|s| s.to_uppercase()).as_deref() {
        Some("TXT") => DnsRecordType::Txt,
        Some("A") => DnsRecordType::A,
        Some("AAAA") => DnsRecordType::Aaaa,
        Some("CNAME") => DnsRecordType::Cname,
        Some("MX") => DnsRecordType::Mx,
        Some("NULL") => DnsRecordType::Null,
        _ => DnsRecordType::Txt,
    }
}

fn parse_https_method(method: &Option<String>) -> HttpsTunnelMethod {
    match method.as_ref().map(|s| s.to_lowercase()).as_deref() {
        Some("headers") => HttpsTunnelMethod::Headers,
        Some("body") => HttpsTunnelMethod::Body,
        Some("url_params") | Some("urlparams") => HttpsTunnelMethod::UrlParams,
        Some("cookies") => HttpsTunnelMethod::Cookies,
        Some("custom_header") | Some("customheader") => HttpsTunnelMethod::CustomHeader,
        Some("mixed") => HttpsTunnelMethod::Mixed,
        _ => HttpsTunnelMethod::Body,
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure tunneling routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tunneling")
            // Protocol information
            .route("/protocols", web::get().to(get_protocols))
            .route("/icmp/capability", web::get().to(check_icmp_capability))
            // DNS tunneling
            .route("/dns/encode", web::post().to(dns_encode))
            .route("/dns/decode", web::post().to(dns_decode))
            // HTTPS tunneling
            .route("/https/encode", web::post().to(https_encode))
            // ICMP tunneling
            .route("/icmp/encode", web::post().to(icmp_encode))
            // Session management
            .route("/sessions", web::get().to(list_sessions))
            .route("/sessions", web::post().to(create_session))
            .route("/sessions/{id}", web::get().to(get_session))
            .route("/sessions/{id}", web::delete().to(delete_session)),
    );
}
