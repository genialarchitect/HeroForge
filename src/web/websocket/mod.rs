pub mod aggregator;
pub mod exploitation;

use actix::{Actor, AsyncContext, StreamHandler, ActorContext};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use crate::web::broadcast;
use crate::web::auth::jwt;
use crate::db;
use sqlx::SqlitePool;
use std::time::{Duration, Instant};

/// Query parameters for WebSocket authentication
#[derive(Debug, serde::Deserialize)]
pub struct WsAuthQuery {
    /// JWT token for authentication
    pub token: String,
}

// Connection management constants
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ScanWebSocket {
    pub scan_id: String,
    last_heartbeat: Instant,
    message_count: u64,
    bytes_sent: u64,
}

impl ScanWebSocket {
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            last_heartbeat: Instant::now(),
            message_count: 0,
            bytes_sent: 0,
        }
    }

    /// Start heartbeat monitoring
    fn start_heartbeat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // Check if client is still alive
            if Instant::now().duration_since(act.last_heartbeat) > CLIENT_TIMEOUT {
                log::warn!(
                    "WebSocket client timeout for scan: {}, closing connection",
                    act.scan_id
                );
                ctx.stop();
                return;
            }

            // Send ping to client
            ctx.ping(b"");

            // Log connection metrics periodically
            log::debug!(
                "WebSocket metrics for scan {}: {} messages, {} bytes sent",
                act.scan_id,
                act.message_count,
                act.bytes_sent
            );
        });
    }
}

impl Actor for ScanWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        log::info!("WebSocket connection established for scan: {}", self.scan_id);

        // Start heartbeat monitoring
        self.start_heartbeat(ctx);

        // Subscribe to scan progress updates and start listening
        let scan_id = self.scan_id.clone();
        let addr = ctx.address();

        tokio::spawn(async move {
            if let Some(mut rx) = broadcast::subscribe_to_scan(&scan_id).await {
                log::info!("Subscribed to scan progress for: {}", scan_id);

                loop {
                    match rx.recv().await {
                        Ok(msg) => {
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let size = json.len();
                                addr.do_send(BroadcastMessage {
                                    content: json,
                                    size,
                                });
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::info!("Broadcast channel closed for scan: {}", scan_id);
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            log::warn!(
                                "WebSocket lagged behind broadcast for scan: {}, skipped {} messages",
                                scan_id,
                                skipped
                            );
                            // Send lag notification to client
                            let lag_msg = serde_json::json!({
                                "type": "lag",
                                "skippedMessages": skipped,
                                "scanId": scan_id
                            });
                            if let Ok(json) = serde_json::to_string(&lag_msg) {
                                addr.do_send(BroadcastMessage {
                                    content: json.clone(),
                                    size: json.len(),
                                });
                            }
                        }
                    }
                }

                // Send connection closing notification
                log::info!("Sending close notification for scan: {}", scan_id);
                addr.do_send(CloseConnection);
            } else {
                log::warn!("No broadcast channel found for scan: {}", scan_id);
                // Send error message to client
                let error_msg = serde_json::json!({
                    "type": "error",
                    "message": "Scan channel not found",
                    "scanId": scan_id
                });
                if let Ok(json) = serde_json::to_string(&error_msg) {
                    addr.do_send(BroadcastMessage {
                        content: json.clone(),
                        size: json.len(),
                    });
                }
            }
        });
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        log::info!(
            "WebSocket connection closed for scan: {} (sent {} messages, {} bytes total)",
            self.scan_id,
            self.message_count,
            self.bytes_sent
        );
    }
}

// Message type for forwarding broadcast messages to WebSocket
#[derive(actix::Message)]
#[rtype(result = "()")]
struct BroadcastMessage {
    content: String,
    size: usize,
}

impl actix::Handler<BroadcastMessage> for ScanWebSocket {
    type Result = ();

    fn handle(&mut self, msg: BroadcastMessage, ctx: &mut Self::Context) {
        // Optionally compress large messages (>10KB)
        if msg.size > 10_240 {
            // For now, just log it. In production, you could use flate2 or similar
            log::debug!(
                "Large message ({} bytes) for scan: {}, consider compression",
                msg.size,
                self.scan_id
            );
        }

        ctx.text(msg.content);

        // Update metrics
        self.message_count += 1;
        self.bytes_sent += msg.size as u64;
    }
}

// Message type for gracefully closing connection
#[derive(actix::Message)]
#[rtype(result = "()")]
struct CloseConnection;

impl actix::Handler<CloseConnection> for ScanWebSocket {
    type Result = ();

    fn handle(&mut self, _msg: CloseConnection, ctx: &mut Self::Context) {
        ctx.close(Some(ws::CloseReason {
            code: ws::CloseCode::Normal,
            description: Some("Scan completed".to_string()),
        }));
        ctx.stop();
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ScanWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.last_heartbeat = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Text(text)) => {
                // Handle client messages (e.g., subscription preferences)
                log::debug!("Received client message for scan {}: {}", self.scan_id, text);
                self.last_heartbeat = Instant::now();
                // Client messages are mostly ignored for now
            }
            Ok(ws::Message::Binary(_)) => {
                // Binary messages are ignored
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Close(reason)) => {
                log::info!("Client closed WebSocket for scan: {}", self.scan_id);
                ctx.close(reason);
                ctx.stop();
            }
            Ok(ws::Message::Continuation(_)) => {
                log::warn!("Continuation frame received, not supported");
            }
            Ok(ws::Message::Nop) => {}
            Err(err) => {
                log::error!(
                    "WebSocket protocol error for scan {}: {:?}",
                    self.scan_id,
                    err
                );
                ctx.stop();
            }
        }
    }
}

pub async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    scan_id: web::Path<String>,
    query: web::Query<WsAuthQuery>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, Error> {
    let scan_id_str = scan_id.into_inner();

    log::info!("WebSocket connection request for scan: {}", scan_id_str);

    // Validate JWT token from query parameters
    let claims = match jwt::verify_jwt(&query.token) {
        Ok(claims) => claims,
        Err(e) => {
            log::warn!("WebSocket authentication failed for scan {}: {}", scan_id_str, e);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired authentication token"
            })));
        }
    };

    // Verify scan ownership (user owns the scan or is admin)
    let scan = match db::get_scan_by_id(&pool, &scan_id_str).await {
        Ok(Some(scan)) => scan,
        Ok(None) => {
            log::warn!("WebSocket: Scan {} not found", scan_id_str);
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
        Err(e) => {
            log::error!("WebSocket: Database error fetching scan {}: {}", scan_id_str, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify scan access"
            })));
        }
    };

    // Check if user owns the scan or has admin role
    let is_admin = claims.roles.contains(&"admin".to_string());
    if scan.user_id != claims.sub && !is_admin {
        log::warn!(
            "WebSocket: User {} attempted to access scan {} owned by {}",
            claims.sub,
            scan_id_str,
            scan.user_id
        );
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied - you do not own this scan"
        })));
    }

    log::info!(
        "WebSocket authenticated: user {} connecting to scan {}",
        claims.username,
        scan_id_str
    );

    let resp = ws::start(ScanWebSocket::new(scan_id_str), &req, stream)?;
    Ok(resp)
}

// ============================================================================
// Report WebSocket Handler
// ============================================================================

pub struct ReportWebSocket {
    pub report_id: String,
    last_heartbeat: Instant,
    message_count: u64,
    bytes_sent: u64,
}

impl ReportWebSocket {
    pub fn new(report_id: String) -> Self {
        Self {
            report_id,
            last_heartbeat: Instant::now(),
            message_count: 0,
            bytes_sent: 0,
        }
    }

    fn start_heartbeat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.last_heartbeat) > CLIENT_TIMEOUT {
                log::warn!(
                    "WebSocket client timeout for report: {}, closing connection",
                    act.report_id
                );
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }
}

impl Actor for ReportWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        log::info!("WebSocket connection established for report: {}", self.report_id);

        self.start_heartbeat(ctx);

        let report_id = self.report_id.clone();
        let addr = ctx.address();

        tokio::spawn(async move {
            if let Some(mut rx) = broadcast::subscribe_to_report(&report_id).await {
                log::info!("Subscribed to report progress for: {}", report_id);

                loop {
                    match rx.recv().await {
                        Ok(msg) => {
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let size = json.len();
                                addr.do_send(ReportBroadcastMessage {
                                    content: json,
                                    size,
                                });
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::info!("Broadcast channel closed for report: {}", report_id);
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            log::warn!(
                                "WebSocket lagged behind broadcast for report: {}, skipped {} messages",
                                report_id,
                                skipped
                            );
                        }
                    }
                }

                log::info!("Sending close notification for report: {}", report_id);
                addr.do_send(CloseConnection);
            } else {
                log::warn!("No broadcast channel found for report: {}", report_id);
                let error_msg = serde_json::json!({
                    "type": "error",
                    "message": "Report channel not found",
                    "reportId": report_id
                });
                if let Ok(json) = serde_json::to_string(&error_msg) {
                    addr.do_send(ReportBroadcastMessage {
                        content: json.clone(),
                        size: json.len(),
                    });
                }
            }
        });
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        log::info!(
            "WebSocket connection closed for report: {} (sent {} messages, {} bytes total)",
            self.report_id,
            self.message_count,
            self.bytes_sent
        );
    }
}

#[derive(actix::Message)]
#[rtype(result = "()")]
struct ReportBroadcastMessage {
    content: String,
    size: usize,
}

impl actix::Handler<ReportBroadcastMessage> for ReportWebSocket {
    type Result = ();

    fn handle(&mut self, msg: ReportBroadcastMessage, ctx: &mut Self::Context) {
        ctx.text(msg.content);
        self.message_count += 1;
        self.bytes_sent += msg.size as u64;
    }
}

impl actix::Handler<CloseConnection> for ReportWebSocket {
    type Result = ();

    fn handle(&mut self, _msg: CloseConnection, ctx: &mut Self::Context) {
        ctx.close(Some(ws::CloseReason {
            code: ws::CloseCode::Normal,
            description: Some("Report completed".to_string()),
        }));
        ctx.stop();
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ReportWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.last_heartbeat = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Text(_)) => {
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Binary(_)) => {
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Close(reason)) => {
                log::info!("Client closed WebSocket for report: {}", self.report_id);
                ctx.close(reason);
                ctx.stop();
            }
            Ok(ws::Message::Continuation(_)) => {}
            Ok(ws::Message::Nop) => {}
            Err(err) => {
                log::error!(
                    "WebSocket protocol error for report {}: {:?}",
                    self.report_id,
                    err
                );
                ctx.stop();
            }
        }
    }
}

/// WebSocket handler for report progress updates
pub async fn report_ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    report_id: web::Path<String>,
    query: web::Query<WsAuthQuery>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, Error> {
    let report_id_str = report_id.into_inner();

    log::info!("WebSocket connection request for report: {}", report_id_str);

    // Validate JWT token from query parameters
    let claims = match jwt::verify_jwt(&query.token) {
        Ok(claims) => claims,
        Err(e) => {
            log::warn!("WebSocket authentication failed for report {}: {}", report_id_str, e);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired authentication token"
            })));
        }
    };

    // Verify report ownership (user owns the report or is admin)
    let report = match db::get_report_by_id(&pool, &report_id_str).await {
        Ok(Some(report)) => report,
        Ok(None) => {
            log::warn!("WebSocket: Report {} not found", report_id_str);
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Report not found"
            })));
        }
        Err(e) => {
            log::error!("WebSocket: Database error fetching report {}: {}", report_id_str, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify report access"
            })));
        }
    };

    // Check if user owns the report or has admin role
    let is_admin = claims.roles.contains(&"admin".to_string());
    if report.user_id != claims.sub && !is_admin {
        log::warn!(
            "WebSocket: User {} attempted to access report {} owned by {}",
            claims.sub,
            report_id_str,
            report.user_id
        );
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied - you do not own this report"
        })));
    }

    log::info!(
        "WebSocket authenticated: user {} connecting to report {}",
        claims.username,
        report_id_str
    );

    let resp = ws::start(ReportWebSocket::new(report_id_str), &req, stream)?;
    Ok(resp)
}
