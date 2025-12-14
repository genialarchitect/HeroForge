use actix::{Actor, AsyncContext, StreamHandler, ActorContext};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use crate::web::broadcast;

pub struct ScanWebSocket {
    pub scan_id: String,
}

impl Actor for ScanWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        log::info!("WebSocket connection established for scan: {}", self.scan_id);

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
                                addr.do_send(BroadcastMessage(json));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::info!("Broadcast channel closed for scan: {}", scan_id);
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            log::warn!("WebSocket lagged behind broadcast for scan: {}", scan_id);
                            // Continue receiving messages
                        }
                    }
                }
            } else {
                log::warn!("No broadcast channel found for scan: {}", scan_id);
            }
        });
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        log::info!("WebSocket connection closed for scan: {}", self.scan_id);
    }
}

// Message type for forwarding broadcast messages to WebSocket
#[derive(actix::Message)]
#[rtype(result = "()")]
struct BroadcastMessage(String);

impl actix::Handler<BroadcastMessage> for ScanWebSocket {
    type Result = ();

    fn handle(&mut self, msg: BroadcastMessage, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ScanWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Text(_)) => {
                // Client messages are ignored for now
            },
            Ok(ws::Message::Binary(_)) => {
                // Binary messages are ignored
            },
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => (),
        }
    }
}

pub async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    scan_id: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let resp = ws::start(
        ScanWebSocket {
            scan_id: scan_id.into_inner(),
        },
        &req,
        stream,
    )?;
    Ok(resp)
}
