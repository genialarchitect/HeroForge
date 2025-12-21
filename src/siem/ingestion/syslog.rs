//! Syslog receiver for UDP and TCP connections.
//!
//! Listens on configurable ports (default 514) for both UDP and TCP syslog messages.
//! Supports RFC 3164 (BSD) and RFC 5424 (structured) syslog formats.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{timeout, Duration};

use super::{IngestionMessage, IngestionStats};
use crate::siem::parser::LogParser;
use crate::siem::storage::LogStorage;

/// Maximum UDP packet size (RFC 5426 recommends 2048 for TLS syslog)
const MAX_UDP_PACKET_SIZE: usize = 8192;

/// TCP connection read timeout
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum concurrent TCP connections
const MAX_TCP_CONNECTIONS: usize = 1000;

/// Syslog receiver that handles both UDP and TCP
pub struct SyslogReceiver {
    udp_port: u16,
    tcp_port: u16,
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<RwLock<IngestionStats>>,
    entry_tx: mpsc::Sender<IngestionMessage>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl SyslogReceiver {
    pub fn new(
        udp_port: u16,
        tcp_port: u16,
        storage: Arc<LogStorage>,
        parser: Arc<LogParser>,
        stats: Arc<RwLock<IngestionStats>>,
        entry_tx: mpsc::Sender<IngestionMessage>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            udp_port,
            tcp_port,
            storage,
            parser,
            stats,
            entry_tx,
            shutdown_rx,
        }
    }

    /// Run the syslog receiver (both UDP and TCP)
    pub async fn run(mut self) -> Result<()> {
        // Start UDP receiver
        let udp_handle = {
            let storage = Arc::clone(&self.storage);
            let parser = Arc::clone(&self.parser);
            let stats = Arc::clone(&self.stats);
            let entry_tx = self.entry_tx.clone();
            let port = self.udp_port;

            tokio::spawn(async move {
                if let Err(e) = run_udp_receiver(port, storage, parser, stats, entry_tx).await {
                    log::error!("UDP syslog receiver error: {}", e);
                }
            })
        };

        // Start TCP receiver
        let tcp_handle = {
            let storage = Arc::clone(&self.storage);
            let parser = Arc::clone(&self.parser);
            let stats = Arc::clone(&self.stats);
            let entry_tx = self.entry_tx.clone();
            let port = self.tcp_port;

            tokio::spawn(async move {
                if let Err(e) = run_tcp_receiver(port, storage, parser, stats, entry_tx).await {
                    log::error!("TCP syslog receiver error: {}", e);
                }
            })
        };

        // Wait for shutdown signal
        let _ = self.shutdown_rx.recv().await;

        // Abort receivers
        udp_handle.abort();
        tcp_handle.abort();

        log::info!("Syslog receiver shutdown complete");
        Ok(())
    }
}

/// Run UDP syslog receiver
async fn run_udp_receiver(
    port: u16,
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<RwLock<IngestionStats>>,
    entry_tx: mpsc::Sender<IngestionMessage>,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&bind_addr).await?;

    log::info!("Syslog UDP receiver listening on {}", bind_addr);

    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let data = &buf[..len];

                // Update stats
                {
                    let mut s = stats.write().await;
                    s.record_received(len);
                }

                // Process the message
                if let Err(e) = process_syslog_message(
                    data,
                    addr,
                    &storage,
                    &parser,
                    &stats,
                    &entry_tx,
                )
                .await
                {
                    log::debug!("Failed to process UDP syslog from {}: {}", addr, e);
                    let mut s = stats.write().await;
                    s.record_parse_failure();
                }
            }
            Err(e) => {
                log::error!("UDP recv error: {}", e);
            }
        }
    }
}

/// Run TCP syslog receiver
async fn run_tcp_receiver(
    port: u16,
    storage: Arc<LogStorage>,
    parser: Arc<LogParser>,
    stats: Arc<RwLock<IngestionStats>>,
    entry_tx: mpsc::Sender<IngestionMessage>,
) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind_addr).await?;

    log::info!("Syslog TCP receiver listening on {}", bind_addr);

    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        let (stream, addr) = listener.accept().await?;

        // Update connection count
        {
            let mut s = stats.write().await;
            s.active_connections += 1;
        }

        let storage = Arc::clone(&storage);
        let parser = Arc::clone(&parser);
        let stats = Arc::clone(&stats);
        let entry_tx = entry_tx.clone();
        let semaphore = Arc::clone(&semaphore);

        tokio::spawn(async move {
            // Acquire permit (will block if too many connections)
            let _permit = semaphore.acquire().await;

            if let Err(e) =
                handle_tcp_connection(stream, addr, &storage, &parser, &stats, &entry_tx).await
            {
                log::debug!("TCP connection from {} ended with error: {}", addr, e);
            }

            // Update connection count
            {
                let mut s = stats.write().await;
                s.active_connections = s.active_connections.saturating_sub(1);
            }
        });
    }
}

/// Handle a single TCP connection
async fn handle_tcp_connection(
    stream: TcpStream,
    addr: SocketAddr,
    storage: &Arc<LogStorage>,
    parser: &Arc<LogParser>,
    stats: &Arc<RwLock<IngestionStats>>,
    entry_tx: &mpsc::Sender<IngestionMessage>,
) -> Result<()> {
    log::debug!("Accepted TCP syslog connection from {}", addr);

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();

        // Read with timeout
        match timeout(TCP_READ_TIMEOUT, reader.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                // Connection closed
                log::debug!("TCP connection from {} closed", addr);
                break;
            }
            Ok(Ok(len)) => {
                // Update stats
                {
                    let mut s = stats.write().await;
                    s.record_received(len);
                }

                // Process the message
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Err(e) = process_syslog_message(
                        trimmed.as_bytes(),
                        addr,
                        storage,
                        parser,
                        stats,
                        entry_tx,
                    )
                    .await
                    {
                        log::debug!("Failed to process TCP syslog from {}: {}", addr, e);
                        let mut s = stats.write().await;
                        s.record_parse_failure();
                    }
                }
            }
            Ok(Err(e)) => {
                log::debug!("TCP read error from {}: {}", addr, e);
                break;
            }
            Err(_) => {
                // Timeout
                log::debug!("TCP connection from {} timed out", addr);
                break;
            }
        }
    }

    Ok(())
}

/// Process a syslog message
async fn process_syslog_message(
    data: &[u8],
    addr: SocketAddr,
    storage: &Arc<LogStorage>,
    parser: &Arc<LogParser>,
    stats: &Arc<RwLock<IngestionStats>>,
    entry_tx: &mpsc::Sender<IngestionMessage>,
) -> Result<()> {
    // Convert to string (syslog is UTF-8 or ASCII)
    let raw = std::str::from_utf8(data)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| String::from_utf8_lossy(data).into_owned())
        .trim()
        .to_string();

    if raw.is_empty() {
        return Ok(());
    }

    // Generate source ID from IP address
    let source_id = format!("syslog-{}", addr.ip());

    // Parse the message
    let mut entry = parser.parse_with_source(&raw, &source_id)?;

    // Enrich with source IP
    if entry.source_ip.is_none() {
        entry.source_ip = Some(addr.ip());
    }

    // Store the entry
    storage.store_entry(&entry).await?;

    // Update stats
    {
        let mut s = stats.write().await;
        s.record_parsed();
        s.record_stored();
    }

    // Send to rule evaluation pipeline
    let _ = entry_tx
        .send(IngestionMessage {
            entry: entry.clone(),
            source_id,
        })
        .await;

    Ok(())
}

/// Syslog message with octet counting framing (RFC 5425)
/// Format: MSG-LEN SP SYSLOG-MSG
async fn read_octet_counted_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut len_buf = Vec::new();

    // Read length prefix
    loop {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte).await {
            Ok(_) => {
                if byte[0] == b' ' {
                    // End of length field
                    break;
                } else if byte[0].is_ascii_digit() {
                    len_buf.push(byte[0]);
                    if len_buf.len() > 10 {
                        return Err(anyhow!("Message length too long"));
                    }
                } else {
                    return Err(anyhow!("Invalid character in message length"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
    }

    let len_str = std::str::from_utf8(&len_buf)?;
    let msg_len: usize = len_str.parse()?;

    if msg_len > MAX_UDP_PACKET_SIZE {
        return Err(anyhow!("Message too large: {} bytes", msg_len));
    }

    // Read the message
    let mut msg_buf = vec![0u8; msg_len];
    reader.read_exact(&mut msg_buf).await?;

    Ok(Some(msg_buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_rfc3164_message() {
        let raw = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick";
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let parser = Arc::new(LogParser::new());
        let source_id = format!("syslog-{}", addr.ip());

        let entry = parser.parse_with_source(
            std::str::from_utf8(raw).unwrap(),
            &source_id,
        ).unwrap();

        assert_eq!(entry.source_id, "syslog-192.168.1.100");
        assert!(entry.message.contains("su root"));
    }

    #[tokio::test]
    async fn test_process_rfc5424_message() {
        let raw = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application event";
        let addr: SocketAddr = "10.0.0.5:514".parse().unwrap();

        let parser = Arc::new(LogParser::new());
        let source_id = format!("syslog-{}", addr.ip());

        let entry = parser.parse_with_source(
            std::str::from_utf8(raw).unwrap(),
            &source_id,
        ).unwrap();

        assert_eq!(entry.source_id, "syslog-10.0.0.5");
        assert_eq!(entry.hostname, Some("mymachine.example.com".to_string()));
    }

    #[test]
    fn test_source_id_generation() {
        let addr: SocketAddr = "172.16.0.1:514".parse().unwrap();
        let source_id = format!("syslog-{}", addr.ip());
        assert_eq!(source_id, "syslog-172.16.0.1");
    }
}
