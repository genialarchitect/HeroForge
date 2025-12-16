use super::{SiemEvent, SiemExporter};
use anyhow::Result;
use async_trait::async_trait;
use chrono::SecondsFormat;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

#[derive(Debug)]
pub struct SyslogExporter {
    endpoint: SocketAddr,
    protocol: Protocol,
    hostname: String,
    app_name: String,
}

#[derive(Clone, Debug)]
enum Protocol {
    Tcp,
    Udp,
}

impl SyslogExporter {
    pub fn new(endpoint: &str, protocol: &str) -> Result<Self> {
        let endpoint_addr: SocketAddr = endpoint.parse()?;
        let protocol = match protocol.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => anyhow::bail!("Invalid protocol: {}. Must be 'tcp' or 'udp'", protocol),
        };

        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "heroforge".to_string());

        Ok(Self {
            endpoint: endpoint_addr,
            protocol,
            hostname,
            app_name: "heroforge".to_string(),
        })
    }

    fn format_rfc5424(&self, event: &SiemEvent) -> String {
        // RFC 5424 Syslog Message Format:
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

        // Calculate priority: Facility (16 = local use 0) * 8 + Severity
        let severity_num = match event.severity.to_lowercase().as_str() {
            "critical" => 2, // Critical
            "high" => 3,     // Error
            "medium" => 4,   // Warning
            "low" => 5,      // Notice
            "info" => 6,     // Informational
            _ => 6,
        };
        let facility = 16; // local0
        let priority = facility * 8 + severity_num;

        // Format timestamp in RFC 3339
        let timestamp = event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);

        // PROCID and MSGID
        let procid = "-";
        let msgid = &event.event_type;

        // Structured data with scan context
        let mut structured_data = format!(
            "[heroforge@32473 scan_id=\"{}\" user_id=\"{}\" event_type=\"{}\" severity=\"{}\"",
            event.scan_id, event.user_id, event.event_type, event.severity
        );

        if let Some(src_ip) = &event.source_ip {
            structured_data.push_str(&format!(" source_ip=\"{}\"", src_ip));
        }
        if let Some(dst_ip) = &event.destination_ip {
            structured_data.push_str(&format!(" destination_ip=\"{}\"", dst_ip));
        }
        if let Some(port) = event.port {
            structured_data.push_str(&format!(" port=\"{}\"", port));
        }
        if let Some(protocol) = &event.protocol {
            structured_data.push_str(&format!(" protocol=\"{}\"", protocol));
        }
        if let Some(cvss) = event.cvss_score {
            structured_data.push_str(&format!(" cvss_score=\"{:.1}\"", cvss));
        }
        if !event.cve_ids.is_empty() {
            structured_data.push_str(&format!(" cve_ids=\"{}\"", event.cve_ids.join(",")));
        }
        structured_data.push(']');

        // Message with details
        let message = format!("{} | {}", event.message, event.details);

        format!(
            "<{}>1 {} {} {} {} {} {} {}\n",
            priority,
            timestamp,
            self.hostname,
            self.app_name,
            procid,
            msgid,
            structured_data,
            message
        )
    }

    async fn send_tcp(&self, message: &str) -> Result<()> {
        let mut stream = TcpStream::connect(self.endpoint).await?;
        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn send_udp(&self, message: &str) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(message.as_bytes(), self.endpoint).await?;
        Ok(())
    }
}

#[async_trait]
impl SiemExporter for SyslogExporter {
    async fn export_event(&self, event: &SiemEvent) -> Result<()> {
        let message = self.format_rfc5424(event);

        match self.protocol {
            Protocol::Tcp => self.send_tcp(&message).await,
            Protocol::Udp => self.send_udp(&message).await,
        }
    }

    async fn export_events(&self, events: &[SiemEvent]) -> Result<()> {
        for event in events {
            self.export_event(event).await?;
        }
        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        let test_event = SiemEvent {
            timestamp: chrono::Utc::now(),
            severity: "info".to_string(),
            event_type: "test_connection".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "HeroForge SIEM integration test".to_string(),
            details: serde_json::json!({"test": true}),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "test".to_string(),
            user_id: "test".to_string(),
        };

        self.export_event(&test_event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn create_test_event() -> SiemEvent {
        SiemEvent {
            timestamp: Utc::now(),
            severity: "critical".to_string(),
            event_type: "vulnerability_found".to_string(),
            source_ip: Some("192.168.1.50".to_string()),
            destination_ip: Some("10.0.0.5".to_string()),
            port: Some(80),
            protocol: Some("tcp".to_string()),
            message: "Web server vulnerability".to_string(),
            details: serde_json::json!({"cve": "CVE-2024-9999", "service": "apache"}),
            cve_ids: vec!["CVE-2024-9999".to_string()],
            cvss_score: Some(8.5),
            scan_id: "scan-syslog-test".to_string(),
            user_id: "user-syslog".to_string(),
        }
    }

    #[test]
    fn test_protocol_parsing() {
        // Valid protocols
        let tcp = SyslogExporter::new("127.0.0.1:514", "tcp");
        assert!(tcp.is_ok());

        let udp = SyslogExporter::new("127.0.0.1:514", "udp");
        assert!(udp.is_ok());

        // Case insensitive
        let tcp_upper = SyslogExporter::new("127.0.0.1:514", "TCP");
        assert!(tcp_upper.is_ok());

        // Invalid protocol
        let invalid = SyslogExporter::new("127.0.0.1:514", "sctp");
        assert!(invalid.is_err());
        let err = invalid.err().unwrap().to_string();
        assert!(err.contains("Invalid protocol"));
    }

    #[test]
    fn test_invalid_endpoint() {
        let result = SyslogExporter::new("not-a-valid-address", "tcp");
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc5424_format_structure() {
        let exporter = SyslogExporter::new("127.0.0.1:514", "tcp").unwrap();
        let event = create_test_event();
        let message = exporter.format_rfc5424(&event);

        // RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
        // Check version is 1
        assert!(message.contains(">1 "));

        // Check hostname (might be actual hostname or "heroforge")
        assert!(message.contains(" heroforge ") || message.contains(&exporter.hostname));

        // Check structured data
        assert!(message.contains("[heroforge@32473"));
        assert!(message.contains("scan_id=\"scan-syslog-test\""));
        assert!(message.contains("user_id=\"user-syslog\""));
        assert!(message.contains("event_type=\"vulnerability_found\""));
        assert!(message.contains("severity=\"critical\""));

        // Check optional fields
        assert!(message.contains("source_ip=\"192.168.1.50\""));
        assert!(message.contains("destination_ip=\"10.0.0.5\""));
        assert!(message.contains("port=\"80\""));
        assert!(message.contains("protocol=\"tcp\""));
        assert!(message.contains("cvss_score=\"8.5\""));
        assert!(message.contains("cve_ids=\"CVE-2024-9999\""));

        // Check message ends with newline
        assert!(message.ends_with('\n'));
    }

    #[test]
    fn test_rfc5424_priority_calculation() {
        let exporter = SyslogExporter::new("127.0.0.1:514", "tcp").unwrap();

        // Critical = facility(16) * 8 + severity(2) = 130
        let mut event = create_test_event();
        event.severity = "critical".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<130>"));

        // High = facility(16) * 8 + severity(3) = 131
        event.severity = "high".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<131>"));

        // Medium = facility(16) * 8 + severity(4) = 132
        event.severity = "medium".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<132>"));

        // Low = facility(16) * 8 + severity(5) = 133
        event.severity = "low".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<133>"));

        // Info = facility(16) * 8 + severity(6) = 134
        event.severity = "info".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<134>"));

        // Unknown defaults to info
        event.severity = "unknown".to_string();
        let msg = exporter.format_rfc5424(&event);
        assert!(msg.starts_with("<134>"));
    }

    #[test]
    fn test_rfc5424_minimal_event() {
        let exporter = SyslogExporter::new("127.0.0.1:514", "tcp").unwrap();

        let event = SiemEvent {
            timestamp: Utc::now(),
            severity: "info".to_string(),
            event_type: "test".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "Minimal test".to_string(),
            details: serde_json::json!({}),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "test".to_string(),
            user_id: "test".to_string(),
        };

        let message = exporter.format_rfc5424(&event);

        // Should not contain optional fields
        assert!(!message.contains("source_ip="));
        assert!(!message.contains("destination_ip="));
        assert!(!message.contains("port="));
        assert!(!message.contains("cvss_score="));
        assert!(!message.contains("cve_ids="));

        // Should contain required fields
        assert!(message.contains("scan_id=\"test\""));
        assert!(message.contains("Minimal test"));
    }

    #[test]
    fn test_rfc5424_multiple_cve_ids() {
        let exporter = SyslogExporter::new("127.0.0.1:514", "tcp").unwrap();

        let mut event = create_test_event();
        event.cve_ids = vec![
            "CVE-2024-1111".to_string(),
            "CVE-2024-2222".to_string(),
            "CVE-2024-3333".to_string(),
        ];

        let message = exporter.format_rfc5424(&event);
        assert!(message.contains("cve_ids=\"CVE-2024-1111,CVE-2024-2222,CVE-2024-3333\""));
    }

    #[tokio::test]
    async fn test_tcp_send_success() {
        // Start a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let exporter = SyslogExporter::new(&addr.to_string(), "tcp").unwrap();
        let event = create_test_event();

        // Spawn a task to accept the connection and read the message
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        // Send the event
        let result = exporter.export_event(&event).await;
        assert!(result.is_ok());

        // Verify the message was received
        let received = handle.await.unwrap();
        assert!(received.contains("vulnerability_found"));
        assert!(received.contains("scan-syslog-test"));
    }

    #[tokio::test]
    async fn test_tcp_connection_refused() {
        // Use a port that's not listening
        let exporter = SyslogExporter::new("127.0.0.1:59999", "tcp").unwrap();
        let event = create_test_event();

        let result = exporter.export_event(&event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_send_success() {
        // Start a UDP socket to receive
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = receiver.local_addr().unwrap();

        let exporter = SyslogExporter::new(&addr.to_string(), "udp").unwrap();
        let event = create_test_event();

        // Spawn a task to receive the message
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        // Send the event
        let result = exporter.export_event(&event).await;
        assert!(result.is_ok());

        // Verify the message was received
        let received = handle.await.unwrap();
        assert!(received.contains("vulnerability_found"));
        assert!(received.contains("scan-syslog-test"));
    }

    #[tokio::test]
    async fn test_export_events_batch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let exporter = SyslogExporter::new(&addr.to_string(), "tcp").unwrap();

        let events = vec![create_test_event(), create_test_event()];

        // Spawn a task to accept connections and count messages
        let handle = tokio::spawn(async move {
            let mut messages = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                messages.push(String::from_utf8_lossy(&buf[..n]).to_string());
            }
            messages
        });

        let result = exporter.export_events(&events).await;
        assert!(result.is_ok());

        let received = handle.await.unwrap();
        assert_eq!(received.len(), 2);
    }

    #[tokio::test]
    async fn test_connection_test_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let exporter = SyslogExporter::new(&addr.to_string(), "tcp").unwrap();

        // Spawn a task to accept the connection
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let result = exporter.test_connection().await;
        assert!(result.is_ok());

        let received = handle.await.unwrap();
        assert!(received.contains("test_connection"));
        assert!(received.contains("HeroForge SIEM integration test"));
    }
}
