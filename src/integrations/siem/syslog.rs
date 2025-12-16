use super::{SiemEvent, SiemExporter};
use anyhow::Result;
use async_trait::async_trait;
use chrono::SecondsFormat;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

pub struct SyslogExporter {
    endpoint: SocketAddr,
    protocol: Protocol,
    hostname: String,
    app_name: String,
}

#[derive(Clone)]
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
