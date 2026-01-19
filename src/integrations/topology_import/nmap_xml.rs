//! Nmap XML output parser
//!
//! Parses nmap's XML output format (-oX flag)

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use quick_xml::events::Event;
use quick_xml::Reader;

use super::types::{
    HostStatus, ImportedPort, ImportedTopologyHost, PortState, ScanMetadata, ScriptResult,
    TopologyImportResult, TopologyImportSource,
};

/// Parser for Nmap XML output
pub struct NmapXmlParser;

impl NmapXmlParser {
    /// Parse nmap XML content
    pub fn parse(content: &str) -> Result<TopologyImportResult> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut result = TopologyImportResult::new(TopologyImportSource::NmapXml);
        result.metadata.scanner = "nmap".to_string();

        let mut current_host: Option<ImportedTopologyHost> = None;
        let mut current_port: Option<ImportedPort> = None;
        let mut in_host = false;
        let mut in_port = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    match name.as_str() {
                        "nmaprun" => {
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "scanner" => result.metadata.scanner = value,
                                    "args" => result.metadata.command_line = Some(value),
                                    "version" => result.metadata.scanner_version = Some(value),
                                    "startstr" | "start" => {
                                        if let Ok(ts) = value.parse::<i64>() {
                                            result.metadata.start_time = Utc.timestamp_opt(ts, 0).single();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "scaninfo" => {
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "type" {
                                    result.metadata.scan_type = Some(value);
                                }
                            }
                        }
                        "host" => {
                            in_host = true;
                            let mut host = ImportedTopologyHost::default();

                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "starttime" => {
                                        if let Ok(ts) = value.parse::<i64>() {
                                            host.scan_time = Utc.timestamp_opt(ts, 0).single();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            current_host = Some(host);
                        }
                        "status" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    match key.as_str() {
                                        "state" => {
                                            host.status = match value.as_str() {
                                                "up" => HostStatus::Up,
                                                "down" => HostStatus::Down,
                                                _ => HostStatus::Unknown,
                                            };
                                        }
                                        "reason" => host.status_reason = Some(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "address" if in_host => {
                            if let Some(ref mut host) = current_host {
                                let mut addr_type = String::new();
                                let mut addr = String::new();
                                let mut vendor = None;

                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    match key.as_str() {
                                        "addr" => addr = value,
                                        "addrtype" => addr_type = value,
                                        "vendor" => vendor = Some(value),
                                        _ => {}
                                    }
                                }

                                match addr_type.as_str() {
                                    "ipv4" => host.ip = addr,
                                    "ipv6" => host.ipv6 = Some(addr),
                                    "mac" => {
                                        host.mac_address = Some(addr);
                                        host.mac_vendor = vendor;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "hostname" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    if key == "name" && host.hostname.is_none() {
                                        host.hostname = Some(value);
                                    }
                                }
                            }
                        }
                        "port" if in_host => {
                            in_port = true;
                            let mut port = ImportedPort::default();

                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "protocol" => port.protocol = value,
                                    "portid" => port.port = value.parse().unwrap_or(0),
                                    _ => {}
                                }
                            }
                            current_port = Some(port);
                        }
                        "state" if in_port => {
                            if let Some(ref mut port) = current_port {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    if key == "state" {
                                        port.state = PortState::from_str(&value);
                                    }
                                }
                            }
                        }
                        "service" if in_port => {
                            if let Some(ref mut port) = current_port {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    match key.as_str() {
                                        "name" => port.service = Some(value),
                                        "product" => port.product = Some(value),
                                        "version" => port.version = Some(value),
                                        "extrainfo" => port.extra_info = Some(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "script" if in_port => {
                            let mut script = ScriptResult::default();
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "id" => script.id = value,
                                    "output" => script.output = value,
                                    _ => {}
                                }
                            }
                            if let Some(ref mut port) = current_port {
                                port.scripts.push(script);
                            }
                        }
                        "osmatch" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    match key.as_str() {
                                        "name" => {
                                            if host.os.is_none() {
                                                host.os = Some(value);
                                            }
                                        }
                                        "accuracy" => {
                                            if host.os_accuracy.is_none() {
                                                host.os_accuracy = value.parse().ok();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "osclass" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    if key == "osfamily" && host.os_family.is_none() {
                                        host.os_family = Some(value);
                                    }
                                }
                            }
                        }
                        "uptime" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    match key.as_str() {
                                        "seconds" => host.uptime = value.parse().ok(),
                                        "lastboot" => host.last_boot = Some(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "distance" if in_host => {
                            if let Some(ref mut host) = current_host {
                                for attr in e.attributes().filter_map(|a| a.ok()) {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let value = String::from_utf8_lossy(&attr.value).to_string();
                                    if key == "value" {
                                        host.distance = value.parse().ok();
                                    }
                                }
                            }
                        }
                        "runstats" => {
                            // Parse end time from runstats/finished
                        }
                        "finished" => {
                            for attr in e.attributes().filter_map(|a| a.ok()) {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "time" {
                                    if let Ok(ts) = value.parse::<i64>() {
                                        result.metadata.end_time = Utc.timestamp_opt(ts, 0).single();
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    match name.as_str() {
                        "host" => {
                            if let Some(host) = current_host.take() {
                                if !host.ip.is_empty() {
                                    result.hosts.push(host);
                                } else if let Some(ipv6) = host.ipv6.clone() {
                                    let mut h = host;
                                    h.ip = ipv6;
                                    result.hosts.push(h);
                                }
                            }
                            in_host = false;
                        }
                        "port" => {
                            if let Some(port) = current_port.take() {
                                if let Some(ref mut host) = current_host {
                                    host.ports.push(port);
                                }
                            }
                            in_port = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    result.errors.push(format!("XML parse error: {}", e));
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_xml() {
        let xml = r#"<?xml version="1.0"?>
        <nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1609459200" version="7.91">
            <host starttime="1609459200">
                <status state="up" reason="syn-ack"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <hostnames>
                    <hostname name="router.local" type="PTR"/>
                </hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.0"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.18"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Linux 5.4" accuracy="95"/>
                    <osclass osfamily="Linux"/>
                </os>
            </host>
        </nmaprun>"#;

        let result = NmapXmlParser::parse(xml).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ip, "192.168.1.1");
        assert_eq!(result.hosts[0].hostname, Some("router.local".to_string()));
        assert_eq!(result.hosts[0].status, HostStatus::Up);
        assert_eq!(result.hosts[0].ports.len(), 2);
        assert_eq!(result.hosts[0].ports[0].port, 22);
        assert_eq!(result.hosts[0].ports[0].service, Some("ssh".to_string()));
        assert_eq!(result.hosts[0].os, Some("Linux 5.4".to_string()));
        assert_eq!(result.metadata.scanner, "nmap");
        assert_eq!(result.metadata.scanner_version, Some("7.91".to_string()));
    }
}
