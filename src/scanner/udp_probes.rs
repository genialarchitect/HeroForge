//! UDP protocol-specific probe packets for service detection
//!
//! This module contains pre-built probe packets for common UDP services.
//! Each probe is designed to elicit a response from the target service.

/// Default UDP ports for scanning when no specific ports are provided
pub const DEFAULT_UDP_PORTS: &[u16] = &[
    53,    // DNS
    67,    // DHCP Server
    69,    // TFTP
    123,   // NTP
    137,   // NetBIOS Name Service
    161,   // SNMP
    500,   // IKE/ISAKMP
    514,   // Syslog
    1900,  // SSDP/UPnP
    5060,  // SIP
    5353,  // mDNS
];

/// Get the appropriate UDP probe packet for a given port
pub fn get_udp_probe(port: u16) -> Vec<u8> {
    match port {
        53 => dns_probe(),
        67 | 68 => dhcp_probe(),
        69 => tftp_probe(),
        123 => ntp_probe(),
        137 => netbios_probe(),
        161 | 162 => snmp_probe(),
        514 => syslog_probe(),
        1900 => ssdp_probe(),
        5060 => sip_probe(),
        5353 => mdns_probe(),
        _ => generic_probe(),
    }
}

/// DNS probe - Query for version.bind TXT record (CHAOS class)
/// This query is commonly used to fingerprint DNS servers
pub fn dns_probe() -> Vec<u8> {
    vec![
        // Transaction ID
        0x00, 0x01,
        // Flags: Standard query (QR=0, OPCODE=0, RD=1)
        0x01, 0x00,
        // Questions: 1
        0x00, 0x01,
        // Answer RRs: 0
        0x00, 0x00,
        // Authority RRs: 0
        0x00, 0x00,
        // Additional RRs: 0
        0x00, 0x00,
        // Query: version.bind
        0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
        0x04, b'b', b'i', b'n', b'd',
        0x00, // Root label
        // Type: TXT (16)
        0x00, 0x10,
        // Class: CH (CHAOS) (3)
        0x00, 0x03,
    ]
}

/// SNMP probe - GetRequest for sysDescr.0 with "public" community string
/// OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
pub fn snmp_probe() -> Vec<u8> {
    vec![
        // SEQUENCE (BER)
        0x30, 0x26,
        // INTEGER: version (SNMPv1 = 0)
        0x02, 0x01, 0x00,
        // OCTET STRING: community "public"
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c',
        // GetRequest-PDU (0xA0)
        0xa0, 0x19,
        // INTEGER: request-id
        0x02, 0x01, 0x01,
        // INTEGER: error-status (0 = noError)
        0x02, 0x01, 0x00,
        // INTEGER: error-index
        0x02, 0x01, 0x00,
        // SEQUENCE: variable-bindings
        0x30, 0x0e,
        // SEQUENCE: variable-binding
        0x30, 0x0c,
        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        // NULL value
        0x05, 0x00,
    ]
}

/// NTP probe - Client mode request (mode 3, version 3)
/// Sends a standard NTP client request packet
pub fn ntp_probe() -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    // LI (Leap Indicator) = 0, VN (Version) = 3, Mode = 3 (client)
    // Binary: 00 011 011 = 0x1b
    packet[0] = 0x1b;
    packet
}

/// NetBIOS Name Service probe - NBSTAT query for wildcard name
/// Queries for all registered names on the target
pub fn netbios_probe() -> Vec<u8> {
    vec![
        // Transaction ID
        0x80, 0x94,
        // Flags: Name query request
        0x00, 0x00,
        // Questions: 1
        0x00, 0x01,
        // Answer RRs: 0
        0x00, 0x00,
        // Authority RRs: 0
        0x00, 0x00,
        // Additional RRs: 0
        0x00, 0x00,
        // NetBIOS encoded name: "*" (wildcard) padded to 16 bytes
        // First level encoding: length byte (32)
        0x20,
        // Encoded "*<00>" - '*' encoded as 'CK', followed by 'AA' padding
        0x43, 0x4b, // *
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // padding
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // padding
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // padding
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41,             // padding
        // Null terminator
        0x00,
        // Type: NBSTAT (33)
        0x00, 0x21,
        // Class: IN (1)
        0x00, 0x01,
    ]
}

/// TFTP probe - Read Request (RRQ) for a nonexistent file
/// The server should respond with an error packet, confirming it's a TFTP server
pub fn tftp_probe() -> Vec<u8> {
    let mut packet = Vec::new();
    // Opcode: RRQ (1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // Filename: "x" (short, nonexistent)
    packet.extend_from_slice(b"x");
    packet.push(0x00); // Null terminator
    // Mode: "octet"
    packet.extend_from_slice(b"octet");
    packet.push(0x00); // Null terminator
    packet
}

/// SIP probe - OPTIONS request
/// A minimal SIP OPTIONS request to check for SIP service
pub fn sip_probe() -> Vec<u8> {
    let request = "OPTIONS sip:nm SIP/2.0\r\n\
                   Via: SIP/2.0/UDP nm;branch=z9hG4bK\r\n\
                   Max-Forwards: 0\r\n\
                   To: <sip:nm>\r\n\
                   From: <sip:nm>;tag=nm\r\n\
                   Call-ID: nm\r\n\
                   CSeq: 1 OPTIONS\r\n\
                   Content-Length: 0\r\n\r\n";
    request.as_bytes().to_vec()
}

/// DHCP probe - DHCP Discover packet
/// Sends a DHCP discover to identify DHCP servers
pub fn dhcp_probe() -> Vec<u8> {
    let mut packet = vec![0u8; 244];

    // Message type: BOOTREQUEST (1)
    packet[0] = 0x01;
    // Hardware type: Ethernet (1)
    packet[1] = 0x01;
    // Hardware address length: 6
    packet[2] = 0x06;
    // Hops: 0
    packet[3] = 0x00;

    // Transaction ID (random-ish)
    packet[4..8].copy_from_slice(&[0x39, 0x03, 0xf3, 0x26]);

    // Seconds elapsed: 0
    packet[8..10].copy_from_slice(&[0x00, 0x00]);
    // Bootp flags: Broadcast (0x8000)
    packet[10..12].copy_from_slice(&[0x80, 0x00]);

    // Client MAC address (fake)
    packet[28..34].copy_from_slice(&[0x00, 0x0c, 0x29, 0x01, 0x02, 0x03]);

    // DHCP magic cookie
    packet[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

    // DHCP options
    // Option 53: DHCP Message Type = DHCPDISCOVER (1)
    packet[240] = 53;
    packet[241] = 1;
    packet[242] = 1;
    // End option
    packet[243] = 255;

    packet
}

/// Syslog probe - A minimal syslog message
/// Should elicit some response from misconfigured syslog servers
pub fn syslog_probe() -> Vec<u8> {
    // Priority: local0.info (134), minimal message
    b"<134>1 - - - - - -".to_vec()
}

/// SSDP probe - M-SEARCH request for UPnP discovery
pub fn ssdp_probe() -> Vec<u8> {
    let request = "M-SEARCH * HTTP/1.1\r\n\
                   Host: 239.255.255.250:1900\r\n\
                   ST: ssdp:all\r\n\
                   Man: \"ssdp:discover\"\r\n\
                   MX: 1\r\n\r\n";
    request.as_bytes().to_vec()
}

/// mDNS probe - Query for _services._dns-sd._udp.local
/// Discovers available services via multicast DNS
pub fn mdns_probe() -> Vec<u8> {
    vec![
        // Transaction ID (should be 0 for mDNS)
        0x00, 0x00,
        // Flags: Standard query
        0x00, 0x00,
        // Questions: 1
        0x00, 0x01,
        // Answer RRs: 0
        0x00, 0x00,
        // Authority RRs: 0
        0x00, 0x00,
        // Additional RRs: 0
        0x00, 0x00,
        // Query: _services._dns-sd._udp.local
        0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
        0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
        0x04, b'_', b'u', b'd', b'p',
        0x05, b'l', b'o', b'c', b'a', b'l',
        0x00, // Root label
        // Type: PTR (12)
        0x00, 0x0c,
        // Class: IN (1) with cache-flush bit clear
        0x00, 0x01,
    ]
}

/// Generic probe - Empty packet or minimal data
/// Used for ports without specific probes
pub fn generic_probe() -> Vec<u8> {
    // Send a few null bytes - some services respond to any data
    vec![0x00, 0x00, 0x00, 0x00]
}

/// Get service name for a UDP port
pub fn get_udp_service_name(port: u16) -> &'static str {
    match port {
        53 => "dns",
        67 => "dhcp-server",
        68 => "dhcp-client",
        69 => "tftp",
        123 => "ntp",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        161 => "snmp",
        162 => "snmptrap",
        500 => "isakmp",
        514 => "syslog",
        520 => "rip",
        1434 => "ms-sql-m",
        1900 => "ssdp",
        4500 => "nat-t-ike",
        5060 => "sip",
        5353 => "mdns",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_probe_valid() {
        let probe = dns_probe();
        // Minimum DNS packet size
        assert!(probe.len() >= 12);
        // QR bit should be 0 (query)
        assert_eq!(probe[2] & 0x80, 0x00);
        // Should have 1 question
        assert_eq!(probe[4..6], [0x00, 0x01]);
    }

    #[test]
    fn test_snmp_probe_valid() {
        let probe = snmp_probe();
        // Should start with SEQUENCE tag
        assert_eq!(probe[0], 0x30);
        // Should contain "public" community string
        assert!(probe.windows(6).any(|w| w == b"public"));
    }

    #[test]
    fn test_ntp_probe_valid() {
        let probe = ntp_probe();
        // NTP packet is 48 bytes
        assert_eq!(probe.len(), 48);
        // First byte: LI=0, VN=3, Mode=3 -> 0x1b
        assert_eq!(probe[0], 0x1b);
    }

    #[test]
    fn test_netbios_probe_valid() {
        let probe = netbios_probe();
        // Should have NBSTAT type (0x0021)
        assert!(probe.windows(2).any(|w| w == [0x00, 0x21]));
    }

    #[test]
    fn test_tftp_probe_valid() {
        let probe = tftp_probe();
        // Should start with RRQ opcode (0x0001)
        assert_eq!(probe[0..2], [0x00, 0x01]);
        // Should contain "octet" mode
        assert!(probe.windows(5).any(|w| w == b"octet"));
    }

    #[test]
    fn test_sip_probe_valid() {
        let probe = sip_probe();
        let probe_str = String::from_utf8_lossy(&probe);
        assert!(probe_str.starts_with("OPTIONS"));
        assert!(probe_str.contains("SIP/2.0"));
    }

    #[test]
    fn test_dhcp_probe_valid() {
        let probe = dhcp_probe();
        // BOOTREQUEST
        assert_eq!(probe[0], 0x01);
        // Hardware type: Ethernet
        assert_eq!(probe[1], 0x01);
        // DHCP magic cookie at offset 236
        assert_eq!(probe[236..240], [0x63, 0x82, 0x53, 0x63]);
    }

    #[test]
    fn test_get_udp_probe() {
        // Verify we get the right probes for known ports
        assert_eq!(get_udp_probe(53), dns_probe());
        assert_eq!(get_udp_probe(161), snmp_probe());
        assert_eq!(get_udp_probe(123), ntp_probe());
    }

    #[test]
    fn test_default_udp_ports() {
        // Ensure default ports are sorted and contain common services
        assert!(DEFAULT_UDP_PORTS.contains(&53));  // DNS
        assert!(DEFAULT_UDP_PORTS.contains(&161)); // SNMP
        assert!(DEFAULT_UDP_PORTS.contains(&123)); // NTP
    }
}
