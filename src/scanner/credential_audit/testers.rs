//! Service-specific credential testers
//!
//! This module contains implementations for testing credentials against
//! various services. Each tester handles the protocol-specific authentication.

use super::types::{Credential, CredentialServiceType, CredentialTestResult};
use anyhow::Result;
use log::debug;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Hash a password for secure storage/logging
/// SECURITY: Never store or log plaintext passwords
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Test credentials against a service
pub async fn test_credential(
    host: &str,
    port: u16,
    service_type: CredentialServiceType,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> CredentialTestResult {
    let start = Instant::now();

    let result = match service_type {
        CredentialServiceType::Ssh => test_ssh(host, port, credential, timeout).await,
        CredentialServiceType::Ftp => test_ftp(host, port, credential, timeout).await,
        CredentialServiceType::Telnet => test_telnet(host, port, credential, timeout).await,
        CredentialServiceType::Mysql => test_mysql(host, port, credential, timeout).await,
        CredentialServiceType::Postgresql => test_postgresql(host, port, credential, timeout).await,
        CredentialServiceType::Redis => test_redis(host, port, credential, timeout).await,
        CredentialServiceType::TomcatManager => {
            test_tomcat(host, port, credential, timeout, use_ssl, path).await
        }
        CredentialServiceType::WordPress => {
            test_wordpress(host, port, credential, timeout, use_ssl, path).await
        }
        CredentialServiceType::Snmp => test_snmp(host, port, credential, timeout).await,
        CredentialServiceType::Rdp => test_rdp(host, port, credential, timeout).await,
        CredentialServiceType::Vnc => test_vnc(host, port, credential, timeout).await,
        CredentialServiceType::Mssql => test_mssql(host, port, credential, timeout).await,
        CredentialServiceType::Mongodb => test_mongodb(host, port, credential, timeout).await,
        CredentialServiceType::PhpMyAdmin => {
            test_phpmyadmin(host, port, credential, timeout, use_ssl, path).await
        }
        CredentialServiceType::Joomla => {
            test_joomla(host, port, credential, timeout, use_ssl, path).await
        }
        CredentialServiceType::Drupal => {
            test_drupal(host, port, credential, timeout, use_ssl, path).await
        }
        CredentialServiceType::RouterOs => test_routeros(host, port, credential, timeout).await,
        CredentialServiceType::CiscoIos => test_cisco_ios(host, port, credential, timeout).await,
        CredentialServiceType::Smtp => test_smtp(host, port, credential, timeout, use_ssl).await,
        CredentialServiceType::Pop3 => test_pop3(host, port, credential, timeout, use_ssl).await,
        CredentialServiceType::Imap => test_imap(host, port, credential, timeout, use_ssl).await,
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(success) => CredentialTestResult {
            success,
            username: credential.username.clone(),
            password_hash: hash_password(&credential.password),
            error: None,
            duration_ms,
        },
        Err(e) => CredentialTestResult {
            success: false,
            username: credential.username.clone(),
            password_hash: hash_password(&credential.password),
            error: Some(e.to_string()),
            duration_ms,
        },
    }
}

/// Test SSH credentials
async fn test_ssh(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let port = port;
    let username = credential.username.clone();
    let _password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        // Connect with timeout
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut reader = BufReader::new(&stream);

        // Read server banner
        let mut banner = String::new();
        reader.read_line(&mut banner)?;

        if !banner.starts_with("SSH-") {
            return Err(anyhow::anyhow!("Not an SSH server"));
        }

        // For actual SSH password auth, we would need to implement the full
        // SSH protocol or use an SSH library. For now, we'll indicate that
        // SSH testing requires additional tooling.
        //
        // In a real implementation, you would use the `ssh2` crate:
        // ```
        // use ssh2::Session;
        // let tcp = TcpStream::connect(&addr)?;
        // let mut sess = Session::new()?;
        // sess.set_tcp_stream(tcp);
        // sess.handshake()?;
        // match sess.userauth_password(&username, &password) {
        //     Ok(_) => Ok(sess.authenticated()),
        //     Err(_) => Ok(false),
        // }
        // ```

        // For security scanning purposes, we'll attempt a basic connection test
        // Real credential testing would require the ssh2 crate
        debug!(
            "SSH server detected at {}:{}, username={} (auth test would require ssh2 crate)",
            host, port, username
        );

        // Return false - actual implementation would test auth
        // This is a placeholder that indicates the service is reachable
        Ok(false)
    })
    .await?
}

/// Test FTP credentials
async fn test_ftp(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Clone stream for separate read/write handles
        let read_stream = stream.try_clone()?;
        let mut write_stream = stream;
        let mut reader = BufReader::new(read_stream);

        // Read welcome banner
        let mut response = String::new();
        reader.read_line(&mut response)?;

        if !response.starts_with("220") {
            return Err(anyhow::anyhow!("FTP server not ready"));
        }

        // Send USER command
        let user_cmd = format!("USER {}\r\n", username);
        write_stream.write_all(user_cmd.as_bytes())?;
        write_stream.flush()?;

        response.clear();
        reader.read_line(&mut response)?;

        // 331 = password required, 230 = logged in (anonymous)
        if response.starts_with("230") {
            return Ok(true); // Logged in without password
        }

        if !response.starts_with("331") {
            return Ok(false); // User rejected
        }

        // Send PASS command
        let pass_cmd = format!("PASS {}\r\n", password);
        write_stream.write_all(pass_cmd.as_bytes())?;
        write_stream.flush()?;

        response.clear();
        reader.read_line(&mut response)?;

        // 230 = login successful
        if response.starts_with("230") {
            // Send QUIT
            let _ = write_stream.write_all(b"QUIT\r\n");
            return Ok(true);
        }

        Ok(false)
    })
    .await?
}

/// Test Telnet credentials
async fn test_telnet(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Read until we see a login prompt
        let mut buffer = vec![0u8; 4096];
        let mut accumulated = String::new();

        for _ in 0..10 {
            match std::io::Read::read(&mut stream, &mut buffer) {
                Ok(n) if n > 0 => {
                    accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
                _ => break,
            }

            let lower = accumulated.to_lowercase();
            if lower.contains("login:") || lower.contains("username:") {
                break;
            }
        }

        // Send username
        let user_cmd = format!("{}\r\n", username);
        stream.write_all(user_cmd.as_bytes())?;
        stream.flush()?;

        // Wait for password prompt
        std::thread::sleep(Duration::from_millis(500));
        accumulated.clear();

        for _ in 0..10 {
            match std::io::Read::read(&mut stream, &mut buffer) {
                Ok(n) if n > 0 => {
                    accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
                _ => break,
            }

            let lower = accumulated.to_lowercase();
            if lower.contains("password:") {
                break;
            }
        }

        // Send password
        let pass_cmd = format!("{}\r\n", password);
        stream.write_all(pass_cmd.as_bytes())?;
        stream.flush()?;

        // Check for success indicators
        std::thread::sleep(Duration::from_millis(1000));
        accumulated.clear();

        for _ in 0..5 {
            match std::io::Read::read(&mut stream, &mut buffer) {
                Ok(n) if n > 0 => {
                    accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
                _ => break,
            }
        }

        let lower = accumulated.to_lowercase();

        // Success indicators
        if lower.contains("last login:")
            || lower.contains("$ ")
            || lower.contains("# ")
            || lower.contains("> ")
            || lower.contains("welcome")
        {
            return Ok(true);
        }

        // Failure indicators
        if lower.contains("login incorrect")
            || lower.contains("authentication failed")
            || lower.contains("login failed")
            || lower.contains("access denied")
        {
            return Ok(false);
        }

        Ok(false)
    })
    .await?
}

/// Test MySQL credentials
async fn test_mysql(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let _password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;

        // Read MySQL greeting packet
        let mut buffer = vec![0u8; 1024];
        let n = std::io::Read::read(&mut (&stream), &mut buffer)?;

        if n < 5 {
            return Err(anyhow::anyhow!("Invalid MySQL response"));
        }

        // Check for MySQL protocol signature
        // First 3 bytes are packet length, 4th is sequence, 5th is protocol version
        if buffer[4] != 10 && buffer[4] != 9 {
            // MySQL 5.x uses protocol 10, older uses 9
            return Err(anyhow::anyhow!("Not a MySQL server"));
        }

        // For actual MySQL auth, we would need to implement the MySQL protocol
        // or use a MySQL client library
        debug!(
            "MySQL server detected at {}:{}, username={} (full auth requires mysql crate)",
            host, port, username
        );

        // Return false - actual implementation would test auth
        Ok(false)
    })
    .await?
}

/// Test PostgreSQL credentials
async fn test_postgresql(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Send PostgreSQL startup message
        // Format: Length (4) + Protocol Version (4) + Parameters
        let mut startup_msg = Vec::new();

        // Protocol version 3.0
        startup_msg.extend_from_slice(&[0, 3, 0, 0]);

        // User parameter
        startup_msg.extend_from_slice(b"user\0");
        startup_msg.extend_from_slice(username.as_bytes());
        startup_msg.push(0);

        // Database parameter
        startup_msg.extend_from_slice(b"database\0");
        startup_msg.extend_from_slice(username.as_bytes());
        startup_msg.push(0);

        // Terminator
        startup_msg.push(0);

        // Prepend length
        let total_len = (startup_msg.len() + 4) as u32;
        let mut packet = Vec::new();
        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.extend(startup_msg);

        stream.write_all(&packet)?;
        stream.flush()?;

        // Read response
        let mut response = vec![0u8; 1024];
        let n = std::io::Read::read(&mut stream, &mut response)?;

        if n > 0 {
            match response[0] as char {
                'R' => {
                    // Authentication request
                    debug!("PostgreSQL authentication required for user {}", username);
                    // Would need to handle different auth methods here
                    Ok(false)
                }
                'E' => {
                    // Error response
                    Ok(false)
                }
                _ => Ok(false),
            }
        } else {
            Err(anyhow::anyhow!("No response from PostgreSQL"))
        }
    })
    .await?
}

/// Test Redis credentials
async fn test_redis(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
) -> Result<bool> {
    let host = host.to_string();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Clone stream for separate read/write handles
        let read_stream = stream.try_clone()?;
        let mut write_stream = stream;

        // Try PING first to see if auth is required
        write_stream.write_all(b"PING\r\n")?;
        write_stream.flush()?;

        let mut reader = BufReader::new(read_stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;

        // If PONG, no auth required
        if response.contains("+PONG") || response.contains("PONG") {
            if password.is_empty() {
                return Ok(true); // No password required
            }
            // No auth needed but password provided
            return Ok(false);
        }

        // If NOAUTH, auth is required
        if response.contains("-NOAUTH") || response.contains("NOAUTH") {
            if password.is_empty() {
                return Ok(false); // Password required but none provided
            }

            // Try AUTH command
            let auth_cmd = format!("AUTH {}\r\n", password);
            write_stream.write_all(auth_cmd.as_bytes())?;
            write_stream.flush()?;

            response.clear();
            reader.read_line(&mut response)?;

            if response.starts_with("+OK") {
                return Ok(true);
            }
        }

        Ok(false)
    })
    .await?
}

/// Test Tomcat Manager credentials
async fn test_tomcat(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> Result<bool> {
    let url = if use_ssl {
        format!(
            "https://{}:{}{}/html",
            host,
            port,
            path.unwrap_or("/manager")
        )
    } else {
        format!(
            "http://{}:{}{}/html",
            host,
            port,
            path.unwrap_or("/manager")
        )
    };

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client
        .get(&url)
        .basic_auth(&credential.username, Some(&credential.password))
        .send()
        .await?;

    // 200 = success, 401/403 = auth failed
    Ok(response.status().is_success())
}

/// Test WordPress credentials
async fn test_wordpress(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> Result<bool> {
    let base_url = if use_ssl {
        format!("https://{}:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    };

    let login_url = format!("{}{}/wp-login.php", base_url, path.unwrap_or(""));

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // First, get the login page to extract any nonces
    let _get_response = client.get(&login_url).send().await?;

    // Attempt login
    let params = [
        ("log", credential.username.as_str()),
        ("pwd", credential.password.as_str()),
        ("wp-submit", "Log In"),
        ("redirect_to", &format!("{}/wp-admin/", base_url)),
        ("testcookie", "1"),
    ];

    let response = client.post(&login_url).form(&params).send().await?;

    // Check for redirect to wp-admin (success) or stay on login page (failure)
    if let Some(location) = response.headers().get("location") {
        let loc = location.to_str().unwrap_or("");
        if loc.contains("wp-admin") && !loc.contains("wp-login.php") {
            return Ok(true);
        }
    }

    // Check response body for error messages
    let body = response.text().await?;
    if body.contains("wp-admin") && !body.contains("login_error") {
        return Ok(true);
    }

    Ok(false)
}

/// Test SNMP community string
async fn test_snmp(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
) -> Result<bool> {
    let host = host.to_string();
    // For SNMP, the "password" is actually the community string
    let community = if credential.password.is_empty() {
        &credential.username
    } else {
        &credential.password
    };
    let community = community.clone();

    tokio::task::spawn_blocking(move || {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        let addr = format!("{}:{}", host, port);
        socket.connect(&addr)?;

        // Build SNMP v1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
        let mut packet = Vec::new();

        // SNMP message wrapper
        packet.push(0x30); // Sequence
        let msg_len_pos = packet.len();
        packet.push(0); // Placeholder for length

        // Version: SNMPv1 (0)
        packet.push(0x02); // Integer
        packet.push(0x01); // Length
        packet.push(0x00); // Value: 0 (v1)

        // Community string
        packet.push(0x04); // OctetString
        packet.push(community.len() as u8);
        packet.extend_from_slice(community.as_bytes());

        // GetRequest PDU
        packet.push(0xA0); // GetRequest
        let pdu_len_pos = packet.len();
        packet.push(0); // Placeholder for PDU length

        // Request ID
        packet.push(0x02); // Integer
        packet.push(0x04); // Length
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ID: 1

        // Error status
        packet.push(0x02); // Integer
        packet.push(0x01); // Length
        packet.push(0x00); // No error

        // Error index
        packet.push(0x02); // Integer
        packet.push(0x01); // Length
        packet.push(0x00); // Index: 0

        // Variable bindings
        packet.push(0x30); // Sequence
        let varbind_len_pos = packet.len();
        packet.push(0); // Placeholder for varbind length

        // Single varbind: sysDescr
        packet.push(0x30); // Sequence
        let vb_len_pos = packet.len();
        packet.push(0); // Placeholder

        // OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        let oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        packet.extend_from_slice(&oid);

        // NULL value
        packet.push(0x05); // NULL
        packet.push(0x00); // Length: 0

        // Fix lengths
        let vb_len = packet.len() - vb_len_pos - 1;
        packet[vb_len_pos] = vb_len as u8;

        let varbind_len = packet.len() - varbind_len_pos - 1;
        packet[varbind_len_pos] = varbind_len as u8;

        let pdu_len = packet.len() - pdu_len_pos - 1;
        packet[pdu_len_pos] = pdu_len as u8;

        let msg_len = packet.len() - msg_len_pos - 1;
        packet[msg_len_pos] = msg_len as u8;

        // Send packet
        socket.send(&packet)?;

        // Receive response
        let mut buf = [0u8; 1500];
        match socket.recv(&mut buf) {
            Ok(n) if n > 0 => {
                // Got a response - community string is valid
                // Check if it's an error response
                if n > 10 {
                    // Look for error status field
                    // A response means the community string was accepted
                    return Ok(true);
                }
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    Ok(false) // Timeout = likely invalid community
                } else {
                    Err(anyhow::anyhow!("SNMP error: {}", e))
                }
            }
        }
    })
    .await?
}

/// Test RDP credentials
/// Note: RDP protocol is complex; this performs basic connection testing
async fn test_rdp(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let _password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        // Connect to RDP port
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // RDP requires a complex handshake with CredSSP or NLA
        // For basic testing, verify the service is reachable and responds
        debug!(
            "RDP server detected at {}:{}, username={} (full auth requires RDP library)",
            host, port, username
        );

        // Check if we got the RDP header (0x03 = TPKT version)
        let mut buf = [0u8; 4];
        std::io::Read::read(&mut &stream, &mut buf)?;

        if buf[0] == 0x03 {
            // Valid TPKT header - RDP service is running
            Ok(false) // Can't test credentials without full protocol
        } else {
            Err(anyhow::anyhow!("Not an RDP server"))
        }
    })
    .await?
}

/// Test VNC credentials
async fn test_vnc(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Read VNC protocol version
        let mut version = [0u8; 12];
        std::io::Read::read_exact(&mut stream, &mut version)?;

        let version_str = String::from_utf8_lossy(&version);
        if !version_str.starts_with("RFB ") {
            return Err(anyhow::anyhow!("Not a VNC server"));
        }

        // Send our version (usually RFB 003.008)
        stream.write_all(b"RFB 003.008\n")?;
        stream.flush()?;

        // Read security types
        let mut num_types = [0u8; 1];
        std::io::Read::read_exact(&mut stream, &mut num_types)?;

        if num_types[0] == 0 {
            // Connection failed
            return Ok(false);
        }

        let mut types = vec![0u8; num_types[0] as usize];
        std::io::Read::read_exact(&mut stream, &mut types)?;

        // Check for VNC authentication (type 2)
        if !types.contains(&2) {
            // No VNC auth supported (might be no-auth or other)
            if types.contains(&1) {
                // No authentication required
                return Ok(true);
            }
            return Ok(false);
        }

        // Select VNC authentication
        stream.write_all(&[2])?;
        stream.flush()?;

        // Read challenge
        let mut challenge = [0u8; 16];
        std::io::Read::read_exact(&mut stream, &mut challenge)?;

        // DES encrypt challenge with password (VNC uses weird key derivation)
        // For security testing, we indicate VNC auth is available
        debug!("VNC auth challenge received, password={}", password.len());

        // Full VNC authentication would require DES encryption
        // Return false to indicate auth testing needs full implementation
        Ok(false)
    })
    .await?
}

/// Test MSSQL credentials
async fn test_mssql(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Build TDS 7.0+ prelogin packet
        let mut prelogin: Vec<u8> = Vec::new();

        // Packet header (type 0x12 = prelogin)
        prelogin.push(0x12); // Type
        prelogin.push(0x01); // Status (EOM)
        prelogin.push(0x00); prelogin.push(0x00); // Length placeholder
        prelogin.push(0x00); prelogin.push(0x00); // SPID
        prelogin.push(0x00); // Packet ID
        prelogin.push(0x00); // Window

        // Prelogin options
        // VERSION
        prelogin.push(0x00); // Token
        prelogin.push(0x00); prelogin.push(0x15); // Offset
        prelogin.push(0x00); prelogin.push(0x06); // Length
        // ENCRYPTION
        prelogin.push(0x01); // Token
        prelogin.push(0x00); prelogin.push(0x1B); // Offset
        prelogin.push(0x00); prelogin.push(0x01); // Length
        // TERMINATOR
        prelogin.push(0xFF);

        // Version data
        prelogin.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Encryption (0 = off, 1 = on, 2 = not supported, 3 = required)
        prelogin.push(0x02);

        // Fix length
        let len = prelogin.len() as u16;
        prelogin[2] = (len >> 8) as u8;
        prelogin[3] = (len & 0xFF) as u8;

        stream.write_all(&prelogin)?;
        stream.flush()?;

        // Read prelogin response
        let mut header = [0u8; 8];
        std::io::Read::read_exact(&mut stream, &mut header)?;

        if header[0] != 0x04 {
            // Not a proper MSSQL response
            return Err(anyhow::anyhow!("Invalid MSSQL response"));
        }

        debug!(
            "MSSQL server detected at {}:{}, testing credentials username={}",
            host, port, username
        );

        // Full TDS login would require building Login7 packet
        // For security testing, we confirm MSSQL is available
        let _ = password; // Would be used in Login7 packet
        Ok(false) // Indicate server is reachable but full auth needs TDS implementation
    })
    .await?
}

/// Test MongoDB credentials
async fn test_mongodb(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Build MongoDB isMaster command (wire protocol)
        let mut doc = bson_doc(vec![("isMaster", "1")]);

        // Build message
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[0u8; 4]); // Length placeholder
        msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Request ID
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Response To
        msg.extend_from_slice(&[0xD4, 0x07, 0x00, 0x00]); // OpCode (OP_QUERY = 2004)
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Flags
        msg.extend_from_slice(b"admin.$cmd\0"); // Collection
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Number to skip
        msg.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Number to return
        msg.extend_from_slice(&doc);

        // Fix length
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_le_bytes());

        stream.write_all(&msg)?;
        stream.flush()?;

        // Read response header
        let mut header = [0u8; 16];
        std::io::Read::read_exact(&mut stream, &mut header)?;

        let response_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if response_len > 16 && response_len < 65536 {
            debug!(
                "MongoDB server detected at {}:{}, username={}",
                host, port, username
            );
            // Server responded - would need SCRAM-SHA-1/256 for auth
            let _ = password;
            Ok(false)
        } else {
            Err(anyhow::anyhow!("Invalid MongoDB response"))
        }
    })
    .await?
}

/// Build a simple BSON document for MongoDB
fn bson_doc(fields: Vec<(&str, &str)>) -> Vec<u8> {
    let mut doc: Vec<u8> = Vec::new();
    doc.extend_from_slice(&[0u8; 4]); // Length placeholder

    for (key, value) in fields {
        doc.push(0x02); // String type
        doc.extend_from_slice(key.as_bytes());
        doc.push(0x00); // Null terminator
        let len = (value.len() + 1) as u32;
        doc.extend_from_slice(&len.to_le_bytes());
        doc.extend_from_slice(value.as_bytes());
        doc.push(0x00);
    }

    doc.push(0x00); // Document terminator

    // Fix length
    let len = doc.len() as u32;
    doc[0..4].copy_from_slice(&len.to_le_bytes());

    doc
}

/// Test phpMyAdmin credentials
async fn test_phpmyadmin(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> Result<bool> {
    let scheme = if use_ssl { "https" } else { "http" };
    let path = path.unwrap_or("/phpmyadmin/");
    let url = format!("{}://{}:{}{}", scheme, host, port, path);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()?;

    // First get the login page to extract token
    let login_page = client.get(&url).send().await?;
    let body = login_page.text().await?;

    // Extract token from form
    let token = extract_form_token(&body, "token");

    // Build login form
    let mut form = std::collections::HashMap::new();
    form.insert("pma_username".to_string(), credential.username.clone());
    form.insert("pma_password".to_string(), credential.password.clone());
    form.insert("server".to_string(), "1".to_string());
    if let Some(t) = token {
        form.insert("token".to_string(), t);
    }

    // Submit login
    let response = client
        .post(&url)
        .form(&form)
        .send()
        .await?;

    let response_body = response.text().await?;

    // Check for successful login indicators
    let success = !response_body.contains("Cannot log in to the MySQL server")
        && !response_body.contains("Access denied")
        && (response_body.contains("phpMyAdmin") || response_body.contains("db_structure"));

    Ok(success)
}

/// Test Joomla credentials
async fn test_joomla(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> Result<bool> {
    let scheme = if use_ssl { "https" } else { "http" };
    let path = path.unwrap_or("/administrator/");
    let url = format!("{}://{}:{}{}", scheme, host, port, path);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Get login page to extract token
    let login_page = client.get(&url).send().await?;
    let body = login_page.text().await?;

    // Extract Joomla token
    let token = extract_joomla_token(&body);

    // Build login form
    let mut form = std::collections::HashMap::new();
    form.insert("username".to_string(), credential.username.clone());
    form.insert("passwd".to_string(), credential.password.clone());
    form.insert("option".to_string(), "com_login".to_string());
    form.insert("task".to_string(), "login".to_string());
    if let Some(t) = token {
        form.insert(t, "1".to_string());
    }

    // Submit login
    let response = client
        .post(&url)
        .form(&form)
        .send()
        .await?;

    let response_body = response.text().await?;

    // Check for successful login
    let success = !response_body.contains("Username and password do not match")
        && !response_body.contains("Login denied")
        && (response_body.contains("Control Panel") || response_body.contains("com_cpanel"));

    Ok(success)
}

/// Extract Joomla CSRF token from HTML
fn extract_joomla_token(html: &str) -> Option<String> {
    // Joomla uses a random token name like "abc123def456"
    let re = regex::Regex::new(r#"<input type="hidden" name="([a-f0-9]{32})" value="1""#).ok()?;
    re.captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Test Drupal credentials
async fn test_drupal(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
    path: Option<&str>,
) -> Result<bool> {
    let scheme = if use_ssl { "https" } else { "http" };
    let path = path.unwrap_or("/user/login");
    let url = format!("{}://{}:{}{}", scheme, host, port, path);

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Get login page to extract form build ID
    let login_page = client.get(&url).send().await?;
    let body = login_page.text().await?;

    // Extract Drupal form tokens
    let form_build_id = extract_form_token(&body, "form_build_id");
    let form_token = extract_form_token(&body, "form_token");

    // Build login form
    let mut form = std::collections::HashMap::new();
    form.insert("name".to_string(), credential.username.clone());
    form.insert("pass".to_string(), credential.password.clone());
    form.insert("form_id".to_string(), "user_login_form".to_string());
    form.insert("op".to_string(), "Log in".to_string());
    if let Some(fbi) = form_build_id {
        form.insert("form_build_id".to_string(), fbi);
    }
    if let Some(ft) = form_token {
        form.insert("form_token".to_string(), ft);
    }

    // Submit login
    let response = client
        .post(&url)
        .form(&form)
        .send()
        .await?;

    let final_url = response.url().to_string();
    let response_body = response.text().await?;

    // Check for successful login
    let success = !response_body.contains("Unrecognized username or password")
        && !response_body.contains("Sorry, unrecognized username")
        && (final_url.contains("/user/") || response_body.contains("Log out"));

    Ok(success)
}

/// Extract form token from HTML
fn extract_form_token(html: &str, name: &str) -> Option<String> {
    let pattern = format!(r#"name="{}"\s+value="([^"]+)""#, name);
    regex::Regex::new(&pattern)
        .ok()?
        .captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Test RouterOS (MikroTik) credentials via API
async fn test_routeros(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // RouterOS API uses a word-based protocol
        // First, send /login command
        write_ros_word(&mut stream, "/login")?;
        write_ros_word(&mut stream, &format!("=name={}", username))?;
        write_ros_word(&mut stream, &format!("=password={}", password))?;
        write_ros_word(&mut stream, "")?; // Empty word to end sentence

        stream.flush()?;

        // Read response
        let mut response = Vec::new();
        loop {
            let word = read_ros_word(&mut stream)?;
            if word.is_empty() {
                break;
            }
            response.push(word);
        }

        // Check if login succeeded
        if response.iter().any(|w| w == "!done") {
            Ok(true)
        } else if response.iter().any(|w| w.starts_with("!trap")) {
            Ok(false) // Auth failed
        } else {
            Ok(false)
        }
    })
    .await?
}

/// Write a RouterOS API word
fn write_ros_word(stream: &mut TcpStream, word: &str) -> std::io::Result<()> {
    let len = word.len();
    if len < 0x80 {
        stream.write_all(&[len as u8])?;
    } else if len < 0x4000 {
        stream.write_all(&[((len >> 8) | 0x80) as u8, (len & 0xFF) as u8])?;
    } else if len < 0x200000 {
        stream.write_all(&[
            ((len >> 16) | 0xC0) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ])?;
    } else {
        stream.write_all(&[
            ((len >> 24) | 0xE0) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ])?;
    }
    stream.write_all(word.as_bytes())?;
    Ok(())
}

/// Read a RouterOS API word
fn read_ros_word(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut first = [0u8; 1];
    std::io::Read::read_exact(stream, &mut first)?;

    let len = if first[0] < 0x80 {
        first[0] as usize
    } else if first[0] < 0xC0 {
        let mut second = [0u8; 1];
        std::io::Read::read_exact(stream, &mut second)?;
        (((first[0] & 0x3F) as usize) << 8) | second[0] as usize
    } else if first[0] < 0xE0 {
        let mut rest = [0u8; 2];
        std::io::Read::read_exact(stream, &mut rest)?;
        (((first[0] & 0x1F) as usize) << 16) | ((rest[0] as usize) << 8) | rest[1] as usize
    } else {
        let mut rest = [0u8; 3];
        std::io::Read::read_exact(stream, &mut rest)?;
        (((first[0] & 0x0F) as usize) << 24)
            | ((rest[0] as usize) << 16)
            | ((rest[1] as usize) << 8)
            | rest[2] as usize
    };

    if len == 0 {
        return Ok(String::new());
    }

    let mut buf = vec![0u8; len];
    std::io::Read::read_exact(stream, &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// Test Cisco IOS credentials via Telnet
async fn test_cisco_ios(host: &str, port: u16, credential: &Credential, timeout: Duration) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let mut buffer = vec![0u8; 4096];
        let mut accumulated = String::new();

        // Read until we see a prompt
        for _ in 0..20 {
            match std::io::Read::read(&mut stream, &mut buffer) {
                Ok(n) if n > 0 => {
                    accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
                _ => break,
            }

            let lower = accumulated.to_lowercase();
            if lower.contains("username:") || lower.contains("login:") {
                break;
            }
            if lower.contains("password:") {
                // No username prompt, just password
                break;
            }
        }

        let lower = accumulated.to_lowercase();

        // Send username if prompted
        if lower.contains("username:") || lower.contains("login:") {
            stream.write_all(format!("{}\r\n", username).as_bytes())?;
            stream.flush()?;
            std::thread::sleep(Duration::from_millis(500));

            accumulated.clear();
            for _ in 0..10 {
                match std::io::Read::read(&mut stream, &mut buffer) {
                    Ok(n) if n > 0 => {
                        accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    }
                    _ => break,
                }
                if accumulated.to_lowercase().contains("password:") {
                    break;
                }
            }
        }

        // Send password
        if accumulated.to_lowercase().contains("password:") {
            stream.write_all(format!("{}\r\n", password).as_bytes())?;
            stream.flush()?;
            std::thread::sleep(Duration::from_millis(500));

            accumulated.clear();
            for _ in 0..10 {
                match std::io::Read::read(&mut stream, &mut buffer) {
                    Ok(n) if n > 0 => {
                        accumulated.push_str(&String::from_utf8_lossy(&buffer[..n]));
                    }
                    _ => break,
                }
            }

            // Check for successful login
            let lower = accumulated.to_lowercase();
            if lower.contains(">") || lower.contains("#") {
                // Got a prompt, likely logged in
                Ok(true)
            } else if lower.contains("% bad") || lower.contains("% login invalid") {
                Ok(false)
            } else {
                Ok(false)
            }
        } else {
            Err(anyhow::anyhow!("No password prompt received"))
        }
    })
    .await?
}

/// Test SMTP credentials (AUTH LOGIN or AUTH PLAIN)
async fn test_smtp(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    use_ssl: bool,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let read_stream = stream.try_clone()?;
        let mut write_stream = stream;
        let mut reader = BufReader::new(read_stream);

        // Read greeting
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if !response.starts_with("220") {
            return Err(anyhow::anyhow!("SMTP server not ready"));
        }

        // Send EHLO
        write_stream.write_all(b"EHLO localhost\r\n")?;
        write_stream.flush()?;

        // Read EHLO response (may be multi-line)
        let mut ehlo_response = String::new();
        loop {
            response.clear();
            reader.read_line(&mut response)?;
            ehlo_response.push_str(&response);
            if response.len() >= 4 && &response[3..4] == " " {
                break;
            }
        }

        // Check for STARTTLS if not already using SSL
        if !use_ssl && ehlo_response.contains("STARTTLS") {
            // Would need to upgrade connection - skip for basic testing
            debug!("SMTP server supports STARTTLS");
        }

        // Check for AUTH support
        if !ehlo_response.contains("AUTH") {
            return Err(anyhow::anyhow!("SMTP server does not support AUTH"));
        }

        // Try AUTH PLAIN (base64 encoded: \0username\0password)
        let auth_string = format!("\0{}\0{}", username, password);
        let auth_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth_string.as_bytes(),
        );

        write_stream.write_all(format!("AUTH PLAIN {}\r\n", auth_b64).as_bytes())?;
        write_stream.flush()?;

        response.clear();
        reader.read_line(&mut response)?;

        // 235 = auth successful, 535 = auth failed
        if response.starts_with("235") {
            // Send QUIT
            let _ = write_stream.write_all(b"QUIT\r\n");
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?
}

/// Test POP3 credentials
async fn test_pop3(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    _use_ssl: bool,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let read_stream = stream.try_clone()?;
        let mut write_stream = stream;
        let mut reader = BufReader::new(read_stream);

        // Read greeting
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if !response.starts_with("+OK") {
            return Err(anyhow::anyhow!("POP3 server not ready"));
        }

        // Send USER command
        write_stream.write_all(format!("USER {}\r\n", username).as_bytes())?;
        write_stream.flush()?;

        response.clear();
        reader.read_line(&mut response)?;
        if !response.starts_with("+OK") {
            return Ok(false); // User rejected
        }

        // Send PASS command
        write_stream.write_all(format!("PASS {}\r\n", password).as_bytes())?;
        write_stream.flush()?;

        response.clear();
        reader.read_line(&mut response)?;

        if response.starts_with("+OK") {
            // Send QUIT
            let _ = write_stream.write_all(b"QUIT\r\n");
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?
}

/// Test IMAP credentials
async fn test_imap(
    host: &str,
    port: u16,
    credential: &Credential,
    timeout: Duration,
    _use_ssl: bool,
) -> Result<bool> {
    let host = host.to_string();
    let username = credential.username.clone();
    let password = credential.password.clone();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", host, port);

        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let read_stream = stream.try_clone()?;
        let mut write_stream = stream;
        let mut reader = BufReader::new(read_stream);

        // Read greeting
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if !response.starts_with("* OK") {
            return Err(anyhow::anyhow!("IMAP server not ready"));
        }

        // Send LOGIN command
        let login_cmd = format!("A001 LOGIN \"{}\" \"{}\"\r\n", username, password);
        write_stream.write_all(login_cmd.as_bytes())?;
        write_stream.flush()?;

        // Read response (may be multiline, look for "A001")
        loop {
            response.clear();
            reader.read_line(&mut response)?;
            if response.starts_with("A001") {
                break;
            }
        }

        if response.contains("OK") {
            // Send LOGOUT
            let _ = write_stream.write_all(b"A002 LOGOUT\r\n");
            Ok(true)
        } else {
            Ok(false)
        }
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let hash1 = hash_password("password123");
        let hash2 = hash_password("password123");
        assert_eq!(hash1, hash2);

        let hash3 = hash_password("different");
        assert_ne!(hash1, hash3);

        // Should be SHA256 hex (64 chars)
        assert_eq!(hash1.len(), 64);
    }
}
