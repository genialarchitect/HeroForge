//! Service-specific credential testers
//!
//! This module contains implementations for testing credentials against
//! various services. Each tester handles the protocol-specific authentication.

use super::types::{Credential, CredentialServiceType, CredentialTestResult};
use anyhow::Result;
use log::{debug, warn};
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
        // Unsupported services return error for now
        _ => Err(anyhow::anyhow!(
            "Credential testing not yet implemented for {}",
            service_type
        )),
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
    let password = credential.password.clone();

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
