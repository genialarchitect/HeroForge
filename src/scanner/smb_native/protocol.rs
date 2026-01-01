//! SMB Protocol Handler
//!
//! Manages SMB2/3 connections, authentication, and session state.

use super::ntlm_auth::{NtlmContext, NtlmCredentials};
use super::smb2::*;
use super::types::*;
use log::{debug, trace, warn};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default SMB port
pub const SMB_PORT: u16 = 445;

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read/write timeout
const IO_TIMEOUT: Duration = Duration::from_secs(30);

// Internal: send raw data
async fn send_raw(stream: &mut TcpStream, data: &[u8]) -> SmbResult<()> {
    timeout(IO_TIMEOUT, stream.write_all(data))
        .await
        .map_err(|_| SmbError::Timeout)?
        .map_err(SmbError::Io)?;

    timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| SmbError::Timeout)?
        .map_err(SmbError::Io)?;

    Ok(())
}

// Internal: receive raw data (NetBIOS framed)
async fn recv_raw(stream: &mut TcpStream) -> SmbResult<Vec<u8>> {
    // Read NetBIOS header (4 bytes)
    let mut header = [0u8; 4];
    timeout(IO_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| SmbError::Timeout)?
        .map_err(SmbError::Io)?;

    // Parse length (24-bit big-endian)
    let length =
        ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);

    if length > 16 * 1024 * 1024 {
        // 16MB max
        return Err(SmbError::Protocol(format!(
            "Response too large: {} bytes",
            length
        )));
    }

    // Read payload
    let mut payload = vec![0u8; length];
    timeout(IO_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| SmbError::Timeout)?
        .map_err(SmbError::Io)?;

    Ok(payload)
}

/// SMB client connection
pub struct SmbConnection {
    stream: Option<TcpStream>,
    state: SmbConnectionState,
    host: String,
    port: u16,
}

impl SmbConnection {
    /// Create a new SMB connection (not yet connected)
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            stream: None,
            state: SmbConnectionState::default(),
            host: host.to_string(),
            port,
        }
    }

    /// Connect to SMB server
    pub async fn connect(&mut self) -> SmbResult<()> {
        let addr = format!("{}:{}", self.host, self.port);
        debug!("Connecting to SMB server at {}", addr);

        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| SmbError::Timeout)?
            .map_err(|e| SmbError::Connection(e.to_string()))?;

        stream.set_nodelay(true).ok();
        self.stream = Some(stream);

        Ok(())
    }

    /// Negotiate SMB protocol version
    pub async fn negotiate(&mut self) -> SmbResult<Smb2NegotiateResponse> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let negotiate = Smb2NegotiateRequest::default();
        let msg_id = self.state.next_message_id();
        let request = negotiate.serialize(msg_id);
        let packet = wrap_netbios(&request);

        trace!("Sending NEGOTIATE request");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        // Parse header first to check status
        let header = Smb2Header::parse(smb_data)?;
        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2NegotiateResponse::parse(smb_data)?;

        debug!(
            "Negotiated dialect: {}, server GUID: {:02x?}",
            response.dialect, response.server_guid
        );

        // Update state
        self.state.dialect = Some(response.dialect);
        self.state.server_guid = response.server_guid;
        self.state.max_read_size = response.max_read_size;
        self.state.max_write_size = response.max_write_size;
        self.state.max_transact_size = response.max_transact_size;
        self.state.signing_required = (response.security_mode & 0x02) != 0;
        self.state.encryption_supported =
            (response.capabilities & smb2_capabilities::ENCRYPTION) != 0;

        Ok(response)
    }

    /// Authenticate with NTLM
    pub async fn authenticate(&mut self, credentials: &NtlmCredentials) -> SmbResult<()> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let mut ntlm = NtlmContext::new(credentials.clone());

        // Step 1: Send NTLM Type 1 (Negotiate) in SESSION_SETUP
        let negotiate_token = ntlm.create_negotiate_message();
        let msg_id = self.state.next_message_id();
        let request = Smb2SessionSetupRequest::new(negotiate_token);
        let packet = wrap_netbios(&request.serialize(msg_id, 0));

        trace!("Sending SESSION_SETUP with NTLM Type 1");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        // Should get STATUS_MORE_PROCESSING_REQUIRED
        if header.status != NtStatus::MORE_PROCESSING_REQUIRED {
            if header.status.is_error() {
                return Err(SmbError::from(header.status));
            }
        }

        let session_response = Smb2SessionSetupResponse::parse(smb_data)?;
        let session_id = header.session_id;

        // Parse NTLM Type 2 (Challenge)
        let challenge = ntlm.parse_challenge_message(&session_response.security_buffer)?;
        debug!("Received NTLM challenge from: {}", challenge.target_name);

        // Step 2: Send NTLM Type 3 (Authenticate) in second SESSION_SETUP
        let auth_token = ntlm.create_authenticate_message(&challenge)?;
        let msg_id = self.state.next_message_id();
        let request = Smb2SessionSetupRequest::new(auth_token);
        let packet = wrap_netbios(&request.serialize(msg_id, session_id));

        trace!("Sending SESSION_SETUP with NTLM Type 3");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        self.state.session_id = header.session_id;
        debug!(
            "Authentication successful, session ID: 0x{:016x}",
            self.state.session_id
        );

        Ok(())
    }

    /// Connect to a share
    pub async fn tree_connect(&mut self, share: &str) -> SmbResult<Smb2TreeConnectResponse> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        // Build UNC path
        let path = if share.starts_with("\\\\") {
            share.to_string()
        } else {
            format!("\\\\{}\\{}", self.host, share)
        };

        let msg_id = self.state.next_message_id();
        let request = Smb2TreeConnectRequest::new(&path);
        let packet = wrap_netbios(&request.serialize(msg_id, self.state.session_id));

        trace!("Sending TREE_CONNECT to {}", path);
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2TreeConnectResponse::parse(smb_data)?;
        self.state.tree_id = header.tree_id;

        debug!(
            "Connected to share: {}, type: {}, tree ID: 0x{:08x}",
            share, response.share_type, self.state.tree_id
        );

        Ok(response)
    }

    /// Disconnect from current tree
    pub async fn tree_disconnect(&mut self) -> SmbResult<()> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let packet = wrap_netbios(&Smb2TreeDisconnectRequest::serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Sending TREE_DISCONNECT");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            warn!("Tree disconnect returned status: {}", header.status);
        }

        self.state.tree_id = 0;
        Ok(())
    }

    /// Open a named pipe
    pub async fn open_pipe(&mut self, pipe_name: &str) -> SmbResult<[u8; 16]> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let request = Smb2CreateRequest::open_pipe(pipe_name);
        let packet = wrap_netbios(&request.serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Opening named pipe: {}", pipe_name);
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2CreateResponse::parse(smb_data)?;
        debug!("Opened pipe {}, file ID: {:02x?}", pipe_name, response.file_id);

        Ok(response.file_id)
    }

    /// Close a file handle
    pub async fn close(&mut self, file_id: [u8; 16]) -> SmbResult<()> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let request = Smb2CloseRequest::new(file_id);
        let packet = wrap_netbios(&request.serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Closing file handle");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            warn!("Close returned status: {}", header.status);
        }

        Ok(())
    }

    /// Perform IOCTL (used for DCE/RPC transact)
    pub async fn ioctl(
        &mut self,
        ctl_code: u32,
        file_id: [u8; 16],
        input: &[u8],
    ) -> SmbResult<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let request = Smb2IoctlRequest::new(ctl_code, file_id, input.to_vec());
        let packet = wrap_netbios(&request.serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Sending IOCTL 0x{:08x}", ctl_code);
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2IoctlResponse::parse(smb_data)?;
        Ok(response.output_data)
    }

    /// Read from file/pipe
    pub async fn read(
        &mut self,
        file_id: [u8; 16],
        offset: u64,
        length: u32,
    ) -> SmbResult<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let request = Smb2ReadRequest::new(file_id, offset, length);
        let packet = wrap_netbios(&request.serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Reading {} bytes at offset {}", length, offset);
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2ReadResponse::parse(smb_data)?;
        Ok(response.data)
    }

    /// Write to file/pipe
    pub async fn write(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> SmbResult<u32> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let request = Smb2WriteRequest::new(file_id, offset, data.to_vec());
        let packet = wrap_netbios(&request.serialize(
            msg_id,
            self.state.session_id,
            self.state.tree_id,
        ));

        trace!("Writing {} bytes at offset {}", data.len(), offset);
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            return Err(SmbError::from(header.status));
        }

        let response = Smb2WriteResponse::parse(smb_data)?;
        Ok(response.count)
    }

    /// Log off from session
    pub async fn logoff(&mut self) -> SmbResult<()> {
        let stream = self.stream.as_mut().ok_or(SmbError::NotConnected)?;

        let msg_id = self.state.next_message_id();
        let packet = wrap_netbios(&Smb2LogoffRequest::serialize(msg_id, self.state.session_id));

        trace!("Sending LOGOFF");
        send_raw(stream, &packet).await?;

        let response_data = recv_raw(stream).await?;
        let smb_data = unwrap_netbios(&response_data)?;

        let header = Smb2Header::parse(smb_data)?;

        if header.status.is_error() {
            warn!("Logoff returned status: {}", header.status);
        }

        self.state.session_id = 0;
        Ok(())
    }

    /// Disconnect from server
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }
        self.state = SmbConnectionState::default();
    }

    /// Get current connection state
    pub fn state(&self) -> &SmbConnectionState {
        &self.state
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.state.session_id != 0
    }

    /// Get negotiated dialect
    pub fn dialect(&self) -> Option<SmbDialect> {
        self.state.dialect
    }
}

impl Drop for SmbConnection {
    fn drop(&mut self) {
        // Connection cleanup happens automatically when stream is dropped
    }
}

/// High-level SMB client with automatic connection management
pub struct SmbClient {
    connection: SmbConnection,
    credentials: Option<NtlmCredentials>,
}

impl SmbClient {
    /// Create a new SMB client
    pub fn new(host: &str) -> Self {
        Self {
            connection: SmbConnection::new(host, SMB_PORT),
            credentials: None,
        }
    }

    /// Create client with custom port
    pub fn with_port(host: &str, port: u16) -> Self {
        Self {
            connection: SmbConnection::new(host, port),
            credentials: None,
        }
    }

    /// Set credentials for authentication
    pub fn with_credentials(mut self, domain: &str, username: &str, password: &str) -> Self {
        self.credentials = Some(NtlmCredentials::new(domain, username, password));
        self
    }

    /// Connect and authenticate
    pub async fn connect(&mut self) -> SmbResult<()> {
        self.connection.connect().await?;
        self.connection.negotiate().await?;

        if let Some(creds) = &self.credentials {
            self.connection.authenticate(creds).await?;
        }

        Ok(())
    }

    /// Connect to a share
    pub async fn connect_share(&mut self, share: &str) -> SmbResult<ShareType> {
        let response = self.connection.tree_connect(share).await?;
        Ok(response.share_type)
    }

    /// Disconnect from current share
    pub async fn disconnect_share(&mut self) -> SmbResult<()> {
        self.connection.tree_disconnect().await
    }

    /// Get underlying connection for advanced operations
    pub fn connection(&mut self) -> &mut SmbConnection {
        &mut self.connection
    }

    /// Disconnect completely
    pub async fn disconnect(&mut self) {
        if self.connection.is_authenticated() {
            let _ = self.connection.logoff().await;
        }
        self.connection.disconnect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_default() {
        let state = SmbConnectionState::default();
        assert_eq!(state.session_id, 0);
        assert_eq!(state.tree_id, 0);
        assert_eq!(state.message_id, 0);
        assert!(state.dialect.is_none());
    }

    #[test]
    fn test_message_id_increment() {
        let mut state = SmbConnectionState::default();
        assert_eq!(state.next_message_id(), 0);
        assert_eq!(state.next_message_id(), 1);
        assert_eq!(state.next_message_id(), 2);
    }
}
