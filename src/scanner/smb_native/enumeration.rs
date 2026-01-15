//! High-Level SMB Enumeration Functions
//!
//! Provides user-friendly interfaces for SMB enumeration operations.

use super::protocol::SmbClient;
use super::rpc::{samr::*, srvsvc::*, types::*};
use super::smb2::ioctl_codes;
use super::types::*;
use log::{debug, info};
use std::cell::Cell;

/// SMB enumeration client
pub struct SmbEnumerator {
    client: SmbClient,
    call_id: Cell<u32>,
}

impl SmbEnumerator {
    /// Create a new SMB enumerator
    pub fn new(host: &str) -> Self {
        Self {
            client: SmbClient::new(host),
            call_id: Cell::new(1),
        }
    }

    /// Create with credentials
    pub fn with_credentials(host: &str, domain: &str, username: &str, password: &str) -> Self {
        Self {
            client: SmbClient::new(host).with_credentials(domain, username, password),
            call_id: Cell::new(1),
        }
    }

    /// Connect to the server
    pub async fn connect(&mut self) -> SmbResult<()> {
        self.client.connect().await
    }

    /// Get next call ID (interior mutability via Cell)
    fn next_call_id(&self) -> u32 {
        let id = self.call_id.get();
        self.call_id.set(id + 1);
        id
    }

    /// Enumerate shares via SRVSVC
    pub async fn enumerate_shares(&mut self) -> SmbResult<Vec<SmbShare>> {
        info!("Enumerating shares via SRVSVC");

        // Pre-allocate call IDs before borrowing connection
        let bind_call_id = self.next_call_id();
        let enum_call_id = self.next_call_id();

        // Connect to IPC$ share
        self.client.connect_share("IPC$").await?;

        let conn = self.client.connection();

        // Open srvsvc pipe
        let file_id = conn.open_pipe("srvsvc").await?;

        // Bind to SRVSVC
        let bind = create_srvsvc_bind(bind_call_id);
        let bind_response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &bind)
            .await?;

        let bind_ack = RpcBindAck::parse(&bind_response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse bind ack".to_string()))?;

        if !bind_ack.is_accepted() {
            return Err(SmbError::Protocol("SRVSVC bind rejected".to_string()));
        }

        debug!("SRVSVC bind successful");

        // Enumerate shares
        let server_name = conn.state().server_guid.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let request = create_share_enum_request(&server_name, enum_call_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &request)
            .await?;

        // Parse RPC response
        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse RPC response".to_string()))?;

        let shares = parse_share_enum_response(&rpc_response.stub_data)?;

        info!("Found {} shares", shares.len());

        // Cleanup
        conn.close(file_id).await.ok();
        let _ = &conn; // Release borrow
        self.client.disconnect_share().await.ok();

        Ok(shares)
    }

    /// Get server information
    pub async fn get_server_info(&mut self) -> SmbResult<ServerInfo> {
        info!("Getting server information via SRVSVC");

        // Pre-allocate call IDs
        let bind_call_id = self.next_call_id();
        let info_call_id = self.next_call_id();

        self.client.connect_share("IPC$").await?;
        let conn = self.client.connection();

        let file_id = conn.open_pipe("srvsvc").await?;

        // Bind
        let bind = create_srvsvc_bind(bind_call_id);
        let bind_response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &bind)
            .await?;

        let bind_ack = RpcBindAck::parse(&bind_response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse bind ack".to_string()))?;

        if !bind_ack.is_accepted() {
            return Err(SmbError::Protocol("SRVSVC bind rejected".to_string()));
        }

        // Get server info (level 101)
        let request = create_server_get_info_request("", 101, info_call_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &request)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse RPC response".to_string()))?;

        let server_info = parse_server_get_info_response(&rpc_response.stub_data)?;

        conn.close(file_id).await.ok();
        let _ = &conn;
        self.client.disconnect_share().await.ok();

        Ok(server_info)
    }

    /// Enumerate sessions
    pub async fn enumerate_sessions(&mut self) -> SmbResult<Vec<SessionInfo>> {
        info!("Enumerating sessions via SRVSVC");

        // Pre-allocate call IDs
        let bind_call_id = self.next_call_id();
        let enum_call_id = self.next_call_id();

        self.client.connect_share("IPC$").await?;
        let conn = self.client.connection();

        let file_id = conn.open_pipe("srvsvc").await?;

        // Bind
        let bind = create_srvsvc_bind(bind_call_id);
        let bind_response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &bind)
            .await?;

        let bind_ack = RpcBindAck::parse(&bind_response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse bind ack".to_string()))?;

        if !bind_ack.is_accepted() {
            return Err(SmbError::Protocol("SRVSVC bind rejected".to_string()));
        }

        let request = create_session_enum_request("", enum_call_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &request)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse RPC response".to_string()))?;

        let sessions = parse_session_enum_response(&rpc_response.stub_data)?;

        conn.close(file_id).await.ok();
        let _ = &conn;
        self.client.disconnect_share().await.ok();

        Ok(sessions)
    }

    /// Enumerate users via SAMR
    pub async fn enumerate_users(&mut self) -> SmbResult<Vec<SamrUserEntry>> {
        info!("Enumerating users via SAMR");

        // Pre-allocate all call IDs (8 operations)
        let bind_id = self.next_call_id();
        let connect_id = self.next_call_id();
        let enum_domains_id = self.next_call_id();
        let lookup_domain_id = self.next_call_id();
        let open_domain_id = self.next_call_id();
        let enum_users_id = self.next_call_id();
        let close_domain_id = self.next_call_id();
        let close_server_id = self.next_call_id();

        self.client.connect_share("IPC$").await?;
        let conn = self.client.connection();

        let file_id = conn.open_pipe("samr").await?;

        // Bind to SAMR
        let bind = create_samr_bind(bind_id);
        let bind_response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &bind)
            .await?;

        let bind_ack = RpcBindAck::parse(&bind_response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse bind ack".to_string()))?;

        if !bind_ack.is_accepted() {
            return Err(SmbError::Protocol("SAMR bind rejected".to_string()));
        }

        debug!("SAMR bind successful");

        // Connect to SAM server
        let connect_req = create_samr_connect(
            "",
            samr_access::SAM_SERVER_ENUMERATE_DOMAINS | samr_access::SAM_SERVER_LOOKUP_DOMAIN,
            connect_id,
        );

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &connect_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse connect response".to_string()))?;

        let server_handle = parse_samr_connect_response(&rpc_response.stub_data)?;
        debug!("Got SAM server handle");

        // Enumerate domains
        let enum_domains_req = create_enumerate_domains(&server_handle, enum_domains_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &enum_domains_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse enum domains response".to_string()))?;

        let domains = parse_enumerate_domains_response(&rpc_response.stub_data)?;
        debug!("Found {} domains", domains.len());

        // Find non-Builtin domain
        let target_domain = domains
            .iter()
            .find(|d| d.name.to_uppercase() != "BUILTIN")
            .or_else(|| domains.first());

        let target_domain = match target_domain {
            Some(d) => d,
            None => {
                conn.close(file_id).await.ok();
                let _ = &conn;
                self.client.disconnect_share().await.ok();
                return Ok(Vec::new());
            }
        };

        debug!("Using domain: {}", target_domain.name);

        // Lookup domain SID
        let lookup_req = create_lookup_domain(&server_handle, &target_domain.name, lookup_domain_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &lookup_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse lookup domain response".to_string()))?;

        let domain_sid = parse_lookup_domain_response(&rpc_response.stub_data)?;
        debug!("Got domain SID ({} bytes)", domain_sid.len());

        // Open domain
        let open_domain_req = create_open_domain(
            &server_handle,
            &domain_sid,
            samr_access::DOMAIN_LIST_ACCOUNTS | samr_access::DOMAIN_LOOKUP,
            open_domain_id,
        );

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &open_domain_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse open domain response".to_string()))?;

        let domain_handle = parse_open_domain_response(&rpc_response.stub_data)?;
        debug!("Got domain handle");

        // Enumerate users
        let enum_users_req = create_enumerate_users(
            &domain_handle,
            0, // All users
            enum_users_id,
        );

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &enum_users_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse enum users response".to_string()))?;

        let users = parse_enumerate_users_response(&rpc_response.stub_data)?;
        info!("Found {} users", users.len());

        // Cleanup handles
        let close_req = create_close_handle(&domain_handle, close_domain_id);
        conn.ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &close_req)
            .await
            .ok();

        let close_req = create_close_handle(&server_handle, close_server_id);
        conn.ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &close_req)
            .await
            .ok();

        conn.close(file_id).await.ok();
        let _ = &conn;
        self.client.disconnect_share().await.ok();

        Ok(users)
    }

    /// Enumerate groups via SAMR
    pub async fn enumerate_groups(&mut self) -> SmbResult<Vec<SamrGroupEntry>> {
        info!("Enumerating groups via SAMR");

        // Pre-allocate all call IDs (8 operations)
        let bind_id = self.next_call_id();
        let connect_id = self.next_call_id();
        let enum_domains_id = self.next_call_id();
        let lookup_domain_id = self.next_call_id();
        let open_domain_id = self.next_call_id();
        let enum_groups_id = self.next_call_id();
        let close_domain_id = self.next_call_id();
        let close_server_id = self.next_call_id();

        self.client.connect_share("IPC$").await?;
        let conn = self.client.connection();

        let file_id = conn.open_pipe("samr").await?;

        // Bind to SAMR
        let bind = create_samr_bind(bind_id);
        let bind_response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &bind)
            .await?;

        let bind_ack = RpcBindAck::parse(&bind_response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse bind ack".to_string()))?;

        if !bind_ack.is_accepted() {
            return Err(SmbError::Protocol("SAMR bind rejected".to_string()));
        }

        // Connect
        let connect_req = create_samr_connect(
            "",
            samr_access::SAM_SERVER_ENUMERATE_DOMAINS | samr_access::SAM_SERVER_LOOKUP_DOMAIN,
            connect_id,
        );

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &connect_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse connect response".to_string()))?;

        let server_handle = parse_samr_connect_response(&rpc_response.stub_data)?;

        // Enumerate domains
        let enum_domains_req = create_enumerate_domains(&server_handle, enum_domains_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &enum_domains_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse enum domains response".to_string()))?;

        let domains = parse_enumerate_domains_response(&rpc_response.stub_data)?;

        let target_domain = domains
            .iter()
            .find(|d| d.name.to_uppercase() != "BUILTIN")
            .or_else(|| domains.first());

        let target_domain = match target_domain {
            Some(d) => d,
            None => {
                conn.close(file_id).await.ok();
                let _ = &conn;
                self.client.disconnect_share().await.ok();
                return Ok(Vec::new());
            }
        };

        // Lookup domain SID
        let lookup_req = create_lookup_domain(&server_handle, &target_domain.name, lookup_domain_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &lookup_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse lookup domain response".to_string()))?;

        let domain_sid = parse_lookup_domain_response(&rpc_response.stub_data)?;

        // Open domain
        let open_domain_req = create_open_domain(
            &server_handle,
            &domain_sid,
            samr_access::DOMAIN_LIST_ACCOUNTS,
            open_domain_id,
        );

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &open_domain_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse open domain response".to_string()))?;

        let domain_handle = parse_open_domain_response(&rpc_response.stub_data)?;

        // Enumerate groups
        let enum_groups_req = create_enumerate_groups(&domain_handle, enum_groups_id);

        let response = conn
            .ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &enum_groups_req)
            .await?;

        let rpc_response = RpcResponse::parse(&response)
            .ok_or_else(|| SmbError::Protocol("Failed to parse enum groups response".to_string()))?;

        let groups = parse_enumerate_groups_response(&rpc_response.stub_data)?;
        info!("Found {} groups", groups.len());

        // Cleanup
        let close_req = create_close_handle(&domain_handle, close_domain_id);
        conn.ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &close_req)
            .await
            .ok();

        let close_req = create_close_handle(&server_handle, close_server_id);
        conn.ioctl(ioctl_codes::FSCTL_PIPE_TRANSCEIVE, file_id, &close_req)
            .await
            .ok();

        conn.close(file_id).await.ok();
        let _ = &conn;
        self.client.disconnect_share().await.ok();

        Ok(groups)
    }

    /// Disconnect from server
    pub async fn disconnect(&mut self) {
        self.client.disconnect().await;
    }
}

/// Convenience function to enumerate shares
pub async fn enumerate_shares(
    host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> SmbResult<Vec<SmbShare>> {
    let mut enumerator = SmbEnumerator::with_credentials(host, domain, username, password);
    enumerator.connect().await?;
    let shares = enumerator.enumerate_shares().await?;
    enumerator.disconnect().await;
    Ok(shares)
}

/// Convenience function to enumerate users
pub async fn enumerate_users(
    host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> SmbResult<Vec<SamrUserEntry>> {
    let mut enumerator = SmbEnumerator::with_credentials(host, domain, username, password);
    enumerator.connect().await?;
    let users = enumerator.enumerate_users().await?;
    enumerator.disconnect().await;
    Ok(users)
}

/// Convenience function to enumerate groups
pub async fn enumerate_groups(
    host: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> SmbResult<Vec<SamrGroupEntry>> {
    let mut enumerator = SmbEnumerator::with_credentials(host, domain, username, password);
    enumerator.connect().await?;
    let groups = enumerator.enumerate_groups().await?;
    enumerator.disconnect().await;
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerator_creation() {
        let enumerator = SmbEnumerator::new("192.168.1.1");
        assert_eq!(enumerator.call_id.get(), 1);
    }

    #[test]
    fn test_enumerator_with_credentials() {
        let enumerator =
            SmbEnumerator::with_credentials("192.168.1.1", "DOMAIN", "user", "password");
        assert_eq!(enumerator.call_id.get(), 1);
    }
}
