//! C2 Framework Manager
//!
//! Unified interface for managing multiple C2 frameworks and their sessions.

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::cobaltstrike::CobaltStrikeClient;
use super::sliver::SliverClient;
use super::havoc::HavocClient;
use super::mythic::MythicClient;
use super::custom::CustomC2Client;
use super::types::*;

/// C2 client trait for framework implementations
#[async_trait::async_trait]
pub trait C2Client: Send + Sync {
    async fn test_connection(&self) -> Result<bool>;
    async fn is_connected(&self) -> bool;
    async fn list_sessions(&self) -> Result<Vec<Session>>;
    async fn list_listeners(&self) -> Result<Vec<Listener>>;
    async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener>;
    async fn stop_listener(&self, listener_id: &str) -> Result<()>;
    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>>;
    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task>;
    async fn kill_session(&self, session_id: &str) -> Result<()>;
}

/// Manager for C2 framework integrations
pub struct C2Manager {
    pool: SqlitePool,
    clients: Arc<RwLock<HashMap<String, Arc<dyn C2Client>>>>,
}

impl C2Manager {
    /// Create a new C2 manager
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Connect to a C2 server
    pub async fn connect(&self, config_id: &str) -> Result<bool> {
        let config = self.get_config(config_id).await?
            .ok_or_else(|| anyhow!("C2 config not found"))?;

        let client: Arc<dyn C2Client> = match config.framework {
            C2Framework::CobaltStrike => {
                let cs = CobaltStrikeClient::new(config.clone())?;
                Arc::new(CobaltStrikeClientWrapper(cs))
            }
            C2Framework::Sliver => {
                let sliver = SliverClient::new(config.clone())?;
                Arc::new(SliverClientWrapper(sliver))
            }
            C2Framework::Havoc => {
                let havoc = HavocClient::new(config.clone())?;
                Arc::new(HavocClientWrapper(havoc))
            }
            C2Framework::Mythic => {
                let mythic = MythicClient::new(config.clone())?;
                Arc::new(MythicClientWrapper(mythic))
            }
            C2Framework::Custom => {
                let custom = CustomC2Client::new(config.clone())?;
                Arc::new(CustomC2ClientWrapper(custom))
            }
        };

        let connected = client.test_connection().await?;

        if connected {
            // Store the client
            self.clients.write().await.insert(config_id.to_string(), client);

            // Update connection status in database
            sqlx::query(
                "UPDATE c2_configs SET connected = true, last_connected = ? WHERE id = ?"
            )
            .bind(Utc::now().to_rfc3339())
            .bind(config_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(connected)
    }

    /// Disconnect from a C2 server
    pub async fn disconnect(&self, config_id: &str) -> Result<()> {
        self.clients.write().await.remove(config_id);

        sqlx::query("UPDATE c2_configs SET connected = false WHERE id = ?")
            .bind(config_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get a connected client
    pub async fn get_client(&self, config_id: &str) -> Option<Arc<dyn C2Client>> {
        self.clients.read().await.get(config_id).cloned()
    }

    /// Create a new C2 configuration
    pub async fn create_config(&self, user_id: &str, req: CreateC2ConfigRequest) -> Result<C2Config> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let config = C2Config {
            id: id.clone(),
            name: req.name,
            framework: req.framework,
            host: req.host,
            port: req.port,
            api_token: req.api_token,
            mtls_cert: req.mtls_cert,
            mtls_key: req.mtls_key,
            ca_cert: req.ca_cert,
            verify_ssl: req.verify_ssl.unwrap_or(true),
            user_id: user_id.to_string(),
            connected: false,
            last_connected: None,
            created_at: now,
            updated_at: now,
        };

        sqlx::query(
            r#"
            INSERT INTO c2_configs (
                id, name, framework, host, port, api_token,
                mtls_cert, mtls_key, ca_cert, verify_ssl,
                user_id, connected, last_connected, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&config.id)
        .bind(&config.name)
        .bind(config.framework.to_string())
        .bind(&config.host)
        .bind(config.port as i32)
        .bind(&config.api_token)
        .bind(&config.mtls_cert)
        .bind(&config.mtls_key)
        .bind(&config.ca_cert)
        .bind(config.verify_ssl)
        .bind(&config.user_id)
        .bind(config.connected)
        .bind(config.last_connected.map(|dt| dt.to_rfc3339()))
        .bind(config.created_at.to_rfc3339())
        .bind(config.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(config)
    }

    /// Get a C2 configuration by ID
    pub async fn get_config(&self, config_id: &str) -> Result<Option<C2Config>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, i32, Option<String>,
            Option<String>, Option<String>, Option<String>, bool,
            String, bool, Option<String>, String, String,
        )>(
            r#"
            SELECT id, name, framework, host, port, api_token,
                   mtls_cert, mtls_key, ca_cert, verify_ssl,
                   user_id, connected, last_connected, created_at, updated_at
            FROM c2_configs WHERE id = ?
            "#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| C2Config {
            id: r.0,
            name: r.1,
            framework: r.2.parse().unwrap_or(C2Framework::Custom),
            host: r.3,
            port: r.4 as u16,
            api_token: r.5,
            mtls_cert: r.6,
            mtls_key: r.7,
            ca_cert: r.8,
            verify_ssl: r.9,
            user_id: r.10,
            connected: r.11,
            last_connected: r.12.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.13).unwrap().with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
        }))
    }

    /// List C2 configurations for a user
    pub async fn list_configs(&self, user_id: &str) -> Result<Vec<C2Summary>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, String, i32, bool, Option<String>,
        )>(
            r#"
            SELECT id, name, framework, host, port, connected, last_connected
            FROM c2_configs WHERE user_id = ?
            ORDER BY created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut summaries = Vec::new();
        for r in rows {
            // Count listeners and sessions for this config
            let listener_count: (i32,) = sqlx::query_as(
                "SELECT COUNT(*) FROM c2_listeners WHERE c2_config_id = ?"
            )
            .bind(&r.0)
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0,));

            let session_count: (i32,) = sqlx::query_as(
                "SELECT COUNT(*) FROM c2_sessions WHERE c2_config_id = ? AND status = 'active'"
            )
            .bind(&r.0)
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0,));

            summaries.push(C2Summary {
                id: r.0,
                name: r.1,
                framework: r.2.parse().unwrap_or(C2Framework::Custom),
                host: r.3,
                port: r.4 as u16,
                connected: r.5,
                listener_count: listener_count.0 as u32,
                session_count: session_count.0 as u32,
                last_connected: r.6.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
            });
        }

        Ok(summaries)
    }

    /// Delete a C2 configuration
    pub async fn delete_config(&self, config_id: &str) -> Result<()> {
        // Disconnect first
        self.disconnect(config_id).await?;

        // Delete from database
        sqlx::query("DELETE FROM c2_configs WHERE id = ?")
            .bind(config_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Sync sessions from C2 framework
    pub async fn sync_sessions(&self, config_id: &str) -> Result<Vec<Session>> {
        let client = self.get_client(config_id).await
            .ok_or_else(|| anyhow!("Not connected to C2 server"))?;

        let sessions = client.list_sessions().await?;

        // Update local database
        for session in &sessions {
            self.save_session(session).await?;
        }

        Ok(sessions)
    }

    /// Save a session to the database
    async fn save_session(&self, session: &Session) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO c2_sessions (
                id, c2_config_id, c2_session_id, implant_id, name,
                hostname, username, domain, ip_address, external_ip,
                os, os_version, arch, pid, process_name, integrity,
                status, is_elevated, locale, first_seen, last_checkin,
                next_checkin, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&session.id)
        .bind(&session.c2_config_id)
        .bind(&session.c2_session_id)
        .bind(&session.implant_id)
        .bind(&session.name)
        .bind(&session.hostname)
        .bind(&session.username)
        .bind(&session.domain)
        .bind(&session.ip_address)
        .bind(&session.external_ip)
        .bind(&session.os)
        .bind(&session.os_version)
        .bind(session.arch.to_string())
        .bind(session.pid as i32)
        .bind(&session.process_name)
        .bind(&session.integrity)
        .bind(session.status.to_string())
        .bind(session.is_elevated)
        .bind(&session.locale)
        .bind(session.first_seen.to_rfc3339())
        .bind(session.last_checkin.to_rfc3339())
        .bind(session.next_checkin.map(|dt| dt.to_rfc3339()))
        .bind(&session.notes)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get dashboard statistics
    pub async fn get_dashboard_stats(&self, user_id: &str) -> Result<C2DashboardStats> {
        let total_servers: (i32,) = sqlx::query_as(
            "SELECT COUNT(*) FROM c2_configs WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let connected_servers: (i32,) = sqlx::query_as(
            "SELECT COUNT(*) FROM c2_configs WHERE user_id = ? AND connected = true"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let total_listeners: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_listeners l
            JOIN c2_configs c ON l.c2_config_id = c.id
            WHERE c.user_id = ?
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let active_listeners: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_listeners l
            JOIN c2_configs c ON l.c2_config_id = c.id
            WHERE c.user_id = ? AND l.status = 'active'
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let total_sessions: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_sessions s
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ?
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let active_sessions: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_sessions s
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ? AND s.status = 'active'
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let total_implants: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_implants i
            JOIN c2_configs c ON i.c2_config_id = c.id
            WHERE c.user_id = ?
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let total_credentials: (i32,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM c2_credentials cr
            JOIN c2_sessions s ON cr.session_id = s.id
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ?
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Get sessions by OS
        let os_rows: Vec<(String, i32)> = sqlx::query_as(
            r#"
            SELECT s.os, COUNT(*) FROM c2_sessions s
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ? AND s.status = 'active'
            GROUP BY s.os
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let sessions_by_os: HashMap<String, u32> = os_rows.into_iter()
            .map(|(os, count)| (os, count as u32))
            .collect();

        // Get sessions by framework
        let framework_rows: Vec<(String, i32)> = sqlx::query_as(
            r#"
            SELECT c.framework, COUNT(*) FROM c2_sessions s
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ? AND s.status = 'active'
            GROUP BY c.framework
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let sessions_by_framework: HashMap<String, u32> = framework_rows.into_iter()
            .map(|(fw, count)| (fw, count as u32))
            .collect();

        Ok(C2DashboardStats {
            total_servers: total_servers.0 as u32,
            connected_servers: connected_servers.0 as u32,
            total_listeners: total_listeners.0 as u32,
            active_listeners: active_listeners.0 as u32,
            total_sessions: total_sessions.0 as u32,
            active_sessions: active_sessions.0 as u32,
            total_implants: total_implants.0 as u32,
            total_credentials: total_credentials.0 as u32,
            sessions_by_os,
            sessions_by_framework,
        })
    }

    /// List sessions for a config
    pub async fn list_sessions(&self, config_id: &str) -> Result<Vec<SessionSummary>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, String, String, String, String, String, bool, String,
        )>(
            r#"
            SELECT id, name, hostname, username, ip_address, os, arch, status, is_elevated, last_checkin
            FROM c2_sessions WHERE c2_config_id = ?
            ORDER BY last_checkin DESC
            "#
        )
        .bind(config_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| SessionSummary {
            id: r.0,
            name: r.1,
            hostname: r.2,
            username: r.3,
            ip_address: r.4,
            os: r.5,
            arch: r.6,
            status: r.7.parse().unwrap_or(SessionStatus::Dead),
            is_elevated: r.8,
            last_checkin: chrono::DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
        }).collect())
    }

    /// Save a task
    pub async fn save_task(&self, task: &Task) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO c2_tasks (
                id, session_id, c2_task_id, task_type, command, args,
                status, output, error, created_at, sent_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&task.id)
        .bind(&task.session_id)
        .bind(&task.c2_task_id)
        .bind(&task.task_type)
        .bind(&task.command)
        .bind(serde_json::to_string(&task.args).unwrap_or_default())
        .bind(task.status.to_string())
        .bind(&task.output)
        .bind(&task.error)
        .bind(task.created_at.to_rfc3339())
        .bind(task.sent_at.map(|dt| dt.to_rfc3339()))
        .bind(task.completed_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save a credential
    pub async fn save_credential(&self, credential: &C2Credential) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO c2_credentials (
                id, session_id, credential_type, username, domain,
                secret, source, target, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&credential.id)
        .bind(&credential.session_id)
        .bind(credential.credential_type.to_string())
        .bind(&credential.username)
        .bind(&credential.domain)
        .bind(&credential.secret)
        .bind(&credential.source)
        .bind(&credential.target)
        .bind(&credential.notes)
        .bind(credential.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List credentials for a user
    pub async fn list_credentials(&self, user_id: &str, limit: i32, offset: i32) -> Result<Vec<C2Credential>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, String, Option<String>,
            String, String, Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT cr.id, cr.session_id, cr.credential_type, cr.username, cr.domain,
                   cr.secret, cr.source, cr.target, cr.notes, cr.created_at
            FROM c2_credentials cr
            JOIN c2_sessions s ON cr.session_id = s.id
            JOIN c2_configs c ON s.c2_config_id = c.id
            WHERE c.user_id = ?
            ORDER BY cr.created_at DESC
            LIMIT ? OFFSET ?
            "#
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| C2Credential {
            id: r.0,
            session_id: r.1,
            credential_type: match r.2.as_str() {
                "plaintext" => CredentialType::Plaintext,
                "ntlm" => CredentialType::NtlmHash,
                "kerberos" => CredentialType::Kerberos,
                "certificate" => CredentialType::Certificate,
                "ssh_key" => CredentialType::SshKey,
                "token" => CredentialType::Token,
                "cookie" => CredentialType::Cookie,
                "api_key" => CredentialType::ApiKey,
                _ => CredentialType::Plaintext,
            },
            username: r.3,
            domain: r.4,
            secret: r.5,
            source: r.6,
            target: r.7,
            notes: r.8,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
        }).collect())
    }
}

// Wrapper to implement C2Client trait for SliverClient
struct SliverClientWrapper(SliverClient);

#[async_trait::async_trait]
impl C2Client for SliverClientWrapper {
    async fn test_connection(&self) -> Result<bool> {
        self.0.test_connection().await
    }

    async fn is_connected(&self) -> bool {
        self.0.is_connected().await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.0.get_all_sessions().await
    }

    async fn list_listeners(&self) -> Result<Vec<Listener>> {
        self.0.list_listeners().await
    }

    async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        match req.protocol {
            ListenerProtocol::Http | ListenerProtocol::Https => {
                self.0.start_http_listener(req).await
            }
            ListenerProtocol::Mtls => {
                self.0.start_mtls_listener(req).await
            }
            _ => Err(anyhow!("Listener protocol not supported for Sliver")),
        }
    }

    async fn stop_listener(&self, listener_id: &str) -> Result<()> {
        self.0.stop_listener(listener_id).await
    }

    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        self.0.generate_implant(config).await
    }

    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        self.0.execute_task(session_id, task).await
    }

    async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.0.kill_session(session_id).await
    }
}

// Wrapper to implement C2Client trait for CobaltStrikeClient
struct CobaltStrikeClientWrapper(CobaltStrikeClient);

#[async_trait::async_trait]
impl C2Client for CobaltStrikeClientWrapper {
    async fn test_connection(&self) -> Result<bool> {
        self.0.test_connection().await
    }

    async fn is_connected(&self) -> bool {
        self.0.is_connected().await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.0.list_beacons().await
    }

    async fn list_listeners(&self) -> Result<Vec<Listener>> {
        self.0.list_listeners().await
    }

    async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        self.0.start_listener(req).await
    }

    async fn stop_listener(&self, listener_id: &str) -> Result<()> {
        self.0.stop_listener(listener_id).await
    }

    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        self.0.generate_implant(config).await
    }

    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        self.0.execute_task(session_id, task).await
    }

    async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.0.kill_beacon(session_id).await
    }
}

// Wrapper to implement C2Client trait for HavocClient
struct HavocClientWrapper(HavocClient);

#[async_trait::async_trait]
impl C2Client for HavocClientWrapper {
    async fn test_connection(&self) -> Result<bool> {
        self.0.test_connection().await
    }

    async fn is_connected(&self) -> bool {
        self.0.is_connected().await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.0.list_demons().await
    }

    async fn list_listeners(&self) -> Result<Vec<Listener>> {
        self.0.list_listeners().await
    }

    async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        self.0.start_listener(req).await
    }

    async fn stop_listener(&self, listener_id: &str) -> Result<()> {
        self.0.stop_listener(listener_id).await
    }

    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        self.0.generate_implant(config).await
    }

    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        self.0.execute_task(session_id, task).await
    }

    async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.0.kill_demon(session_id).await
    }
}

// Wrapper to implement C2Client trait for MythicClient
struct MythicClientWrapper(MythicClient);

#[async_trait::async_trait]
impl C2Client for MythicClientWrapper {
    async fn test_connection(&self) -> Result<bool> {
        self.0.test_connection().await
    }

    async fn is_connected(&self) -> bool {
        self.0.is_connected().await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.0.list_callbacks().await
    }

    async fn list_listeners(&self) -> Result<Vec<Listener>> {
        self.0.list_c2_profiles().await
    }

    async fn start_listener(&self, _req: &CreateListenerRequest) -> Result<Listener> {
        Err(anyhow!("Mythic C2 profiles must be started via the web UI"))
    }

    async fn stop_listener(&self, _listener_id: &str) -> Result<()> {
        Err(anyhow!("Mythic C2 profiles must be stopped via the web UI"))
    }

    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        self.0.generate_payload(config).await
    }

    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        self.0.execute_task(session_id, task).await
    }

    async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.0.kill_callback(session_id).await
    }
}

// Wrapper to implement C2Client trait for CustomC2Client
struct CustomC2ClientWrapper(CustomC2Client);

#[async_trait::async_trait]
impl C2Client for CustomC2ClientWrapper {
    async fn test_connection(&self) -> Result<bool> {
        self.0.test_connection().await
    }

    async fn is_connected(&self) -> bool {
        self.0.is_connected().await
    }

    async fn list_sessions(&self) -> Result<Vec<Session>> {
        self.0.list_sessions().await
    }

    async fn list_listeners(&self) -> Result<Vec<Listener>> {
        self.0.list_listeners().await
    }

    async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        self.0.start_listener(req).await
    }

    async fn stop_listener(&self, listener_id: &str) -> Result<()> {
        self.0.stop_listener(listener_id).await
    }

    async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        self.0.generate_implant(config).await
    }

    async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        self.0.execute_task(session_id, task).await
    }

    async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.0.kill_session(session_id).await
    }
}
