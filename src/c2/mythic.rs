//! Mythic C2 Framework Integration
//!
//! Client for interacting with Mythic C2 server via its GraphQL API.
//! Mythic is an open-source C2 framework with a modern web interface.
//!
//! References:
//! - https://docs.mythic-c2.net/
//! - GraphQL API documentation at https://{mythic_host}/graphql

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::*;

/// Mythic C2 client using GraphQL API
pub struct MythicClient {
    config: C2Config,
    client: Client,
    connected: Arc<RwLock<bool>>,
}

// GraphQL request/response types
#[derive(Debug, Serialize)]
struct GraphQLRequest {
    query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    variables: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

// Mythic-specific types
#[derive(Debug, Deserialize)]
struct MythicCallback {
    id: i64,
    display_id: i32,
    agent_callback_id: String,
    user: String,
    host: String,
    ip: String,
    external_ip: Option<String>,
    domain: Option<String>,
    os: String,
    architecture: String,
    pid: i32,
    process_name: Option<String>,
    integrity_level: Option<i32>,
    active: bool,
    description: Option<String>,
    init_callback: String,
    last_checkin: String,
}

#[derive(Debug, Deserialize)]
struct MythicPayload {
    id: i64,
    uuid: String,
    description: Option<String>,
    build_message: Option<String>,
    build_phase: String,
    build_stderr: Option<String>,
    build_stdout: Option<String>,
    payload_type: MythicPayloadType,
    os: String,
    #[serde(rename = "creation_time")]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct MythicPayloadType {
    name: String,
}

#[derive(Debug, Deserialize)]
struct MythicC2Profile {
    id: i64,
    name: String,
    description: Option<String>,
    is_p2p: bool,
    is_server_routed: bool,
    running: bool,
}

#[derive(Debug, Deserialize)]
struct MythicTask {
    id: i64,
    display_id: i32,
    command_name: String,
    original_params: String,
    #[serde(rename = "params")]
    parameters: Option<String>,
    status: String,
    completed: bool,
    stdout: Option<String>,
    stderr: Option<String>,
    timestamp: String,
    #[serde(rename = "completed_timestamp")]
    completed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MythicCredential {
    id: i64,
    #[serde(rename = "type")]
    credential_type: String,
    account: String,
    realm: Option<String>,
    credential: String,
    comment: Option<String>,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct MythicFile {
    id: i64,
    agent_file_id: String,
    filename_utf8: String,
    full_remote_path_utf8: Option<String>,
    total_chunks: i32,
    chunks_received: i32,
    complete: bool,
    is_download_from_agent: bool,
    timestamp: String,
}

// GraphQL response wrapper types
#[derive(Debug, Deserialize)]
struct CallbacksResponse {
    callback: Vec<MythicCallback>,
}

#[derive(Debug, Deserialize)]
struct PayloadsResponse {
    payload: Vec<MythicPayload>,
}

#[derive(Debug, Deserialize)]
struct C2ProfilesResponse {
    c2profile: Vec<MythicC2Profile>,
}

#[derive(Debug, Deserialize)]
struct TasksResponse {
    task: Vec<MythicTask>,
}

#[derive(Debug, Deserialize)]
struct CredentialsResponse {
    credential: Vec<MythicCredential>,
}

#[derive(Debug, Deserialize)]
struct FilesResponse {
    filemeta: Vec<MythicFile>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct CreateTaskResponse {
    createTask: Option<CreateTaskResult>,
}

#[derive(Debug, Deserialize)]
struct CreateTaskResult {
    status: String,
    id: Option<i64>,
    error: Option<String>,
}

impl MythicClient {
    /// Create a new Mythic client
    pub fn new(config: C2Config) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()?;

        Ok(Self {
            config,
            client,
            connected: Arc::new(RwLock::new(false)),
        })
    }

    /// Get GraphQL endpoint URL
    fn graphql_url(&self) -> String {
        format!("https://{}:{}/graphql", self.config.host, self.config.port)
    }

    /// Get authorization header (Mythic uses API tokens)
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.api_token.as_deref().unwrap_or(""))
    }

    /// Execute a GraphQL query
    async fn execute_query<T: for<'de> Deserialize<'de>>(
        &self,
        query: &str,
        variables: Option<serde_json::Value>,
    ) -> Result<T> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let resp = self.client
            .post(&self.graphql_url())
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("GraphQL request failed: {}", resp.status()));
        }

        let gql_response: GraphQLResponse<T> = resp.json().await?;

        if let Some(errors) = gql_response.errors {
            if !errors.is_empty() {
                return Err(anyhow!("GraphQL errors: {}", errors[0].message));
            }
        }

        gql_response.data.ok_or_else(|| anyhow!("No data in GraphQL response"))
    }

    /// Test connection to Mythic server
    pub async fn test_connection(&self) -> Result<bool> {
        let query = r#"
            query TestConnection {
                callback(limit: 1) {
                    id
                }
            }
        "#;

        match self.execute_query::<CallbacksResponse>(query, None).await {
            Ok(_) => {
                *self.connected.write().await = true;
                Ok(true)
            }
            Err(e) => {
                *self.connected.write().await = false;
                Err(anyhow!("Failed to connect to Mythic: {}", e))
            }
        }
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// List all callbacks (agents)
    pub async fn list_callbacks(&self) -> Result<Vec<Session>> {
        let query = r#"
            query GetCallbacks {
                callback(order_by: {last_checkin: desc}) {
                    id
                    display_id
                    agent_callback_id
                    user
                    host
                    ip
                    external_ip
                    domain
                    os
                    architecture
                    pid
                    process_name
                    integrity_level
                    active
                    description
                    init_callback
                    last_checkin
                }
            }
        "#;

        let response: CallbacksResponse = self.execute_query(query, None).await?;
        Ok(response.callback.into_iter().map(|c| self.convert_callback(c)).collect())
    }

    /// List C2 profiles (listeners)
    pub async fn list_c2_profiles(&self) -> Result<Vec<Listener>> {
        let query = r#"
            query GetC2Profiles {
                c2profile {
                    id
                    name
                    description
                    is_p2p
                    is_server_routed
                    running
                }
            }
        "#;

        let response: C2ProfilesResponse = self.execute_query(query, None).await?;
        Ok(response.c2profile.into_iter().map(|p| self.convert_c2_profile(p)).collect())
    }

    /// Start a C2 profile
    pub async fn start_c2_profile(&self, profile_id: i64) -> Result<()> {
        let query = r#"
            mutation StartC2Profile($id: Int!) {
                startc2profile(id: $id) {
                    status
                    error
                }
            }
        "#;

        let variables = serde_json::json!({
            "id": profile_id
        });

        let _: serde_json::Value = self.execute_query(query, Some(variables)).await?;
        Ok(())
    }

    /// Stop a C2 profile
    pub async fn stop_c2_profile(&self, profile_id: i64) -> Result<()> {
        let query = r#"
            mutation StopC2Profile($id: Int!) {
                stopc2profile(id: $id) {
                    status
                    error
                }
            }
        "#;

        let variables = serde_json::json!({
            "id": profile_id
        });

        let _: serde_json::Value = self.execute_query(query, Some(variables)).await?;
        Ok(())
    }

    /// List payloads (implants)
    pub async fn list_payloads(&self) -> Result<Vec<Implant>> {
        let query = r#"
            query GetPayloads {
                payload(order_by: {creation_time: desc}) {
                    id
                    uuid
                    description
                    build_message
                    build_phase
                    build_stderr
                    build_stdout
                    payload_type {
                        name
                    }
                    os
                    creation_time
                }
            }
        "#;

        let response: PayloadsResponse = self.execute_query(query, None).await?;
        Ok(response.payload.into_iter().map(|p| self.convert_payload(p)).collect())
    }

    /// Create a new task for a callback
    pub async fn create_task(
        &self,
        callback_id: i64,
        command: &str,
        params: Option<&str>,
    ) -> Result<Task> {
        let query = r#"
            mutation CreateTask($callback_id: Int!, $command: String!, $params: String!) {
                createTask(callback_id: $callback_id, command: $command, params: $params) {
                    status
                    id
                    error
                }
            }
        "#;

        let variables = serde_json::json!({
            "callback_id": callback_id,
            "command": command,
            "params": params.unwrap_or("")
        });

        let response: CreateTaskResponse = self.execute_query(query, Some(variables)).await?;

        if let Some(result) = response.createTask {
            if result.status == "success" {
                Ok(Task {
                    id: uuid::Uuid::new_v4().to_string(),
                    session_id: callback_id.to_string(),
                    c2_task_id: result.id.map(|id| id.to_string()),
                    task_type: command.to_string(),
                    command: command.to_string(),
                    args: params.map(|p| vec![p.to_string()]).unwrap_or_default(),
                    status: TaskStatus::Sent,
                    output: None,
                    error: None,
                    created_at: Utc::now(),
                    sent_at: Some(Utc::now()),
                    completed_at: None,
                })
            } else {
                Err(anyhow!("Failed to create task: {}", result.error.unwrap_or_default()))
            }
        } else {
            Err(anyhow!("No response from createTask mutation"))
        }
    }

    /// Get task output
    pub async fn get_task_output(&self, task_id: i64) -> Result<Task> {
        let query = r#"
            query GetTask($id: Int!) {
                task(where: {id: {_eq: $id}}) {
                    id
                    display_id
                    command_name
                    original_params
                    params
                    status
                    completed
                    stdout
                    stderr
                    timestamp
                    completed_timestamp
                }
            }
        "#;

        let variables = serde_json::json!({
            "id": task_id
        });

        let response: TasksResponse = self.execute_query(query, Some(variables)).await?;

        response.task.into_iter().next()
            .map(|t| self.convert_task(t))
            .ok_or_else(|| anyhow!("Task not found"))
    }

    /// List tasks for a callback
    pub async fn list_tasks(&self, callback_id: i64) -> Result<Vec<Task>> {
        let query = r#"
            query GetTasks($callback_id: Int!) {
                task(where: {callback_id: {_eq: $callback_id}}, order_by: {timestamp: desc}) {
                    id
                    display_id
                    command_name
                    original_params
                    params
                    status
                    completed
                    stdout
                    stderr
                    timestamp
                    completed_timestamp
                }
            }
        "#;

        let variables = serde_json::json!({
            "callback_id": callback_id
        });

        let response: TasksResponse = self.execute_query(query, Some(variables)).await?;
        Ok(response.task.into_iter().map(|t| self.convert_task(t)).collect())
    }

    /// Execute a task (wrapper for create_task with ExecuteTaskRequest)
    pub async fn execute_task(&self, callback_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        let callback_id: i64 = callback_id.parse()
            .map_err(|_| anyhow!("Invalid callback ID"))?;

        let params = task.args.as_ref()
            .map(|args| args.join(" "));

        self.create_task(callback_id, &task.command, params.as_deref()).await
    }

    /// Kill a callback
    pub async fn kill_callback(&self, callback_id: &str) -> Result<()> {
        let id: i64 = callback_id.parse()
            .map_err(|_| anyhow!("Invalid callback ID"))?;

        // Issue exit command
        self.create_task(id, "exit", None).await?;
        Ok(())
    }

    /// List credentials
    pub async fn list_credentials(&self) -> Result<Vec<C2Credential>> {
        let query = r#"
            query GetCredentials {
                credential(order_by: {timestamp: desc}) {
                    id
                    type
                    account
                    realm
                    credential
                    comment
                    timestamp
                }
            }
        "#;

        let response: CredentialsResponse = self.execute_query(query, None).await?;
        Ok(response.credential.into_iter().map(|c| self.convert_credential(c)).collect())
    }

    /// List downloaded files
    pub async fn list_files(&self, callback_id: Option<i64>) -> Result<Vec<DownloadedFile>> {
        let query = if callback_id.is_some() {
            r#"
                query GetFiles($callback_id: Int!) {
                    filemeta(where: {callback_id: {_eq: $callback_id}}, order_by: {timestamp: desc}) {
                        id
                        agent_file_id
                        filename_utf8
                        full_remote_path_utf8
                        total_chunks
                        chunks_received
                        complete
                        is_download_from_agent
                        timestamp
                    }
                }
            "#
        } else {
            r#"
                query GetFiles {
                    filemeta(order_by: {timestamp: desc}) {
                        id
                        agent_file_id
                        filename_utf8
                        full_remote_path_utf8
                        total_chunks
                        chunks_received
                        complete
                        is_download_from_agent
                        timestamp
                    }
                }
            "#
        };

        let variables = callback_id.map(|id| serde_json::json!({"callback_id": id}));
        let response: FilesResponse = self.execute_query(query, variables).await?;
        Ok(response.filemeta.into_iter().map(|f| self.convert_file(f)).collect())
    }

    /// Generate a payload (request build)
    pub async fn generate_payload(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        // Mythic payload generation is more complex and requires specifying
        // payload type, c2 profiles, and build parameters
        let query = r#"
            mutation CreatePayload(
                $payload_type: String!,
                $c2_profiles: [PayloadC2ProfilesInput!]!,
                $build_parameters: [BuildParameterInput!]!,
                $description: String,
                $selected_os: String!
            ) {
                createPayload(
                    payload_type: $payload_type,
                    c2_profiles: $c2_profiles,
                    build_parameters: $build_parameters,
                    description: $description,
                    selected_os: $selected_os
                ) {
                    status
                    error
                    uuid
                }
            }
        "#;

        let os = match config.platform {
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::MacOS => "macOS",
            Platform::FreeBSD => "FreeBSD",
        };

        let variables = serde_json::json!({
            "payload_type": "apollo",  // Example payload type
            "c2_profiles": [{
                "c2_profile": "http",
                "c2_profile_parameters": {}
            }],
            "build_parameters": [],
            "description": config.name,
            "selected_os": os
        });

        #[derive(Debug, Deserialize)]
        #[allow(non_snake_case)]
        struct CreatePayloadResponse {
            createPayload: Option<CreatePayloadResult>,
        }

        #[derive(Debug, Deserialize)]
        struct CreatePayloadResult {
            status: String,
            error: Option<String>,
            uuid: Option<String>,
        }

        let response: CreatePayloadResponse = self.execute_query(query, Some(variables)).await?;

        if let Some(result) = response.createPayload {
            if result.status == "success" && result.uuid.is_some() {
                // Wait for build and download
                let uuid = result.uuid.unwrap();
                self.download_payload(&uuid).await
            } else {
                Err(anyhow!("Payload creation failed: {}", result.error.unwrap_or_default()))
            }
        } else {
            Err(anyhow!("No response from createPayload mutation"))
        }
    }

    /// Download a built payload
    async fn download_payload(&self, uuid: &str) -> Result<Vec<u8>> {
        let url = format!(
            "https://{}:{}/api/v1.4/payloads/download/{}",
            self.config.host, self.config.port, uuid
        );

        let resp = self.client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to download payload: {}", resp.status()));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    // Conversion helpers
    fn convert_callback(&self, c: MythicCallback) -> Session {
        let arch = if c.architecture.contains("64") {
            Architecture::X64
        } else if c.architecture.contains("arm") {
            Architecture::Arm64
        } else {
            Architecture::X86
        };

        let status = if c.active {
            SessionStatus::Active
        } else {
            SessionStatus::Dead
        };

        let integrity = c.integrity_level.map(|level| {
            match level {
                4 => "System".to_string(),
                3 => "High".to_string(),
                2 => "Medium".to_string(),
                _ => "Low".to_string(),
            }
        });

        Session {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: c.agent_callback_id,
            implant_id: None,
            name: format!("Callback-{}", c.display_id),
            hostname: c.host,
            username: c.user,
            domain: c.domain,
            ip_address: c.ip,
            external_ip: c.external_ip,
            os: c.os,
            os_version: None,
            arch,
            pid: c.pid as u32,
            process_name: c.process_name.unwrap_or_else(|| "unknown".to_string()),
            integrity,
            status,
            is_elevated: c.integrity_level.map(|l| l >= 3).unwrap_or(false),
            locale: None,
            first_seen: DateTime::parse_from_rfc3339(&c.init_callback)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_checkin: DateTime::parse_from_rfc3339(&c.last_checkin)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            next_checkin: None,
            notes: c.description,
        }
    }

    fn convert_c2_profile(&self, p: MythicC2Profile) -> Listener {
        let protocol = if p.name.to_lowercase().contains("http") {
            if p.name.to_lowercase().contains("https") {
                ListenerProtocol::Https
            } else {
                ListenerProtocol::Http
            }
        } else if p.name.to_lowercase().contains("dns") {
            ListenerProtocol::Dns
        } else if p.name.to_lowercase().contains("tcp") {
            ListenerProtocol::Tcp
        } else {
            ListenerProtocol::Http
        };

        let status = if p.running {
            ListenerStatus::Active
        } else {
            ListenerStatus::Stopped
        };

        Listener {
            id: p.id.to_string(),
            c2_config_id: self.config.id.clone(),
            name: p.name,
            protocol,
            host: self.config.host.clone(),
            port: self.config.port,
            status,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn convert_payload(&self, p: MythicPayload) -> Implant {
        let platform = if p.os.to_lowercase().contains("windows") {
            Platform::Windows
        } else if p.os.to_lowercase().contains("linux") {
            Platform::Linux
        } else if p.os.to_lowercase().contains("macos") {
            Platform::MacOS
        } else {
            Platform::Linux
        };

        Implant {
            id: p.uuid.clone(),
            c2_config_id: self.config.id.clone(),
            name: p.description.unwrap_or_else(|| p.payload_type.name.clone()),
            platform,
            arch: Architecture::X64,
            format: ImplantFormat::Exe,
            implant_type: ImplantType::Beacon,
            listener_id: String::new(),
            file_path: None,
            file_hash: None,
            file_size: None,
            download_count: 0,
            created_at: DateTime::parse_from_rfc3339(&p.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }

    fn convert_task(&self, t: MythicTask) -> Task {
        let status = match t.status.to_lowercase().as_str() {
            "completed" => TaskStatus::Completed,
            "error" => TaskStatus::Failed,
            "submitted" => TaskStatus::Pending,
            "processing" => TaskStatus::Running,
            _ => TaskStatus::Pending,
        };

        Task {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: String::new(),
            c2_task_id: Some(t.id.to_string()),
            task_type: t.command_name.clone(),
            command: t.command_name,
            args: t.parameters.map(|p| vec![p]).unwrap_or_default(),
            status,
            output: t.stdout,
            error: t.stderr,
            created_at: DateTime::parse_from_rfc3339(&t.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            sent_at: Some(Utc::now()),
            completed_at: t.completed_at.and_then(|ts| {
                DateTime::parse_from_rfc3339(&ts).ok().map(|dt| dt.with_timezone(&Utc))
            }),
        }
    }

    fn convert_credential(&self, c: MythicCredential) -> C2Credential {
        let cred_type = match c.credential_type.to_lowercase().as_str() {
            "plaintext" | "password" => CredentialType::Plaintext,
            "ntlm" | "hash" => CredentialType::NtlmHash,
            "kerberos" | "ticket" => CredentialType::Kerberos,
            "certificate" | "cert" => CredentialType::Certificate,
            "ssh" | "ssh_key" => CredentialType::SshKey,
            "token" => CredentialType::Token,
            _ => CredentialType::Plaintext,
        };

        C2Credential {
            id: c.id.to_string(),
            session_id: String::new(),
            credential_type: cred_type,
            username: c.account,
            domain: c.realm,
            secret: c.credential,
            source: "Mythic".to_string(),
            target: None,
            notes: c.comment,
            created_at: DateTime::parse_from_rfc3339(&c.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }

    fn convert_file(&self, f: MythicFile) -> DownloadedFile {
        DownloadedFile {
            id: f.agent_file_id,
            session_id: String::new(),
            remote_path: f.full_remote_path_utf8.unwrap_or_default(),
            local_path: format!("./downloads/{}", f.filename_utf8),
            file_name: f.filename_utf8,
            file_size: 0,
            file_hash: String::new(),
            downloaded_at: DateTime::parse_from_rfc3339(&f.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_request_serialization() {
        let req = GraphQLRequest {
            query: "query { test }".to_string(),
            variables: Some(serde_json::json!({"id": 1})),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("query"));
        assert!(json.contains("variables"));
    }
}
