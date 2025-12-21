# HeroForge Agent Implementation Guide

This document provides a reference implementation for building a HeroForge scanning agent.

## Agent Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HeroForge Agent                       │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  Heartbeat  │  │    Task     │  │     Result      │  │
│  │   Manager   │  │   Manager   │  │    Submitter    │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                   │          │
│  ┌──────┴────────────────┴───────────────────┴──────┐   │
│  │                   API Client                      │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│  ┌──────────────────────┴───────────────────────────┐   │
│  │                  Scan Engine                      │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐  │   │
│  │  │  Port   │ │ Service │ │  Vuln   │ │   OS   │  │   │
│  │  │ Scanner │ │ Detect  │ │ Scanner │ │  Detect│  │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └────────┘  │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Rust Reference Implementation

### Cargo.toml

```toml
[package]
name = "heroforge-agent"
version = "1.0.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
sysinfo = "0.30"
```

### Main Agent Structure

```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AgentConfig {
    pub server_url: String,
    pub agent_id: String,
    pub token: String,
    pub max_concurrent_tasks: usize,
    pub heartbeat_interval_secs: u64,
}

pub struct Agent {
    config: AgentConfig,
    client: reqwest::Client,
    active_tasks: Arc<RwLock<usize>>,
    running: Arc<RwLock<bool>>,
}

impl Agent {
    pub fn new(config: AgentConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            config,
            client,
            active_tasks: Arc::new(RwLock::new(0)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn run(&self) -> Result<()> {
        *self.running.write().await = true;
        tracing::info!("Agent starting...");

        // Spawn heartbeat task
        let heartbeat_handle = self.spawn_heartbeat();

        // Spawn task polling loop
        let task_handle = self.spawn_task_loop();

        // Wait for shutdown
        tokio::select! {
            _ = heartbeat_handle => {},
            _ = task_handle => {},
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutdown signal received");
                *self.running.write().await = false;
            }
        }

        Ok(())
    }

    fn spawn_heartbeat(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let client = self.client.clone();
        let active_tasks = self.active_tasks.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut sys = sysinfo::System::new_all();

            while *running.read().await {
                sys.refresh_all();

                let cpu_usage = sys.global_cpu_info().cpu_usage();
                let memory_usage = (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0;

                let heartbeat = HeartbeatRequest {
                    cpu_usage,
                    memory_usage,
                    disk_usage: 0.0, // Implement disk check
                    active_tasks: *active_tasks.read().await,
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    os_info: sys.long_os_version().unwrap_or_default(),
                };

                let result = client
                    .post(format!(
                        "{}/api/agents/{}/heartbeat",
                        config.server_url, config.agent_id
                    ))
                    .header("Authorization", format!("Bearer {}", config.token))
                    .json(&heartbeat)
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::debug!("Heartbeat sent successfully");
                    }
                    Ok(resp) => {
                        tracing::warn!("Heartbeat failed: {}", resp.status());
                    }
                    Err(e) => {
                        tracing::error!("Heartbeat error: {}", e);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(
                    config.heartbeat_interval_secs,
                ))
                .await;
            }
        })
    }

    fn spawn_task_loop(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let client = self.client.clone();
        let active_tasks = self.active_tasks.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while *running.read().await {
                let current_tasks = *active_tasks.read().await;

                if current_tasks < config.max_concurrent_tasks {
                    // Fetch pending tasks
                    let result = client
                        .get(format!(
                            "{}/api/agents/{}/tasks?status=pending&limit={}",
                            config.server_url,
                            config.agent_id,
                            config.max_concurrent_tasks - current_tasks
                        ))
                        .header("Authorization", format!("Bearer {}", config.token))
                        .send()
                        .await;

                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(tasks) = resp.json::<TasksResponse>().await {
                                for task in tasks.tasks {
                                    *active_tasks.write().await += 1;

                                    let client = client.clone();
                                    let config = config.clone();
                                    let active_tasks = active_tasks.clone();

                                    tokio::spawn(async move {
                                        execute_task(&client, &config, task).await;
                                        *active_tasks.write().await -= 1;
                                    });
                                }
                            }
                        }
                        _ => {
                            tracing::debug!("No tasks available or fetch failed");
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        })
    }
}

async fn execute_task(client: &reqwest::Client, config: &AgentConfig, task: AgentTask) {
    tracing::info!("Executing task: {} ({})", task.id, task.task_type);

    // Update status to running
    let _ = update_task_status(client, config, &task.id, "running", 0, None).await;

    // Execute the scan based on task type
    let result = match task.task_type.as_str() {
        "full_scan" => run_full_scan(&task.config).await,
        "host_discovery" => run_host_discovery(&task.config).await,
        "port_scan" => run_port_scan(&task.config).await,
        "service_detection" => run_service_detection(&task.config).await,
        "vulnerability_scan" => run_vulnerability_scan(&task.config).await,
        _ => Err(anyhow::anyhow!("Unknown task type: {}", task.task_type)),
    };

    match result {
        Ok(scan_result) => {
            // Submit results
            let _ = submit_results(client, config, &task.id, scan_result).await;
            let _ = update_task_status(client, config, &task.id, "completed", 100, None).await;
        }
        Err(e) => {
            tracing::error!("Task {} failed: {}", task.id, e);
            let _ = update_task_status(
                client,
                config,
                &task.id,
                "failed",
                0,
                Some(e.to_string()),
            )
            .await;
        }
    }
}

async fn update_task_status(
    client: &reqwest::Client,
    config: &AgentConfig,
    task_id: &str,
    status: &str,
    progress: u8,
    message: Option<String>,
) -> Result<()> {
    let body = serde_json::json!({
        "status": status,
        "progress": progress,
        "message": message,
    });

    client
        .put(format!(
            "{}/api/agents/{}/tasks/{}/status",
            config.server_url, config.agent_id, task_id
        ))
        .header("Authorization", format!("Bearer {}", config.token))
        .json(&body)
        .send()
        .await?;

    Ok(())
}

async fn submit_results(
    client: &reqwest::Client,
    config: &AgentConfig,
    task_id: &str,
    result: ScanResult,
) -> Result<()> {
    let body = ResultSubmission {
        task_id: task_id.to_string(),
        result_data: result.hosts,
        hosts_discovered: result.hosts_discovered,
        ports_discovered: result.ports_discovered,
        vulnerabilities_found: result.vulnerabilities_found,
        started_at: result.started_at,
        completed_at: result.completed_at,
    };

    client
        .post(format!(
            "{}/api/agents/{}/results",
            config.server_url, config.agent_id
        ))
        .header("Authorization", format!("Bearer {}", config.token))
        .json(&body)
        .send()
        .await?;

    Ok(())
}

// Placeholder scan functions - implement with actual scanning logic
async fn run_full_scan(config: &TaskConfig) -> Result<ScanResult> {
    // Implement full scan logic using your preferred scanning library
    // Example: socket scanning, nmap integration, or custom implementation
    todo!("Implement full_scan")
}

async fn run_host_discovery(config: &TaskConfig) -> Result<ScanResult> {
    // ICMP ping, ARP scan, TCP SYN to common ports
    todo!("Implement host_discovery")
}

async fn run_port_scan(config: &TaskConfig) -> Result<ScanResult> {
    // TCP/UDP port scanning
    todo!("Implement port_scan")
}

async fn run_service_detection(config: &TaskConfig) -> Result<ScanResult> {
    // Banner grabbing, protocol detection
    todo!("Implement service_detection")
}

async fn run_vulnerability_scan(config: &TaskConfig) -> Result<ScanResult> {
    // CVE checks, misconfigurations
    todo!("Implement vulnerability_scan")
}
```

### Data Types

```rust
#[derive(Debug, Serialize)]
struct HeartbeatRequest {
    cpu_usage: f32,
    memory_usage: f32,
    disk_usage: f32,
    active_tasks: usize,
    agent_version: String,
    os_info: String,
}

#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    acknowledged: bool,
    server_time: String,
    pending_tasks: usize,
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TasksResponse {
    tasks: Vec<AgentTask>,
}

#[derive(Debug, Deserialize)]
struct AgentTask {
    id: String,
    scan_id: String,
    task_type: String,
    config: TaskConfig,
    priority: i32,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct TaskConfig {
    targets: Vec<String>,
    port_range: Option<[u16; 2]>,
    threads: Option<u32>,
    enable_os_detection: Option<bool>,
    enable_service_detection: Option<bool>,
    enable_vuln_scan: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ResultSubmission {
    task_id: String,
    result_data: Vec<HostResult>,
    hosts_discovered: u32,
    ports_discovered: u32,
    vulnerabilities_found: u32,
    started_at: String,
    completed_at: String,
}

#[derive(Debug, Serialize)]
struct HostResult {
    ip: String,
    hostname: Option<String>,
    os_info: Option<OsInfo>,
    ports: Vec<PortResult>,
    vulnerabilities: Vec<VulnResult>,
}

#[derive(Debug, Serialize)]
struct OsInfo {
    name: String,
    version: Option<String>,
    confidence: f32,
}

#[derive(Debug, Serialize)]
struct PortResult {
    port: u16,
    protocol: String,
    state: String,
    service: Option<ServiceInfo>,
}

#[derive(Debug, Serialize)]
struct ServiceInfo {
    name: String,
    version: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Serialize)]
struct VulnResult {
    id: String,
    title: String,
    severity: String,
    cvss_score: Option<f32>,
    description: String,
    remediation: Option<String>,
}

struct ScanResult {
    hosts: Vec<HostResult>,
    hosts_discovered: u32,
    ports_discovered: u32,
    vulnerabilities_found: u32,
    started_at: String,
    completed_at: String,
}
```

### Main Entry Point

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "heroforge-agent")]
#[command(about = "HeroForge distributed scanning agent")]
struct Cli {
    #[arg(long, env = "HEROFORGE_SERVER")]
    server: String,

    #[arg(long, env = "HEROFORGE_AGENT_ID")]
    agent_id: String,

    #[arg(long, env = "HEROFORGE_AGENT_TOKEN")]
    token: String,

    #[arg(long, default_value = "5")]
    max_tasks: usize,

    #[arg(long, default_value = "30")]
    heartbeat_interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::init();

    let cli = Cli::parse();

    let config = AgentConfig {
        server_url: cli.server,
        agent_id: cli.agent_id,
        token: cli.token,
        max_concurrent_tasks: cli.max_tasks,
        heartbeat_interval_secs: cli.heartbeat_interval,
    };

    let agent = Agent::new(config);
    agent.run().await
}
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/heroforge-agent /usr/local/bin/

# Non-root user for security
RUN useradd -m -s /bin/bash agent
USER agent

ENV HEROFORGE_SERVER=""
ENV HEROFORGE_AGENT_ID=""
ENV HEROFORGE_AGENT_TOKEN=""

ENTRYPOINT ["heroforge-agent"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  heroforge-agent:
    build: .
    container_name: heroforge-agent
    restart: unless-stopped
    environment:
      - HEROFORGE_SERVER=https://heroforge.example.com
      - HEROFORGE_AGENT_ID=${AGENT_ID}
      - HEROFORGE_AGENT_TOKEN=${AGENT_TOKEN}
      - RUST_LOG=info
    # Required for network scanning
    cap_add:
      - NET_RAW
      - NET_ADMIN
    networks:
      - scan-network

networks:
  scan-network:
    driver: bridge
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HEROFORGE_SERVER` | Yes | HeroForge server URL |
| `HEROFORGE_AGENT_ID` | Yes | Agent UUID from registration |
| `HEROFORGE_AGENT_TOKEN` | Yes | Agent authentication token |
| `RUST_LOG` | No | Log level (trace, debug, info, warn, error) |

## Security Considerations

1. **Token Security**: Store agent token in secure secret management (Vault, AWS Secrets Manager)
2. **Network Isolation**: Run agent in a dedicated network segment
3. **Least Privilege**: Only grant capabilities needed for scanning
4. **TLS Verification**: Always verify server certificates
5. **Log Sanitization**: Don't log sensitive data (tokens, passwords)

## Troubleshooting

### Agent not appearing online

1. Check token is correct: `echo $HEROFORGE_AGENT_TOKEN | head -c 20`
2. Verify server connectivity: `curl -I https://heroforge.example.com/api/health`
3. Check agent logs: `docker logs heroforge-agent`

### Tasks not being picked up

1. Verify agent status is "online" in web UI
2. Check agent is assigned to correct network zones
3. Ensure agent has capacity (max_tasks not reached)

### Scan results not appearing

1. Check task status in agent logs
2. Verify result submission response
3. Check server-side error logs
