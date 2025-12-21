//! Database operations for agent-based scanning
//!
//! This module provides CRUD operations for:
//! - Scan agents
//! - Agent groups
//! - Agent tasks
//! - Agent results
//! - Agent heartbeats

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::agents::types::{
    AgentGroup, AgentGroupMember, AgentHeartbeat, AgentResult, AgentStats, AgentStatus,
    AgentTask, ScanAgent, TaskStatus,
};

// ============================================================================
// Agent CRUD Operations
// ============================================================================

/// Create a new scan agent
pub async fn create_agent(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
    token_hash: &str,
    token_prefix: &str,
    network_zones: Option<&[String]>,
    max_concurrent_tasks: i32,
) -> Result<ScanAgent> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let network_zones_json = network_zones.map(|zones| serde_json::to_string(zones).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO scan_agents (
            id, user_id, name, description, token_hash, token_prefix,
            status, network_zones, max_concurrent_tasks, current_tasks,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?10)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(token_hash)
    .bind(token_prefix)
    .bind(AgentStatus::Pending.as_str())
    .bind(&network_zones_json)
    .bind(max_concurrent_tasks)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(ScanAgent {
        id,
        user_id: user_id.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        token_hash: token_hash.to_string(),
        token_prefix: token_prefix.to_string(),
        status: AgentStatus::Pending.as_str().to_string(),
        version: None,
        hostname: None,
        ip_address: None,
        os_info: None,
        capabilities: None,
        network_zones: network_zones_json,
        max_concurrent_tasks,
        current_tasks: 0,
        last_heartbeat_at: None,
        last_task_at: None,
        created_at: now,
        updated_at: now,
    })
}

/// Get all agents for a user
pub async fn get_user_agents(pool: &SqlitePool, user_id: &str) -> Result<Vec<ScanAgent>> {
    let agents = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT * FROM scan_agents
        WHERE user_id = ?1
        ORDER BY name ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(agents)
}

/// Get an agent by ID
pub async fn get_agent_by_id(pool: &SqlitePool, agent_id: &str) -> Result<Option<ScanAgent>> {
    let agent = sqlx::query_as::<_, ScanAgent>(
        "SELECT * FROM scan_agents WHERE id = ?1",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Find agents by token prefix
pub async fn find_agents_by_token_prefix(pool: &SqlitePool, prefix: &str) -> Result<Vec<ScanAgent>> {
    let agents = sqlx::query_as::<_, ScanAgent>(
        "SELECT * FROM scan_agents WHERE token_prefix = ?1",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await?;

    Ok(agents)
}

/// Update an agent
pub async fn update_agent(
    pool: &SqlitePool,
    agent_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    network_zones: Option<&[String]>,
    max_concurrent_tasks: Option<i32>,
    status: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    if let Some(name) = name {
        sqlx::query("UPDATE scan_agents SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = description {
        sqlx::query("UPDATE scan_agents SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(zones) = network_zones {
        let zones_json = serde_json::to_string(zones)?;
        sqlx::query("UPDATE scan_agents SET network_zones = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(zones_json)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(max_tasks) = max_concurrent_tasks {
        sqlx::query("UPDATE scan_agents SET max_concurrent_tasks = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(max_tasks)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(status) = status {
        sqlx::query("UPDATE scan_agents SET status = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Update agent heartbeat information
pub async fn update_agent_heartbeat(
    pool: &SqlitePool,
    agent_id: &str,
    version: Option<&str>,
    hostname: Option<&str>,
    os_info: Option<&str>,
    capabilities: Option<&[String]>,
) -> Result<()> {
    let now = Utc::now();
    let capabilities_json = capabilities.map(|caps| serde_json::to_string(caps).unwrap_or_default());

    sqlx::query(
        r#"
        UPDATE scan_agents SET
            status = ?1,
            version = COALESCE(?2, version),
            hostname = COALESCE(?3, hostname),
            os_info = COALESCE(?4, os_info),
            capabilities = COALESCE(?5, capabilities),
            last_heartbeat_at = ?6,
            updated_at = ?6
        WHERE id = ?7
        "#,
    )
    .bind(AgentStatus::Online.as_str())
    .bind(version)
    .bind(hostname)
    .bind(os_info)
    .bind(capabilities_json)
    .bind(now)
    .bind(agent_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an agent
pub async fn delete_agent(pool: &SqlitePool, agent_id: &str) -> Result<()> {
    // Delete group memberships
    sqlx::query("DELETE FROM agent_group_members WHERE agent_id = ?1")
        .bind(agent_id)
        .execute(pool)
        .await?;

    // Delete agent
    sqlx::query("DELETE FROM scan_agents WHERE id = ?1")
        .bind(agent_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Mark agents as offline if heartbeat timeout exceeded
pub async fn mark_offline_agents(pool: &SqlitePool, timeout_seconds: i64) -> Result<u64> {
    let cutoff = Utc::now() - Duration::seconds(timeout_seconds);

    let result = sqlx::query(
        r#"
        UPDATE scan_agents
        SET status = ?1, updated_at = ?2
        WHERE status IN ('online', 'busy')
        AND last_heartbeat_at < ?3
        "#,
    )
    .bind(AgentStatus::Offline.as_str())
    .bind(Utc::now())
    .bind(cutoff)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Find an available agent for a user
pub async fn find_available_agent(pool: &SqlitePool, user_id: &str) -> Result<Option<ScanAgent>> {
    let agent = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT * FROM scan_agents
        WHERE user_id = ?1
        AND status = 'online'
        AND current_tasks < max_concurrent_tasks
        ORDER BY last_task_at ASC NULLS FIRST
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Find least busy agent
pub async fn find_least_busy_agent(pool: &SqlitePool, user_id: &str) -> Result<Option<ScanAgent>> {
    let agent = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT * FROM scan_agents
        WHERE user_id = ?1
        AND status = 'online'
        AND current_tasks < max_concurrent_tasks
        ORDER BY current_tasks ASC, last_task_at ASC NULLS FIRST
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Find agent matching network zone
pub async fn find_agent_for_network(
    pool: &SqlitePool,
    user_id: &str,
    network: &str,
) -> Result<Option<ScanAgent>> {
    // This is a simplified implementation - would need proper CIDR matching
    let agent = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT * FROM scan_agents
        WHERE user_id = ?1
        AND status = 'online'
        AND current_tasks < max_concurrent_tasks
        AND network_zones LIKE ?2
        ORDER BY current_tasks ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(format!("%{}%", network))
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Find available agent in a group
pub async fn find_available_agent_in_group(pool: &SqlitePool, group_id: &str) -> Result<Option<ScanAgent>> {
    let agent = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT a.* FROM scan_agents a
        INNER JOIN agent_group_members m ON a.id = m.agent_id
        WHERE m.group_id = ?1
        AND a.status = 'online'
        AND a.current_tasks < a.max_concurrent_tasks
        ORDER BY a.current_tasks ASC, a.last_task_at ASC NULLS FIRST
        LIMIT 1
        "#,
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?;

    Ok(agent)
}

/// Get agent statistics for a user
pub async fn get_agent_stats(pool: &SqlitePool, user_id: &str) -> Result<AgentStats> {
    let row: (i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
            SUM(CASE WHEN status = 'busy' THEN 1 ELSE 0 END) as busy,
            SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
        FROM scan_agents
        WHERE user_id = ?1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let task_row: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN t.status = 'failed' THEN 1 ELSE 0 END) as failed
        FROM agent_tasks t
        INNER JOIN scan_agents a ON t.agent_id = a.id
        WHERE a.user_id = ?1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0));

    let avg_duration: Option<(f64,)> = sqlx::query_as(
        r#"
        SELECT AVG(
            CAST((julianday(completed_at) - julianday(started_at)) * 86400 AS REAL)
        ) as avg_secs
        FROM agent_tasks t
        INNER JOIN scan_agents a ON t.agent_id = a.id
        WHERE a.user_id = ?1
        AND t.status = 'completed'
        AND t.started_at IS NOT NULL
        AND t.completed_at IS NOT NULL
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(AgentStats {
        total_agents: row.0,
        online_agents: row.1,
        busy_agents: row.2,
        offline_agents: row.3,
        total_tasks_completed: task_row.0,
        total_tasks_failed: task_row.1,
        average_task_duration_secs: avg_duration.and_then(|r| if r.0 > 0.0 { Some(r.0) } else { None }),
    })
}

// ============================================================================
// Agent Group Operations
// ============================================================================

/// Create an agent group
pub async fn create_agent_group(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
    network_ranges: Option<&[String]>,
    color: &str,
) -> Result<AgentGroup> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let network_ranges_json = network_ranges.map(|ranges| serde_json::to_string(ranges).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO agent_groups (id, user_id, name, description, network_ranges, color, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(&network_ranges_json)
    .bind(color)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentGroup {
        id,
        user_id: user_id.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        network_ranges: network_ranges_json,
        color: color.to_string(),
        created_at: now,
        updated_at: now,
    })
}

/// Get all agent groups for a user
pub async fn get_user_agent_groups(pool: &SqlitePool, user_id: &str) -> Result<Vec<AgentGroup>> {
    let groups = sqlx::query_as::<_, AgentGroup>(
        "SELECT * FROM agent_groups WHERE user_id = ?1 ORDER BY name ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get an agent group by ID
pub async fn get_agent_group_by_id(pool: &SqlitePool, group_id: &str) -> Result<Option<AgentGroup>> {
    let group = sqlx::query_as::<_, AgentGroup>(
        "SELECT * FROM agent_groups WHERE id = ?1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Update an agent group
pub async fn update_agent_group(
    pool: &SqlitePool,
    group_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    network_ranges: Option<&[String]>,
    color: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    if let Some(name) = name {
        sqlx::query("UPDATE agent_groups SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = description {
        sqlx::query("UPDATE agent_groups SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(ranges) = network_ranges {
        let ranges_json = serde_json::to_string(ranges)?;
        sqlx::query("UPDATE agent_groups SET network_ranges = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(ranges_json)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(color) = color {
        sqlx::query("UPDATE agent_groups SET color = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(color)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Delete an agent group
pub async fn delete_agent_group(pool: &SqlitePool, group_id: &str) -> Result<()> {
    // Delete memberships
    sqlx::query("DELETE FROM agent_group_members WHERE group_id = ?1")
        .bind(group_id)
        .execute(pool)
        .await?;

    // Delete group
    sqlx::query("DELETE FROM agent_groups WHERE id = ?1")
        .bind(group_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Add an agent to a group
pub async fn add_agent_to_group(pool: &SqlitePool, agent_id: &str, group_id: &str) -> Result<()> {
    sqlx::query(
        r#"
        INSERT OR IGNORE INTO agent_group_members (agent_id, group_id, added_at)
        VALUES (?1, ?2, ?3)
        "#,
    )
    .bind(agent_id)
    .bind(group_id)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(())
}

/// Remove an agent from a group
pub async fn remove_agent_from_group(pool: &SqlitePool, agent_id: &str, group_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM agent_group_members WHERE agent_id = ?1 AND group_id = ?2")
        .bind(agent_id)
        .bind(group_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get groups for an agent
pub async fn get_agent_groups(pool: &SqlitePool, agent_id: &str) -> Result<Vec<AgentGroup>> {
    let groups = sqlx::query_as::<_, AgentGroup>(
        r#"
        SELECT g.* FROM agent_groups g
        INNER JOIN agent_group_members m ON g.id = m.group_id
        WHERE m.agent_id = ?1
        ORDER BY g.name ASC
        "#,
    )
    .bind(agent_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get agents in a group
pub async fn get_group_agents(pool: &SqlitePool, group_id: &str) -> Result<Vec<ScanAgent>> {
    let agents = sqlx::query_as::<_, ScanAgent>(
        r#"
        SELECT a.* FROM scan_agents a
        INNER JOIN agent_group_members m ON a.id = m.agent_id
        WHERE m.group_id = ?1
        ORDER BY a.name ASC
        "#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    Ok(agents)
}

/// Get agent count in a group
pub async fn get_group_agent_count(pool: &SqlitePool, group_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM agent_group_members WHERE group_id = ?1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

// ============================================================================
// Agent Task Operations
// ============================================================================

/// Create an agent task
pub async fn create_agent_task(
    pool: &SqlitePool,
    scan_id: &str,
    agent_id: Option<&str>,
    group_id: Option<&str>,
    user_id: &str,
    task_type: &str,
    config: &str,
    targets: &str,
    priority: i32,
    timeout_seconds: i32,
) -> Result<AgentTask> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO agent_tasks (
            id, scan_id, agent_id, group_id, user_id, status, task_type,
            config, targets, priority, timeout_seconds, retry_count, max_retries,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, 3, ?12, ?12)
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(agent_id)
    .bind(group_id)
    .bind(user_id)
    .bind(TaskStatus::Pending.as_str())
    .bind(task_type)
    .bind(config)
    .bind(targets)
    .bind(priority)
    .bind(timeout_seconds)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentTask {
        id,
        scan_id: scan_id.to_string(),
        agent_id: agent_id.map(String::from),
        group_id: group_id.map(String::from),
        user_id: user_id.to_string(),
        status: TaskStatus::Pending.as_str().to_string(),
        task_type: task_type.to_string(),
        config: config.to_string(),
        targets: targets.to_string(),
        priority,
        timeout_seconds,
        retry_count: 0,
        max_retries: 3,
        error_message: None,
        assigned_at: None,
        started_at: None,
        completed_at: None,
        created_at: now,
        updated_at: now,
    })
}

/// Get pending tasks
pub async fn get_pending_tasks(pool: &SqlitePool, limit: i32) -> Result<Vec<AgentTask>> {
    let tasks = sqlx::query_as::<_, AgentTask>(
        r#"
        SELECT * FROM agent_tasks
        WHERE status = 'pending'
        ORDER BY priority DESC, created_at ASC
        LIMIT ?1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

/// Get tasks assigned to an agent
pub async fn get_tasks_for_agent(pool: &SqlitePool, agent_id: &str, limit: i32) -> Result<Vec<AgentTask>> {
    let tasks = sqlx::query_as::<_, AgentTask>(
        r#"
        SELECT * FROM agent_tasks
        WHERE agent_id = ?1
        AND status IN ('assigned', 'pending')
        ORDER BY priority DESC, created_at ASC
        LIMIT ?2
        "#,
    )
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

/// Get all tasks for a scan
pub async fn get_tasks_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<AgentTask>> {
    let tasks = sqlx::query_as::<_, AgentTask>(
        "SELECT * FROM agent_tasks WHERE scan_id = ?1 ORDER BY created_at ASC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(tasks)
}

/// Assign a task to an agent
pub async fn assign_task_to_agent(pool: &SqlitePool, task_id: &str, agent_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE agent_tasks
        SET agent_id = ?1, status = 'assigned', assigned_at = ?2, updated_at = ?2
        WHERE id = ?3
        "#,
    )
    .bind(agent_id)
    .bind(now)
    .bind(task_id)
    .execute(pool)
    .await?;

    // Increment agent's current task count
    sqlx::query(
        "UPDATE scan_agents SET current_tasks = current_tasks + 1, updated_at = ?1 WHERE id = ?2",
    )
    .bind(now)
    .bind(agent_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update task status
pub async fn update_task_status(
    pool: &SqlitePool,
    task_id: &str,
    status: &str,
    _agent_id: Option<&str>,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now();
    let is_terminal = TaskStatus::from_str(status).map(|s| s.is_terminal()).unwrap_or(false);

    // Get current agent before update
    let task: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT agent_id FROM agent_tasks WHERE id = ?1",
    )
    .bind(task_id)
    .fetch_optional(pool)
    .await?;

    // Update task
    if status == TaskStatus::Running.as_str() {
        sqlx::query(
            "UPDATE agent_tasks SET status = ?1, started_at = ?2, updated_at = ?2 WHERE id = ?3",
        )
        .bind(status)
        .bind(now)
        .bind(task_id)
        .execute(pool)
        .await?;
    } else if is_terminal {
        sqlx::query(
            r#"
            UPDATE agent_tasks
            SET status = ?1, completed_at = ?2, error_message = ?3, updated_at = ?2
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(now)
        .bind(error_message)
        .bind(task_id)
        .execute(pool)
        .await?;

        // Decrement agent's current task count
        if let Some((Some(agent_id),)) = task {
            sqlx::query(
                r#"
                UPDATE scan_agents
                SET current_tasks = MAX(0, current_tasks - 1),
                    last_task_at = ?1,
                    updated_at = ?1
                WHERE id = ?2
                "#,
            )
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
        }
    } else {
        sqlx::query("UPDATE agent_tasks SET status = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(now)
            .bind(task_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Timeout stale tasks
pub async fn timeout_stale_tasks(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query(
        r#"
        UPDATE agent_tasks
        SET status = 'timed_out',
            completed_at = datetime('now'),
            error_message = 'Task timed out',
            updated_at = datetime('now')
        WHERE status IN ('assigned', 'running')
        AND datetime(COALESCE(started_at, assigned_at, created_at), '+' || timeout_seconds || ' seconds') < datetime('now')
        "#,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// Agent Result Operations
// ============================================================================

/// Create an agent result
pub async fn create_agent_result(
    pool: &SqlitePool,
    task_id: &str,
    agent_id: &str,
    result_data: &str,
    hosts_discovered: i32,
    ports_found: i32,
    vulnerabilities_found: i32,
) -> Result<AgentResult> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO agent_results (id, task_id, agent_id, result_data, hosts_discovered, ports_found, vulnerabilities_found, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(task_id)
    .bind(agent_id)
    .bind(result_data)
    .bind(hosts_discovered)
    .bind(ports_found)
    .bind(vulnerabilities_found)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentResult {
        id,
        task_id: task_id.to_string(),
        agent_id: agent_id.to_string(),
        result_data: result_data.to_string(),
        hosts_discovered,
        ports_found,
        vulnerabilities_found,
        created_at: now,
    })
}

/// Get results for a task
pub async fn get_results_for_task(pool: &SqlitePool, task_id: &str) -> Result<Vec<AgentResult>> {
    let results = sqlx::query_as::<_, AgentResult>(
        "SELECT * FROM agent_results WHERE task_id = ?1 ORDER BY created_at ASC",
    )
    .bind(task_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Get results for a scan
pub async fn get_results_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<Vec<AgentResult>> {
    let results = sqlx::query_as::<_, AgentResult>(
        r#"
        SELECT r.* FROM agent_results r
        INNER JOIN agent_tasks t ON r.task_id = t.id
        WHERE t.scan_id = ?1
        ORDER BY r.created_at ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

// ============================================================================
// Agent Heartbeat Operations
// ============================================================================

/// Create a heartbeat record
pub async fn create_heartbeat(
    pool: &SqlitePool,
    agent_id: &str,
    cpu_usage: Option<f64>,
    memory_usage: Option<f64>,
    disk_usage: Option<f64>,
    active_tasks: i32,
    queued_tasks: i32,
) -> Result<AgentHeartbeat> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO agent_heartbeats (id, agent_id, cpu_usage, memory_usage, disk_usage, active_tasks, queued_tasks, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(agent_id)
    .bind(cpu_usage)
    .bind(memory_usage)
    .bind(disk_usage)
    .bind(active_tasks)
    .bind(queued_tasks)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentHeartbeat {
        id,
        agent_id: agent_id.to_string(),
        cpu_usage,
        memory_usage,
        disk_usage,
        active_tasks,
        queued_tasks,
        latency_ms: None,
        created_at: now,
    })
}

/// Get recent heartbeats for an agent
pub async fn get_agent_heartbeats(pool: &SqlitePool, agent_id: &str, limit: i32) -> Result<Vec<AgentHeartbeat>> {
    let heartbeats = sqlx::query_as::<_, AgentHeartbeat>(
        "SELECT * FROM agent_heartbeats WHERE agent_id = ?1 ORDER BY created_at DESC LIMIT ?2",
    )
    .bind(agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(heartbeats)
}

/// Cleanup old heartbeats (keep last 24 hours)
pub async fn cleanup_old_heartbeats(pool: &SqlitePool) -> Result<u64> {
    let cutoff = Utc::now() - Duration::hours(24);

    let result = sqlx::query("DELETE FROM agent_heartbeats WHERE created_at < ?1")
        .bind(cutoff)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
