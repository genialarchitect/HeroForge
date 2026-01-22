use super::types::{DbType, EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use super::wordlists::WordlistManager;
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

// Database client imports
use mysql_async::prelude::*;
use sqlx::Row;

// Lazy static wordlist manager for database credential enumeration
lazy_static::lazy_static! {
    static ref WORDLISTS: WordlistManager = WordlistManager::new();
}

/// Enumerate database service
pub async fn enumerate_database(
    target: &ScanTarget,
    port: u16,
    db_type: DbType,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting {:?} enumeration for {}:{} with depth: {:?}",
        db_type, target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();

    // Passive: Just version info (already captured in service detection)
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Database(db_type.clone()),
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Dispatch to appropriate database enumeration based on type
    match db_type {
        DbType::MySQL => {
            findings.extend(enumerate_mysql(target, port, depth, timeout, progress_tx).await);
        }
        DbType::PostgreSQL => {
            findings.extend(enumerate_postgres(target, port, depth, timeout, progress_tx).await);
        }
        DbType::MongoDB => {
            findings.extend(enumerate_mongodb(target, port, depth, timeout, progress_tx).await);
        }
        DbType::Redis => {
            findings.extend(enumerate_redis(target, port, depth, timeout, progress_tx).await);
        }
        DbType::Elasticsearch => {
            findings.extend(enumerate_elasticsearch(target, port, depth, timeout).await);
        }
    }

    metadata.insert("findings_count".to_string(), findings.len().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Database(db_type),
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// MySQL enumeration
async fn enumerate_mysql(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get credentials from wordlist manager
    let credentials = WORDLISTS.get_db_credentials(depth);
    info!("Testing {} credential combinations for MySQL on {}:{}", credentials.len(), target.ip, port);

    for (username, password) in credentials {
        let username = username.as_str();
        let password = password.as_str();
        let conn_str = format!(
            "mysql://{}:{}@{}:{}/mysql",
            username, password, target.ip, port
        );

        match tokio::time::timeout(
            timeout,
            mysql_async::Conn::new(mysql_async::OptsBuilder::from_opts(
                mysql_async::Opts::from_url(&conn_str).unwrap_or_default(),
            )),
        )
        .await
        {
            Ok(Ok(mut conn)) => {
                // Successfully connected with default credentials
                findings.push(
                    Finding::with_confidence(
                        FindingType::DefaultCredentials,
                        format!("MySQL: {}:{}", username, if password.is_empty() { "(empty)" } else { password }),
                        95,
                    )
                    .with_metadata("username".to_string(), username.to_string())
                    .with_metadata("password".to_string(), password.to_string()),
                );

                // Send progress
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                        ip: target.ip.to_string(),
                        port,
                        finding_type: "DefaultCredentials".to_string(),
                        value: format!("MySQL: {}", username),
                    });
                }

                // Try to list databases
                if let Ok(databases) = conn.query::<String, _>("SHOW DATABASES").await {
                    for db in databases {
                        findings.push(
                            Finding::new(FindingType::DatabaseList, db.clone())
                                .with_metadata("database_type".to_string(), "MySQL".to_string()),
                        );
                    }
                }

                // Try to enumerate users (aggressive only)
                if matches!(depth, EnumDepth::Aggressive) {
                    if let Ok(users) = conn
                        .query::<(String, String), _>("SELECT user, host FROM mysql.user")
                        .await
                    {
                        for (user, host) in users {
                            findings.push(
                                Finding::new(FindingType::UserList, format!("{}@{}", user, host))
                                    .with_metadata("username".to_string(), user)
                                    .with_metadata("host".to_string(), host),
                            );
                        }
                    }
                }

                let _ = conn.disconnect().await;
                break; // Found valid credentials, stop trying others
            }
            Ok(Err(_)) | Err(_) => {
                debug!("MySQL connection failed for {}:{}", username, password);
            }
        }
    }

    findings
}

/// PostgreSQL enumeration
async fn enumerate_postgres(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get credentials from wordlist manager
    let credentials = WORDLISTS.get_db_credentials(depth);
    info!("Testing {} credential combinations for PostgreSQL on {}:{}", credentials.len(), target.ip, port);

    for (username, password) in credentials {
        let username = username.as_str();
        let password = password.as_str();
        let conn_str = format!(
            "postgres://{}:{}@{}:{}/postgres",
            username, password, target.ip, port
        );

        match tokio::time::timeout(timeout, sqlx::postgres::PgPool::connect(&conn_str)).await {
            Ok(Ok(pool)) => {
                // Successfully connected
                findings.push(
                    Finding::with_confidence(
                        FindingType::DefaultCredentials,
                        format!("PostgreSQL: {}:{}", username, if password.is_empty() { "(empty)" } else { password }),
                        95,
                    )
                    .with_metadata("username".to_string(), username.to_string())
                    .with_metadata("password".to_string(), password.to_string()),
                );

                // Send progress
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                        ip: target.ip.to_string(),
                        port,
                        finding_type: "DefaultCredentials".to_string(),
                        value: format!("PostgreSQL: {}", username),
                    });
                }

                // List databases
                if let Ok(rows) = sqlx::query("SELECT datname FROM pg_database WHERE datistemplate = false")
                    .fetch_all(&pool)
                    .await
                {
                    for row in rows {
                        if let Ok(db_name) = row.try_get::<String, _>(0) {
                            findings.push(
                                Finding::new(FindingType::DatabaseList, db_name.clone())
                                    .with_metadata("database_type".to_string(), "PostgreSQL".to_string()),
                            );
                        }
                    }
                }

                // Enumerate users (aggressive only)
                if matches!(depth, EnumDepth::Aggressive) {
                    if let Ok(rows) = sqlx::query("SELECT usename FROM pg_user")
                        .fetch_all(&pool)
                        .await
                    {
                        for row in rows {
                            if let Ok(username) = row.try_get::<String, _>(0) {
                                findings.push(
                                    Finding::new(FindingType::UserList, username.clone())
                                        .with_metadata("database_type".to_string(), "PostgreSQL".to_string()),
                                );
                            }
                        }
                    }
                }

                pool.close().await;
                break;
            }
            Ok(Err(_)) | Err(_) => {
                debug!("PostgreSQL connection failed for {}:{}", username, password);
            }
        }
    }

    findings
}

/// MongoDB enumeration
async fn enumerate_mongodb(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try unauthenticated connection first
    let conn_str = format!("mongodb://{}:{}/", target.ip, port);

    match tokio::time::timeout(
        timeout,
        mongodb::Client::with_uri_str(&conn_str),
    )
    .await
    {
        Ok(Ok(client)) => {
            // Check if we can access without authentication
            if let Ok(db_names) = client.list_database_names().await {
                if !db_names.is_empty() {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::DefaultCredentials,
                            "MongoDB: Unauthenticated access".to_string(),
                            95,
                        )
                        .with_metadata("authentication".to_string(), "none".to_string()),
                    );

                    // Send progress
                    if let Some(ref tx) = progress_tx {
                        let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                            ip: target.ip.to_string(),
                            port,
                            finding_type: "DefaultCredentials".to_string(),
                            value: "MongoDB: No authentication".to_string(),
                        });
                    }

                    // List databases
                    for db_name in db_names {
                        findings.push(
                            Finding::new(FindingType::DatabaseList, db_name.clone())
                                .with_metadata("database_type".to_string(), "MongoDB".to_string()),
                        );

                        // For aggressive scans, list collections
                        if matches!(depth, EnumDepth::Aggressive) {
                            let db = client.database(&db_name);
                            if let Ok(collections) = db.list_collection_names().await {
                                for coll in collections {
                                    findings.push(
                                        Finding::new(FindingType::TableList, format!("{}.{}", db_name, coll))
                                            .with_metadata("database".to_string(), db_name.clone())
                                            .with_metadata("collection".to_string(), coll),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(Err(_)) | Err(_) => {
            debug!("MongoDB connection failed");
        }
    }

    findings
}

/// Redis enumeration
async fn enumerate_redis(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try unauthenticated connection
    let conn_str = format!("redis://{}:{}/", target.ip, port);

    // redis::Client::open is synchronous, so call it directly
    if let Ok(client) = redis::Client::open(conn_str.as_str()) {
        // Now get async connection with timeout
        match tokio::time::timeout(timeout, client.get_multiplexed_async_connection()).await {
            Ok(Ok(mut conn)) => {
                // Try INFO command
                match redis::cmd("INFO")
                    .query_async::<String>(&mut conn)
                    .await
                {
                    Ok(info) => {
                        findings.push(
                            Finding::with_confidence(
                                FindingType::DefaultCredentials,
                                "Redis: Unauthenticated access".to_string(),
                                95,
                            )
                            .with_metadata("authentication".to_string(), "none".to_string()),
                        );

                        // Send progress
                        if let Some(ref tx) = progress_tx {
                            let _ = tx.send(ScanProgressMessage::EnumerationFinding {
                                ip: target.ip.to_string(),
                                port,
                                finding_type: "DefaultCredentials".to_string(),
                                value: "Redis: No authentication".to_string(),
                            });
                        }

                        // Parse version from INFO
                        for line in info.lines() {
                            if line.starts_with("redis_version:") {
                                let version = line.split(':').nth(1).unwrap_or("").trim();
                                findings.push(
                                    Finding::new(FindingType::Version, format!("Redis {}", version))
                                        .with_metadata("version".to_string(), version.to_string()),
                                );
                            }
                        }

                        // For aggressive scans, try to get keyspace info
                        if matches!(depth, EnumDepth::Aggressive) {
                            if let Ok(dbsize) = redis::cmd("DBSIZE")
                                .query_async::<i64>(&mut conn)
                                .await
                            {
                                findings.push(
                                    Finding::new(FindingType::DatabaseList, format!("Keys: {}", dbsize))
                                        .with_metadata("key_count".to_string(), dbsize.to_string()),
                                );
                            }

                            // Try CONFIG GET (dangerous if writable)
                            if let Ok(config) = redis::cmd("CONFIG")
                                .arg("GET")
                                .arg("dir")
                                .query_async::<Vec<String>>(&mut conn)
                                .await
                            {
                                if config.len() >= 2 {
                                    findings.push(
                                        Finding::new(
                                            FindingType::Misconfiguration,
                                            format!("CONFIG accessible: dir={}", config[1]),
                                        )
                                        .with_metadata("config_key".to_string(), "dir".to_string())
                                        .with_metadata("config_value".to_string(), config[1].clone()),
                                    );
                                }
                            }
                        }
                    }
                    Err(_) => {
                        debug!("Redis INFO command failed - may require authentication");
                    }
                }
            }
            Ok(Err(_)) | Err(_) => {
                debug!("Redis connection failed");
            }
        }
    }

    findings
}

/// Elasticsearch enumeration (HTTP-based)
async fn enumerate_elasticsearch(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let base_url = format!("http://{}:{}", target.ip, port);
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .unwrap_or_default();

    // Try root endpoint
    if let Ok(response) = client.get(&base_url).send().await {
        if response.status().is_success() {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                // Extract version
                if let Some(version) = json.get("version").and_then(|v| v.get("number")) {
                    findings.push(
                        Finding::new(
                            FindingType::Version,
                            format!("Elasticsearch {}", version.as_str().unwrap_or("unknown")),
                        )
                        .with_metadata("version".to_string(), version.to_string()),
                    );
                }

                findings.push(
                    Finding::with_confidence(
                        FindingType::DefaultCredentials,
                        "Elasticsearch: Unauthenticated access".to_string(),
                        90,
                    )
                    .with_metadata("authentication".to_string(), "none".to_string()),
                );
            }
        }
    }

    // List indices (aggressive only)
    if matches!(depth, EnumDepth::Aggressive) {
        let indices_url = format!("{}/_cat/indices?format=json", base_url);
        if let Ok(response) = client.get(&indices_url).send().await {
            if let Ok(indices) = response.json::<Vec<serde_json::Value>>().await {
                for index in indices {
                    if let Some(index_name) = index.get("index").and_then(|i| i.as_str()) {
                        findings.push(
                            Finding::new(FindingType::DatabaseList, index_name.to_string())
                                .with_metadata("database_type".to_string(), "Elasticsearch".to_string())
                                .with_metadata("type".to_string(), "index".to_string()),
                        );
                    }
                }
            }
        }
    }

    findings
}
