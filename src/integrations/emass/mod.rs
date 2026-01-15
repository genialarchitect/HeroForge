//! eMASS (Enterprise Mission Assurance Support Service) Integration
//!
//! Bidirectional API integration for DoD risk management.
//!
//! ## Features
//!
//! - PKI/CAC certificate authentication via mTLS
//! - System listing and authorization status tracking
//! - Control compliance status synchronization
//! - POA&M lifecycle management
//! - Artifact upload for evidence
//! - Bidirectional sync with HeroForge findings

pub mod types;
pub mod auth;
pub mod client;
pub mod systems;
pub mod controls;
pub mod poam;
pub mod sync;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

pub use types::*;
pub use client::EmassClient;

/// eMASS integration manager
pub struct EmassIntegration {
    client: Arc<RwLock<EmassClient>>,
    settings: EmassSettings,
}

impl EmassIntegration {
    /// Create a new eMASS integration
    pub async fn new(settings: EmassSettings) -> Result<Self> {
        let client = EmassClient::new(&settings).await?;
        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            settings,
        })
    }

    /// Test connection to eMASS
    pub async fn test_connection(&self) -> Result<bool> {
        let client = self.client.read().await;
        client.test_connection().await
    }

    /// List accessible systems
    pub async fn list_systems(&self) -> Result<Vec<EmassSystem>> {
        let client = self.client.read().await;
        client.get_systems().await
    }

    /// Get system details
    pub async fn get_system(&self, system_id: i64) -> Result<EmassSystem> {
        let client = self.client.read().await;
        client.get_system(system_id).await
    }

    /// Sync control status from scan results
    pub async fn sync_controls_from_scan(
        &self,
        system_id: i64,
        findings: &[crate::compliance::types::ComplianceFinding],
    ) -> Result<sync::SyncResult> {
        let client = self.client.read().await;
        sync::sync_controls_from_findings(&client, system_id, findings).await
    }

    /// Create POA&Ms for failed checks
    pub async fn create_poams_for_failures(
        &self,
        system_id: i64,
        findings: &[crate::compliance::types::ComplianceFinding],
    ) -> Result<Vec<EmassPoam>> {
        let client = self.client.read().await;
        poam::create_poams_for_findings(&client, system_id, findings).await
    }

    /// Upload evidence artifact
    pub async fn upload_artifact(
        &self,
        system_id: i64,
        file_path: &str,
        artifact_type: ArtifactType,
    ) -> Result<EmassArtifact> {
        let client = self.client.read().await;
        client.upload_artifact(system_id, file_path, artifact_type).await
    }
}
