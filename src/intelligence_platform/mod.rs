//! Intelligence Platform Integration (Phase 4 Sprint 18)
//!
//! Unified intelligence sources into a single platform

pub mod hub;
pub mod api;
pub mod sharing;
pub mod marketplace;
pub mod operations_center;
pub mod automation;
pub mod types;

pub use types::*;
use anyhow::Result;

/// Initialize intelligence platform
pub async fn initialize_platform(config: &PlatformConfig) -> Result<IntelligencePlatform> {
    let mut platform = IntelligencePlatform::default();

    // Initialize intelligence hub
    platform.hub = hub::initialize_hub(&config.hub_config).await?;

    // Setup intelligence API
    platform.api_endpoints = api::setup_api(&config.api_config).await?;

    // Configure sharing networks
    platform.sharing_networks = sharing::configure_networks(&config.sharing_config).await?;

    // Connect to marketplace
    if config.marketplace_enabled {
        platform.marketplace = Some(marketplace::connect_marketplace(&config.marketplace_config).await?);
    }

    // Setup operations center
    platform.operations_center = operations_center::setup_ioc(&config.ioc_config).await?;

    // Configure automation
    platform.automation = automation::configure_automation(&config.automation_config).await?;

    Ok(platform)
}
