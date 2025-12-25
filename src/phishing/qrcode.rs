//! QR Code Phishing Module
//!
//! Provides QR code generation for phishing campaigns (quishing).
//! Supports multiple output formats, tracking, and integration with
//! existing phishing campaign infrastructure.
//!
//! # Security Notice
//!
//! This module is intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized use of QR phishing (quishing) is illegal. Always obtain proper authorization.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::generate_tracking_id;

// ============================================================================
// Types and Structures
// ============================================================================

/// QR Code output format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum QrCodeFormat {
    Png,
    Svg,
    Base64Png,
    Base64Svg,
}

impl Default for QrCodeFormat {
    fn default() -> Self {
        QrCodeFormat::Png
    }
}

impl std::fmt::Display for QrCodeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrCodeFormat::Png => write!(f, "png"),
            QrCodeFormat::Svg => write!(f, "svg"),
            QrCodeFormat::Base64Png => write!(f, "base64_png"),
            QrCodeFormat::Base64Svg => write!(f, "base64_svg"),
        }
    }
}

impl std::str::FromStr for QrCodeFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "png" => Ok(QrCodeFormat::Png),
            "svg" => Ok(QrCodeFormat::Svg),
            "base64_png" | "base64png" => Ok(QrCodeFormat::Base64Png),
            "base64_svg" | "base64svg" => Ok(QrCodeFormat::Base64Svg),
            _ => Err(format!("Unknown QR code format: {}", s)),
        }
    }
}

/// Error correction level for QR codes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ErrorCorrectionLevel {
    Low,      // ~7% recovery
    Medium,   // ~15% recovery
    Quartile, // ~25% recovery
    High,     // ~30% recovery
}

impl Default for ErrorCorrectionLevel {
    fn default() -> Self {
        ErrorCorrectionLevel::Medium
    }
}

impl std::fmt::Display for ErrorCorrectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCorrectionLevel::Low => write!(f, "low"),
            ErrorCorrectionLevel::Medium => write!(f, "medium"),
            ErrorCorrectionLevel::Quartile => write!(f, "quartile"),
            ErrorCorrectionLevel::High => write!(f, "high"),
        }
    }
}

impl std::str::FromStr for ErrorCorrectionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" | "l" => Ok(ErrorCorrectionLevel::Low),
            "medium" | "m" => Ok(ErrorCorrectionLevel::Medium),
            "quartile" | "q" => Ok(ErrorCorrectionLevel::Quartile),
            "high" | "h" => Ok(ErrorCorrectionLevel::High),
            _ => Err(format!("Unknown error correction level: {}", s)),
        }
    }
}

impl From<ErrorCorrectionLevel> for EcLevel {
    fn from(level: ErrorCorrectionLevel) -> Self {
        match level {
            ErrorCorrectionLevel::Low => EcLevel::L,
            ErrorCorrectionLevel::Medium => EcLevel::M,
            ErrorCorrectionLevel::Quartile => EcLevel::Q,
            ErrorCorrectionLevel::High => EcLevel::H,
        }
    }
}

/// QR Code template type for common use cases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QrCodeTemplateType {
    Url,           // Simple URL redirect
    WiFi,          // WiFi network credentials
    VCard,         // Contact card
    PaymentRequest, // Payment request (generic)
    Custom,        // Custom content
}

impl Default for QrCodeTemplateType {
    fn default() -> Self {
        QrCodeTemplateType::Url
    }
}

impl std::fmt::Display for QrCodeTemplateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrCodeTemplateType::Url => write!(f, "url"),
            QrCodeTemplateType::WiFi => write!(f, "wifi"),
            QrCodeTemplateType::VCard => write!(f, "vcard"),
            QrCodeTemplateType::PaymentRequest => write!(f, "payment_request"),
            QrCodeTemplateType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for QrCodeTemplateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "url" => Ok(QrCodeTemplateType::Url),
            "wifi" => Ok(QrCodeTemplateType::WiFi),
            "vcard" => Ok(QrCodeTemplateType::VCard),
            "payment_request" | "payment" => Ok(QrCodeTemplateType::PaymentRequest),
            "custom" => Ok(QrCodeTemplateType::Custom),
            _ => Err(format!("Unknown QR code template type: {}", s)),
        }
    }
}

/// QR Code campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QrCampaignStatus {
    Draft,
    Active,
    Paused,
    Completed,
    Cancelled,
}

impl Default for QrCampaignStatus {
    fn default() -> Self {
        QrCampaignStatus::Draft
    }
}

impl std::fmt::Display for QrCampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrCampaignStatus::Draft => write!(f, "draft"),
            QrCampaignStatus::Active => write!(f, "active"),
            QrCampaignStatus::Paused => write!(f, "paused"),
            QrCampaignStatus::Completed => write!(f, "completed"),
            QrCampaignStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for QrCampaignStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(QrCampaignStatus::Draft),
            "active" => Ok(QrCampaignStatus::Active),
            "paused" => Ok(QrCampaignStatus::Paused),
            "completed" => Ok(QrCampaignStatus::Completed),
            "cancelled" => Ok(QrCampaignStatus::Cancelled),
            _ => Err(format!("Unknown QR campaign status: {}", s)),
        }
    }
}

/// QR Code configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodeConfig {
    /// Size of QR code in pixels (for PNG) or viewbox units (for SVG)
    pub size: u32,
    /// Error correction level
    pub error_correction: ErrorCorrectionLevel,
    /// Output format
    pub format: QrCodeFormat,
    /// Foreground color (hex)
    pub foreground_color: String,
    /// Background color (hex)
    pub background_color: String,
    /// Quiet zone margin (modules)
    pub margin: u32,
}

impl Default for QrCodeConfig {
    fn default() -> Self {
        Self {
            size: 256,
            error_correction: ErrorCorrectionLevel::Medium,
            format: QrCodeFormat::Png,
            foreground_color: "#000000".to_string(),
            background_color: "#FFFFFF".to_string(),
            margin: 4,
        }
    }
}

/// QR Code phishing campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodeCampaign {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: QrCampaignStatus,
    pub template_type: QrCodeTemplateType,
    pub tracking_domain: String,
    pub landing_page_id: Option<String>,
    pub awareness_training: bool,
    pub training_url: Option<String>,
    pub config: QrCodeConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// QR Code asset (generated QR code)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodeAsset {
    pub id: String,
    pub campaign_id: String,
    pub tracking_id: String,
    pub tracking_url: String,
    pub content_data: String, // The actual data encoded in QR
    pub format: QrCodeFormat,
    pub image_data: Option<String>, // Base64 encoded image or SVG string
    pub target_email: Option<String>,
    pub target_name: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// QR Code scan event for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCodeScanEvent {
    pub id: String,
    pub asset_id: String,
    pub tracking_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub referer: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// QR Code campaign statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCampaignStatistics {
    pub total_assets: u32,
    pub total_scans: u32,
    pub unique_scans: u32,
    pub scan_rate: f32,
    pub scans_by_device: HashMap<String, u32>,
    pub scans_by_os: HashMap<String, u32>,
    pub scans_by_country: HashMap<String, u32>,
    pub scans_over_time: HashMap<String, u32>,
}

// ============================================================================
// Request Types
// ============================================================================

/// Request to create a QR code campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateQrCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub template_type: Option<QrCodeTemplateType>,
    pub tracking_domain: Option<String>,
    pub landing_page_id: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub config: Option<QrCodeConfig>,
}

/// Request to generate a QR code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateQrCodeRequest {
    pub campaign_id: Option<String>,
    /// URL or content to encode
    pub content: String,
    /// Template type for content formatting
    pub template_type: Option<QrCodeTemplateType>,
    /// WiFi-specific settings
    pub wifi_ssid: Option<String>,
    pub wifi_password: Option<String>,
    pub wifi_security: Option<String>, // WPA, WEP, nopass
    pub wifi_hidden: Option<bool>,
    /// vCard-specific settings
    pub vcard_name: Option<String>,
    pub vcard_phone: Option<String>,
    pub vcard_email: Option<String>,
    pub vcard_org: Option<String>,
    /// Target information for personalization
    pub target_email: Option<String>,
    pub target_name: Option<String>,
    /// Generation config overrides
    pub config: Option<QrCodeConfig>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to update a QR campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateQrCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<QrCampaignStatus>,
    pub landing_page_id: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub config: Option<QrCodeConfig>,
}

// ============================================================================
// QR Code Generator
// ============================================================================

/// QR Code Generator for phishing campaigns
pub struct QrCodeGenerator {
    pool: SqlitePool,
}

impl QrCodeGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate a QR code with tracking
    pub fn generate_qr_code(
        &self,
        content: &str,
        config: &QrCodeConfig,
    ) -> Result<QrCodeOutput> {
        // Create QR code with specified error correction
        let ec_level: EcLevel = config.error_correction.clone().into();
        let code = QrCode::with_error_correction_level(content, ec_level)
            .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;

        match config.format {
            QrCodeFormat::Svg | QrCodeFormat::Base64Svg => {
                let svg_string = code
                    .render()
                    .min_dimensions(config.size, config.size)
                    .dark_color(svg::Color(&config.foreground_color))
                    .light_color(svg::Color(&config.background_color))
                    .quiet_zone(config.margin > 0)
                    .build();

                if config.format == QrCodeFormat::Base64Svg {
                    let encoded = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        svg_string.as_bytes(),
                    );
                    Ok(QrCodeOutput {
                        data: encoded,
                        content_type: "text/plain".to_string(),
                        format: QrCodeFormat::Base64Svg,
                    })
                } else {
                    Ok(QrCodeOutput {
                        data: svg_string,
                        content_type: "image/svg+xml".to_string(),
                        format: QrCodeFormat::Svg,
                    })
                }
            }
            QrCodeFormat::Png | QrCodeFormat::Base64Png => {
                // PNG format: Use SVG internally but return as data URI for embedding
                // This avoids needing the image crate dependency
                let svg_string = code
                    .render()
                    .min_dimensions(config.size, config.size)
                    .dark_color(svg::Color(&config.foreground_color))
                    .light_color(svg::Color(&config.background_color))
                    .quiet_zone(config.margin > 0)
                    .build();

                // For PNG requests, we return the SVG as base64 with appropriate metadata
                // The client can either render it as SVG or use a library to convert to PNG
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    svg_string.as_bytes(),
                );

                if config.format == QrCodeFormat::Base64Png {
                    Ok(QrCodeOutput {
                        data: encoded,
                        content_type: "text/plain".to_string(),
                        format: QrCodeFormat::Base64Svg, // Return as SVG since PNG not available
                    })
                } else {
                    // Return SVG content since PNG generation requires image crate
                    Ok(QrCodeOutput {
                        data: svg_string,
                        content_type: "image/svg+xml".to_string(),
                        format: QrCodeFormat::Svg,
                    })
                }
            }
        }
    }

    /// Build content string for WiFi QR code
    pub fn build_wifi_content(
        ssid: &str,
        password: Option<&str>,
        security: Option<&str>,
        hidden: bool,
    ) -> String {
        let security = security.unwrap_or("WPA");
        let password = password.unwrap_or("");
        let hidden = if hidden { "true" } else { "false" };
        format!("WIFI:T:{};S:{};P:{};H:{};;", security, ssid, password, hidden)
    }

    /// Build content string for vCard QR code
    pub fn build_vcard_content(
        name: &str,
        phone: Option<&str>,
        email: Option<&str>,
        org: Option<&str>,
    ) -> String {
        let mut vcard = String::from("BEGIN:VCARD\nVERSION:3.0\n");
        vcard.push_str(&format!("FN:{}\n", name));
        if let Some(phone) = phone {
            vcard.push_str(&format!("TEL:{}\n", phone));
        }
        if let Some(email) = email {
            vcard.push_str(&format!("EMAIL:{}\n", email));
        }
        if let Some(org) = org {
            vcard.push_str(&format!("ORG:{}\n", org));
        }
        vcard.push_str("END:VCARD");
        vcard
    }

    /// Create a QR code campaign
    pub async fn create_campaign(
        &self,
        user_id: &str,
        request: CreateQrCampaignRequest,
    ) -> Result<QrCodeCampaign> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let config = request.config.unwrap_or_default();
        let config_json = serde_json::to_string(&config)?;
        let tracking_domain = request.tracking_domain.unwrap_or_else(|| "track.example.com".to_string());

        sqlx::query(
            r#"
            INSERT INTO qr_campaigns (
                id, user_id, name, description, status, template_type,
                tracking_domain, landing_page_id, awareness_training,
                training_url, config, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(QrCampaignStatus::Draft.to_string())
        .bind(request.template_type.as_ref().unwrap_or(&QrCodeTemplateType::Url).to_string())
        .bind(&tracking_domain)
        .bind(&request.landing_page_id)
        .bind(request.awareness_training.unwrap_or(false))
        .bind(&request.training_url)
        .bind(&config_json)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(QrCodeCampaign {
            id,
            user_id: user_id.to_string(),
            name: request.name,
            description: request.description,
            status: QrCampaignStatus::Draft,
            template_type: request.template_type.unwrap_or_default(),
            tracking_domain,
            landing_page_id: request.landing_page_id,
            awareness_training: request.awareness_training.unwrap_or(false),
            training_url: request.training_url,
            config,
            created_at: now,
            updated_at: now,
        })
    }

    /// Generate a tracked QR code asset
    pub async fn generate_asset(
        &self,
        campaign_id: &str,
        request: GenerateQrCodeRequest,
    ) -> Result<QrCodeAsset> {
        // Get campaign for config
        let campaign = self.get_campaign(campaign_id).await?
            .ok_or_else(|| anyhow!("Campaign not found"))?;

        // Generate tracking ID and URL
        let tracking_id = generate_tracking_id();
        let tracking_url = format!("https://{}/q/{}", campaign.tracking_domain, tracking_id);

        // Build content based on template type
        let template_type = request.template_type.unwrap_or(campaign.template_type.clone());
        let content_data = match template_type {
            QrCodeTemplateType::Url => request.content.clone(),
            QrCodeTemplateType::WiFi => {
                let ssid = request.wifi_ssid.as_deref()
                    .ok_or_else(|| anyhow!("WiFi SSID required for WiFi template"))?;
                Self::build_wifi_content(
                    ssid,
                    request.wifi_password.as_deref(),
                    request.wifi_security.as_deref(),
                    request.wifi_hidden.unwrap_or(false),
                )
            }
            QrCodeTemplateType::VCard => {
                let name = request.vcard_name.as_deref()
                    .ok_or_else(|| anyhow!("Name required for vCard template"))?;
                Self::build_vcard_content(
                    name,
                    request.vcard_phone.as_deref(),
                    request.vcard_email.as_deref(),
                    request.vcard_org.as_deref(),
                )
            }
            QrCodeTemplateType::PaymentRequest | QrCodeTemplateType::Custom => {
                request.content.clone()
            }
        };

        // Use tracking URL for redirect-based tracking
        let qr_content = if matches!(template_type, QrCodeTemplateType::Url) {
            tracking_url.clone()
        } else {
            content_data.clone()
        };

        // Generate QR code
        let config = request.config.unwrap_or(campaign.config.clone());
        let output = self.generate_qr_code(&qr_content, &config)?;

        // Store asset
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let metadata_json = request.metadata.as_ref().map(|m| m.to_string());

        sqlx::query(
            r#"
            INSERT INTO qr_assets (
                id, campaign_id, tracking_id, tracking_url, content_data,
                format, image_data, target_email, target_name, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(campaign_id)
        .bind(&tracking_id)
        .bind(&tracking_url)
        .bind(&content_data)
        .bind(config.format.to_string())
        .bind(&output.data)
        .bind(&request.target_email)
        .bind(&request.target_name)
        .bind(&metadata_json)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(QrCodeAsset {
            id,
            campaign_id: campaign_id.to_string(),
            tracking_id,
            tracking_url,
            content_data,
            format: config.format,
            image_data: Some(output.data),
            target_email: request.target_email,
            target_name: request.target_name,
            metadata: request.metadata,
            created_at: now,
        })
    }

    /// Record a QR code scan event
    pub async fn record_scan(
        &self,
        tracking_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Option<(QrCodeAsset, Option<String>)>> {
        // Find asset by tracking ID
        let asset = self.get_asset_by_tracking_id(tracking_id).await?;

        if let Some(asset) = asset {
            // Parse user agent for device info
            let (device_type, os, browser) = parse_user_agent(user_agent.unwrap_or(""));

            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            sqlx::query(
                r#"
                INSERT INTO qr_scans (
                    id, asset_id, tracking_id, ip_address, user_agent,
                    device_type, os, browser, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&asset.id)
            .bind(tracking_id)
            .bind(ip_address)
            .bind(user_agent)
            .bind(&device_type)
            .bind(&os)
            .bind(&browser)
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;

            // Get campaign for redirect URL
            let campaign = self.get_campaign(&asset.campaign_id).await?;
            let redirect_url = campaign.and_then(|c| {
                if c.awareness_training {
                    c.training_url
                } else {
                    c.landing_page_id.map(|_| format!("/c/{}", tracking_id))
                }
            });

            return Ok(Some((asset, redirect_url)));
        }

        Ok(None)
    }

    /// Get campaign by ID
    pub async fn get_campaign(&self, campaign_id: &str) -> Result<Option<QrCodeCampaign>> {
        let row = sqlx::query_as::<_, (
            String, String, String, Option<String>, String, String,
            String, Option<String>, bool, Option<String>, String,
            String, String,
        )>(
            r#"
            SELECT id, user_id, name, description, status, template_type,
                   tracking_domain, landing_page_id, awareness_training,
                   training_url, config, created_at, updated_at
            FROM qr_campaigns WHERE id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let config: QrCodeConfig = serde_json::from_str(&r.10).unwrap_or_default();
            QrCodeCampaign {
                id: r.0,
                user_id: r.1,
                name: r.2,
                description: r.3,
                status: r.4.parse().unwrap_or_default(),
                template_type: r.5.parse().unwrap_or_default(),
                tracking_domain: r.6,
                landing_page_id: r.7,
                awareness_training: r.8,
                training_url: r.9,
                config,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.11)
                    .unwrap()
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.12)
                    .unwrap()
                    .with_timezone(&Utc),
            }
        }))
    }

    /// Get asset by tracking ID
    pub async fn get_asset_by_tracking_id(&self, tracking_id: &str) -> Result<Option<QrCodeAsset>> {
        let row = sqlx::query_as::<_, (
            String, String, String, String, String, String,
            Option<String>, Option<String>, Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT id, campaign_id, tracking_id, tracking_url, content_data,
                   format, image_data, target_email, target_name, metadata, created_at
            FROM qr_assets WHERE tracking_id = ?
            "#,
        )
        .bind(tracking_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| QrCodeAsset {
            id: r.0,
            campaign_id: r.1,
            tracking_id: r.2,
            tracking_url: r.3,
            content_data: r.4,
            format: r.5.parse().unwrap_or_default(),
            image_data: r.6,
            target_email: r.7,
            target_name: r.8,
            metadata: r.9.and_then(|m| serde_json::from_str(&m).ok()),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.10)
                .unwrap()
                .with_timezone(&Utc),
        }))
    }

    /// List campaigns for a user
    pub async fn list_campaigns(&self, user_id: &str) -> Result<Vec<QrCodeCampaign>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, Option<String>, String, String,
            String, Option<String>, bool, Option<String>, String,
            String, String,
        )>(
            r#"
            SELECT id, user_id, name, description, status, template_type,
                   tracking_domain, landing_page_id, awareness_training,
                   training_url, config, created_at, updated_at
            FROM qr_campaigns WHERE user_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let config: QrCodeConfig = serde_json::from_str(&r.10).unwrap_or_default();
                QrCodeCampaign {
                    id: r.0,
                    user_id: r.1,
                    name: r.2,
                    description: r.3,
                    status: r.4.parse().unwrap_or_default(),
                    template_type: r.5.parse().unwrap_or_default(),
                    tracking_domain: r.6,
                    landing_page_id: r.7,
                    awareness_training: r.8,
                    training_url: r.9,
                    config,
                    created_at: chrono::DateTime::parse_from_rfc3339(&r.11)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&r.12)
                        .unwrap()
                        .with_timezone(&Utc),
                }
            })
            .collect())
    }

    /// List assets for a campaign
    pub async fn list_assets(&self, campaign_id: &str) -> Result<Vec<QrCodeAsset>> {
        let rows = sqlx::query_as::<_, (
            String, String, String, String, String, String,
            Option<String>, Option<String>, Option<String>, Option<String>, String,
        )>(
            r#"
            SELECT id, campaign_id, tracking_id, tracking_url, content_data,
                   format, image_data, target_email, target_name, metadata, created_at
            FROM qr_assets WHERE campaign_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| QrCodeAsset {
                id: r.0,
                campaign_id: r.1,
                tracking_id: r.2,
                tracking_url: r.3,
                content_data: r.4,
                format: r.5.parse().unwrap_or_default(),
                image_data: r.6,
                target_email: r.7,
                target_name: r.8,
                metadata: r.9.and_then(|m| serde_json::from_str(&m).ok()),
                created_at: chrono::DateTime::parse_from_rfc3339(&r.10)
                    .unwrap()
                    .with_timezone(&Utc),
            })
            .collect())
    }

    /// Get campaign statistics
    pub async fn get_campaign_statistics(&self, campaign_id: &str) -> Result<QrCampaignStatistics> {
        // Count assets
        let total_assets = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM qr_assets WHERE campaign_id = ?",
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0 as u32;

        // Count total scans
        let total_scans = sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT COUNT(*) FROM qr_scans s
            JOIN qr_assets a ON s.asset_id = a.id
            WHERE a.campaign_id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0 as u32;

        // Count unique scans (by IP + asset)
        let unique_scans = sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT COUNT(DISTINCT s.ip_address || '-' || s.asset_id) FROM qr_scans s
            JOIN qr_assets a ON s.asset_id = a.id
            WHERE a.campaign_id = ?
            "#,
        )
        .bind(campaign_id)
        .fetch_one(&self.pool)
        .await?
        .0 as u32;

        let scan_rate = if total_assets > 0 {
            unique_scans as f32 / total_assets as f32 * 100.0
        } else {
            0.0
        };

        // Scans by device type
        let device_rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT COALESCE(s.device_type, 'unknown'), COUNT(*) FROM qr_scans s
            JOIN qr_assets a ON s.asset_id = a.id
            WHERE a.campaign_id = ?
            GROUP BY s.device_type
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        let scans_by_device: HashMap<String, u32> = device_rows
            .into_iter()
            .map(|(k, v)| (k, v as u32))
            .collect();

        // Scans by OS
        let os_rows = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT COALESCE(s.os, 'unknown'), COUNT(*) FROM qr_scans s
            JOIN qr_assets a ON s.asset_id = a.id
            WHERE a.campaign_id = ?
            GROUP BY s.os
            "#,
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        let scans_by_os: HashMap<String, u32> = os_rows
            .into_iter()
            .map(|(k, v)| (k, v as u32))
            .collect();

        Ok(QrCampaignStatistics {
            total_assets,
            total_scans,
            unique_scans,
            scan_rate,
            scans_by_device,
            scans_by_os,
            scans_by_country: HashMap::new(), // Would need GeoIP lookup
            scans_over_time: HashMap::new(),  // Would need time bucketing
        })
    }

    /// Update campaign status
    pub async fn update_campaign_status(
        &self,
        campaign_id: &str,
        status: QrCampaignStatus,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE qr_campaigns SET status = ?, updated_at = ? WHERE id = ?",
        )
        .bind(status.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(campaign_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update campaign
    pub async fn update_campaign(
        &self,
        campaign_id: &str,
        request: UpdateQrCampaignRequest,
    ) -> Result<()> {
        let now = Utc::now();

        let mut query_parts = Vec::new();
        let mut bindings: Vec<String> = Vec::new();

        if let Some(name) = &request.name {
            query_parts.push("name = ?");
            bindings.push(name.clone());
        }
        if let Some(description) = &request.description {
            query_parts.push("description = ?");
            bindings.push(description.clone());
        }
        if let Some(status) = &request.status {
            query_parts.push("status = ?");
            bindings.push(status.to_string());
        }
        if let Some(landing_page_id) = &request.landing_page_id {
            query_parts.push("landing_page_id = ?");
            bindings.push(landing_page_id.clone());
        }
        if let Some(awareness_training) = request.awareness_training {
            query_parts.push("awareness_training = ?");
            bindings.push(if awareness_training { "1" } else { "0" }.to_string());
        }
        if let Some(training_url) = &request.training_url {
            query_parts.push("training_url = ?");
            bindings.push(training_url.clone());
        }
        if let Some(config) = &request.config {
            query_parts.push("config = ?");
            bindings.push(serde_json::to_string(config)?);
        }

        query_parts.push("updated_at = ?");
        bindings.push(now.to_rfc3339());

        let query = format!(
            "UPDATE qr_campaigns SET {} WHERE id = ?",
            query_parts.join(", ")
        );

        let mut q = sqlx::query(&query);
        for binding in bindings {
            q = q.bind(binding);
        }
        q = q.bind(campaign_id);

        q.execute(&self.pool).await?;

        Ok(())
    }

    /// Delete a campaign and all associated assets
    pub async fn delete_campaign(&self, campaign_id: &str) -> Result<()> {
        // Delete scans first (FK constraint)
        sqlx::query(
            r#"
            DELETE FROM qr_scans WHERE asset_id IN (
                SELECT id FROM qr_assets WHERE campaign_id = ?
            )
            "#,
        )
        .bind(campaign_id)
        .execute(&self.pool)
        .await?;

        // Delete assets
        sqlx::query("DELETE FROM qr_assets WHERE campaign_id = ?")
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;

        // Delete campaign
        sqlx::query("DELETE FROM qr_campaigns WHERE id = ?")
            .bind(campaign_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

// ============================================================================
// Helper Types
// ============================================================================

/// QR Code generation output
pub struct QrCodeOutput {
    pub data: String,
    pub content_type: String,
    pub format: QrCodeFormat,
}

/// Parse user agent for device info (simplified)
fn parse_user_agent(user_agent: &str) -> (Option<String>, Option<String>, Option<String>) {
    let ua = user_agent.to_lowercase();

    // Device type detection
    let device_type = if ua.contains("mobile") || ua.contains("android") || ua.contains("iphone") {
        Some("mobile".to_string())
    } else if ua.contains("tablet") || ua.contains("ipad") {
        Some("tablet".to_string())
    } else {
        Some("desktop".to_string())
    };

    // OS detection
    let os = if ua.contains("windows") {
        Some("Windows".to_string())
    } else if ua.contains("mac os") || ua.contains("macos") {
        Some("macOS".to_string())
    } else if ua.contains("iphone") || ua.contains("ipad") {
        Some("iOS".to_string())
    } else if ua.contains("android") {
        Some("Android".to_string())
    } else if ua.contains("linux") {
        Some("Linux".to_string())
    } else {
        None
    };

    // Browser detection
    let browser = if ua.contains("chrome") && !ua.contains("edg") {
        Some("Chrome".to_string())
    } else if ua.contains("firefox") {
        Some("Firefox".to_string())
    } else if ua.contains("safari") && !ua.contains("chrome") {
        Some("Safari".to_string())
    } else if ua.contains("edg") {
        Some("Edge".to_string())
    } else {
        None
    };

    (device_type, os, browser)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wifi_content_generation() {
        let content = QrCodeGenerator::build_wifi_content(
            "MyNetwork",
            Some("password123"),
            Some("WPA"),
            false,
        );
        assert_eq!(content, "WIFI:T:WPA;S:MyNetwork;P:password123;H:false;;");
    }

    #[test]
    fn test_vcard_content_generation() {
        let content = QrCodeGenerator::build_vcard_content(
            "John Doe",
            Some("+1234567890"),
            Some("john@example.com"),
            Some("Acme Corp"),
        );
        assert!(content.contains("FN:John Doe"));
        assert!(content.contains("TEL:+1234567890"));
        assert!(content.contains("EMAIL:john@example.com"));
        assert!(content.contains("ORG:Acme Corp"));
    }

    #[test]
    fn test_user_agent_parsing() {
        let (device, os, browser) = parse_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        );
        assert_eq!(device, Some("desktop".to_string()));
        assert_eq!(os, Some("Windows".to_string()));
        assert_eq!(browser, Some("Chrome".to_string()));
    }
}
