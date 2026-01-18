//! eMASS HTTP Client
//!
//! HTTP client with mTLS for eMASS API communication.

use anyhow::{Result, Context, bail};
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

use super::auth::PkiAuth;
use super::types::*;

/// eMASS API client
pub struct EmassClient {
    client: Client,
    settings: EmassSettings,
}

impl EmassClient {
    /// Create a new eMASS client with PKI authentication
    pub async fn new(settings: &EmassSettings) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .danger_accept_invalid_certs(false);

        // Add PKI certificate if configured
        if let (Some(cert_path), Some(cert_password)) =
            (&settings.certificate_path, &settings.certificate_password)
        {
            let identity = PkiAuth::load_pkcs12(cert_path, cert_password)?;
            client_builder = client_builder.identity(identity);
        }

        // Add DoD root CA certificates
        client_builder = Self::add_dod_root_certs(client_builder)?;

        let client = client_builder
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            settings: settings.clone(),
        })
    }

    /// Add DoD root CA certificates to the client builder
    fn add_dod_root_certs(builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        // In production, these would be loaded from a CA bundle file
        // For now, we use the system's root CA store
        Ok(builder.tls_built_in_root_certs(true))
    }

    /// Test connection to eMASS API
    pub async fn test_connection(&self) -> Result<bool> {
        let url = format!("{}/api/systems", self.settings.api_url);

        let response = self.client
            .get(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .send()
            .await
            .context("Failed to connect to eMASS API")?;

        Ok(response.status().is_success())
    }

    /// Make authenticated GET request
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}{}", self.settings.api_url, endpoint);

        let response = self.client
            .get(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .header("Accept", "application/json")
            .send()
            .await
            .context("GET request failed")?;

        self.handle_response(response).await
    }

    /// Make authenticated POST request
    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.settings.api_url, endpoint);

        let response = self.client
            .post(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .context("POST request failed")?;

        self.handle_response(response).await
    }

    /// Make authenticated PUT request
    pub async fn put<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.settings.api_url, endpoint);

        let response = self.client
            .put(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .context("PUT request failed")?;

        self.handle_response(response).await
    }

    /// Make authenticated DELETE request
    pub async fn delete(&self, endpoint: &str) -> Result<()> {
        let url = format!("{}{}", self.settings.api_url, endpoint);

        let response = self.client
            .delete(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .send()
            .await
            .context("DELETE request failed")?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("DELETE failed with status {}: {}", status, text)
        }
    }

    /// Upload multipart file
    ///
    /// Validates file before upload:
    /// - File must exist
    /// - Maximum size: 10MB
    /// - Allowed extensions: pdf, xlsx, docx, xml, zip, txt, json, png, jpg, jpeg, gif, csv
    pub async fn upload_file(&self, endpoint: &str, file_path: &str, file_name: &str) -> Result<Response> {
        use std::path::Path;

        // Maximum file size for eMASS artifacts (10MB)
        const MAX_ARTIFACT_SIZE: u64 = 10 * 1024 * 1024;

        // Allowed file extensions for eMASS artifacts
        const ALLOWED_EXTENSIONS: &[&str] = &[
            "pdf", "xlsx", "xls", "docx", "doc", "xml", "zip",
            "txt", "json", "png", "jpg", "jpeg", "gif", "csv",
            "pptx", "ppt", "rtf", "html", "htm"
        ];

        // Validate file exists and get metadata
        let metadata = tokio::fs::metadata(file_path)
            .await
            .with_context(|| format!("File not found: {}", file_path))?;

        // Validate file size
        if metadata.len() > MAX_ARTIFACT_SIZE {
            bail!(
                "File size ({:.2} MB) exceeds maximum allowed size of 10 MB",
                metadata.len() as f64 / (1024.0 * 1024.0)
            );
        }

        // Validate file extension
        let extension = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !ALLOWED_EXTENSIONS.contains(&extension.as_str()) {
            bail!(
                "File type '.{}' is not allowed for eMASS artifacts. Allowed types: {}",
                extension,
                ALLOWED_EXTENSIONS.join(", ")
            );
        }

        let url = format!("{}{}", self.settings.api_url, endpoint);

        let file_content = tokio::fs::read(file_path)
            .await
            .with_context(|| format!("Failed to read file: {}", file_path))?;

        let part = reqwest::multipart::Part::bytes(file_content)
            .file_name(file_name.to_string());

        let form = reqwest::multipart::Form::new()
            .part("file", part);

        let response = self.client
            .post(&url)
            .header("api-key", &self.settings.api_key)
            .header("user-uid", &self.settings.user_uid)
            .multipart(form)
            .send()
            .await
            .context("File upload failed")?;

        Ok(response)
    }

    /// Handle API response
    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let status = response.status();

        match status {
            StatusCode::OK | StatusCode::CREATED => {
                response.json::<T>()
                    .await
                    .context("Failed to parse response JSON")
            }
            StatusCode::UNAUTHORIZED => {
                bail!("eMASS authentication failed - check API key and certificate")
            }
            StatusCode::FORBIDDEN => {
                bail!("Access forbidden - insufficient permissions for this eMASS resource")
            }
            StatusCode::NOT_FOUND => {
                bail!("eMASS resource not found")
            }
            StatusCode::TOO_MANY_REQUESTS => {
                bail!("eMASS rate limit exceeded - please wait before retrying")
            }
            _ => {
                let text = response.text().await.unwrap_or_default();
                bail!("eMASS API error ({}): {}", status, text)
            }
        }
    }

    // System operations

    /// Get list of accessible systems
    pub async fn get_systems(&self) -> Result<Vec<EmassSystem>> {
        #[derive(serde::Deserialize)]
        struct SystemsResponse {
            data: Vec<EmassSystem>,
        }

        let response: SystemsResponse = self.get("/api/systems").await?;
        Ok(response.data)
    }

    /// Get system by ID
    pub async fn get_system(&self, system_id: i64) -> Result<EmassSystem> {
        #[derive(serde::Deserialize)]
        struct SystemResponse {
            data: EmassSystem,
        }

        let response: SystemResponse = self.get(&format!("/api/systems/{}", system_id)).await?;
        Ok(response.data)
    }

    // Control operations

    /// Get controls for a system
    pub async fn get_controls(&self, system_id: i64) -> Result<Vec<EmassControl>> {
        #[derive(serde::Deserialize)]
        struct ControlsResponse {
            data: Vec<EmassControl>,
        }

        let response: ControlsResponse = self.get(&format!("/api/systems/{}/controls", system_id)).await?;
        Ok(response.data)
    }

    /// Update control status
    pub async fn update_control(&self, system_id: i64, control: &EmassControl) -> Result<EmassControl> {
        #[derive(serde::Deserialize)]
        struct ControlResponse {
            data: EmassControl,
        }

        let response: ControlResponse = self.put(
            &format!("/api/systems/{}/controls", system_id),
            control
        ).await?;
        Ok(response.data)
    }

    // POA&M operations

    /// Get POA&Ms for a system
    pub async fn get_poams(&self, system_id: i64) -> Result<Vec<EmassPoam>> {
        #[derive(serde::Deserialize)]
        struct PoamsResponse {
            data: Vec<EmassPoam>,
        }

        let response: PoamsResponse = self.get(&format!("/api/systems/{}/poams", system_id)).await?;
        Ok(response.data)
    }

    /// Create POA&M
    pub async fn create_poam(&self, system_id: i64, poam: &EmassPoam) -> Result<EmassPoam> {
        #[derive(serde::Deserialize)]
        struct PoamResponse {
            data: EmassPoam,
        }

        let response: PoamResponse = self.post(
            &format!("/api/systems/{}/poams", system_id),
            poam
        ).await?;
        Ok(response.data)
    }

    /// Update POA&M
    pub async fn update_poam(&self, system_id: i64, poam: &EmassPoam) -> Result<EmassPoam> {
        #[derive(serde::Deserialize)]
        struct PoamResponse {
            data: EmassPoam,
        }

        let response: PoamResponse = self.put(
            &format!("/api/systems/{}/poams", system_id),
            poam
        ).await?;
        Ok(response.data)
    }

    // Artifact operations

    /// Get artifacts for a system
    pub async fn get_artifacts(&self, system_id: i64) -> Result<Vec<EmassArtifact>> {
        #[derive(serde::Deserialize)]
        struct ArtifactsResponse {
            data: Vec<EmassArtifact>,
        }

        let response: ArtifactsResponse = self.get(&format!("/api/systems/{}/artifacts", system_id)).await?;
        Ok(response.data)
    }

    /// Upload artifact
    pub async fn upload_artifact(
        &self,
        system_id: i64,
        file_path: &str,
        artifact_type: ArtifactType,
    ) -> Result<EmassArtifact> {
        let file_name = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("artifact");

        let response = self.upload_file(
            &format!("/api/systems/{}/artifacts?artifactType={:?}", system_id, artifact_type),
            file_path,
            file_name,
        ).await?;

        #[derive(serde::Deserialize)]
        struct ArtifactResponse {
            data: EmassArtifact,
        }

        let artifact_response: ArtifactResponse = response.json().await
            .context("Failed to parse artifact upload response")?;

        Ok(artifact_response.data)
    }
}
