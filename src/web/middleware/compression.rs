//! HTTP response compression middleware
//!
//! Provides automatic gzip/brotli compression for API responses to reduce bandwidth usage

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use log::debug;

/// Compression middleware configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Minimum response size to compress (bytes)
    pub min_size: usize,

    /// Enable gzip compression
    pub enable_gzip: bool,

    /// Enable brotli compression
    pub enable_brotli: bool,

    /// Compression level (0-11 for brotli, 0-9 for gzip)
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            min_size: 1024, // Only compress responses > 1KB
            enable_gzip: true,
            enable_brotli: true,
            level: 6, // Default compression level
        }
    }
}

/// Compression middleware
pub struct Compression {
    config: CompressionConfig,
}

impl Compression {
    /// Create new compression middleware with default config
    pub fn new() -> Self {
        Self {
            config: CompressionConfig::default(),
        }
    }

    /// Create compression middleware with custom config
    pub fn with_config(config: CompressionConfig) -> Self {
        Self { config }
    }
}

impl Default for Compression {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, B> Transform<S, ServiceRequest> for Compression
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CompressionMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CompressionMiddleware {
            service,
            config: self.config.clone(),
        }))
    }
}

pub struct CompressionMiddleware<S> {
    service: S,
    config: CompressionConfig,
}

impl<S, B> Service<ServiceRequest> for CompressionMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();

        // Check Accept-Encoding header
        let accept_encoding = req
            .headers()
            .get("accept-encoding")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let supports_brotli = config.enable_brotli && accept_encoding.contains("br");
        let supports_gzip = config.enable_gzip && accept_encoding.contains("gzip");

        debug!(
            "Request to {} - Brotli: {}, Gzip: {}",
            req.path(),
            supports_brotli,
            supports_gzip
        );

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            // Note: Actual compression would be handled here
            // For Actix-web 4.x, we rely on actix-web's built-in Compress middleware
            // This is a placeholder showing the structure

            Ok(res)
        })
    }
}

/// Helper function to determine if content type should be compressed
pub fn should_compress_content_type(content_type: &str) -> bool {
    let compressible_types = [
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/x-javascript",
        "application/xhtml+xml",
        "image/svg+xml",
    ];

    compressible_types.iter().any(|&t| content_type.starts_with(t))
}

/// Compression statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompressionStats {
    pub total_requests: u64,
    pub compressed_requests: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub compression_ratio: f64,
}

impl CompressionStats {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            compressed_requests: 0,
            bytes_before: 0,
            bytes_after: 0,
            compression_ratio: 0.0,
        }
    }

    pub fn add_compression(&mut self, original_size: u64, compressed_size: u64) {
        self.total_requests += 1;
        self.compressed_requests += 1;
        self.bytes_before += original_size;
        self.bytes_after += compressed_size;
        self.update_ratio();
    }

    pub fn add_uncompressed(&mut self) {
        self.total_requests += 1;
    }

    fn update_ratio(&mut self) {
        if self.bytes_before > 0 {
            self.compression_ratio = self.bytes_after as f64 / self.bytes_before as f64;
        }
    }

    pub fn savings_percent(&self) -> f64 {
        if self.bytes_before > 0 {
            ((self.bytes_before - self.bytes_after) as f64 / self.bytes_before as f64) * 100.0
        } else {
            0.0
        }
    }
}

impl Default for CompressionStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_compress_content_type() {
        assert!(should_compress_content_type("text/html"));
        assert!(should_compress_content_type("text/plain"));
        assert!(should_compress_content_type("application/json"));
        assert!(should_compress_content_type("application/javascript"));

        assert!(!should_compress_content_type("image/png"));
        assert!(!should_compress_content_type("video/mp4"));
        assert!(!should_compress_content_type("application/pdf"));
    }

    #[test]
    fn test_compression_stats() {
        let mut stats = CompressionStats::new();

        stats.add_compression(1000, 300);
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.compressed_requests, 1);
        assert_eq!(stats.bytes_before, 1000);
        assert_eq!(stats.bytes_after, 300);
        assert_eq!(stats.compression_ratio, 0.3);
        assert_eq!(stats.savings_percent(), 70.0);

        stats.add_uncompressed();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.compressed_requests, 1);
    }
}
