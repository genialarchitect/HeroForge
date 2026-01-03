//! Region-based request routing (Sprint 9)
//!
//! This module provides geo-based routing for distributing requests to the nearest
//! regional endpoint based on client IP address geolocation.

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::LocalBoxFuture;
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::net::IpAddr;
use std::sync::LazyLock;

/// Available regions for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    UsEast,
    UsWest,
    EuWest,
    EuCentral,
    ApSoutheast,
    ApNortheast,
}

impl Region {
    /// Get the region code string
    pub fn code(&self) -> &'static str {
        match self {
            Region::UsEast => "us-east",
            Region::UsWest => "us-west",
            Region::EuWest => "eu-west",
            Region::EuCentral => "eu-central",
            Region::ApSoutheast => "ap-southeast",
            Region::ApNortheast => "ap-northeast",
        }
    }

    /// Parse region from string code
    pub fn from_code(code: &str) -> Option<Region> {
        match code.to_lowercase().as_str() {
            "us-east" => Some(Region::UsEast),
            "us-west" => Some(Region::UsWest),
            "eu-west" => Some(Region::EuWest),
            "eu-central" => Some(Region::EuCentral),
            "ap-southeast" => Some(Region::ApSoutheast),
            "ap-northeast" => Some(Region::ApNortheast),
            _ => None,
        }
    }
}

/// IP range to region mapping for geolocation
/// This uses a simplified approach based on IP block assignments to regional registries:
/// - ARIN (North America): 3.0.0.0/8, 4.0.0.0/8, 8.0.0.0/8, etc.
/// - RIPE (Europe): 2.0.0.0/8, 5.0.0.0/8, 31.0.0.0/8, etc.
/// - APNIC (Asia-Pacific): 1.0.0.0/8, 14.0.0.0/8, 27.0.0.0/8, etc.
/// - LACNIC (Latin America): 177.0.0.0/8, 179.0.0.0/8, 181.0.0.0/8, etc.
/// - AFRINIC (Africa): 41.0.0.0/8, 102.0.0.0/8, 105.0.0.0/8, etc.
static REGION_MAPPINGS: LazyLock<HashMap<u8, Region>> = LazyLock::new(|| {
    let mut map = HashMap::new();

    // North America (ARIN) - route to US regions
    for first_octet in [3, 4, 8, 12, 13, 15, 16, 17, 18, 19, 20, 23, 24, 32, 34, 35, 38, 40, 44, 45, 47, 48, 50, 52, 54, 55, 56, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146, 147, 148, 149, 152, 155, 156, 157, 158, 159, 160, 161, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216] {
        // Route US IPs based on first octet ranges
        // Lower ranges tend to be East Coast registrations
        if first_octet < 100 {
            map.insert(first_octet, Region::UsEast);
        } else {
            map.insert(first_octet, Region::UsWest);
        }
    }

    // Europe (RIPE NCC)
    for first_octet in [2, 5, 25, 31, 37, 46, 51, 53, 57, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217] {
        // Western Europe (UK, France, Spain, Portugal, Ireland)
        if first_octet < 80 {
            map.insert(first_octet, Region::EuWest);
        } else {
            // Central/Eastern Europe (Germany, Poland, etc.)
            map.insert(first_octet, Region::EuCentral);
        }
    }

    // Asia-Pacific (APNIC)
    for first_octet in [1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223] {
        // Japan, Korea, Taiwan tend to have earlier allocations
        if first_octet < 60 || (first_octet >= 210 && first_octet <= 223) {
            map.insert(first_octet, Region::ApNortheast);
        } else {
            // Southeast Asia, Australia, China
            map.insert(first_octet, Region::ApSoutheast);
        }
    }

    // Latin America (LACNIC) - route to US East as closest major region
    for first_octet in [177, 179, 181, 186, 187, 189, 190, 191, 200, 201] {
        map.insert(first_octet, Region::UsEast);
    }

    // Africa (AFRINIC) - route to EU West as closest major region
    for first_octet in [41, 102, 105, 154, 196, 197] {
        map.insert(first_octet, Region::EuWest);
    }

    map
});

pub struct RegionRouter {
    default_region: String,
}

impl RegionRouter {
    pub fn new(default_region: String) -> Self {
        Self { default_region }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RegionRouter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RegionRouterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RegionRouterMiddleware {
            service,
            default_region: self.default_region.clone(),
        }))
    }
}

pub struct RegionRouterMiddleware<S> {
    service: S,
    default_region: String,
}

impl<S, B> Service<ServiceRequest> for RegionRouterMiddleware<S>
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
        // Get client IP for geo-location
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        // Determine nearest region based on IP geolocation
        let target_region = determine_region_from_ip(&client_ip);

        // Store the determined region in request extensions for downstream handlers
        req.extensions_mut().insert(target_region.clone());

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Determine the nearest region based on client IP address
///
/// This function uses IP block-based geolocation to map IP addresses to their
/// approximate geographic region. It's based on Regional Internet Registry (RIR)
/// allocations:
/// - ARIN (North America)
/// - RIPE NCC (Europe, Middle East, Central Asia)
/// - APNIC (Asia-Pacific)
/// - LACNIC (Latin America, Caribbean)
/// - AFRINIC (Africa)
///
/// For production deployments with higher accuracy requirements, consider using
/// a GeoIP database service like MaxMind GeoLite2 or IP2Location.
pub fn determine_region_from_ip(ip: &str) -> String {
    // Handle IP:port format
    let ip_only = ip.split(':').next().unwrap_or(ip);

    // Parse the IP address
    let parsed_ip: Option<IpAddr> = ip_only.parse().ok();

    match parsed_ip {
        Some(IpAddr::V4(ipv4)) => {
            let first_octet = ipv4.octets()[0];

            // Check for private/local IP ranges - use default region
            if ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() {
                return "us-east".to_string();
            }

            // Look up region based on first octet
            REGION_MAPPINGS
                .get(&first_octet)
                .map(|r| r.code().to_string())
                .unwrap_or_else(|| "us-east".to_string())
        }
        Some(IpAddr::V6(ipv6)) => {
            // For IPv6, use a simplified approach based on common allocations
            // Most IPv6 addresses in production are 2000::/3 (Global Unicast)
            let first_segment = ipv6.segments()[0];

            if ipv6.is_loopback() {
                return "us-east".to_string();
            }

            // Route based on common IPv6 allocations
            // 2001::/32 - IANA special purposes, various RIRs
            // 2400::/12 - APNIC
            // 2600::/12 - ARIN
            // 2800::/12 - LACNIC
            // 2a00::/12 - RIPE NCC
            // 2c00::/12 - AFRINIC
            match first_segment >> 8 {
                0x24 => Region::ApSoutheast.code().to_string(),  // APNIC
                0x26 => Region::UsEast.code().to_string(),       // ARIN
                0x28 => Region::UsEast.code().to_string(),       // LACNIC -> US East
                0x2a => Region::EuCentral.code().to_string(),    // RIPE NCC
                0x2c => Region::EuWest.code().to_string(),       // AFRINIC -> EU West
                _ => "us-east".to_string(),
            }
        }
        None => {
            // Unable to parse IP, use default
            "us-east".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_code_roundtrip() {
        for region in [
            Region::UsEast,
            Region::UsWest,
            Region::EuWest,
            Region::EuCentral,
            Region::ApSoutheast,
            Region::ApNortheast,
        ] {
            let code = region.code();
            let parsed = Region::from_code(code);
            assert_eq!(parsed, Some(region));
        }
    }

    #[test]
    fn test_determine_region_us_east() {
        // 8.8.8.8 is Google DNS, allocated in ARIN's early blocks
        let region = determine_region_from_ip("8.8.8.8");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_determine_region_eu() {
        // 185.x.x.x is allocated to RIPE NCC (Europe)
        let region = determine_region_from_ip("185.199.108.153");
        assert_eq!(region, "eu-central");
    }

    #[test]
    fn test_determine_region_apac() {
        // 1.x.x.x is allocated to APNIC (Asia-Pacific)
        let region = determine_region_from_ip("1.1.1.1");
        assert_eq!(region, "ap-northeast");
    }

    #[test]
    fn test_determine_region_private_ip() {
        // Private IPs should return default region
        let region = determine_region_from_ip("192.168.1.1");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_determine_region_loopback() {
        let region = determine_region_from_ip("127.0.0.1");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_determine_region_with_port() {
        // Should handle IP:port format
        let region = determine_region_from_ip("8.8.8.8:443");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_determine_region_invalid_ip() {
        let region = determine_region_from_ip("invalid");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_determine_region_unknown() {
        let region = determine_region_from_ip("unknown");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_ipv6_arin() {
        // 2600::/12 is ARIN
        let region = determine_region_from_ip("2600:1f18::");
        assert_eq!(region, "us-east");
    }

    #[test]
    fn test_ipv6_ripe() {
        // 2a00::/12 is RIPE NCC
        let region = determine_region_from_ip("2a00:1450::");
        assert_eq!(region, "eu-central");
    }

    #[test]
    fn test_ipv6_apnic() {
        // 2400::/12 is APNIC
        let region = determine_region_from_ip("2400:cb00::");
        assert_eq!(region, "ap-southeast");
    }
}
