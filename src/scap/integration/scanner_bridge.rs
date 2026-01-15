//! Bridge between SCAP and scanner module

use crate::scap::cpe::{Cpe, CpePart, WfnAttribute};
use crate::types::{HostInfo, OsInfo};

/// Bridge for integrating SCAP with scanner results
pub struct ScannerBridge;

impl ScannerBridge {
    /// Extract CPEs from scan results
    pub fn extract_host_cpes(host: &HostInfo) -> Vec<Cpe> {
        let mut cpes = Vec::new();

        // OS CPE
        if let Some(os) = &host.os_guess {
            if let Some(cpe) = Self::os_to_cpe(os) {
                cpes.push(cpe);
            }
        }

        // Service CPEs
        for port in &host.ports {
            if let Some(service) = &port.service {
                if let Some(cpe_str) = &service.cpe {
                    if let Ok(cpe) = Cpe::from_uri(cpe_str) {
                        cpes.push(cpe);
                    }
                }
            }
        }

        cpes
    }

    /// Convert OS info to CPE
    fn os_to_cpe(os: &OsInfo) -> Option<Cpe> {
        let name = os.os_family.to_lowercase();
        let version = os.os_version.as_deref().unwrap_or("*");

        let (vendor, product) = if name.contains("windows") {
            ("microsoft", "windows")
        } else if name.contains("linux") || name.contains("ubuntu") || name.contains("debian") {
            if name.contains("ubuntu") {
                ("canonical", "ubuntu_linux")
            } else if name.contains("debian") {
                ("debian", "debian_linux")
            } else if name.contains("centos") {
                ("centos", "centos")
            } else if name.contains("rhel") || name.contains("red hat") {
                ("redhat", "enterprise_linux")
            } else {
                ("linux", "linux_kernel")
            }
        } else if name.contains("macos") || name.contains("darwin") {
            ("apple", "macos")
        } else {
            return None;
        };

        Some(Cpe {
            part: CpePart::OperatingSystem,
            vendor: WfnAttribute::Value(vendor.to_string()),
            product: WfnAttribute::Value(product.to_string()),
            version: WfnAttribute::Value(version.to_string()),
            update: WfnAttribute::Any,
            edition: WfnAttribute::Any,
            language: WfnAttribute::Any,
            sw_edition: WfnAttribute::Any,
            target_sw: WfnAttribute::Any,
            target_hw: WfnAttribute::Any,
            other: WfnAttribute::Any,
        })
    }

    /// Determine target platform from OS info
    pub fn determine_platform(os: &OsInfo) -> crate::scap::TargetPlatform {
        let name = os.os_family.to_lowercase();

        if name.contains("windows") {
            crate::scap::TargetPlatform::Windows
        } else if name.contains("linux") || name.contains("ubuntu") || name.contains("debian")
            || name.contains("centos") || name.contains("rhel") {
            crate::scap::TargetPlatform::Linux
        } else if name.contains("macos") || name.contains("darwin") {
            crate::scap::TargetPlatform::MacOs
        } else if name.contains("solaris") {
            crate::scap::TargetPlatform::Solaris
        } else if name.contains("aix") {
            crate::scap::TargetPlatform::Aix
        } else if name.contains("cisco") {
            crate::scap::TargetPlatform::CiscoIos
        } else if name.contains("junos") {
            crate::scap::TargetPlatform::Junos
        } else if name.contains("esxi") || name.contains("vmware") {
            crate::scap::TargetPlatform::Esxi
        } else {
            crate::scap::TargetPlatform::Unix
        }
    }
}
