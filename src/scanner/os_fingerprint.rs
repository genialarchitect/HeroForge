use anyhow::Result;
use crate::types::{OsInfo, PortInfo, ScanConfig, ScanTarget};
use log::debug;

pub async fn fingerprint_os(
    target: &ScanTarget,
    ports: &[PortInfo],
    _config: &ScanConfig,
) -> Result<Option<OsInfo>, anyhow::Error> {
    debug!("Attempting OS fingerprinting for {}", target.ip);

    // Passive OS fingerprinting based on:
    // 1. Open port combinations
    // 2. Service banners
    // 3. TTL values (would require raw sockets)

    let os_guess = guess_os_from_ports(ports);

    Ok(os_guess)
}

fn guess_os_from_ports(ports: &[PortInfo]) -> Option<OsInfo> {
    let open_ports: Vec<u16> = ports.iter().map(|p| p.port).collect();

    // Windows indicators
    let has_smb = open_ports.contains(&445);
    let has_rdp = open_ports.contains(&3389);
    let has_winrm = open_ports.contains(&5985) || open_ports.contains(&5986);
    let has_ms_sql = open_ports.contains(&1433);

    if has_smb && has_rdp {
        return Some(OsInfo {
            os_family: "Windows".to_string(),
            os_version: Some("Windows Server or Desktop".to_string()),
            confidence: 85,
        });
    }

    if has_smb || has_rdp || has_winrm || has_ms_sql {
        return Some(OsInfo {
            os_family: "Windows".to_string(),
            os_version: None,
            confidence: 70,
        });
    }

    // Linux indicators
    let has_ssh = open_ports.contains(&22);
    let has_common_linux_ports = open_ports.contains(&111) // rpcbind
        || open_ports.contains(&2049); // NFS

    // Check for service banners that might indicate Linux
    let has_apache_nginx = ports.iter().any(|p| {
        if let Some(ref service) = p.service {
            service.name == "apache" || service.name == "nginx"
        } else {
            false
        }
    });

    if has_ssh && (has_common_linux_ports || has_apache_nginx) {
        // Try to determine distribution from SSH banner
        if let Some(ssh_version) = get_ssh_version(ports) {
            if ssh_version.to_lowercase().contains("ubuntu") {
                return Some(OsInfo {
                    os_family: "Linux".to_string(),
                    os_version: Some("Ubuntu".to_string()),
                    confidence: 75,
                });
            } else if ssh_version.to_lowercase().contains("debian") {
                return Some(OsInfo {
                    os_family: "Linux".to_string(),
                    os_version: Some("Debian".to_string()),
                    confidence: 75,
                });
            }
        }

        return Some(OsInfo {
            os_family: "Linux".to_string(),
            os_version: None,
            confidence: 65,
        });
    }

    // macOS indicators
    let has_afp = open_ports.contains(&548);
    let has_airport = open_ports.contains(&5009);

    if has_afp || has_airport {
        return Some(OsInfo {
            os_family: "macOS".to_string(),
            os_version: None,
            confidence: 70,
        });
    }

    // Unix-like indicators
    if has_ssh {
        return Some(OsInfo {
            os_family: "Unix-like".to_string(),
            os_version: None,
            confidence: 50,
        });
    }

    // Network device indicators
    let has_telnet = open_ports.contains(&23);
    let has_snmp = open_ports.contains(&161);

    if has_telnet && has_snmp {
        return Some(OsInfo {
            os_family: "Network Device".to_string(),
            os_version: Some("Router/Switch".to_string()),
            confidence: 60,
        });
    }

    // Database servers
    let has_mysql = open_ports.contains(&3306);
    let has_postgresql = open_ports.contains(&5432);
    let has_mongodb = open_ports.contains(&27017);
    let has_redis = open_ports.contains(&6379);

    if has_mysql || has_postgresql || has_mongodb || has_redis {
        // Likely Linux, but could be Windows
        return Some(OsInfo {
            os_family: "Linux".to_string(),
            os_version: Some("Database Server".to_string()),
            confidence: 55,
        });
    }

    None
}

fn get_ssh_version(ports: &[PortInfo]) -> Option<String> {
    for port in ports {
        if port.port == 22 {
            if let Some(ref service) = port.service {
                if let Some(ref banner) = service.banner {
                    return Some(banner.clone());
                }
            }
        }
    }
    None
}
