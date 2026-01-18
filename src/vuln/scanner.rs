#![allow(dead_code)]

use anyhow::Result;
use crate::cve::{CveConfig, CveScanner};
use crate::types::{HostInfo, ScanConfig, Severity, Vulnerability};
use log::debug;
use sqlx::SqlitePool;

/// Scan for vulnerabilities on a host (with database for caching)
pub async fn scan_vulnerabilities_with_db(
    host_info: &HostInfo,
    _config: &ScanConfig,
    pool: &SqlitePool,
) -> Result<Vec<Vulnerability>, anyhow::Error> {
    debug!("Scanning for vulnerabilities on {} (with CVE cache)", host_info.target.ip);

    let cve_scanner = CveScanner::new(
        pool.clone(),
        CveConfig::default(),
    );

    let mut vulnerabilities = cve_scanner.lookup_host_cves(&host_info.ports).await?;

    // Add misconfiguration checks
    vulnerabilities.extend(check_misconfigurations(host_info));

    // Add SSL/TLS vulnerabilities
    vulnerabilities.extend(check_ssl_vulnerabilities(host_info));

    Ok(vulnerabilities)
}

/// Scan for vulnerabilities on a host (offline mode, no database)
pub async fn scan_vulnerabilities(
    host_info: &HostInfo,
    _config: &ScanConfig,
) -> Result<Vec<Vulnerability>, anyhow::Error> {
    debug!("Scanning for vulnerabilities on {} (offline mode)", host_info.target.ip);

    let cve_scanner = CveScanner::offline_only();

    let mut vulnerabilities = cve_scanner.lookup_host_cves(&host_info.ports).await?;

    // Add misconfiguration checks
    vulnerabilities.extend(check_misconfigurations(host_info));

    // Add SSL/TLS vulnerabilities
    vulnerabilities.extend(check_ssl_vulnerabilities(host_info));

    Ok(vulnerabilities)
}

/// Check for common misconfigurations based on open ports
fn check_misconfigurations(host_info: &HostInfo) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    let open_ports: Vec<u16> = host_info.ports.iter().map(|p| p.port).collect();

    // ============================================================
    // WINDOWS/ENTERPRISE SERVICES
    // ============================================================

    // Check for SMBv1 potential (MS17-010 EternalBlue)
    if open_ports.contains(&445) {
        vulns.push(Vulnerability {
            cve_id: Some("MS17-010".to_string()),
            title: "Potential SMBv1 Enabled".to_string(),
            severity: Severity::Critical,
            description: "SMB service detected on port 445. If SMBv1 is enabled, system may be vulnerable to EternalBlue. Verify SMBv1 is disabled.".to_string(),
            affected_service: Some("smb:445".to_string()),
        });
    }

    // Check for default RDP port exposure
    if open_ports.contains(&3389) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "RDP Service on Default Port".to_string(),
            severity: Severity::Medium,
            description: "RDP is accessible on the default port 3389. Consider using a non-standard port, VPN, or enabling Network Level Authentication (NLA).".to_string(),
            affected_service: Some("rdp:3389".to_string()),
        });
    }

    // Check for default WinRM ports (potential for lateral movement)
    if open_ports.contains(&5985) || open_ports.contains(&5986) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "WinRM Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Windows Remote Management (WinRM) is exposed. This can be used for lateral movement if credentials are compromised.".to_string(),
            affected_service: Some(format!("winrm:{}", if open_ports.contains(&5986) { 5986 } else { 5985 })),
        });
    }

    // Check for LDAP exposure (potential for enumeration)
    if open_ports.contains(&389) || open_ports.contains(&636) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "LDAP Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "LDAP service is exposed. This could allow enumeration of Active Directory objects if anonymous bind is enabled.".to_string(),
            affected_service: Some(format!("ldap:{}", if open_ports.contains(&636) { 636 } else { 389 })),
        });
    }

    // Check for Kerberos (indicates domain controller)
    if open_ports.contains(&88) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Kerberos Service Detected (Domain Controller)".to_string(),
            severity: Severity::Low,
            description: "Kerberos service detected, indicating this is likely a Domain Controller. Ensure it's properly secured.".to_string(),
            affected_service: Some("kerberos:88".to_string()),
        });
    }

    // ============================================================
    // DATABASE SERVICES
    // ============================================================

    // Check for MS-SQL on default port
    if open_ports.contains(&1433) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "MSSQL on Default Port".to_string(),
            severity: Severity::Low,
            description: "Microsoft SQL Server is exposed on the default port. Verify strong authentication is required.".to_string(),
            affected_service: Some("mssql:1433".to_string()),
        });
    }

    // Check for Oracle on default port
    if open_ports.contains(&1521) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Oracle Database Exposed".to_string(),
            severity: Severity::Medium,
            description: "Oracle database listener is exposed. Verify authentication and TNS configuration.".to_string(),
            affected_service: Some("oracle:1521".to_string()),
        });
    }

    // Check for MongoDB (potential no-auth)
    if open_ports.contains(&27017) || open_ports.contains(&27018) || open_ports.contains(&27019) {
        let port = if open_ports.contains(&27017) { 27017 } else if open_ports.contains(&27018) { 27018 } else { 27019 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "MongoDB Service Exposed".to_string(),
            severity: Severity::High,
            description: "MongoDB is exposed on the network. MongoDB historically defaults to no authentication. Verify authentication is enabled and the service is not accessible from untrusted networks.".to_string(),
            affected_service: Some(format!("mongodb:{}", port)),
        });
    }

    // Check for Redis (commonly no-auth)
    if open_ports.contains(&6379) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Redis Service Exposed".to_string(),
            severity: Severity::High,
            description: "Redis is exposed on the default port. Redis often runs without authentication, allowing arbitrary command execution including file writes and potential RCE. Verify AUTH is configured.".to_string(),
            affected_service: Some("redis:6379".to_string()),
        });
    }

    // Check for Elasticsearch (commonly open)
    if open_ports.contains(&9200) || open_ports.contains(&9300) {
        let port = if open_ports.contains(&9200) { 9200 } else { 9300 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Elasticsearch Service Exposed".to_string(),
            severity: Severity::High,
            description: "Elasticsearch is exposed. By default, Elasticsearch has no authentication and allows full data access. Verify X-Pack security is enabled or access is restricted.".to_string(),
            affected_service: Some(format!("elasticsearch:{}", port)),
        });
    }

    // Check for PostgreSQL
    if open_ports.contains(&5432) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "PostgreSQL Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "PostgreSQL is exposed on the default port. Verify pg_hba.conf restricts access appropriately and trust authentication is not used for remote connections.".to_string(),
            affected_service: Some("postgresql:5432".to_string()),
        });
    }

    // Check for MySQL
    if open_ports.contains(&3306) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "MySQL Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "MySQL is exposed on the default port. Verify authentication is required and the root account is secured.".to_string(),
            affected_service: Some("mysql:3306".to_string()),
        });
    }

    // Check for CouchDB (commonly no-auth)
    if open_ports.contains(&5984) || open_ports.contains(&6984) {
        let port = if open_ports.contains(&5984) { 5984 } else { 6984 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "CouchDB Service Exposed".to_string(),
            severity: Severity::High,
            description: "CouchDB is exposed. CouchDB in admin party mode (default) allows unauthenticated database manipulation. Verify authentication is configured.".to_string(),
            affected_service: Some(format!("couchdb:{}", port)),
        });
    }

    // Check for Cassandra
    if open_ports.contains(&9042) || open_ports.contains(&9160) {
        let port = if open_ports.contains(&9042) { 9042 } else { 9160 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Cassandra Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Apache Cassandra is exposed on the network. Verify authentication is enabled (authenticator is not AllowAllAuthenticator) and SSL is configured.".to_string(),
            affected_service: Some(format!("cassandra:{}", port)),
        });
    }

    // Check for InfluxDB
    if open_ports.contains(&8086) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "InfluxDB Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "InfluxDB is exposed on the default port. Verify authentication is enabled and not running in insecure mode.".to_string(),
            affected_service: Some("influxdb:8086".to_string()),
        });
    }

    // Check for ClickHouse
    if open_ports.contains(&8123) || open_ports.contains(&9000) {
        let port = if open_ports.contains(&8123) { 8123 } else { 9000 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "ClickHouse Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "ClickHouse database is exposed. Verify user authentication is configured and default user access is restricted.".to_string(),
            affected_service: Some(format!("clickhouse:{}", port)),
        });
    }

    // ============================================================
    // CACHING/MESSAGE QUEUE SERVICES
    // ============================================================

    // Check for Memcached (commonly no-auth, DDoS amplification)
    if open_ports.contains(&11211) {
        vulns.push(Vulnerability {
            cve_id: Some("CVE-2018-1000115".to_string()),
            title: "Memcached Service Exposed".to_string(),
            severity: Severity::Critical,
            description: "Memcached is exposed on the network. Memcached has no built-in authentication and can be abused for DDoS amplification attacks. Bind to localhost or use SASL authentication.".to_string(),
            affected_service: Some("memcached:11211".to_string()),
        });
    }

    // Check for RabbitMQ (Management UI and AMQP)
    if open_ports.contains(&15672) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "RabbitMQ Management UI Exposed".to_string(),
            severity: Severity::High,
            description: "RabbitMQ Management UI is exposed. Default credentials are guest/guest. Verify default credentials are changed and access is restricted.".to_string(),
            affected_service: Some("rabbitmq-mgmt:15672".to_string()),
        });
    }

    if open_ports.contains(&5672) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "RabbitMQ AMQP Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "RabbitMQ AMQP protocol is exposed. Verify authentication is required and default credentials are changed.".to_string(),
            affected_service: Some("rabbitmq:5672".to_string()),
        });
    }

    // Check for Apache Kafka
    if open_ports.contains(&9092) || open_ports.contains(&9093) {
        let port = if open_ports.contains(&9092) { 9092 } else { 9093 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Apache Kafka Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Apache Kafka is exposed on the network. Verify SASL authentication is enabled and ACLs are properly configured.".to_string(),
            affected_service: Some(format!("kafka:{}", port)),
        });
    }

    // Check for Apache ActiveMQ
    if open_ports.contains(&61616) || open_ports.contains(&8161) {
        let port = if open_ports.contains(&61616) { 61616 } else { 8161 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Apache ActiveMQ Service Exposed".to_string(),
            severity: Severity::High,
            description: "Apache ActiveMQ is exposed. Default credentials admin/admin may be in use. Verify authentication is enabled and default credentials are changed.".to_string(),
            affected_service: Some(format!("activemq:{}", port)),
        });
    }

    // Check for NATS
    if open_ports.contains(&4222) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "NATS Message Queue Exposed".to_string(),
            severity: Severity::Medium,
            description: "NATS messaging service is exposed. Verify authentication is enabled if containing sensitive messages.".to_string(),
            affected_service: Some("nats:4222".to_string()),
        });
    }

    // ============================================================
    // CONTAINER/ORCHESTRATION SERVICES
    // ============================================================

    // Check for Docker API (CRITICAL - remote code execution)
    if open_ports.contains(&2375) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Docker API Exposed (Unencrypted)".to_string(),
            severity: Severity::Critical,
            description: "Docker API is exposed without TLS on port 2375. This allows unauthenticated remote code execution on the host. Immediately disable remote API access or configure TLS mutual authentication.".to_string(),
            affected_service: Some("docker:2375".to_string()),
        });
    }

    if open_ports.contains(&2376) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Docker API Exposed (TLS)".to_string(),
            severity: Severity::High,
            description: "Docker API is exposed on port 2376. While TLS may be configured, verify mutual TLS authentication is enforced and access is restricted.".to_string(),
            affected_service: Some("docker-tls:2376".to_string()),
        });
    }

    // Check for Kubernetes API Server
    if open_ports.contains(&6443) || open_ports.contains(&8443) {
        let port = if open_ports.contains(&6443) { 6443 } else { 8443 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Kubernetes API Server Exposed".to_string(),
            severity: Severity::High,
            description: "Kubernetes API server is exposed. Verify RBAC is properly configured, anonymous authentication is disabled, and access is restricted to authorized networks.".to_string(),
            affected_service: Some(format!("kubernetes:{}", port)),
        });
    }

    // Check for Kubernetes kubelet
    if open_ports.contains(&10250) || open_ports.contains(&10255) {
        let port = if open_ports.contains(&10250) { 10250 } else { 10255 };
        let severity = if port == 10255 { Severity::Critical } else { Severity::High };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Kubernetes Kubelet API Exposed".to_string(),
            severity,
            description: format!(
                "Kubernetes kubelet is exposed on port {}. {} Verify authentication is required and access is restricted.",
                port,
                if port == 10255 { "Port 10255 is the read-only unauthenticated port, which leaks sensitive information." } else { "This can allow pod execution and node manipulation." }
            ),
            affected_service: Some(format!("kubelet:{}", port)),
        });
    }

    // Check for etcd (Kubernetes backing store)
    if open_ports.contains(&2379) || open_ports.contains(&2380) {
        let port = if open_ports.contains(&2379) { 2379 } else { 2380 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "etcd Service Exposed".to_string(),
            severity: Severity::Critical,
            description: "etcd is exposed on the network. etcd stores Kubernetes secrets and configuration. Unauthenticated access allows reading all cluster secrets. Verify mutual TLS authentication is enforced.".to_string(),
            affected_service: Some(format!("etcd:{}", port)),
        });
    }

    // Check for containerd
    if open_ports.contains(&10010) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "containerd CRI Service Exposed".to_string(),
            severity: Severity::Critical,
            description: "containerd gRPC service is exposed. This allows container manipulation and potential host escape. Access should be restricted to localhost only.".to_string(),
            affected_service: Some("containerd:10010".to_string()),
        });
    }

    // ============================================================
    // CI/CD AND DEVOPS SERVICES
    // ============================================================

    // Check for Jenkins
    if open_ports.contains(&8080) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Potential Jenkins Service on Port 8080".to_string(),
            severity: Severity::Medium,
            description: "Service detected on port 8080 (common Jenkins port). If this is Jenkins, verify authentication is required, script console is secured, and anonymous read access is disabled.".to_string(),
            affected_service: Some("http:8080".to_string()),
        });
    }

    if open_ports.contains(&50000) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Jenkins Agent Port Exposed".to_string(),
            severity: Severity::High,
            description: "Jenkins agent/JNLP port is exposed. This can allow unauthorized agents to connect to the Jenkins controller. Restrict access with agent-to-controller security and JNLP agents whitelist.".to_string(),
            affected_service: Some("jenkins-agent:50000".to_string()),
        });
    }

    // Check for GitLab
    if open_ports.contains(&8929) || open_ports.contains(&8022) {
        let port = if open_ports.contains(&8929) { 8929 } else { 8022 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "GitLab Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "GitLab service detected. Verify sign-up restrictions, public project visibility defaults, and CI/CD runner registration tokens are secured.".to_string(),
            affected_service: Some(format!("gitlab:{}", port)),
        });
    }

    // Check for Nexus/Artifactory
    if open_ports.contains(&8081) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Potential Artifact Repository on Port 8081".to_string(),
            severity: Severity::Medium,
            description: "Service on port 8081 (common for Nexus/Artifactory). If this is an artifact repository, verify anonymous access is disabled and default admin credentials are changed.".to_string(),
            affected_service: Some("artifact-repo:8081".to_string()),
        });
    }

    // Check for SonarQube
    if open_ports.contains(&9001) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Potential SonarQube Service".to_string(),
            severity: Severity::Medium,
            description: "Service on port 9001 (common for SonarQube). If this is SonarQube, verify default admin/admin credentials are changed and anonymous access is disabled.".to_string(),
            affected_service: Some("sonarqube:9001".to_string()),
        });
    }

    // ============================================================
    // MONITORING AND OBSERVABILITY SERVICES
    // ============================================================

    // Check for Grafana
    if open_ports.contains(&3000) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Potential Grafana Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Service on port 3000 (common Grafana port). If this is Grafana, verify default admin/admin credentials are changed and anonymous access is disabled if not intended.".to_string(),
            affected_service: Some("grafana:3000".to_string()),
        });
    }

    // Check for Prometheus
    if open_ports.contains(&9090) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Prometheus Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Prometheus metrics server is exposed. By default, Prometheus has no authentication. Sensitive metrics, targets, and configuration may be accessible. Consider adding authentication via reverse proxy.".to_string(),
            affected_service: Some("prometheus:9090".to_string()),
        });
    }

    // Check for Prometheus Pushgateway
    if open_ports.contains(&9091) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Prometheus Pushgateway Exposed".to_string(),
            severity: Severity::Medium,
            description: "Prometheus Pushgateway is exposed. Unauthenticated access allows pushing arbitrary metrics and deleting existing metrics.".to_string(),
            affected_service: Some("pushgateway:9091".to_string()),
        });
    }

    // Check for Alertmanager
    if open_ports.contains(&9093) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Prometheus Alertmanager Exposed".to_string(),
            severity: Severity::Medium,
            description: "Alertmanager is exposed. Unauthenticated access allows viewing, silencing, and managing alerts. Add authentication via reverse proxy.".to_string(),
            affected_service: Some("alertmanager:9093".to_string()),
        });
    }

    // Check for Jaeger
    if open_ports.contains(&16686) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Jaeger Tracing UI Exposed".to_string(),
            severity: Severity::Medium,
            description: "Jaeger tracing UI is exposed. This may reveal sensitive application flow information, request parameters, and internal service names.".to_string(),
            affected_service: Some("jaeger:16686".to_string()),
        });
    }

    // Check for Zipkin
    if open_ports.contains(&9411) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Zipkin Tracing Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Zipkin distributed tracing is exposed. This may reveal sensitive application flow information and internal service architecture.".to_string(),
            affected_service: Some("zipkin:9411".to_string()),
        });
    }

    // ============================================================
    // REMOTE ACCESS SERVICES
    // ============================================================

    // Check for VNC ports
    if open_ports.iter().any(|&p| (5900..=5909).contains(&p)) {
        let vnc_port = open_ports.iter().find(|&&p| (5900..=5909).contains(&p)).unwrap();
        vulns.push(Vulnerability {
            cve_id: None,
            title: "VNC Service Exposed".to_string(),
            severity: Severity::High,
            description: "VNC remote desktop service is exposed. VNC often has weak authentication and should be accessed via VPN only.".to_string(),
            affected_service: Some(format!("vnc:{}", vnc_port)),
        });
    }

    // Check for Telnet (unencrypted remote access)
    if open_ports.contains(&23) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Telnet Service Exposed".to_string(),
            severity: Severity::High,
            description: "Telnet is exposed. Telnet transmits credentials in cleartext. Replace with SSH and disable Telnet.".to_string(),
            affected_service: Some("telnet:23".to_string()),
        });
    }

    // Check for rsh/rlogin/rexec (legacy insecure protocols)
    if open_ports.contains(&513) || open_ports.contains(&512) || open_ports.contains(&514) {
        let port = if open_ports.contains(&513) { 513 } else if open_ports.contains(&512) { 512 } else { 514 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Legacy r-Services Exposed".to_string(),
            severity: Severity::Critical,
            description: format!("Legacy r-service detected on port {} (rlogin/rexec/rsh). These services use trust-based authentication and transmit data in cleartext. Disable immediately and use SSH.", port),
            affected_service: Some(format!("r-service:{}", port)),
        });
    }

    // Check for X11
    if open_ports.iter().any(|&p| (6000..=6009).contains(&p)) {
        let x11_port = open_ports.iter().find(|&&p| (6000..=6009).contains(&p)).unwrap();
        vulns.push(Vulnerability {
            cve_id: None,
            title: "X11 Service Exposed".to_string(),
            severity: Severity::High,
            description: "X11 display server is exposed. This allows screen capture, keystroke injection, and other GUI attacks. Disable direct X11 access and use SSH X11 forwarding instead.".to_string(),
            affected_service: Some(format!("x11:{}", x11_port)),
        });
    }

    // ============================================================
    // INDUSTRIAL/OT PROTOCOLS
    // ============================================================

    // Check for Modbus
    if open_ports.contains(&502) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Modbus Protocol Exposed".to_string(),
            severity: Severity::Critical,
            description: "Modbus industrial protocol is exposed. Modbus has no built-in authentication and allows direct control of industrial equipment. Immediately segment from general network and implement access controls.".to_string(),
            affected_service: Some("modbus:502".to_string()),
        });
    }

    // Check for BACnet
    if open_ports.contains(&47808) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "BACnet Protocol Exposed".to_string(),
            severity: Severity::Critical,
            description: "BACnet building automation protocol is exposed. This allows control of HVAC, lighting, and access control systems. Segment from general network.".to_string(),
            affected_service: Some("bacnet:47808".to_string()),
        });
    }

    // Check for S7comm (Siemens)
    if open_ports.contains(&102) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "S7comm Protocol Exposed (Siemens PLC)".to_string(),
            severity: Severity::Critical,
            description: "Siemens S7comm protocol is exposed. This allows read/write access to PLC memory and program modification. Immediately segment from general network.".to_string(),
            affected_service: Some("s7comm:102".to_string()),
        });
    }

    // Check for DNP3
    if open_ports.contains(&20000) || open_ports.contains(&19999) {
        let port = if open_ports.contains(&20000) { 20000 } else { 19999 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "DNP3 Protocol Exposed".to_string(),
            severity: Severity::Critical,
            description: "DNP3 SCADA protocol is exposed. This protocol is used for utility and infrastructure control systems. Segment from general network and implement secure authentication.".to_string(),
            affected_service: Some(format!("dnp3:{}", port)),
        });
    }

    // Check for EtherNet/IP
    if open_ports.contains(&44818) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "EtherNet/IP Protocol Exposed".to_string(),
            severity: Severity::Critical,
            description: "EtherNet/IP industrial protocol is exposed. This allows control of industrial automation equipment. Segment from general network.".to_string(),
            affected_service: Some("ethernet-ip:44818".to_string()),
        });
    }

    // ============================================================
    // OBJECT STORAGE AND FILE SERVICES
    // ============================================================

    // Check for MinIO
    if open_ports.contains(&9000) && open_ports.contains(&9001) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "MinIO Object Storage Exposed".to_string(),
            severity: Severity::High,
            description: "MinIO object storage service is exposed. Default credentials are minioadmin/minioadmin. Verify credentials are changed and bucket policies are properly configured.".to_string(),
            affected_service: Some("minio:9000".to_string()),
        });
    }

    // Check for NFS
    if open_ports.contains(&2049) || open_ports.contains(&111) {
        let port = if open_ports.contains(&2049) { 2049 } else { 111 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "NFS Service Exposed".to_string(),
            severity: Severity::High,
            description: "NFS file sharing is exposed. Verify exports are restricted to authorized hosts and no_root_squash is not used inappropriately.".to_string(),
            affected_service: Some(format!("nfs:{}", port)),
        });
    }

    // Check for rsync
    if open_ports.contains(&873) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "rsync Service Exposed".to_string(),
            severity: Severity::High,
            description: "rsync daemon is exposed. Verify modules require authentication and read-only access is enforced where appropriate.".to_string(),
            affected_service: Some("rsync:873".to_string()),
        });
    }

    // ============================================================
    // MISC SERVICES
    // ============================================================

    // Check for SNMP (information disclosure + potential write)
    if open_ports.contains(&161) || open_ports.contains(&162) {
        let port = if open_ports.contains(&161) { 161 } else { 162 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "SNMP Service Exposed".to_string(),
            severity: Severity::High,
            description: "SNMP is exposed. Default community strings (public/private) may allow sensitive information disclosure or configuration changes. Use SNMPv3 with authentication.".to_string(),
            affected_service: Some(format!("snmp:{}", port)),
        });
    }

    // Check for IPMI (BMC access)
    if open_ports.contains(&623) {
        vulns.push(Vulnerability {
            cve_id: Some("CVE-2013-4786".to_string()),
            title: "IPMI Service Exposed".to_string(),
            severity: Severity::Critical,
            description: "IPMI/BMC is exposed on port 623. IPMI has known authentication bypass vulnerabilities and allows full server control. Restrict access to management network only.".to_string(),
            affected_service: Some("ipmi:623".to_string()),
        });
    }

    // Check for Consul
    if open_ports.contains(&8500) || open_ports.contains(&8501) {
        let port = if open_ports.contains(&8500) { 8500 } else { 8501 };
        vulns.push(Vulnerability {
            cve_id: None,
            title: "HashiCorp Consul Exposed".to_string(),
            severity: Severity::High,
            description: "Consul service mesh is exposed. Unauthenticated access can reveal service discovery data, KV store contents, and allow service registration manipulation. Enable ACLs.".to_string(),
            affected_service: Some(format!("consul:{}", port)),
        });
    }

    // Check for Vault
    if open_ports.contains(&8200) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "HashiCorp Vault Exposed".to_string(),
            severity: Severity::High,
            description: "Vault secrets management is exposed. While authentication is required, direct exposure increases attack surface. Access should be through a load balancer with proper network controls.".to_string(),
            affected_service: Some("vault:8200".to_string()),
        });
    }

    // Check for Zookeeper
    if open_ports.contains(&2181) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Apache Zookeeper Exposed".to_string(),
            severity: Severity::High,
            description: "Zookeeper coordination service is exposed. By default, Zookeeper has no authentication. Sensitive cluster configuration and leadership data may be accessible.".to_string(),
            affected_service: Some("zookeeper:2181".to_string()),
        });
    }

    // Check for CockroachDB
    if open_ports.contains(&26257) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "CockroachDB Exposed".to_string(),
            severity: Severity::Medium,
            description: "CockroachDB is exposed on the network. Verify authentication is required and TLS is enabled for all connections.".to_string(),
            affected_service: Some("cockroachdb:26257".to_string()),
        });
    }

    // Check for excessive open ports (potential misconfiguration)
    if open_ports.len() > 20 {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Excessive Open Ports".to_string(),
            severity: Severity::Low,
            description: format!(
                "{} ports are open. This may indicate missing firewall rules or unnecessary services. Review and disable unnecessary services.",
                open_ports.len()
            ),
            affected_service: None,
        });
    }

    vulns
}

/// Check for SSL/TLS security issues
fn check_ssl_vulnerabilities(host_info: &HostInfo) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    for port in &host_info.ports {
        if let Some(ref service) = port.service {
            if let Some(ref ssl) = service.ssl_info {
                let port_str = format!("{}:{}", host_info.target.ip, port.port);

                // Check for expired certificates
                if ssl.cert_expired {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Expired SSL/TLS Certificate".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "The SSL/TLS certificate on {} has expired on {}. This will cause browser warnings and connection failures.",
                            port_str, ssl.valid_until
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for certificates expiring soon
                if !ssl.cert_expired {
                    if let Some(days) = ssl.days_until_expiry {
                        if days < 30 && days > 0 {
                            vulns.push(Vulnerability {
                                cve_id: None,
                                title: "SSL/TLS Certificate Expiring Soon".to_string(),
                                severity: Severity::Medium,
                                description: format!(
                                    "The SSL/TLS certificate on {} will expire in {} days on {}. Plan certificate renewal.",
                                    port_str, days, ssl.valid_until
                                ),
                                affected_service: Some(format!("{}:{}", service.name, port.port)),
                            });
                        }
                    }
                }

                // Check for self-signed certificates
                if ssl.self_signed {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Self-Signed SSL/TLS Certificate".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "The SSL/TLS certificate on {} is self-signed. Use a certificate from a trusted CA for production systems.",
                            port_str
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for hostname mismatch
                if ssl.hostname_mismatch {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "SSL/TLS Certificate Hostname Mismatch".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "The SSL/TLS certificate on {} does not match the hostname. Certificate is for: {}",
                            port_str, ssl.subject
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for weak protocols
                if !ssl.weak_protocols.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Weak SSL/TLS Protocols Enabled".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Weak or deprecated SSL/TLS protocols detected on {}: {}. Disable SSLv3, TLS 1.0, and TLS 1.1.",
                            port_str,
                            ssl.weak_protocols.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for weak ciphers
                if !ssl.weak_ciphers.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Weak SSL/TLS Cipher Suites Enabled".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Weak cipher suites detected on {}: {}. Disable RC4, DES, 3DES, and export ciphers.",
                            port_str,
                            ssl.weak_ciphers.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for missing HSTS
                if !ssl.hsts_enabled && port.port == 443 {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Missing HTTP Strict Transport Security (HSTS)".to_string(),
                        severity: Severity::Low,
                        description: format!(
                            "HSTS header not detected on {}. Enable HSTS to prevent SSL stripping attacks.",
                            port_str
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for certificate chain issues
                if !ssl.chain_issues.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "SSL/TLS Certificate Chain Issues".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Certificate chain issues detected on {}: {}",
                            port_str,
                            ssl.chain_issues.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }
            }
        }
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortInfo, PortState, Protocol, ScanTarget, ServiceInfo};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_host(ports: Vec<u16>) -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: ports
                .into_iter()
                .map(|p| PortInfo {
                    port: p,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "test".to_string(),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                })
                .collect(),
            vulnerabilities: Vec::new(),
            scan_duration: Duration::from_secs(1),
        }
    }

    #[test]
    fn test_misconfig_smb() {
        let host = create_test_host(vec![445]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.cve_id == Some("MS17-010".to_string())));
    }

    #[test]
    fn test_misconfig_rdp() {
        let host = create_test_host(vec![3389]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("RDP")));
    }

    #[test]
    fn test_misconfig_excessive_ports() {
        let host = create_test_host((1..=25).collect());
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Excessive")));
    }

    // Database services tests
    #[test]
    fn test_misconfig_mongodb() {
        let host = create_test_host(vec![27017]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("MongoDB")));
        assert!(vulns.iter().any(|v| v.severity == Severity::High));
    }

    #[test]
    fn test_misconfig_redis() {
        let host = create_test_host(vec![6379]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Redis")));
        assert!(vulns.iter().any(|v| v.description.contains("no authentication") || v.description.contains("without authentication")));
    }

    #[test]
    fn test_misconfig_elasticsearch() {
        let host = create_test_host(vec![9200]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Elasticsearch")));
    }

    #[test]
    fn test_misconfig_memcached() {
        let host = create_test_host(vec![11211]);
        let vulns = check_misconfigurations(&host);
        let memcached_vuln = vulns.iter().find(|v| v.title.contains("Memcached"));
        assert!(memcached_vuln.is_some());
        assert_eq!(memcached_vuln.unwrap().severity, Severity::Critical);
        assert!(memcached_vuln.unwrap().cve_id.is_some());
    }

    #[test]
    fn test_misconfig_couchdb() {
        let host = create_test_host(vec![5984]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("CouchDB")));
    }

    // Container/Orchestration tests
    #[test]
    fn test_misconfig_docker_api_unencrypted() {
        let host = create_test_host(vec![2375]);
        let vulns = check_misconfigurations(&host);
        let docker_vuln = vulns.iter().find(|v| v.title.contains("Docker API") && v.title.contains("Unencrypted"));
        assert!(docker_vuln.is_some());
        assert_eq!(docker_vuln.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_misconfig_kubernetes_api() {
        let host = create_test_host(vec![6443]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Kubernetes API")));
    }

    #[test]
    fn test_misconfig_etcd() {
        let host = create_test_host(vec![2379]);
        let vulns = check_misconfigurations(&host);
        let etcd_vuln = vulns.iter().find(|v| v.title.contains("etcd"));
        assert!(etcd_vuln.is_some());
        assert_eq!(etcd_vuln.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_misconfig_kubelet() {
        // Test read-only port (critical)
        let host = create_test_host(vec![10255]);
        let vulns = check_misconfigurations(&host);
        let kubelet_vuln = vulns.iter().find(|v| v.title.contains("Kubelet"));
        assert!(kubelet_vuln.is_some());
        assert_eq!(kubelet_vuln.unwrap().severity, Severity::Critical);

        // Test authenticated port (high)
        let host2 = create_test_host(vec![10250]);
        let vulns2 = check_misconfigurations(&host2);
        let kubelet_vuln2 = vulns2.iter().find(|v| v.title.contains("Kubelet"));
        assert!(kubelet_vuln2.is_some());
        assert_eq!(kubelet_vuln2.unwrap().severity, Severity::High);
    }

    // Industrial/OT tests
    #[test]
    fn test_misconfig_modbus() {
        let host = create_test_host(vec![502]);
        let vulns = check_misconfigurations(&host);
        let modbus_vuln = vulns.iter().find(|v| v.title.contains("Modbus"));
        assert!(modbus_vuln.is_some());
        assert_eq!(modbus_vuln.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_misconfig_s7comm() {
        let host = create_test_host(vec![102]);
        let vulns = check_misconfigurations(&host);
        let s7_vuln = vulns.iter().find(|v| v.title.contains("S7comm"));
        assert!(s7_vuln.is_some());
        assert_eq!(s7_vuln.unwrap().severity, Severity::Critical);
    }

    // Remote access tests
    #[test]
    fn test_misconfig_telnet() {
        let host = create_test_host(vec![23]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Telnet")));
    }

    #[test]
    fn test_misconfig_vnc() {
        let host = create_test_host(vec![5900]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("VNC")));
    }

    // CI/CD tests
    #[test]
    fn test_misconfig_jenkins_agent() {
        let host = create_test_host(vec![50000]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Jenkins Agent")));
    }

    // Monitoring tests
    #[test]
    fn test_misconfig_prometheus() {
        let host = create_test_host(vec![9090]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Prometheus")));
    }

    // Message queue tests
    #[test]
    fn test_misconfig_rabbitmq() {
        let host = create_test_host(vec![15672]);
        let vulns = check_misconfigurations(&host);
        let rmq_vuln = vulns.iter().find(|v| v.title.contains("RabbitMQ Management"));
        assert!(rmq_vuln.is_some());
        assert!(rmq_vuln.unwrap().description.contains("guest/guest"));
    }

    #[test]
    fn test_misconfig_kafka() {
        let host = create_test_host(vec![9092]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Kafka")));
    }

    // Misc services tests
    #[test]
    fn test_misconfig_ipmi() {
        let host = create_test_host(vec![623]);
        let vulns = check_misconfigurations(&host);
        let ipmi_vuln = vulns.iter().find(|v| v.title.contains("IPMI"));
        assert!(ipmi_vuln.is_some());
        assert_eq!(ipmi_vuln.unwrap().severity, Severity::Critical);
        assert!(ipmi_vuln.unwrap().cve_id.is_some());
    }

    #[test]
    fn test_misconfig_consul() {
        let host = create_test_host(vec![8500]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Consul")));
    }

    #[test]
    fn test_misconfig_zookeeper() {
        let host = create_test_host(vec![2181]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Zookeeper")));
    }

    // Multiple services test
    #[test]
    fn test_misconfig_multiple_services() {
        let host = create_test_host(vec![6379, 27017, 9200, 2375]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Redis")));
        assert!(vulns.iter().any(|v| v.title.contains("MongoDB")));
        assert!(vulns.iter().any(|v| v.title.contains("Elasticsearch")));
        assert!(vulns.iter().any(|v| v.title.contains("Docker")));
        assert!(vulns.len() >= 4);
    }
}
