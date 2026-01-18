use anyhow::Result;
use crate::types::{PortInfo, PortState, Protocol, ScanConfig, ScanTarget, ScanType};
use crate::scanner::{syn_scanner, udp_scanner};
use log::{debug, info};
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub async fn scan_ports(
    config: &ScanConfig,
) -> Result<HashMap<IpAddr, Vec<PortInfo>>, anyhow::Error> {
    let mut results = HashMap::new();

    for target_spec in &config.targets {
        let ip: IpAddr = target_spec.parse()?;
        let target = ScanTarget { ip, hostname: None };
        let ports = scan_target_ports(&target, config).await?;
        results.insert(ip, ports);
    }

    Ok(results)
}

/// Scan ports on a target, dispatching to the appropriate scanner based on scan type
pub async fn scan_target_ports(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>, anyhow::Error> {
    match config.scan_type {
        ScanType::TCPConnect => {
            debug!(
                "TCP Connect scan: ports {}-{} on {}",
                config.port_range.0, config.port_range.1, target.ip
            );
            scan_tcp_connect(target, config).await
        }
        ScanType::UDPScan => {
            info!("UDP scan on {}", target.ip);
            udp_scanner::scan_target_udp_ports(target, config).await
        }
        ScanType::TCPSyn => {
            info!("TCP SYN scan on {}", target.ip);
            syn_scanner::scan_target_syn_ports(target, config).await
        }
        ScanType::Comprehensive => {
            // Run both TCP SYN and UDP scans
            info!("Comprehensive scan (TCP SYN + UDP) on {}", target.ip);

            // TCP SYN scan (stealthier than connect, falls back to connect if no privileges)
            let tcp_ports = match syn_scanner::scan_target_syn_ports(target, config).await {
                Ok(ports) => ports,
                Err(e) => {
                    // SYN scan might fail due to permissions - fall back to TCP Connect
                    log::warn!("SYN scan failed (may require root): {}, falling back to TCP Connect", e);
                    scan_tcp_connect(target, config).await?
                }
            };

            // UDP scan
            let udp_ports = match udp_scanner::scan_target_udp_ports(target, config).await {
                Ok(ports) => ports,
                Err(e) => {
                    // UDP might fail due to permissions - log but continue
                    log::warn!("UDP scan failed (may require root): {}", e);
                    Vec::new()
                }
            };

            // Merge results
            let mut all_ports = tcp_ports;
            all_ports.extend(udp_ports);
            all_ports.sort_by_key(|p| (p.port, matches!(p.protocol, Protocol::UDP)));

            Ok(all_ports)
        }
    }
}

/// TCP Connect scan (original implementation)
async fn scan_tcp_connect(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>, anyhow::Error> {
    // Filter out excluded ports
    let ports: Vec<u16> = (config.port_range.0..=config.port_range.1)
        .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
        .collect();

    if ports.len() != (config.port_range.1 - config.port_range.0 + 1) as usize {
        debug!(
            "Excluded {} port(s) based on exclusion rules ({} remaining)",
            (config.port_range.1 - config.port_range.0 + 1) as usize - ports.len(),
            ports.len()
        );
    }

    let semaphore = Arc::new(Semaphore::new(config.threads));
    let mut tasks = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let ip = target.ip;
        let timeout = config.timeout;

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_port(ip, port, timeout).await
        });

        tasks.push(task);
    }

    let mut open_ports = Vec::new();
    for task in tasks {
        if let Ok(Some(port_info)) = task.await {
            if matches!(port_info.state, PortState::Open) {
                open_ports.push(port_info);
            }
        }
    }

    open_ports.sort_by_key(|p| p.port);
    Ok(open_ports)
}

async fn scan_port(ip: IpAddr, port: u16, timeout: std::time::Duration) -> Option<PortInfo> {
    let addr = format!("{}:{}", ip, port);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Open,
            service: None,
        }),
        Ok(Err(_)) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Closed,
            service: None,
        }),
        Err(_) => Some(PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Filtered,
            service: None,
        }),
    }
}

// Common port to service name mapping
pub fn get_common_service(port: u16) -> Option<&'static str> {
    match port {
        // Standard well-known ports
        1 => Some("tcpmux"),
        7 => Some("echo"),
        9 => Some("discard"),
        11 => Some("systat"),
        13 => Some("daytime"),
        15 => Some("netstat"),
        17 => Some("qotd"),
        19 => Some("chargen"),
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        37 => Some("time"),
        42 => Some("nameserver"),
        43 => Some("whois"),
        49 => Some("tacacs"),
        53 => Some("dns"),
        67 => Some("dhcps"),
        68 => Some("dhcpc"),
        69 => Some("tftp"),
        70 => Some("gopher"),
        79 => Some("finger"),
        80 => Some("http"),
        88 => Some("kerberos"),
        102 => Some("s7comm"),  // Siemens S7 PLC
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        113 => Some("ident"),
        119 => Some("nntp"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        161 => Some("snmp"),
        162 => Some("snmptrap"),
        177 => Some("xdmcp"),
        179 => Some("bgp"),
        194 => Some("irc"),
        201 => Some("appletalk"),
        264 => Some("bgmp"),
        318 => Some("pkix-timestamp"),
        381 => Some("hp-collect"),
        383 => Some("hp-alarm-mgr"),
        389 => Some("ldap"),
        411 => Some("dc"),
        412 => Some("aresource"),
        427 => Some("svrloc"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        464 => Some("kpasswd5"),
        465 => Some("smtps"),
        497 => Some("retrospect"),
        500 => Some("isakmp"),
        502 => Some("modbus"),  // Industrial protocol
        512 => Some("rexec"),
        513 => Some("rlogin"),
        514 => Some("syslog"),
        515 => Some("printer"),
        520 => Some("rip"),
        524 => Some("ncp"),
        530 => Some("rpc"),
        543 => Some("klogin"),
        544 => Some("kshell"),
        548 => Some("afp"),
        554 => Some("rtsp"),
        587 => Some("submission"),
        593 => Some("http-rpc-epmap"),
        623 => Some("ipmi"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        646 => Some("ldp"),
        691 => Some("ms-exchange"),
        749 => Some("kerberos-adm"),
        873 => Some("rsync"),
        902 => Some("vmware-auth"),
        903 => Some("vmware-auth-https"),
        912 => Some("apex"),
        981 => Some("sofaware"),
        989 => Some("ftps-data"),
        990 => Some("ftps"),
        992 => Some("telnets"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1025 => Some("nfs-or-rpc"),
        1026..=1029 => Some("ms-rpc"),
        1080 => Some("socks"),
        1099 => Some("rmi"),
        1194 => Some("openvpn"),
        1214 => Some("kazaa"),
        1241 => Some("nessus"),
        1311 => Some("rxmon"),
        1337 => Some("waste"),
        1352 => Some("lotusnotes"),
        1433 => Some("ms-sql-s"),
        1434 => Some("ms-sql-m"),
        1494 => Some("citrix-ica"),
        1521 => Some("oracle"),
        1583 => Some("simbaexpress"),
        1723 => Some("pptp"),
        1755 => Some("wms"),
        1812 => Some("radius"),
        1813 => Some("radius-acct"),
        1883 => Some("mqtt"),
        1900 => Some("upnp"),
        1935 => Some("rtmp"),
        1947 => Some("hasp"),
        1962 => Some("biap-mp"),
        2000 => Some("cisco-sccp"),
        2049 => Some("nfs"),
        2082 => Some("cpanel"),
        2083 => Some("cpanel-ssl"),
        2086 => Some("whm"),
        2087 => Some("whm-ssl"),
        2100 => Some("amiganetfs"),
        2121 => Some("ccproxy-ftp"),
        2181 => Some("zookeeper"),
        2222 => Some("directadmin"),
        2323 => Some("3d-nfsd"),
        2375 => Some("docker"),
        2376 => Some("docker-tls"),
        2379 => Some("etcd-client"),
        2380 => Some("etcd-server"),
        2483 => Some("oracle-tns"),
        2484 => Some("oracle-tns-ssl"),
        2525 => Some("smtp-alt"),
        2598 => Some("new-ibs"),
        2701 => Some("sms-rcinfo"),
        2702 => Some("sms-xfer"),
        2710 => Some("sso-service"),
        2717 => Some("pn-requester"),
        2800 => Some("acc-raid"),
        2947 => Some("gpsd"),
        2967 => Some("ssc-agent"),
        3000 => Some("ppp"),  // Also Grafana
        3001 => Some("nessus"),
        3050 => Some("firebird"),
        3128 => Some("squid-http"),
        3260 => Some("iscsi"),
        3268 => Some("globalcat-ldap"),
        3269 => Some("globalcat-ldap-ssl"),
        3283 => Some("net-assistant"),
        3299 => Some("saprouter"),
        3306 => Some("mysql"),
        3333 => Some("dec-notes"),
        3389 => Some("ms-wbt-server"),
        3478 => Some("stun"),
        3500 => Some("rtmp-port"),
        3541 => Some("voispeed-port"),
        3632 => Some("distcc"),
        3690 => Some("svn"),
        3749 => Some("cimtrak"),
        3780 => Some("nexpose"),
        3784 => Some("bfd-control"),
        3868 => Some("diameter"),
        3872 => Some("oem-agent"),
        4000 => Some("remoteanything"),
        4022 => Some("dnox"),
        4040 => Some("yo-main"),
        4100 => Some("sieve"),
        4111 => Some("xgrid"),
        4125 => Some("rww"),
        4222 => Some("nats"),
        4243 => Some("vrml-multi-use"),
        4369 => Some("epmd"),  // Erlang Port Mapper
        4433 => Some("vop"),
        4443 => Some("pharos"),
        4444 => Some("krb524"),
        4445 => Some("upnotifyp"),
        4500 => Some("nat-t-ike"),
        4505 => Some("saltmaster"),
        4506 => Some("saltmaster-event"),
        4567 => Some("tram"),
        4665..=4669 => Some("edonkey"),
        4711 => Some("trinity"),
        4786 => Some("smart-install"),  // Cisco Smart Install
        4848 => Some("glassfish"),
        5000 => Some("upnp"),  // Also Flask default
        5001 => Some("commplex-link"),
        5003 => Some("filemaker"),
        5004 => Some("rtp-audio"),
        5005 => Some("rtp-video"),
        5009 => Some("airport-admin"),
        5010 => Some("telelpathstart"),
        5050 => Some("mmcc"),
        5060 => Some("sip"),
        5061 => Some("sip-tls"),
        5093 => Some("sentinel-lm"),
        5101 => Some("admdog"),
        5104 => Some("cfengine"),
        5190 => Some("aol"),
        5222 => Some("xmpp-client"),
        5269 => Some("xmpp-server"),
        5280 => Some("xmpp-bosh"),
        5353 => Some("mdns"),
        5355 => Some("llmnr"),
        5357 => Some("wsdapi"),
        5400 => Some("vpc"),
        5432 => Some("postgresql"),
        5500 => Some("vnc-server"),
        5555 => Some("adb"),  // Android Debug Bridge
        5556 => Some("freeciv"),
        5601 => Some("kibana"),
        5631 => Some("pcanywheredata"),
        5632 => Some("pcanywherestat"),
        5666 => Some("nrpe"),  // Nagios
        5672 => Some("amqp"),  // RabbitMQ
        5683 => Some("coap"),  // Constrained Application Protocol
        5800 => Some("vnc-http"),
        5801 => Some("vnc-http-1"),
        5900..=5909 => Some("vnc"),
        5984 => Some("couchdb"),
        5985 => Some("wsman"),  // WinRM HTTP
        5986 => Some("wsman-ssl"),  // WinRM HTTPS
        6000..=6007 => Some("x11"),
        6379 => Some("redis"),
        6432 => Some("pgbouncer"),
        6443 => Some("kubernetes-api"),
        6514 => Some("syslog-tls"),
        6560 => Some("hp-dataprotect"),
        6566 => Some("sane-port"),
        6588 => Some("analogx"),
        6667 => Some("irc"),
        6668 => Some("irc"),
        6697 => Some("irc-ssl"),
        6699 => Some("napster"),
        6881..=6889 => Some("bittorrent"),
        6984 => Some("couchdb-ssl"),
        7000 => Some("afs3-fileserver"),
        7001 => Some("weblogic"),  // Oracle WebLogic
        7002 => Some("weblogic-ssl"),
        7070 => Some("realserver"),
        7474 => Some("neo4j"),
        7547 => Some("cwmp"),
        7777 => Some("cbt"),
        7778 => Some("interwise"),
        7779 => Some("vstat"),
        7787 => Some("gfi-sandbox"),
        8000 => Some("http-alt"),
        8001 => Some("vcom-tunnel"),
        8008 => Some("http-alt"),
        8009 => Some("ajp13"),  // Apache JServ Protocol
        8010 => Some("xmpp"),
        8020 => Some("hdfs-nn"),  // HDFS NameNode
        8022 => Some("oa-system"),
        8042 => Some("hadoop-nodemanager"),
        8051 => Some("rocrail"),
        8069 => Some("odoo"),
        8080 => Some("http-proxy"),
        8081 => Some("http-proxy"),
        8082 => Some("http-proxy"),
        8083 => Some("http-proxy"),
        8084 => Some("http-proxy"),
        8085 => Some("http-proxy"),
        8086 => Some("influxdb"),
        8088 => Some("http-rpc"),
        8089 => Some("splunk-management"),
        8090 => Some("http-proxy"),
        8091 => Some("couchbase"),
        8092 => Some("couchbase-views"),
        8093 => Some("couchbase-query"),
        8096 => Some("jellyfin"),
        8099 => Some("http-proxy"),
        8100 => Some("xprint-server"),
        8111 => Some("teamcity"),
        8123 => Some("clickhouse-http"),
        8125 => Some("statsd"),
        8140 => Some("puppet"),
        8161 => Some("activemq-web"),
        8172 => Some("web-deploy"),
        8181 => Some("intermapper"),
        8200 => Some("vault"),  // HashiCorp Vault
        8222 => Some("nats-monitor"),
        8243 => Some("https-proxy"),
        8280 => Some("http-proxy"),
        8291 => Some("mikrotik-api"),
        8333 => Some("bitcoin"),
        8334 => Some("bitcoin-json-rpc"),
        8384 => Some("syncthing"),
        8443 => Some("https-alt"),
        8500 => Some("consul"),
        8501 => Some("consul-https"),
        8530 => Some("wsus-http"),
        8531 => Some("wsus-https"),
        8554 => Some("rtsp-proxy"),
        8649 => Some("ganglia"),
        8765 => Some("http-proxy"),
        8834 => Some("nessus-web"),
        8848 => Some("nacos"),  // Service discovery
        8880 => Some("cddbp-alt"),
        8883 => Some("mqtt-ssl"),
        8888 => Some("http-proxy"),
        8889 => Some("ddi-tcp"),
        8920 => Some("jellyfin-https"),
        8929 => Some("gitlab-registry"),
        8983 => Some("solr"),  // Apache Solr
        9000 => Some("cslistener"),  // Also ClickHouse, SonarQube
        9001 => Some("tor-orport"),  // Also SonarQube
        9002 => Some("dynamid"),
        9003 => Some("eol-svc"),
        9009 => Some("pichat"),
        9010 => Some("sdr"),
        9042 => Some("cassandra"),
        9043 => Some("websphere-admin"),
        9050 => Some("tor-socks"),
        9051 => Some("tor-control"),
        9080 => Some("glrpc"),
        9081 => Some("cisco-aqos"),
        9090 => Some("prometheus"),
        9091 => Some("pushgateway"),
        9092 => Some("kafka"),
        9093 => Some("kafka-tls"),
        9100 => Some("jetdirect"),  // Also Prometheus Node Exporter
        9160 => Some("cassandra-thrift"),
        9200 => Some("elasticsearch"),
        9201 => Some("elasticsearch-tribe"),
        9300 => Some("elasticsearch-transport"),
        9333 => Some("seaweedfs"),
        9389 => Some("adws"),  // Active Directory Web Services
        9400 => Some("hp-laserjet"),
        9411 => Some("zipkin"),
        9418 => Some("git"),
        9443 => Some("https-alt"),
        9600 => Some("omnilink"),
        9673 => Some("zonecast"),
        9800 => Some("webdav"),
        9809..=9815 => Some("websphere"),
        9875 => Some("sapv1"),
        9999 => Some("abyss"),
        10000 => Some("webmin"),
        10001 => Some("scp-config"),
        10010 => Some("containerd-grpc"),
        10050 => Some("zabbix-agent"),
        10051 => Some("zabbix-server"),
        10080 => Some("amanda"),
        10250 => Some("kubelet"),
        10255 => Some("kubelet-ro"),
        10256 => Some("kube-proxy"),
        10443 => Some("https-proxy"),
        10514 => Some("syslog-tcp-ietf"),
        11211 => Some("memcached"),
        11300 => Some("beanstalkd"),
        11371 => Some("pgp-hkp"),
        12222 => Some("direct-connect"),
        12345 => Some("netbus"),
        13000 => Some("http-proxy"),
        13080 => Some("harbor"),
        13443 => Some("harbor-ssl"),
        14265 => Some("iota-api"),
        15000 => Some("hydap"),
        15432 => Some("citrix-cds"),
        15672 => Some("rabbitmq-management"),
        16010 => Some("hbase-master"),
        16020 => Some("hbase-regionserver"),
        16030 => Some("hbase-master-web"),
        16686 => Some("jaeger-ui"),
        17000 => Some("ftp"),
        18080 => Some("http-proxy"),
        18081 => Some("monero-rpc"),
        18091..=18093 => Some("couchbase"),
        19132 => Some("minecraft-bedrock"),
        19999 => Some("dnp3"),  // Industrial protocol
        20000 => Some("dnp3"),
        20547 => Some("propoint"),
        21025 => Some("prolink"),
        22222 => Some("easyengine"),
        23023 => Some("telnet-ssl"),
        25565 => Some("minecraft"),
        25575 => Some("minecraft-rcon"),
        26257 => Some("cockroachdb"),
        27017 => Some("mongodb"),
        27018 => Some("mongodb-config"),
        27019 => Some("mongodb-shard"),
        27080 => Some("mongodb-http"),
        28015 => Some("rethinkdb"),
        28017 => Some("mongodb-web"),
        29418 => Some("gerrit"),
        30303 => Some("ethereum"),
        32400 => Some("plex"),
        32768..=32900 => Some("filenet-tms"),
        33060 => Some("mysqlx"),
        34443 => Some("parallels-ssl"),
        37777 => Some("dahua-dvr"),
        38292 => Some("landesk"),
        44818 => Some("ethernet-ip"),  // Industrial protocol
        47808 => Some("bacnet"),  // Building automation
        50000 => Some("jenkins-agent"),
        50002 => Some("iiimsf"),
        50030 => Some("hadoop-jobtracker"),
        50070 => Some("hdfs-web"),
        50075 => Some("hdfs-datanode"),
        50090 => Some("hdfs-secondary-nn"),
        50443 => Some("ssl-proxy"),
        54321 => Some("bo2k"),
        54328 => Some("kube-scheduler"),
        55555 => Some("metasploitd"),
        60443 => Some("ssl-proxy"),
        61616 => Some("activemq"),
        62078 => Some("iphone-sync"),
        64738 => Some("mumble"),
        _ => None,
    }
}
