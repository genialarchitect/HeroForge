//! DNS Protocol Handler
//!
//! Executes DNS-based template requests.

use crate::scanner::template_engine::matcher::{execute_matchers, ResponseData};
use crate::scanner::template_engine::types::*;
use log::debug;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// DNS protocol handler
pub struct DnsHandler {
    options: ExecutionOptions,
}

impl DnsHandler {
    /// Create a new DNS handler
    pub fn new(options: ExecutionOptions) -> Self {
        Self { options }
    }

    /// Execute a DNS request from template
    pub async fn execute(
        &self,
        request: &DnsRequest,
        target: &str,
        variables: &HashMap<String, String>,
    ) -> Result<Vec<TemplateResult>, TemplateError> {
        let name = self.substitute_variables(&request.name, target, variables);

        let result = self.execute_query(&name, request).await?;
        Ok(vec![result])
    }

    /// Execute a DNS query
    async fn execute_query(
        &self,
        name: &str,
        request: &DnsRequest,
    ) -> Result<TemplateResult, TemplateError> {
        let start = Instant::now();

        debug!("Querying DNS: {} (type: {})", name, request.query_type);

        // Create resolver with custom nameservers if provided
        let resolver = if request.resolvers.is_empty() {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        } else {
            // Build custom resolver configuration from provided resolvers
            let nameservers: Vec<NameServerConfig> = request
                .resolvers
                .iter()
                .filter_map(|resolver_addr| {
                    // Parse the resolver address (supports "ip:port" or just "ip" with default port 53)
                    let socket_addr: SocketAddr = if resolver_addr.contains(':') {
                        resolver_addr.parse().ok()?
                    } else {
                        format!("{}:53", resolver_addr).parse().ok()?
                    };

                    // Create nameserver configs for both UDP and TCP protocols
                    Some(vec![
                        NameServerConfig {
                            socket_addr,
                            protocol: Protocol::Udp,
                            tls_dns_name: None,
                            trust_negative_responses: true,
                            bind_addr: None,
                        },
                        NameServerConfig {
                            socket_addr,
                            protocol: Protocol::Tcp,
                            tls_dns_name: None,
                            trust_negative_responses: true,
                            bind_addr: None,
                        },
                    ])
                })
                .flatten()
                .collect();

            if nameservers.is_empty() {
                debug!("No valid custom resolvers parsed, using system defaults");
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            } else {
                debug!("Using {} custom nameservers", nameservers.len() / 2);
                let config = ResolverConfig::from_parts(None, vec![], nameservers);
                TokioAsyncResolver::tokio(config, ResolverOpts::default())
            }
        };

        let query_type = request.query_type.to_uppercase();
        let mut response_body = String::new();
        let mut matched = false;

        match query_type.as_str() {
            "A" => {
                if let Ok(response) = resolver.lookup_ip(name).await {
                    for ip in response.iter() {
                        response_body.push_str(&format!("{}\n", ip));
                    }
                }
            }
            "AAAA" => {
                if let Ok(response) = resolver.lookup_ip(name).await {
                    for ip in response.iter() {
                        if ip.is_ipv6() {
                            response_body.push_str(&format!("{}\n", ip));
                        }
                    }
                }
            }
            "CNAME" => {
                if let Ok(response) = resolver.lookup(
                    name,
                    trust_dns_resolver::proto::rr::RecordType::CNAME,
                ).await {
                    for record in response.iter() {
                        response_body.push_str(&format!("{}\n", record));
                    }
                }
            }
            "MX" => {
                if let Ok(response) = resolver.mx_lookup(name).await {
                    for mx in response.iter() {
                        response_body.push_str(&format!(
                            "{} {}\n",
                            mx.preference(),
                            mx.exchange()
                        ));
                    }
                }
            }
            "NS" => {
                if let Ok(response) = resolver.ns_lookup(name).await {
                    for ns in response.iter() {
                        response_body.push_str(&format!("{}\n", ns));
                    }
                }
            }
            "TXT" => {
                if let Ok(response) = resolver.txt_lookup(name).await {
                    for txt in response.iter() {
                        for s in txt.txt_data() {
                            response_body.push_str(&format!(
                                "{}\n",
                                String::from_utf8_lossy(s)
                            ));
                        }
                    }
                }
            }
            "SOA" => {
                if let Ok(response) = resolver.soa_lookup(name).await {
                    for soa in response.iter() {
                        response_body.push_str(&format!(
                            "{} {} {} {} {} {} {}\n",
                            soa.mname(),
                            soa.rname(),
                            soa.serial(),
                            soa.refresh(),
                            soa.retry(),
                            soa.expire(),
                            soa.minimum()
                        ));
                    }
                }
            }
            "PTR" => {
                if let Ok(response) = resolver.reverse_lookup(
                    name.parse().map_err(|e| TemplateError::Validation(format!("Invalid IP: {}", e)))?
                ).await {
                    for ptr in response.iter() {
                        response_body.push_str(&format!("{}\n", ptr));
                    }
                }
            }
            _ => {
                debug!("Unsupported DNS query type: {}", query_type);
            }
        }

        let elapsed = start.elapsed();

        // Create response data
        let response_data = ResponseData::new(
            if response_body.is_empty() { 0 } else { 200 },
            HashMap::new(),
            response_body.clone(),
        );

        // Execute matchers
        let match_result = execute_matchers(
            &request.matchers,
            request.matchers_condition,
            &response_data,
        );

        Ok(TemplateResult {
            template_id: String::new(),
            template_name: String::new(),
            severity: Severity::Unknown,
            matched: match_result.matched,
            extracted: HashMap::new(),
            matched_at: name.to_string(),
            matcher_name: match_result.matcher_name,
            request_url: None,
            request_method: Some(format!("DNS-{}", query_type)),
            response_status: None,
            response_time: elapsed,
            curl_command: Some(format!("dig {} {}", query_type, name)),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Substitute variables in string
    fn substitute_variables(
        &self,
        input: &str,
        target: &str,
        variables: &HashMap<String, String>,
    ) -> String {
        let mut result = input.to_string();

        // Substitute {{FQDN}}
        result = result.replace("{{FQDN}}", target);

        // Substitute {{Hostname}}
        if result.contains("{{Hostname}}") {
            let hostname = target.split(':').next().unwrap_or(target);
            result = result.replace("{{Hostname}}", hostname);
        }

        // Substitute template variables
        for (key, value) in variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_variables() {
        let handler = DnsHandler::new(ExecutionOptions::default());
        let mut vars = HashMap::new();
        vars.insert("subdomain".to_string(), "test".to_string());

        let result = handler.substitute_variables(
            "{{subdomain}}.{{FQDN}}",
            "example.com",
            &vars,
        );
        assert_eq!(result, "test.example.com");
    }
}
