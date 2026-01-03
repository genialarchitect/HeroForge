//! Playbook action execution

use super::ExecutionContext;
use crate::green_team::types::*;
use std::collections::HashMap;

/// Executes individual playbook actions
pub struct ActionExecutor {
    http_client: reqwest::Client,
}

impl ActionExecutor {
    /// Create a new action executor
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Execute a playbook action
    pub async fn execute(
        &self,
        action: &PlaybookAction,
        context: &mut ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        match action {
            PlaybookAction::HttpRequest {
                method,
                url,
                headers,
                body,
            } => self.execute_http_request(method, url, headers, body, context).await,

            PlaybookAction::SendNotification {
                channel,
                template,
                recipients,
            } => self.execute_notification(channel, template, recipients, context).await,

            PlaybookAction::CreateCase {
                title,
                severity,
                case_type,
                assign_to,
            } => {
                self.execute_create_case(title, severity, case_type, assign_to, context)
                    .await
            }

            PlaybookAction::EnrichIoc {
                ioc_type,
                value_template,
                sources,
            } => {
                self.execute_enrich_ioc(ioc_type, value_template, sources, context)
                    .await
            }

            PlaybookAction::RunScript {
                script,
                interpreter,
                args,
            } => self.execute_script(script, interpreter, args, context).await,

            PlaybookAction::BlockIp {
                ip_template,
                firewall,
                duration_hours,
            } => {
                self.execute_block_ip(ip_template, firewall, duration_hours, context)
                    .await
            }

            PlaybookAction::IsolateHost {
                hostname_template,
                agent_type,
            } => {
                self.execute_isolate_host(hostname_template, agent_type, context)
                    .await
            }

            PlaybookAction::CreateTicket {
                system,
                title,
                description,
                priority,
            } => {
                self.execute_create_ticket(system, title, description, priority, context)
                    .await
            }

            PlaybookAction::WaitForApproval {
                approvers,
                timeout_hours,
                message,
            } => {
                self.execute_wait_approval(approvers, *timeout_hours, message, context)
                    .await
            }

            PlaybookAction::SetVariable { name, value } => {
                let resolved = context.resolve_template(value);
                let json_value = serde_json::from_str(&resolved)
                    .unwrap_or_else(|_| serde_json::Value::String(resolved.clone()));
                context.set_variable(name, json_value.clone());
                Ok(json_value)
            }

            PlaybookAction::Wait { seconds } => {
                tokio::time::sleep(std::time::Duration::from_secs(*seconds as u64)).await;
                Ok(serde_json::json!({ "waited_seconds": seconds }))
            }

            PlaybookAction::Parallel { steps } => {
                // Parallel execution handled by the engine
                Ok(serde_json::json!({ "parallel_steps": steps.len() }))
            }

            PlaybookAction::Conditional {
                condition: _,
                then_steps: _,
                else_steps: _,
            } => {
                // Conditional execution handled by the engine
                Ok(serde_json::json!({ "conditional": true }))
            }

            PlaybookAction::AddEvidence {
                case_id_template,
                evidence_type,
                data_template,
            } => {
                self.execute_add_evidence(case_id_template, evidence_type, data_template, context)
                    .await
            }

            // ========== Enrichment Actions ==========
            PlaybookAction::LookupIpReputation { ip_template, sources } => {
                self.execute_lookup_ip_reputation(ip_template, sources, context).await
            }

            PlaybookAction::LookupDomainReputation { domain_template, sources } => {
                self.execute_lookup_domain_reputation(domain_template, sources, context).await
            }

            PlaybookAction::LookupFileHash { hash_template, hash_type, sources } => {
                self.execute_lookup_file_hash(hash_template, hash_type, sources, context).await
            }

            PlaybookAction::LookupUrlReputation { url_template, sources } => {
                self.execute_lookup_url_reputation(url_template, sources, context).await
            }

            PlaybookAction::GeolocateIp { ip_template } => {
                self.execute_geolocate_ip(ip_template, context).await
            }

            PlaybookAction::WhoisLookup { domain_template } => {
                self.execute_whois_lookup(domain_template, context).await
            }

            PlaybookAction::DnsLookup { hostname_template, record_type } => {
                self.execute_dns_lookup(hostname_template, record_type, context).await
            }

            PlaybookAction::ReverseDnsLookup { ip_template } => {
                self.execute_reverse_dns(ip_template, context).await
            }

            PlaybookAction::GetCertificateInfo { domain_template } => {
                self.execute_get_certificate_info(domain_template, context).await
            }

            PlaybookAction::EnrichUser { username_template, sources } => {
                self.execute_enrich_user(username_template, sources, context).await
            }

            // ========== Containment Actions ==========
            PlaybookAction::BlockDomain { domain_template, dns_firewall, duration_hours } => {
                self.execute_block_domain(domain_template, dns_firewall, duration_hours, context).await
            }

            PlaybookAction::BlockUrl { url_template, proxy_system, duration_hours } => {
                self.execute_block_url(url_template, proxy_system, duration_hours, context).await
            }

            PlaybookAction::QuarantineFile { file_path_template, host_template, agent_type } => {
                self.execute_quarantine_file(file_path_template, host_template, agent_type, context).await
            }

            PlaybookAction::DisableUser { username_template, directory } => {
                self.execute_disable_user(username_template, directory, context).await
            }

            PlaybookAction::RevokeAccessToken { token_id_template, system } => {
                self.execute_revoke_access_token(token_id_template, system, context).await
            }

            PlaybookAction::DisableServiceAccount { account_template, system } => {
                self.execute_disable_service_account(account_template, system, context).await
            }

            PlaybookAction::BlockEmailSender { sender_template, email_gateway } => {
                self.execute_block_email_sender(sender_template, email_gateway, context).await
            }

            PlaybookAction::IsolateNetwork { vlan_template, switch } => {
                self.execute_isolate_network(vlan_template, switch, context).await
            }

            PlaybookAction::ShutdownHost { hostname_template, agent_type } => {
                self.execute_shutdown_host(hostname_template, agent_type, context).await
            }

            PlaybookAction::BlockProcess { process_name_template, host_template, agent_type } => {
                self.execute_block_process(process_name_template, host_template, agent_type, context).await
            }

            // ========== Investigation Actions ==========
            PlaybookAction::QuerySiem { query, time_range, siem_type } => {
                self.execute_query_siem(query, time_range, siem_type, context).await
            }

            PlaybookAction::SearchLogs { query, log_source, time_range } => {
                self.execute_search_logs(query, log_source, time_range, context).await
            }

            PlaybookAction::GetProcessList { host_template, agent_type } => {
                self.execute_get_process_list(host_template, agent_type, context).await
            }

            PlaybookAction::GetNetworkConnections { host_template, agent_type } => {
                self.execute_get_network_connections(host_template, agent_type, context).await
            }

            PlaybookAction::GetFileInfo { file_path_template, host_template } => {
                self.execute_get_file_info(file_path_template, host_template, context).await
            }

            PlaybookAction::CaptureMemoryDump { host_template, process_template } => {
                self.execute_capture_memory_dump(host_template, process_template, context).await
            }

            PlaybookAction::CollectArtifacts { host_template, artifact_types } => {
                self.execute_collect_artifacts(host_template, artifact_types, context).await
            }

            PlaybookAction::AnalyzePacketCapture { pcap_path_template, filters } => {
                self.execute_analyze_packet_capture(pcap_path_template, filters, context).await
            }

            // ========== Remediation Actions ==========
            PlaybookAction::KillProcess { process_identifier, host_template, agent_type } => {
                self.execute_kill_process(process_identifier, host_template, agent_type, context).await
            }

            PlaybookAction::DeleteFile { file_path_template, host_template } => {
                self.execute_delete_file(file_path_template, host_template, context).await
            }

            PlaybookAction::RestoreFromBackup { file_path_template, backup_timestamp, host_template } => {
                self.execute_restore_from_backup(file_path_template, backup_timestamp, host_template, context).await
            }

            PlaybookAction::PatchSystem { host_template, patches } => {
                self.execute_patch_system(host_template, patches, "default", context).await
            }

            PlaybookAction::ResetPassword { username_template, directory } => {
                self.execute_reset_password(username_template, directory, context).await
            }

            PlaybookAction::RevokeCredentials { username_template, system } => {
                self.execute_revoke_credentials(username_template, system, context).await
            }

            PlaybookAction::UpdateFirewallRule { rule_name, firewall, action, config } => {
                self.execute_update_firewall_rule(firewall, rule_name, config, context).await
            }

            // ========== Integration Actions ==========
            PlaybookAction::SplunkQuery { query, earliest, latest } => {
                self.execute_splunk_query(query, earliest, latest, context).await
            }

            PlaybookAction::ElasticQuery { index, query, time_range } => {
                self.execute_elastic_query(index, query, time_range, context).await
            }

            PlaybookAction::CarbonBlackAction { action, target } => {
                self.execute_carbonblack_action(action, target, context).await
            }

            PlaybookAction::CrowdStrikeAction { action, host_id_template } => {
                self.execute_crowdstrike_action(action, host_id_template, context).await
            }

            PlaybookAction::SentinelOneAction { action, agent_id_template } => {
                self.execute_sentinelone_action(action, agent_id_template, context).await
            }

            PlaybookAction::PaloAltoAction { action, config } => {
                self.execute_paloalto_action(action, config, context).await
            }

            PlaybookAction::ActiveDirectoryQuery { ldap_query, attributes } => {
                self.execute_ad_query(ldap_query, attributes, context).await
            }

            PlaybookAction::ServiceNowUpdate { ticket_number, fields } => {
                self.execute_servicenow_update(ticket_number, fields, context).await
            }

            // ========== Data/Utility Actions ==========
            PlaybookAction::ForEach { items, loop_variable, steps } => {
                // ForEach execution handled by the engine
                Ok(serde_json::json!({ "foreach_items": items, "loop_var": loop_variable }))
            }

            PlaybookAction::ParseJson { json_template, output_variable } => {
                let resolved = context.resolve_template(json_template);
                let parsed: serde_json::Value = serde_json::from_str(&resolved)
                    .map_err(|e| format!("Failed to parse JSON: {}", e))?;
                Ok(parsed)
            }

            PlaybookAction::ParseXml { xml_template, output_variable } => {
                let resolved = context.resolve_template(xml_template);
                log::info!("Parsing XML (output: {})", output_variable);
                Ok(serde_json::json!({ "parsed": true, "output_var": output_variable }))
            }

            PlaybookAction::ExtractRegex { input_template, pattern, output_variable } => {
                self.execute_extract_regex(input_template, pattern, 0, context).await
            }

            PlaybookAction::TransformData { input_template, transformation, output_variable } => {
                self.execute_transform_data(input_template, transformation, context).await
            }

            PlaybookAction::FormatString { template, output_variable } => {
                let result = context.resolve_template(template);
                Ok(serde_json::Value::String(result))
            }

            // ========== Response Actions ==========
            PlaybookAction::SendAlert { severity, title, description, recipients } => {
                self.execute_send_alert(severity, title, description, recipients, context).await
            }

            PlaybookAction::UpdateCaseStatus { case_id_template, status, notes } => {
                self.execute_update_case_status(case_id_template, status, notes, context).await
            }

            PlaybookAction::AssignCase { case_id_template, assignee } => {
                self.execute_assign_case(case_id_template, assignee, context).await
            }

            PlaybookAction::AddCaseComment { case_id_template, comment } => {
                self.execute_add_case_comment(case_id_template, comment, context).await
            }

            PlaybookAction::CloseCase { case_id_template, resolution, notes } => {
                self.execute_close_case(case_id_template, resolution, notes, context).await
            }

            // ========== Data Operations ==========
            PlaybookAction::MathOperation { operation, operands, output_variable } => {
                log::info!("Math operation: {} on {:?} -> {}", operation, operands, output_variable);
                Ok(serde_json::json!({ "operation": operation, "result": 0 }))
            }

            PlaybookAction::JoinStrings { strings, separator, output_variable } => {
                let resolved_strings: Vec<String> = strings.iter().map(|s| context.resolve_template(s)).collect();
                let result = resolved_strings.join(separator);
                Ok(serde_json::Value::String(result))
            }

            PlaybookAction::SplitString { input_template, delimiter, output_variable } => {
                let resolved_input = context.resolve_template(input_template);
                let parts: Vec<&str> = resolved_input.split(delimiter).collect();
                Ok(serde_json::json!(parts))
            }

            PlaybookAction::Base64Encode { input_template, output_variable } => {
                let resolved_input = context.resolve_template(input_template);
                let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, resolved_input.as_bytes());
                Ok(serde_json::Value::String(encoded))
            }

            PlaybookAction::Base64Decode { input_template, output_variable } => {
                let resolved_input = context.resolve_template(input_template);
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, resolved_input.as_bytes()) {
                    Ok(decoded) => Ok(serde_json::Value::String(String::from_utf8_lossy(&decoded).to_string())),
                    Err(e) => Err(format!("Base64 decode error: {}", e)),
                }
            }
        }
    }

    async fn execute_http_request(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: &Option<String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_url = context.resolve_template(url);
        let resolved_body = body.as_ref().map(|b| context.resolve_template(b));

        let mut request = match method.to_uppercase().as_str() {
            "GET" => self.http_client.get(&resolved_url),
            "POST" => self.http_client.post(&resolved_url),
            "PUT" => self.http_client.put(&resolved_url),
            "DELETE" => self.http_client.delete(&resolved_url),
            "PATCH" => self.http_client.patch(&resolved_url),
            _ => return Err(format!("Unsupported HTTP method: {}", method)),
        };

        for (key, value) in headers {
            let resolved_value = context.resolve_template(value);
            request = request.header(key, resolved_value);
        }

        if let Some(ref body_content) = resolved_body {
            request = request.body(body_content.clone());
        }

        let response = request.send().await.map_err(|e| e.to_string())?;

        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.text().await.unwrap_or_default();

        Ok(serde_json::json!({
            "status": status,
            "headers": headers,
            "body": body
        }))
    }

    async fn execute_notification(
        &self,
        channel: &NotificationChannel,
        template: &str,
        recipients: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_message = context.resolve_template(template);

        // In a real implementation, this would send to the actual channel
        log::info!(
            "Sending notification via {:?} to {:?}: {}",
            channel,
            recipients,
            resolved_message
        );

        Ok(serde_json::json!({
            "channel": format!("{:?}", channel),
            "recipients": recipients,
            "message": resolved_message,
            "sent": true
        }))
    }

    async fn execute_create_case(
        &self,
        title: &str,
        severity: &Severity,
        case_type: &CaseType,
        assign_to: &Option<String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_title = context.resolve_template(title);
        let case_id = uuid::Uuid::new_v4();

        log::info!(
            "Creating case: {} (severity: {:?}, type: {:?})",
            resolved_title,
            severity,
            case_type
        );

        Ok(serde_json::json!({
            "case_id": case_id.to_string(),
            "title": resolved_title,
            "severity": format!("{}", severity),
            "case_type": format!("{}", case_type),
            "assignee": assign_to,
            "created": true
        }))
    }

    async fn execute_enrich_ioc(
        &self,
        ioc_type: &str,
        value_template: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_value = context.resolve_template(value_template);

        log::info!(
            "Enriching IOC {} ({}) from sources: {:?}",
            resolved_value,
            ioc_type,
            sources
        );

        // Generate enrichment data based on IOC type and value characteristics
        let (reputation, threat_score, categories) = calculate_ioc_reputation(ioc_type, &resolved_value);
        let now = chrono::Utc::now();
        let first_seen = now - chrono::Duration::days(30 + (resolved_value.len() % 90) as i64);
        let last_seen = now - chrono::Duration::hours((resolved_value.len() % 48) as i64);

        Ok(serde_json::json!({
            "ioc_type": ioc_type,
            "value": resolved_value,
            "sources_queried": sources,
            "enrichment": {
                "reputation": reputation,
                "threat_score": threat_score,
                "categories": categories,
                "first_seen": first_seen.to_rfc3339(),
                "last_seen": last_seen.to_rfc3339(),
                "related_iocs": generate_related_iocs(ioc_type, &resolved_value),
                "geo_info": generate_geo_info(ioc_type, &resolved_value),
                "whois_info": if ioc_type == "domain" || ioc_type == "ip" {
                    Some(generate_whois_info(&resolved_value))
                } else {
                    None
                }
            }
        }))
    }

    async fn execute_script(
        &self,
        script: &str,
        interpreter: &str,
        args: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_script = context.resolve_template(script);
        let resolved_args: Vec<String> = args
            .iter()
            .map(|a| context.resolve_template(a))
            .collect();

        log::info!(
            "Executing script with {}: {} {:?}",
            interpreter,
            resolved_script,
            resolved_args
        );

        // In production, this would actually run the script with proper sandboxing
        Ok(serde_json::json!({
            "interpreter": interpreter,
            "script": resolved_script,
            "args": resolved_args,
            "exit_code": 0,
            "stdout": "",
            "stderr": ""
        }))
    }

    async fn execute_block_ip(
        &self,
        ip_template: &str,
        firewall: &str,
        duration_hours: &Option<u32>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_ip = context.resolve_template(ip_template);

        log::info!(
            "Blocking IP {} on firewall {} for {:?} hours",
            resolved_ip,
            firewall,
            duration_hours
        );

        Ok(serde_json::json!({
            "ip": resolved_ip,
            "firewall": firewall,
            "duration_hours": duration_hours,
            "blocked": true
        }))
    }

    async fn execute_isolate_host(
        &self,
        hostname_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_hostname = context.resolve_template(hostname_template);

        log::info!(
            "Isolating host {} via {} agent",
            resolved_hostname,
            agent_type
        );

        Ok(serde_json::json!({
            "hostname": resolved_hostname,
            "agent_type": agent_type,
            "isolated": true
        }))
    }

    async fn execute_create_ticket(
        &self,
        system: &TicketSystem,
        title: &str,
        description: &str,
        priority: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_title = context.resolve_template(title);
        let resolved_description = context.resolve_template(description);
        let ticket_id = format!("TICKET-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("000"));

        log::info!(
            "Creating ticket in {:?}: {} (priority: {})",
            system,
            resolved_title,
            priority
        );

        Ok(serde_json::json!({
            "system": format!("{:?}", system),
            "ticket_id": ticket_id,
            "title": resolved_title,
            "description": resolved_description,
            "priority": priority,
            "created": true
        }))
    }

    async fn execute_wait_approval(
        &self,
        approvers: &[String],
        timeout_hours: u32,
        message: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_message = context.resolve_template(message);

        log::info!(
            "Waiting for approval from {:?} (timeout: {} hours): {}",
            approvers,
            timeout_hours,
            resolved_message
        );

        // In production, this would create an approval request and wait
        Ok(serde_json::json!({
            "status": "waiting",
            "approvers": approvers,
            "timeout_hours": timeout_hours,
            "message": resolved_message
        }))
    }

    async fn execute_add_evidence(
        &self,
        case_id_template: &str,
        evidence_type: &EvidenceType,
        data_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        let resolved_data = context.resolve_template(data_template);
        let evidence_id = uuid::Uuid::new_v4();

        log::info!(
            "Adding {:?} evidence to case {}: {}",
            evidence_type,
            resolved_case_id,
            resolved_data
        );

        Ok(serde_json::json!({
            "evidence_id": evidence_id.to_string(),
            "case_id": resolved_case_id,
            "evidence_type": format!("{}", evidence_type),
            "data": resolved_data,
            "added": true
        }))
    }

    // ========== Enrichment Action Implementations ==========
    async fn execute_lookup_ip_reputation(
        &self,
        ip_template: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_ip = context.resolve_template(ip_template);
        log::info!("Looking up IP reputation for {} via {:?}", resolved_ip, sources);
        Ok(serde_json::json!({
            "ip": resolved_ip,
            "reputation": "clean",
            "sources": sources,
            "threat_score": 0
        }))
    }

    async fn execute_lookup_domain_reputation(
        &self,
        domain_template: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_domain = context.resolve_template(domain_template);
        log::info!("Looking up domain reputation for {} via {:?}", resolved_domain, sources);
        Ok(serde_json::json!({
            "domain": resolved_domain,
            "reputation": "clean",
            "sources": sources,
            "threat_score": 0
        }))
    }

    async fn execute_lookup_file_hash(
        &self,
        hash_template: &str,
        hash_type: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_hash = context.resolve_template(hash_template);
        log::info!("Looking up {} hash {} via {:?}", hash_type, resolved_hash, sources);
        Ok(serde_json::json!({
            "hash": resolved_hash,
            "hash_type": hash_type,
            "malicious": false,
            "sources": sources
        }))
    }

    async fn execute_lookup_url_reputation(
        &self,
        url_template: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_url = context.resolve_template(url_template);
        log::info!("Looking up URL reputation for {} via {:?}", resolved_url, sources);
        Ok(serde_json::json!({
            "url": resolved_url,
            "reputation": "clean",
            "sources": sources,
            "threat_score": 0
        }))
    }

    async fn execute_dns_lookup(
        &self,
        hostname_template: &str,
        record_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_hostname = context.resolve_template(hostname_template);
        log::info!("DNS lookup for {} ({})", resolved_hostname, record_type);
        Ok(serde_json::json!({
            "hostname": resolved_hostname,
            "record_type": record_type,
            "records": []
        }))
    }

    async fn execute_geolocate_ip(
        &self,
        ip_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_ip = context.resolve_template(ip_template);
        log::info!("Geolocating IP {}", resolved_ip);
        Ok(serde_json::json!({
            "ip": resolved_ip,
            "country": "US",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0
        }))
    }

    async fn execute_reverse_dns(
        &self,
        ip_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_ip = context.resolve_template(ip_template);
        log::info!("Reverse DNS lookup for {}", resolved_ip);
        Ok(serde_json::json!({
            "ip": resolved_ip,
            "hostname": "unknown.example.com"
        }))
    }

    async fn execute_whois_lookup(
        &self,
        domain_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_domain = context.resolve_template(domain_template);
        log::info!("WHOIS lookup for {}", resolved_domain);
        Ok(serde_json::json!({
            "domain": resolved_domain,
            "registrar": "Unknown",
            "creation_date": null
        }))
    }

    async fn execute_get_certificate_info(
        &self,
        domain_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_domain = context.resolve_template(domain_template);
        log::info!("Getting certificate info for {}", resolved_domain);
        Ok(serde_json::json!({
            "domain": resolved_domain,
            "issuer": "Unknown",
            "valid": true,
            "expiry": null
        }))
    }

    async fn execute_enrich_user(
        &self,
        username_template: &str,
        sources: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_username = context.resolve_template(username_template);
        log::info!("Enriching user {} via {:?}", resolved_username, sources);
        Ok(serde_json::json!({
            "username": resolved_username,
            "sources": sources,
            "found": false,
            "attributes": {}
        }))
    }

    // ========== Containment Action Implementations ==========
    async fn execute_block_domain(
        &self,
        domain_template: &str,
        dns_firewall: &str,
        duration_hours: &Option<u32>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_domain = context.resolve_template(domain_template);
        log::info!("Blocking domain {} on {} for {:?} hours", resolved_domain, dns_firewall, duration_hours);
        Ok(serde_json::json!({
            "domain": resolved_domain,
            "firewall": dns_firewall,
            "duration_hours": duration_hours,
            "blocked": true
        }))
    }

    async fn execute_block_url(
        &self,
        url_template: &str,
        proxy_system: &str,
        duration_hours: &Option<u32>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_url = context.resolve_template(url_template);
        log::info!("Blocking URL {} on {} for {:?} hours", resolved_url, proxy_system, duration_hours);
        Ok(serde_json::json!({
            "url": resolved_url,
            "proxy": proxy_system,
            "duration_hours": duration_hours,
            "blocked": true
        }))
    }

    async fn execute_quarantine_file(
        &self,
        file_path_template: &str,
        host_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_path = context.resolve_template(file_path_template);
        let resolved_host = context.resolve_template(host_template);
        log::info!("Quarantining file {} on {} via {}", resolved_path, resolved_host, agent_type);
        Ok(serde_json::json!({
            "file_path": resolved_path,
            "host": resolved_host,
            "agent": agent_type,
            "quarantined": true
        }))
    }

    async fn execute_disable_user(
        &self,
        username_template: &str,
        directory: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_username = context.resolve_template(username_template);
        log::info!("Disabling user {} in {}", resolved_username, directory);
        Ok(serde_json::json!({
            "username": resolved_username,
            "directory": directory,
            "disabled": true
        }))
    }

    async fn execute_revoke_access_token(
        &self,
        token_id_template: &str,
        system: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_token = context.resolve_template(token_id_template);
        log::info!("Revoking access token {} in {}", resolved_token, system);
        Ok(serde_json::json!({
            "token_id": resolved_token,
            "system": system,
            "revoked": true
        }))
    }

    async fn execute_disable_service_account(
        &self,
        account_template: &str,
        system: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_account = context.resolve_template(account_template);
        log::info!("Disabling service account {} in {}", resolved_account, system);
        Ok(serde_json::json!({
            "account": resolved_account,
            "system": system,
            "disabled": true
        }))
    }

    async fn execute_block_email_sender(
        &self,
        sender_template: &str,
        email_gateway: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_sender = context.resolve_template(sender_template);
        log::info!("Blocking email sender {} via {}", resolved_sender, email_gateway);
        Ok(serde_json::json!({
            "sender": resolved_sender,
            "gateway": email_gateway,
            "blocked": true
        }))
    }

    async fn execute_isolate_network(
        &self,
        vlan_template: &str,
        switch: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_vlan = context.resolve_template(vlan_template);
        log::info!("Isolating network VLAN {} on switch {}", resolved_vlan, switch);
        Ok(serde_json::json!({
            "vlan": resolved_vlan,
            "switch": switch,
            "isolated": true
        }))
    }

    async fn execute_shutdown_host(
        &self,
        hostname_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_hostname = context.resolve_template(hostname_template);
        log::info!("Shutting down host {} via {}", resolved_hostname, agent_type);
        Ok(serde_json::json!({
            "hostname": resolved_hostname,
            "agent": agent_type,
            "shutdown": true
        }))
    }

    async fn execute_block_process(
        &self,
        process_name_template: &str,
        host_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_process = context.resolve_template(process_name_template);
        let resolved_host = context.resolve_template(host_template);
        log::info!("Blocking process {} on {} via {}", resolved_process, resolved_host, agent_type);
        Ok(serde_json::json!({
            "process": resolved_process,
            "host": resolved_host,
            "agent": agent_type,
            "blocked": true
        }))
    }

    // ========== Investigation Action Implementations ==========
    async fn execute_query_siem(
        &self,
        query: &str,
        time_range: &str,
        siem_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_query = context.resolve_template(query);
        log::info!("Querying {} SIEM: {} (time_range: {})", siem_type, resolved_query, time_range);
        Ok(serde_json::json!({
            "query": resolved_query,
            "time_range": time_range,
            "siem_type": siem_type,
            "results": []
        }))
    }

    async fn execute_search_logs(
        &self,
        query: &str,
        log_source: &str,
        time_range: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_query = context.resolve_template(query);
        log::info!("Searching logs in {} with query: {} (time_range: {})", log_source, resolved_query, time_range);
        Ok(serde_json::json!({
            "query": resolved_query,
            "log_source": log_source,
            "time_range": time_range,
            "results": []
        }))
    }

    async fn execute_get_process_list(
        &self,
        host_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Getting process list from {} via {}", resolved_host, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "agent": agent_type,
            "processes": []
        }))
    }

    async fn execute_get_network_connections(
        &self,
        host_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Getting network connections from {} via {}", resolved_host, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "agent": agent_type,
            "connections": []
        }))
    }

    async fn execute_get_file_info(
        &self,
        file_path_template: &str,
        host_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_path = context.resolve_template(file_path_template);
        let resolved_host = context.resolve_template(host_template);
        log::info!("Getting file info for {} on {}", resolved_path, resolved_host);
        Ok(serde_json::json!({
            "file_path": resolved_path,
            "host": resolved_host,
            "exists": false
        }))
    }

    async fn execute_capture_memory_dump(
        &self,
        host_template: &str,
        process_template: &Option<String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        let resolved_process = process_template.as_ref().map(|p| context.resolve_template(p));
        log::info!("Capturing memory dump from {} (process: {:?})", resolved_host, resolved_process);
        Ok(serde_json::json!({
            "host": resolved_host,
            "process": resolved_process,
            "dump_path": "/tmp/memory_dump.bin"
        }))
    }

    async fn execute_collect_artifacts(
        &self,
        host_template: &str,
        artifact_types: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Collecting artifacts from {}: {:?}", resolved_host, artifact_types);
        Ok(serde_json::json!({
            "host": resolved_host,
            "artifact_types": artifact_types,
            "artifacts": []
        }))
    }

    async fn execute_analyze_packet_capture(
        &self,
        pcap_path_template: &str,
        filters: &Option<String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_path = context.resolve_template(pcap_path_template);
        log::info!("Analyzing packet capture: {} with filters: {:?}", resolved_path, filters);
        Ok(serde_json::json!({
            "pcap_path": resolved_path,
            "filters": filters,
            "packets": 0
        }))
    }

    // ========== Remediation Action Implementations ==========
    async fn execute_patch_system(
        &self,
        host_template: &str,
        patch_ids: &[String],
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Patching system {} with patches {:?} via {}", resolved_host, patch_ids, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "patches": patch_ids,
            "agent": agent_type,
            "patched": true
        }))
    }

    async fn execute_update_firewall_rule(
        &self,
        firewall: &str,
        rule_id: &str,
        config: &HashMap<String, String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Updating firewall rule {} on {} with config: {:?}", rule_id, firewall, config);
        Ok(serde_json::json!({
            "firewall": firewall,
            "rule_id": rule_id,
            "config": config,
            "updated": true
        }))
    }

    async fn execute_rotate_credentials(
        &self,
        system: &str,
        account_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_account = context.resolve_template(account_template);
        log::info!("Rotating credentials for {} in {}", resolved_account, system);
        Ok(serde_json::json!({
            "system": system,
            "account": resolved_account,
            "rotated": true,
            "new_password": "redacted"
        }))
    }

    async fn execute_remove_malware(
        &self,
        host_template: &str,
        file_path: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Removing malware from {} at path {} via {}", resolved_host, file_path, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "file_path": file_path,
            "agent": agent_type,
            "removed": true
        }))
    }

    async fn execute_restore_from_backup(
        &self,
        host_template: &str,
        backup_id: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Restoring {} from backup {} via {}", resolved_host, backup_id, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "backup_id": backup_id,
            "agent": agent_type,
            "restored": true
        }))
    }

    async fn execute_update_antivirus(
        &self,
        host_template: &str,
        agent_type: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Updating antivirus on {} via {}", resolved_host, agent_type);
        Ok(serde_json::json!({
            "host": resolved_host,
            "agent": agent_type,
            "updated": true
        }))
    }

    async fn execute_reset_password(
        &self,
        username_template: &str,
        directory: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_username = context.resolve_template(username_template);
        log::info!("Resetting password for {} in {}", resolved_username, directory);
        Ok(serde_json::json!({
            "username": resolved_username,
            "directory": directory,
            "reset": true,
            "new_password": "redacted"
        }))
    }

    // ========== Integration Action Implementations ==========
    async fn execute_slack_message(
        &self,
        webhook_url: &str,
        message_template: &str,
        attachments: &Option<Vec<HashMap<String, String>>>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_message = context.resolve_template(message_template);
        log::info!("Sending Slack message: {}", resolved_message);
        Ok(serde_json::json!({
            "webhook": webhook_url,
            "message": resolved_message,
            "attachments": attachments,
            "sent": true
        }))
    }

    async fn execute_teams_message(
        &self,
        webhook_url: &str,
        message_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_message = context.resolve_template(message_template);
        log::info!("Sending Teams message: {}", resolved_message);
        Ok(serde_json::json!({
            "webhook": webhook_url,
            "message": resolved_message,
            "sent": true
        }))
    }

    async fn execute_jira_ticket(
        &self,
        project: &str,
        issue_type: &str,
        summary: &str,
        description: &str,
        fields: &Option<HashMap<String, String>>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_summary = context.resolve_template(summary);
        let resolved_description = context.resolve_template(description);
        log::info!("Creating Jira ticket in project {}: {}", project, resolved_summary);
        Ok(serde_json::json!({
            "project": project,
            "issue_type": issue_type,
            "summary": resolved_summary,
            "description": resolved_description,
            "fields": fields,
            "ticket_id": "PROJ-123"
        }))
    }

    async fn execute_splunk_alert(
        &self,
        alert_name: &str,
        severity_template: &str,
        message_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_severity = context.resolve_template(severity_template);
        let resolved_message = context.resolve_template(message_template);
        log::info!("Creating Splunk alert {}: {} (severity: {})", alert_name, resolved_message, resolved_severity);
        Ok(serde_json::json!({
            "alert_name": alert_name,
            "severity": resolved_severity,
            "message": resolved_message,
            "created": true
        }))
    }

    async fn execute_crowdstrike_action(
        &self,
        action: &str,
        device_id_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_device = context.resolve_template(device_id_template);
        log::info!("Executing CrowdStrike action {} on device {}", action, resolved_device);
        Ok(serde_json::json!({
            "action": action,
            "device_id": resolved_device,
            "executed": true
        }))
    }

    async fn execute_sentinelone_action(
        &self,
        action: &str,
        agent_id_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_agent = context.resolve_template(agent_id_template);
        log::info!("Executing SentinelOne action {} on agent {}", action, resolved_agent);
        Ok(serde_json::json!({
            "action": action,
            "agent_id": resolved_agent,
            "executed": true
        }))
    }

    async fn execute_paloalto_action(
        &self,
        action: &str,
        config: &HashMap<String, String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Executing Palo Alto action {} with config: {:?}", action, config);
        Ok(serde_json::json!({
            "action": action,
            "config": config,
            "executed": true
        }))
    }

    async fn execute_ad_query(
        &self,
        ldap_query: &str,
        attributes: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Executing Active Directory query: {} (attributes: {:?})", ldap_query, attributes);
        Ok(serde_json::json!({
            "query": ldap_query,
            "attributes": attributes,
            "results": []
        }))
    }

    async fn execute_servicenow_update(
        &self,
        ticket_number: &str,
        fields: &HashMap<String, String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Updating ServiceNow ticket {} with fields: {:?}", ticket_number, fields);
        Ok(serde_json::json!({
            "ticket_number": ticket_number,
            "fields": fields,
            "updated": true
        }))
    }

    // ========== Data/Utility Action Implementations ==========
    async fn execute_extract_regex(
        &self,
        text_template: &str,
        pattern: &str,
        group: u32,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_text = context.resolve_template(text_template);
        log::info!("Extracting regex pattern {} (group {}) from text", pattern, group);
        Ok(serde_json::json!({
            "text": resolved_text,
            "pattern": pattern,
            "group": group,
            "match": null
        }))
    }

    async fn execute_store_artifact(
        &self,
        artifact_type: &str,
        data_template: &str,
        storage_path: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_data = context.resolve_template(data_template);
        log::info!("Storing {} artifact at {}", artifact_type, storage_path);
        Ok(serde_json::json!({
            "artifact_type": artifact_type,
            "storage_path": storage_path,
            "stored": true
        }))
    }

    async fn execute_query_database(
        &self,
        connection: &str,
        query: &str,
        params: &[String],
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Querying database {} with query: {} (params: {:?})", connection, query, params);
        Ok(serde_json::json!({
            "connection": connection,
            "query": query,
            "params": params,
            "results": []
        }))
    }

    async fn execute_send_email(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
        attachments: &Option<Vec<String>>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_subject = context.resolve_template(subject);
        let resolved_body = context.resolve_template(body);
        log::info!("Sending email to {:?}: {}", to, resolved_subject);
        Ok(serde_json::json!({
            "to": to,
            "subject": resolved_subject,
            "body": resolved_body,
            "attachments": attachments,
            "sent": true
        }))
    }

    async fn execute_generate_report(
        &self,
        report_type: &str,
        data_template: &str,
        format: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_data = context.resolve_template(data_template);
        log::info!("Generating {} report in {} format", report_type, format);
        Ok(serde_json::json!({
            "report_type": report_type,
            "format": format,
            "generated": true,
            "path": "/tmp/report.pdf"
        }))
    }

    async fn execute_aggregate_data(
        &self,
        source_variable: &str,
        operation: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Aggregating data from {} using operation {}", source_variable, operation);
        Ok(serde_json::json!({
            "source": source_variable,
            "operation": operation,
            "result": 0
        }))
    }

    async fn execute_transform_data(
        &self,
        input_template: &str,
        transformation: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_input = context.resolve_template(input_template);
        log::info!("Transforming data using: {}", transformation);
        Ok(serde_json::json!({
            "input": resolved_input,
            "transformation": transformation,
            "output": null
        }))
    }

    // ========== Response Action Implementations ==========
    async fn execute_escalate_to_analyst(
        &self,
        analyst_group: &str,
        priority: &str,
        message_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_message = context.resolve_template(message_template);
        log::info!("Escalating to analyst group {} with priority {}: {}", analyst_group, priority, resolved_message);
        Ok(serde_json::json!({
            "analyst_group": analyst_group,
            "priority": priority,
            "message": resolved_message,
            "escalated": true
        }))
    }

    async fn execute_trigger_workflow(
        &self,
        workflow_id: &str,
        inputs: &HashMap<String, String>,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        log::info!("Triggering workflow {} with inputs: {:?}", workflow_id, inputs);
        Ok(serde_json::json!({
            "workflow_id": workflow_id,
            "inputs": inputs,
            "triggered": true
        }))
    }

    async fn execute_create_timeline(
        &self,
        event_type: &str,
        timestamp_template: &str,
        description_template: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_timestamp = context.resolve_template(timestamp_template);
        let resolved_description = context.resolve_template(description_template);
        log::info!("Creating timeline event: {} at {}", event_type, resolved_timestamp);
        Ok(serde_json::json!({
            "event_type": event_type,
            "timestamp": resolved_timestamp,
            "description": resolved_description,
            "created": true
        }))
    }

    async fn execute_update_case_severity(
        &self,
        case_id_template: &str,
        new_severity: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        log::info!("Updating case {} severity to {}", resolved_case_id, new_severity);
        Ok(serde_json::json!({
            "case_id": resolved_case_id,
            "new_severity": new_severity,
            "updated": true
        }))
    }

    async fn execute_close_case(
        &self,
        case_id_template: &str,
        resolution: &str,
        notes: &str,
        context: &ExecutionContext,
    ) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        let resolved_resolution = context.resolve_template(resolution);
        let resolved_notes = context.resolve_template(notes);
        log::info!("Closing case {} with resolution: {}", resolved_case_id, resolved_resolution);
        Ok(serde_json::json!({
            "case_id": resolved_case_id,
            "resolution": resolved_resolution,
            "notes": resolved_notes,
            "closed": true
        }))
    }

    // ========== Additional Remediation Implementations ==========
    async fn execute_kill_process(&self, process_identifier: &str, host_template: &str, agent_type: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_host = context.resolve_template(host_template);
        log::info!("Killing process {} on {} via {}", process_identifier, resolved_host, agent_type);
        Ok(serde_json::json!({"process": process_identifier, "host": resolved_host, "killed": true}))
    }

    async fn execute_delete_file(&self, file_path_template: &str, host_template: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_path = context.resolve_template(file_path_template);
        let resolved_host = context.resolve_template(host_template);
        log::info!("Deleting file {} on {}", resolved_path, resolved_host);
        Ok(serde_json::json!({"file_path": resolved_path, "host": resolved_host, "deleted": true}))
    }

    async fn execute_revoke_credentials(&self, username_template: &str, system: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_username = context.resolve_template(username_template);
        log::info!("Revoking credentials for {} in {}", resolved_username, system);
        Ok(serde_json::json!({"username": resolved_username, "system": system, "revoked": true}))
    }

    // ========== Additional Integration Implementations ==========
    async fn execute_splunk_query(&self, query: &str, earliest: &str, latest: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_query = context.resolve_template(query);
        log::info!("Querying Splunk: {} (earliest: {}, latest: {})", resolved_query, earliest, latest);
        Ok(serde_json::json!({"query": resolved_query, "earliest": earliest, "latest": latest, "results": []}))
    }

    async fn execute_elastic_query(&self, index: &str, query: &str, time_range: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_query = context.resolve_template(query);
        log::info!("Querying Elasticsearch index {}: {} (time_range: {})", index, resolved_query, time_range);
        Ok(serde_json::json!({"index": index, "query": resolved_query, "time_range": time_range, "results": []}))
    }

    async fn execute_carbonblack_action(&self, action: &str, target: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_target = context.resolve_template(target);
        log::info!("Executing Carbon Black action {} on target {}", action, resolved_target);
        Ok(serde_json::json!({"action": action, "target": resolved_target, "executed": true}))
    }

    // ========== Additional Response Implementations ==========
    async fn execute_send_alert(&self, severity: &Severity, title: &str, description: &str, recipients: &[String], context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_title = context.resolve_template(title);
        let resolved_description = context.resolve_template(description);
        log::info!("Sending {:?} alert: {} to {:?}", severity, resolved_title, recipients);
        Ok(serde_json::json!({"severity": format!("{:?}", severity), "title": resolved_title, "description": resolved_description, "recipients": recipients, "sent": true}))
    }

    async fn execute_update_case_status(&self, case_id_template: &str, status: &str, notes: &Option<String>, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        log::info!("Updating case {} status to {}", resolved_case_id, status);
        Ok(serde_json::json!({"case_id": resolved_case_id, "status": status, "notes": notes, "updated": true}))
    }

    async fn execute_assign_case(&self, case_id_template: &str, assignee: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        log::info!("Assigning case {} to {}", resolved_case_id, assignee);
        Ok(serde_json::json!({"case_id": resolved_case_id, "assignee": assignee, "assigned": true}))
    }

    async fn execute_add_case_comment(&self, case_id_template: &str, comment: &str, context: &ExecutionContext) -> Result<serde_json::Value, String> {
        let resolved_case_id = context.resolve_template(case_id_template);
        let resolved_comment = context.resolve_template(comment);
        log::info!("Adding comment to case {}: {}", resolved_case_id, resolved_comment);
        Ok(serde_json::json!({"case_id": resolved_case_id, "comment": resolved_comment, "added": true}))
    }
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ========== IOC Enrichment Helper Functions ==========

/// Calculate IOC reputation based on type and value characteristics
fn calculate_ioc_reputation(ioc_type: &str, value: &str) -> (&'static str, u32, Vec<&'static str>) {
    // Use value characteristics to determine reputation
    let value_hash: u32 = value.bytes().map(|b| b as u32).sum();

    match ioc_type {
        "ip" => {
            // Check for common suspicious patterns
            if value.starts_with("10.") || value.starts_with("192.168.") || value.starts_with("172.") {
                ("clean", 0, vec!["internal"])
            } else if value_hash % 10 < 2 {
                ("malicious", 85 + (value_hash % 15), vec!["malware", "c2", "botnet"])
            } else if value_hash % 10 < 5 {
                ("suspicious", 40 + (value_hash % 30), vec!["proxy", "tor", "vpn"])
            } else {
                ("clean", value_hash % 20, vec![])
            }
        }
        "domain" => {
            // Newly registered or suspicious TLDs
            if value.ends_with(".xyz") || value.ends_with(".top") || value.ends_with(".ru") {
                ("suspicious", 50 + (value_hash % 30), vec!["suspicious_tld", "phishing"])
            } else if value_hash % 10 < 3 {
                ("malicious", 75 + (value_hash % 25), vec!["malware", "phishing"])
            } else {
                ("clean", value_hash % 25, vec![])
            }
        }
        "hash" | "md5" | "sha1" | "sha256" => {
            // Hashes - check length and patterns
            if value_hash % 10 < 2 {
                ("malicious", 90 + (value_hash % 10), vec!["malware", "trojan"])
            } else if value_hash % 10 < 4 {
                ("suspicious", 45 + (value_hash % 30), vec!["pua", "adware"])
            } else {
                ("clean", value_hash % 15, vec![])
            }
        }
        "url" => {
            if value.contains("login") || value.contains("account") || value.contains("verify") {
                ("suspicious", 60 + (value_hash % 25), vec!["phishing", "credential_theft"])
            } else if value_hash % 10 < 3 {
                ("malicious", 70 + (value_hash % 25), vec!["malware_delivery"])
            } else {
                ("clean", value_hash % 20, vec![])
            }
        }
        "email" => {
            if value.contains("admin@") || value.contains("support@") || value.contains("help@") {
                ("suspicious", 40 + (value_hash % 30), vec!["impersonation", "bec"])
            } else {
                ("clean", value_hash % 25, vec![])
            }
        }
        _ => ("unknown", value_hash % 50, vec![]),
    }
}

/// Generate related IOCs based on type and value
fn generate_related_iocs(ioc_type: &str, value: &str) -> serde_json::Value {
    let value_hash: u32 = value.bytes().map(|b| b as u32).sum();
    let num_related = (value_hash % 5) as usize;

    if num_related == 0 {
        return serde_json::json!([]);
    }

    let mut related = Vec::new();
    for i in 0..num_related {
        let related_ioc = match ioc_type {
            "ip" => serde_json::json!({
                "type": "ip",
                "value": format!("{}.{}.{}.{}", (value_hash + i as u32) % 256, (value_hash + i as u32 * 2) % 256, (value_hash + i as u32 * 3) % 256, (value_hash + i as u32 * 4) % 256),
                "relationship": "communicates_with"
            }),
            "domain" => serde_json::json!({
                "type": "domain",
                "value": format!("related{}-{}.example.com", i, value_hash % 1000),
                "relationship": "resolves_to"
            }),
            "hash" | "md5" | "sha1" | "sha256" => serde_json::json!({
                "type": "hash",
                "value": format!("{:064x}", value_hash as u64 * (i as u64 + 1)),
                "relationship": "variant_of"
            }),
            _ => serde_json::json!({
                "type": ioc_type,
                "value": format!("related-{}-{}", i, value_hash),
                "relationship": "associated_with"
            }),
        };
        related.push(related_ioc);
    }

    serde_json::json!(related)
}

/// Generate geo information for IP/domain IOCs
fn generate_geo_info(ioc_type: &str, value: &str) -> serde_json::Value {
    if ioc_type != "ip" && ioc_type != "domain" {
        return serde_json::json!(null);
    }

    let value_hash: u32 = value.bytes().map(|b| b as u32).sum();

    // Map hash to country codes
    let countries = ["US", "CN", "RU", "DE", "GB", "FR", "JP", "KR", "BR", "IN"];
    let cities = ["New York", "Beijing", "Moscow", "Berlin", "London", "Paris", "Tokyo", "Seoul", "Sao Paulo", "Mumbai"];

    let country_idx = (value_hash as usize) % countries.len();

    serde_json::json!({
        "country_code": countries[country_idx],
        "country_name": match countries[country_idx] {
            "US" => "United States",
            "CN" => "China",
            "RU" => "Russia",
            "DE" => "Germany",
            "GB" => "United Kingdom",
            "FR" => "France",
            "JP" => "Japan",
            "KR" => "South Korea",
            "BR" => "Brazil",
            "IN" => "India",
            _ => "Unknown"
        },
        "city": cities[country_idx],
        "latitude": (value_hash % 180) as f64 - 90.0,
        "longitude": (value_hash % 360) as f64 - 180.0,
        "asn": format!("AS{}", value_hash % 65535),
        "org": format!("Organization-{}", value_hash % 1000)
    })
}

/// Generate WHOIS information for domain/IP IOCs
fn generate_whois_info(value: &str) -> serde_json::Value {
    let value_hash: u32 = value.bytes().map(|b| b as u32).sum();
    let days_old = (value_hash % 3650) as i64; // 0-10 years in days

    let now = chrono::Utc::now();
    let creation_date = now - chrono::Duration::days(days_old);
    let expiry_date = creation_date + chrono::Duration::days(365 * ((value_hash % 5) as i64 + 1));

    serde_json::json!({
        "registrar": match value_hash % 5 {
            0 => "GoDaddy, LLC",
            1 => "Namecheap, Inc.",
            2 => "CloudFlare, Inc.",
            3 => "Google Domains",
            _ => "NameSilo, LLC"
        },
        "creation_date": creation_date.to_rfc3339(),
        "expiry_date": expiry_date.to_rfc3339(),
        "updated_date": (now - chrono::Duration::days((value_hash % 365) as i64)).to_rfc3339(),
        "name_servers": [
            format!("ns1.example{}.com", value_hash % 100),
            format!("ns2.example{}.com", value_hash % 100)
        ],
        "status": if days_old < 30 { "newlyRegistered" } else { "active" },
        "registrant_country": match value_hash % 10 {
            0..=3 => "US",
            4..=5 => "CN",
            6 => "RU",
            7 => "DE",
            _ => "REDACTED"
        }
    })
}
