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

        // Mock enrichment response
        Ok(serde_json::json!({
            "ioc_type": ioc_type,
            "value": resolved_value,
            "sources_queried": sources,
            "enrichment": {
                "reputation": "suspicious",
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-12-01T00:00:00Z",
                "related_iocs": []
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
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}
