# HeroForge Agent Protocol Documentation

This document describes the communication protocol between HeroForge scanning agents and the central server.

## Overview

HeroForge agents are lightweight scanning components that can be deployed in various network zones to perform distributed vulnerability scans. They communicate with the central HeroForge server via REST API and use token-based authentication.

## Authentication

### Token Format

Agent tokens follow this format:
```
hfa_<base64-encoded-random-256-bit-value>
```

Example: `hfa_a3J5cHRvZ3JhcGhpY2FsbHktc2VjdXJlLXJhbmRvbS10b2tlbg==`

The token is generated during agent registration and is only shown once. Store it securely.

### Authentication Header

All agent API requests must include the token in the Authorization header:
```
Authorization: Bearer hfa_<token>
```

## API Endpoints

### Agent Registration (Server-side)

Agents are registered through the web UI or admin API. This generates a token that the agent will use.

```
POST /api/agents/register
Content-Type: application/json
Authorization: Bearer <user-jwt-token>

{
  "name": "DMZ Agent",
  "description": "Scans DMZ network segment",
  "network_zones": ["dmz", "10.0.1.0/24"],
  "max_concurrent_tasks": 5
}

Response:
{
  "id": "uuid",
  "name": "DMZ Agent",
  "token": "hfa_<full-token>",
  "token_prefix": "hfa_a3J5",
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Heartbeat

Agents must send heartbeat every 30 seconds to maintain online status.

```
POST /api/agents/{agent_id}/heartbeat
Authorization: Bearer hfa_<agent-token>
Content-Type: application/json

{
  "cpu_usage": 45.5,
  "memory_usage": 62.3,
  "disk_usage": 28.1,
  "active_tasks": 2,
  "agent_version": "1.0.0",
  "os_info": "Linux 5.15.0-generic x86_64"
}

Response:
{
  "acknowledged": true,
  "server_time": "2025-01-15T10:30:00Z",
  "pending_tasks": 3,
  "commands": []
}
```

### Fetch Tasks

Agents poll for pending tasks assigned to them.

```
GET /api/agents/{agent_id}/tasks?status=pending&limit=5
Authorization: Bearer hfa_<agent-token>

Response:
{
  "tasks": [
    {
      "id": "task-uuid",
      "scan_id": "scan-uuid",
      "task_type": "full_scan",
      "config": {
        "targets": ["192.168.1.0/24"],
        "port_range": [1, 1000],
        "threads": 50,
        "enable_os_detection": true,
        "enable_service_detection": true,
        "enable_vuln_scan": true
      },
      "priority": 5,
      "created_at": "2025-01-15T10:00:00Z"
    }
  ]
}
```

### Update Task Status

```
PUT /api/agents/{agent_id}/tasks/{task_id}/status
Authorization: Bearer hfa_<agent-token>
Content-Type: application/json

{
  "status": "running",
  "progress": 45,
  "message": "Scanning 192.168.1.50"
}

Response:
{
  "success": true
}
```

### Submit Results

```
POST /api/agents/{agent_id}/results
Authorization: Bearer hfa_<agent-token>
Content-Type: application/json

{
  "task_id": "task-uuid",
  "result_data": {
    "hosts": [
      {
        "ip": "192.168.1.10",
        "hostname": "server1.local",
        "os_info": {
          "name": "Linux",
          "version": "5.15.0",
          "confidence": 0.95
        },
        "ports": [
          {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": {
              "name": "ssh",
              "version": "OpenSSH 8.9",
              "banner": "SSH-2.0-OpenSSH_8.9"
            }
          },
          {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": {
              "name": "http",
              "version": "nginx/1.22.0"
            }
          }
        ],
        "vulnerabilities": [
          {
            "id": "CVE-2023-XXXX",
            "title": "OpenSSH Vulnerability",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "...",
            "remediation": "Upgrade to OpenSSH 9.0+"
          }
        ]
      }
    ]
  },
  "hosts_discovered": 15,
  "ports_discovered": 42,
  "vulnerabilities_found": 3,
  "started_at": "2025-01-15T10:00:00Z",
  "completed_at": "2025-01-15T10:15:00Z"
}

Response:
{
  "success": true,
  "result_id": "result-uuid"
}
```

## Task Types

| Type | Description |
|------|-------------|
| `full_scan` | Complete scan (discovery + ports + services + vulns) |
| `host_discovery` | Host/network discovery only |
| `port_scan` | Port scanning only |
| `service_detection` | Service fingerprinting |
| `vulnerability_scan` | Vulnerability assessment |
| `os_fingerprint` | Operating system detection |
| `ssl_scan` | SSL/TLS certificate analysis |
| `dns_recon` | DNS reconnaissance |

## Task Statuses

| Status | Description |
|--------|-------------|
| `pending` | Task created, waiting for assignment |
| `assigned` | Task assigned to agent |
| `running` | Agent is executing the task |
| `completed` | Task finished successfully |
| `failed` | Task execution failed |
| `cancelled` | Task was cancelled |
| `timed_out` | Task exceeded timeout |

## Agent Statuses

| Status | Description |
|--------|-------------|
| `pending` | Agent registered but not yet connected |
| `online` | Agent is connected and healthy |
| `busy` | Agent is at max concurrent tasks |
| `offline` | No heartbeat received (90s timeout) |
| `disabled` | Agent administratively disabled |

## Error Handling

API errors return standard HTTP status codes with JSON error body:

```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired agent token",
  "code": "AGENT_AUTH_FAILED"
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AGENT_AUTH_FAILED` | 401 | Invalid/expired token |
| `AGENT_NOT_FOUND` | 404 | Agent ID not found |
| `AGENT_DISABLED` | 403 | Agent is disabled |
| `TASK_NOT_FOUND` | 404 | Task ID not found |
| `TASK_NOT_ASSIGNED` | 403 | Task not assigned to this agent |
| `RATE_LIMITED` | 429 | Too many requests |

## Security Considerations

1. **Token Storage**: Store agent tokens securely (encrypted at rest)
2. **TLS Required**: All API communication must use HTTPS
3. **Token Rotation**: Regenerate tokens periodically
4. **Network Isolation**: Agents should only have network access to their scan targets and the HeroForge server
5. **Least Privilege**: Agents run with minimal permissions needed for scanning

## Timeouts and Retries

| Setting | Value |
|---------|-------|
| Heartbeat interval | 30 seconds |
| Offline detection | 90 seconds (3 missed heartbeats) |
| Task timeout | Configurable per task (default 1 hour) |
| API request timeout | 30 seconds |
| Retry on failure | 3 attempts with exponential backoff |

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| Heartbeat | 10/minute |
| Task fetch | 60/minute |
| Result submit | 30/minute |
| Status update | 60/minute |
