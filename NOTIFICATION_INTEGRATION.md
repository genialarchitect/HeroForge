# Notification System Integration

This document describes the integration of Slack and Teams webhook notifications with scan events in HeroForge.

## Overview

The notification system automatically sends webhook notifications to Slack and/or Microsoft Teams when:
1. A scan completes successfully
2. Critical or high-severity vulnerabilities are discovered

## Implementation

### Files Modified/Created

1. **`src/notifications/sender.rs`** (NEW)
   - Contains helper functions to send notifications based on scan events
   - `send_scan_completion_notification()` - Sends summary when a scan completes
   - `send_critical_vulnerability_notifications()` - Sends alerts for critical/high severity vulnerabilities

2. **`src/notifications/mod.rs`** (MODIFIED)
   - Added `pub mod sender;` to expose the notification sender module

3. **`src/web/api/scans.rs`** (MODIFIED)
   - Added notification triggers in the scan completion handler (lines 480-505)
   - Notifications are sent asynchronously in a spawned task to avoid blocking scan completion

## How It Works

### Scan Completion Flow

```
1. Scan completes successfully
2. Results are saved to database
3. Notification task is spawned (non-blocking)
4. User's notification settings are retrieved from database
5. If Slack webhook URL is configured → Send Slack notification
6. If Teams webhook URL is configured → Send Teams notification
```

### Scan Completion Notification

Includes:
- Scan name
- Number of hosts discovered
- Number of open ports
- Total vulnerabilities found
- Breakdown by severity (Critical/High/Medium/Low)

Color-coded based on highest severity:
- Red: Critical vulnerabilities present
- Orange: High vulnerabilities present
- Yellow: Medium vulnerabilities present
- Green: No critical/high/medium vulnerabilities

### Critical Vulnerability Notifications

- Only sent if user has `email_on_critical_vuln` enabled in notification settings
- Sends one notification per critical/high severity vulnerability
- Includes:
  - Scan name
  - Host IP address
  - Port and protocol
  - Service name
  - Severity level
  - Vulnerability title and description

### Error Handling

- Notification failures are logged but **do not** fail the scan
- Notifications are sent asynchronously in a separate task
- Each notification (Slack/Teams) is attempted independently
- Errors are logged with context for debugging

## Configuration

Users configure webhooks in the HeroForge Settings page:
- **Slack Webhook URL**: Settings → Notifications → Slack Webhook URL
- **Teams Webhook URL**: Settings → Notifications → Teams Webhook URL
- **Email on Critical Vulnerabilities**: Toggle to enable/disable critical vuln notifications

Settings are stored in the `notification_settings` table with the following schema:

```sql
CREATE TABLE notification_settings (
    user_id TEXT PRIMARY KEY,
    email_on_scan_complete BOOLEAN NOT NULL DEFAULT FALSE,
    email_on_critical_vuln BOOLEAN NOT NULL DEFAULT TRUE,
    email_address TEXT NOT NULL,
    slack_webhook_url TEXT,
    teams_webhook_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

## Testing

To test the notification integration:

1. **Configure webhooks**:
   - Go to Settings → Notifications
   - Add your Slack and/or Teams webhook URL
   - Ensure "Email on Critical Vulnerabilities" is enabled

2. **Run a scan**:
   ```bash
   # From the HeroForge web UI, create a new scan
   # OR use the API:
   curl -X POST https://heroforge.genialarchitect.io/api/scans \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Test Scan",
       "targets": ["scanme.nmap.org"],
       "port_range": [1, 1000],
       "threads": 100,
       "enable_os_detection": true,
       "enable_service_detection": true,
       "enable_vuln_scan": true
     }'
   ```

3. **Verify notifications**:
   - Check your Slack/Teams channel for the scan completion message
   - If vulnerabilities are found, check for critical vulnerability alerts
   - Monitor logs: `docker logs heroforge -f | grep -i notification`

## Logs

Notification events are logged at various levels:

```
INFO  - Sent Slack notification for completed scan 'My Scan'
INFO  - Sent Teams notification for completed scan 'My Scan'
INFO  - Found 3 critical/high vulnerabilities in scan 'My Scan', sending notifications
DEBUG - Sent Slack notification for critical vulnerability
ERROR - Failed to send Slack notification for scan 'My Scan': connection timeout
ERROR - Failed to get notification settings for user abc123: database error
```

## Future Enhancements

Potential improvements:
1. Add support for more notification providers (PagerDuty, Email, Discord)
2. Add configurable thresholds (e.g., only notify if >5 critical vulns)
3. Add notification templates/customization
4. Add rate limiting to prevent notification spam
5. Add digest mode (batch notifications instead of per-vulnerability)
6. Add support for scheduled scan notifications (already has event types defined)

## Related Files

- `/root/Development/HeroForge/src/notifications/slack.rs` - Slack webhook implementation
- `/root/Development/HeroForge/src/notifications/teams.rs` - Teams webhook implementation
- `/root/Development/HeroForge/src/notifications/mod.rs` - Notification event types
- `/root/Development/HeroForge/src/db/models.rs` - NotificationSettings model (lines 383-393)
- `/root/Development/HeroForge/src/db/mod.rs` - Database functions for notification settings
- `/root/Development/HeroForge/src/web/api/notifications.rs` - API endpoints for managing notification settings
