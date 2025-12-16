# Remediation Workflow Implementation

This document contains the additional code needed to complete the Remediation Workflow feature implementation.

## Database Functions (Add to `/root/Development/HeroForge/src/db/mod.rs`)

```rust
// ============================================================================
// Remediation Workflow Functions
// ============================================================================

/// Get remediation timeline for a vulnerability
pub async fn get_remediation_timeline(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::RemediationTimelineEventWithUser>> {
    let events = sqlx::query_as::<_, (String, String, String, String, String, Option<String>, Option<String>, Option<String>, DateTime<Utc>)>(
        r#"
        SELECT
            rt.id,
            rt.vulnerability_tracking_id,
            rt.user_id,
            u.username,
            rt.event_type,
            rt.old_value,
            rt.new_value,
            rt.comment,
            rt.created_at
        FROM remediation_timeline rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.vulnerability_tracking_id = ?1
        ORDER BY rt.created_at DESC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|(id, vulnerability_tracking_id, user_id, username, event_type, old_value, new_value, comment, created_at)| {
        models::RemediationTimelineEventWithUser {
            id,
            vulnerability_tracking_id,
            user_id,
            username,
            event_type,
            old_value,
            new_value,
            comment,
            created_at,
        }
    })
    .collect();

    Ok(events)
}

/// Create timeline event
async fn create_timeline_event(
    pool: &SqlitePool,
    vuln_id: &str,
    user_id: &str,
    event_type: &str,
    old_value: Option<&str>,
    new_value: Option<&str>,
    comment: Option<&str>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(event_type)
    .bind(old_value)
    .bind(new_value)
    .bind(comment)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Create timeline events for update request
async fn create_timeline_events_for_update(
    pool: &SqlitePool,
    vuln_id: &str,
    request: &models::UpdateVulnerabilityRequest,
    user_id: &str,
) -> Result<()> {
    // Get current vulnerability before update
    let current = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_optional(pool)
    .await?;

    if let Some(curr) = current {
        // Status change
        if let Some(new_status) = &request.status {
            if new_status != &curr.status {
                create_timeline_event(
                    pool,
                    vuln_id,
                    user_id,
                    "status_change",
                    Some(&curr.status),
                    Some(new_status),
                    None,
                )
                .await?;
            }
        }

        // Assignment change
        if let Some(new_assignee) = &request.assignee_id {
            let old_assignee = curr.assignee_id.as_deref();
            if Some(new_assignee.as_str()) != old_assignee {
                create_timeline_event(
                    pool,
                    vuln_id,
                    user_id,
                    "assignment",
                    old_assignee,
                    Some(new_assignee),
                    None,
                )
                .await?;
            }
        }

        // Priority change
        if let Some(new_priority) = &request.priority {
            let old_priority = curr.priority.as_deref();
            if Some(new_priority.as_str()) != old_priority {
                create_timeline_event(
                    pool,
                    vuln_id,
                    user_id,
                    "priority_change",
                    old_priority,
                    Some(new_priority),
                    None,
                )
                .await?;
            }
        }

        // Remediation steps update
        if let Some(new_steps) = &request.remediation_steps {
            if Some(new_steps.as_str()) != curr.remediation_steps.as_deref() {
                create_timeline_event(
                    pool,
                    vuln_id,
                    user_id,
                    "remediation_steps_updated",
                    None,
                    None,
                    Some("Remediation steps updated"),
                )
                .await?;
            }
        }
    }

    Ok(())
}

/// Mark vulnerability for verification
pub async fn mark_vulnerability_for_verification(
    pool: &SqlitePool,
    vuln_id: &str,
    scan_id: Option<&str>,
    user_id: &str,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Update status to pending_verification
    let mut query = "UPDATE vulnerability_tracking SET status = 'pending_verification', updated_at = ?1".to_string();

    if scan_id.is_some() {
        query.push_str(", verification_scan_id = ?2 WHERE id = ?3");
    } else {
        query.push_str(" WHERE id = ?2");
    }

    let mut q = sqlx::query(&query).bind(now);

    if let Some(sid) = scan_id {
        q = q.bind(sid).bind(vuln_id);
    } else {
        q = q.bind(vuln_id);
    }

    q.execute(pool).await?;

    // Create timeline event
    create_timeline_event(
        pool,
        vuln_id,
        user_id,
        "verification_requested",
        None,
        scan_id,
        Some("Marked for verification"),
    )
    .await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Bulk assign vulnerabilities to a user
pub async fn bulk_assign_vulnerabilities(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    assignee_id: &str,
    user_id: &str,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Update assignee
        let result = sqlx::query(
            "UPDATE vulnerability_tracking SET updated_at = ?1, assignee_id = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(assignee_id)
        .bind(vuln_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            // Create timeline event
            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'assignment', NULL, ?4, 'Bulk assigned', ?5)
                "#,
            )
            .bind(&event_id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(assignee_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            updated_count += 1;
        }
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Validate workflow state transitions
pub fn validate_status_transition(current_status: &str, new_status: &str) -> Result<()> {
    // State machine: open -> in_progress -> pending_verification -> resolved
    // Can also go to false_positive or accepted_risk from any state
    let valid_transitions = match current_status {
        "open" => vec!["in_progress", "false_positive", "accepted_risk", "resolved"],
        "in_progress" => vec!["open", "pending_verification", "resolved", "false_positive", "accepted_risk"],
        "pending_verification" => vec!["in_progress", "resolved", "false_positive"],
        "resolved" => vec!["in_progress", "open"], // Allow reopening
        "false_positive" => vec!["open", "in_progress"],
        "accepted_risk" => vec!["open", "in_progress"],
        _ => vec![],
    };

    if !valid_transitions.contains(&new_status) {
        return Err(anyhow::anyhow!(
            "Invalid status transition from '{}' to '{}'",
            current_status,
            new_status
        ));
    }

    Ok(())
}
```

## API Endpoints (Add to `/root/Development/HeroForge/src/web/api/vulnerabilities.rs`)

```rust
/// Get timeline for vulnerability
pub async fn get_vulnerability_timeline(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_remediation_timeline(pool.get_ref(), &vuln_id).await {
        Ok(timeline) => HttpResponse::Ok().json(timeline),
        Err(e) => {
            log::error!("Failed to get vulnerability timeline: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve timeline"
            }))
        }
    }
}

/// Mark vulnerability for verification
pub async fn mark_for_verification(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<models::VerifyVulnerabilityRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::mark_vulnerability_for_verification(
        pool.get_ref(),
        &vuln_id,
        request.scan_id.as_deref(),
        &claims.sub,
    )
    .await
    {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => {
            log::error!("Failed to mark vulnerability for verification: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to mark for verification"
            }))
        }
    }
}

/// Bulk assign vulnerabilities
pub async fn bulk_assign(
    pool: web::Data<SqlitePool>,
    request: web::Json<models::BulkAssignVulnerabilitiesRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::bulk_assign_vulnerabilities(
        pool.get_ref(),
        &request.vulnerability_ids,
        &request.assignee_id,
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "updated": count
        })),
        Err(e) => {
            log::error!("Failed to bulk assign vulnerabilities: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to bulk assign"
            }))
        }
    }
}

// Update the configure_routes function:
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/vulnerabilities")
            .route("", web::get().to(list_vulnerabilities))
            .route("/{id}", web::get().to(get_vulnerability))
            .route("/{id}", web::put().to(update_vulnerability))
            .route("/{id}/comments", web::post().to(add_comment))
            .route("/{id}/timeline", web::get().to(get_vulnerability_timeline))
            .route("/{id}/verify", web::post().to(mark_for_verification))
            .route("/bulk-update", web::post().to(bulk_update_vulnerabilities))
            .route("/bulk-assign", web::post().to(bulk_assign))
            .route("/stats", web::get().to(get_vulnerability_stats)),
    );
}
```

## Implementation Summary

The remediation workflow feature has been partially implemented with the following components:

### Completed:
1. Database schema extended with:
   - `priority`, `remediation_steps`, `estimated_effort`, `actual_effort` fields in `vulnerability_tracking`
   - `verification_scan_id`, `verified_at`, `verified_by` fields for verification tracking
   - New `remediation_timeline` table for complete audit trail

2. Models updated with:
   - Extended `VulnerabilityTracking` struct with remediation fields
   - New `RemediationTimelineEvent` and `RemediationTimelineEventWithUser` types
   - `VerifyVulnerabilityRequest` and `BulkAssignVulnerabilitiesRequest`
   - Updated `VulnerabilityDetail` to include timeline and verified_by_user

3. Database migrations created for:
   - Adding new columns to existing `vulnerability_tracking` table
   - Creating `remediation_timeline` table with proper indexes

### Remaining Work:

You'll need to manually add the database functions and API endpoints from this document to complete the backend implementation.

Then update the frontend as described in the following sections.

## Frontend TypeScript Types (Update `/root/Development/HeroForge/frontend/src/types/index.ts`)

Add these new types and update existing ones:

```typescript
// Update VulnerabilityTracking interface:
export interface VulnerabilityTracking {
  id: string;
  scan_id: string;
  host_ip: string;
  port: number | null;
  vulnerability_id: string;
  severity: string;
  status: string;
  assignee_id: string | null;
  notes: string | null;
  due_date: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  // Remediation workflow fields
  priority: string | null;
  remediation_steps: string | null;
  estimated_effort: number | null;
  actual_effort: number | null;
  verification_scan_id: string | null;
  verified_at: string | null;
  verified_by: string | null;
}

// Update VulnerabilityDetail interface:
export interface VulnerabilityDetail {
  vulnerability: VulnerabilityTracking;
  comments: VulnerabilityCommentWithUser[];
  timeline: RemediationTimelineEvent[];
  assignee: User | null;
  resolved_by_user: User | null;
  verified_by_user: User | null;
}

// Update UpdateVulnerabilityRequest interface:
export interface UpdateVulnerabilityRequest {
  status?: string;
  assignee_id?: string;
  notes?: string;
  due_date?: string;
  // Remediation workflow fields
  priority?: string;
  remediation_steps?: string;
  estimated_effort?: number;
  actual_effort?: number;
}

// Add new interfaces:
export interface BulkAssignVulnerabilitiesRequest {
  vulnerability_ids: string[];
  assignee_id: string;
}

export interface VerifyVulnerabilityRequest {
  scan_id?: string;
}

export interface RemediationTimelineEvent {
  id: string;
  vulnerability_tracking_id: string;
  user_id: string;
  username: string;
  event_type: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_at: string;
}
```

## Enhanced VulnerabilityDetail Component

Update `/root/Development/HeroForge/frontend/src/components/vulnerabilities/VulnerabilityDetail.tsx` with remediation workflow UI.

Key additions:
1. Priority selector (Critical, High, Medium, Low)
2. Remediation steps editor (markdown textarea)
3. Effort tracking fields (estimated vs actual hours)
4. Verification request button
5. Timeline view showing all changes

See the complete enhanced component in the appendix below.

## RemediationBoard Kanban Component

Create `/root/Development/HeroForge/frontend/src/components/vulnerabilities/RemediationBoard.tsx`:

```typescript
import React, { useState, useEffect } from 'react';
import { vulnerabilityAPI } from '../../services/api';
import type { VulnerabilityTracking } from '../../types';

interface RemediationBoardProps {
  scanId?: string;
}

const RemediationBoard: React.FC<RemediationBoardProps> = ({ scanId }) => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityTracking[]>([]);
  const [loading, setLoading] = useState(true);
  const [draggedItem, setDraggedItem] = useState<VulnerabilityTracking | null>(null);

  const columns = [
    { id: 'open', title: 'Open', color: 'bg-red-100 border-red-300' },
    { id: 'in_progress', title: 'In Progress', color: 'bg-yellow-100 border-yellow-300' },
    { id: 'pending_verification', title: 'Pending Verification', color: 'bg-blue-100 border-blue-300' },
    { id: 'resolved', title: 'Resolved', color: 'bg-green-100 border-green-300' },
  ];

  useEffect(() => {
    loadVulnerabilities();
  }, [scanId]);

  const loadVulnerabilities = async () => {
    try {
      setLoading(true);
      const params = scanId ? { scan_id: scanId } : {};
      const response = await vulnerabilityAPI.list(params);
      setVulnerabilities(response.data);
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDragStart = (vuln: VulnerabilityTracking) => {
    setDraggedItem(vuln);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = async (newStatus: string) => {
    if (!draggedItem) return;

    try {
      await vulnerabilityAPI.update(draggedItem.id, { status: newStatus });
      await loadVulnerabilities();
      setDraggedItem(null);
    } catch (error) {
      console.error('Failed to update vulnerability status:', error);
      alert('Failed to update status');
    }
  };

  const getVulnerabilitiesByStatus = (status: string) => {
    return vulnerabilities.filter((v) => v.status === status);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'border-l-4 border-red-500';
      case 'high':
        return 'border-l-4 border-orange-500';
      case 'medium':
        return 'border-l-4 border-yellow-500';
      case 'low':
        return 'border-l-4 border-blue-500';
      default:
        return 'border-l-4 border-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Remediation Board</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {columns.map((column) => (
          <div
            key={column.id}
            className={`rounded-lg border-2 ${column.color} p-4 min-h-[500px]`}
            onDragOver={handleDragOver}
            onDrop={() => handleDrop(column.id)}
          >
            <h3 className="font-semibold text-lg mb-4">
              {column.title}
              <span className="ml-2 text-sm text-gray-600">
                ({getVulnerabilitiesByStatus(column.id).length})
              </span>
            </h3>

            <div className="space-y-2">
              {getVulnerabilitiesByStatus(column.id).map((vuln) => (
                <div
                  key={vuln.id}
                  draggable
                  onDragStart={() => handleDragStart(vuln)}
                  className={`bg-white p-3 rounded shadow cursor-move hover:shadow-md transition-shadow ${getSeverityColor(
                    vuln.severity
                  )}`}
                >
                  <div className="font-medium text-sm">{vuln.vulnerability_id}</div>
                  <div className="text-xs text-gray-600 mt-1">{vuln.host_ip}</div>
                  {vuln.assignee_id && (
                    <div className="text-xs text-gray-500 mt-1">Assigned</div>
                  )}
                  {vuln.due_date && (
                    <div className="text-xs text-red-500 mt-1">
                      Due: {new Date(vuln.due_date).toLocaleDateString()}
                    </div>
                  )}
                  {vuln.priority && (
                    <div className="text-xs mt-1">
                      <span className="font-semibold">P:</span> {vuln.priority}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RemediationBoard;
```

## API Service Updates

Update `/root/Development/HeroForge/frontend/src/services/api.ts` to add new endpoints:

```typescript
// Add to vulnerabilityAPI object:
export const vulnerabilityAPI = {
  // ... existing methods ...

  getTimeline: (id: string) => api.get<RemediationTimelineEvent[]>(`/api/vulnerabilities/${id}/timeline`),

  markForVerification: (id: string, data: VerifyVulnerabilityRequest) =>
    api.post<VulnerabilityTracking>(`/api/vulnerabilities/${id}/verify`, data),

  bulkAssign: (data: BulkAssignVulnerabilitiesRequest) =>
    api.post<{ updated: number }>('/api/vulnerabilities/bulk-assign', data),
};
```

## Appendix: Complete Enhanced VulnerabilityDetail Component

```typescript
import React, { useState, useEffect } from 'react';
import { vulnerabilityAPI } from '../../services/api';
import type { VulnerabilityDetail as VulnDetail, RemediationTimelineEvent } from '../../types';

interface VulnerabilityDetailProps {
  vulnerabilityId: string;
  onClose: () => void;
  onUpdate?: () => void;
}

const VulnerabilityDetail: React.FC<VulnerabilityDetailProps> = ({
  vulnerabilityId,
  onClose,
  onUpdate,
}) => {
  const [detail, setDetail] = useState<VulnDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [activeTab, setActiveTab] = useState<'info' | 'remediation' | 'timeline'>('info');

  // Form state
  const [status, setStatus] = useState('');
  const [priority, setPriority] = useState('');
  const [notes, setNotes] = useState('');
  const [remediationSteps, setRemediationSteps] = useState('');
  const [estimatedEffort, setEstimatedEffort] = useState<number | ''>('');
  const [actualEffort, setActualEffort] = useState<number | ''>('');
  const [newComment, setNewComment] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadDetail();
  }, [vulnerabilityId]);

  const loadDetail = async () => {
    try {
      setLoading(true);
      const response = await vulnerabilityAPI.get(vulnerabilityId);
      setDetail(response.data);

      // Initialize form state
      setStatus(response.data.vulnerability.status);
      setPriority(response.data.vulnerability.priority || 'medium');
      setNotes(response.data.vulnerability.notes || '');
      setRemediationSteps(response.data.vulnerability.remediation_steps || '');
      setEstimatedEffort(response.data.vulnerability.estimated_effort || '');
      setActualEffort(response.data.vulnerability.actual_effort || '');
    } catch (error) {
      console.error('Failed to load vulnerability detail:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async () => {
    if (!detail) return;

    try {
      setSubmitting(true);
      await vulnerabilityAPI.update(vulnerabilityId, {
        status: status !== detail.vulnerability.status ? status : undefined,
        priority: priority !== (detail.vulnerability.priority || 'medium') ? priority : undefined,
        notes: notes !== (detail.vulnerability.notes || '') ? notes : undefined,
        remediation_steps: remediationSteps !== (detail.vulnerability.remediation_steps || '') ? remediationSteps : undefined,
        estimated_effort: typeof estimatedEffort === 'number' ? estimatedEffort : undefined,
        actual_effort: typeof actualEffort === 'number' ? actualEffort : undefined,
      });
      await loadDetail();
      setEditing(false);
      onUpdate?.();
    } catch (error) {
      console.error('Failed to update vulnerability:', error);
      alert('Failed to update vulnerability');
    } finally {
      setSubmitting(false);
    }
  };

  const handleMarkForVerification = async () => {
    try {
      setSubmitting(true);
      await vulnerabilityAPI.markForVerification(vulnerabilityId, {});
      await loadDetail();
      onUpdate?.();
    } catch (error) {
      console.error('Failed to mark for verification:', error);
      alert('Failed to mark for verification');
    } finally {
      setSubmitting(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newComment.trim()) return;

    try {
      setSubmitting(true);
      await vulnerabilityAPI.addComment(vulnerabilityId, newComment);
      setNewComment('');
      await loadDetail();
    } catch (error) {
      console.error('Failed to add comment:', error);
      alert('Failed to add comment');
    } finally {
      setSubmitting(false);
    }
  };

  const renderTimeline = () => {
    if (!detail) return null;

    return (
      <div className="space-y-4">
        {detail.timeline.map((event) => (
          <div key={event.id} className="border-l-2 border-blue-500 pl-4 pb-4">
            <div className="flex justify-between items-start mb-1">
              <div className="font-medium">{event.username}</div>
              <div className="text-xs text-gray-500">
                {new Date(event.created_at).toLocaleString()}
              </div>
            </div>
            <div className="text-sm text-gray-700 mb-1">
              <span className="font-semibold">{event.event_type.replace('_', ' ')}</span>
            </div>
            {event.old_value && event.new_value && (
              <div className="text-xs text-gray-600">
                Changed from <span className="font-mono bg-gray-100 px-1">{event.old_value}</span>{' '}
                to <span className="font-mono bg-gray-100 px-1">{event.new_value}</span>
              </div>
            )}
            {event.comment && (
              <div className="text-sm text-gray-600 mt-1">{event.comment}</div>
            )}
          </div>
        ))}
      </div>
    );
  };

  if (loading || !detail) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  const { vulnerability } = detail;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg max-w-5xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-bold text-gray-900">{vulnerability.vulnerability_id}</h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-2xl">
              &times;
            </button>
          </div>

          {/* Tabs */}
          <div className="flex gap-4 mt-4 border-b">
            {[
              { id: 'info', label: 'Information' },
              { id: 'remediation', label: 'Remediation' },
              { id: 'timeline', label: 'Timeline' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-2 px-1 ${
                  activeTab === tab.id
                    ? 'border-b-2 border-blue-500 text-blue-600 font-semibold'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {activeTab === 'info' && (
            <div className="space-y-6">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Host</label>
                  <div className="text-gray-900">{vulnerability.host_ip}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
                  <div className="text-gray-900">{vulnerability.port || 'N/A'}</div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                  <div>
                    <span className={`px-3 py-1 text-sm font-semibold rounded-full ${
                      vulnerability.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      vulnerability.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      vulnerability.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-blue-100 text-blue-800'
                    }`}>
                      {vulnerability.severity.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                  {editing ? (
                    <select
                      value={status}
                      onChange={(e) => setStatus(e.target.value)}
                      className="block w-full rounded-md border-gray-300 shadow-sm"
                    >
                      <option value="open">Open</option>
                      <option value="in_progress">In Progress</option>
                      <option value="pending_verification">Pending Verification</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                      <option value="accepted_risk">Accepted Risk</option>
                    </select>
                  ) : (
                    <span className={`px-3 py-1 text-sm font-semibold rounded-full ${
                      vulnerability.status === 'open' ? 'bg-red-100 text-red-800' :
                      vulnerability.status === 'in_progress' ? 'bg-yellow-100 text-yellow-800' :
                      vulnerability.status === 'pending_verification' ? 'bg-blue-100 text-blue-800' :
                      vulnerability.status === 'resolved' ? 'bg-green-100 text-green-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {vulnerability.status.replace('_', ' ').toUpperCase()}
                    </span>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                  {editing ? (
                    <select
                      value={priority}
                      onChange={(e) => setPriority(e.target.value)}
                      className="block w-full rounded-md border-gray-300 shadow-sm"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  ) : (
                    <div>{(vulnerability.priority || 'medium').toUpperCase()}</div>
                  )}
                </div>
              </div>

              {/* Notes */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Notes</label>
                {editing ? (
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={4}
                    className="block w-full rounded-md border-gray-300 shadow-sm"
                    placeholder="Add notes about this vulnerability..."
                  />
                ) : (
                  <div className="text-gray-900 whitespace-pre-wrap bg-gray-50 p-3 rounded-md">
                    {vulnerability.notes || 'No notes'}
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex gap-2">
                {editing ? (
                  <>
                    <button
                      onClick={handleUpdate}
                      disabled={submitting}
                      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300"
                    >
                      {submitting ? 'Saving...' : 'Save Changes'}
                    </button>
                    <button
                      onClick={() => {
                        setEditing(false);
                        setStatus(vulnerability.status);
                        setNotes(vulnerability.notes || '');
                      }}
                      disabled={submitting}
                      className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      onClick={() => setEditing(true)}
                      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    >
                      Edit
                    </button>
                    {vulnerability.status === 'in_progress' && (
                      <button
                        onClick={handleMarkForVerification}
                        disabled={submitting}
                        className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:bg-gray-300"
                      >
                        Mark for Verification
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-6">
              {/* Effort Tracking */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Estimated Effort (hours)
                  </label>
                  {editing ? (
                    <input
                      type="number"
                      value={estimatedEffort}
                      onChange={(e) => setEstimatedEffort(e.target.value ? parseInt(e.target.value) : '')}
                      className="block w-full rounded-md border-gray-300 shadow-sm"
                      placeholder="Hours"
                    />
                  ) : (
                    <div>{vulnerability.estimated_effort || 'Not set'} hours</div>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Actual Effort (hours)
                  </label>
                  {editing ? (
                    <input
                      type="number"
                      value={actualEffort}
                      onChange={(e) => setActualEffort(e.target.value ? parseInt(e.target.value) : '')}
                      className="block w-full rounded-md border-gray-300 shadow-sm"
                      placeholder="Hours"
                    />
                  ) : (
                    <div>{vulnerability.actual_effort || 'Not set'} hours</div>
                  )}
                </div>
              </div>

              {/* Remediation Steps */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Remediation Steps
                </label>
                {editing ? (
                  <textarea
                    value={remediationSteps}
                    onChange={(e) => setRemediationSteps(e.target.value)}
                    rows={10}
                    className="block w-full rounded-md border-gray-300 shadow-sm font-mono text-sm"
                    placeholder="Enter detailed remediation steps (markdown supported)..."
                  />
                ) : (
                  <div className="bg-gray-50 p-4 rounded-md whitespace-pre-wrap">
                    {vulnerability.remediation_steps || 'No remediation steps defined'}
                  </div>
                )}
              </div>

              {editing && (
                <div className="flex gap-2">
                  <button
                    onClick={handleUpdate}
                    disabled={submitting}
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300"
                  >
                    {submitting ? 'Saving...' : 'Save Changes'}
                  </button>
                  <button
                    onClick={() => {
                      setEditing(false);
                      setRemediationSteps(vulnerability.remediation_steps || '');
                      setEstimatedEffort(vulnerability.estimated_effort || '');
                      setActualEffort(vulnerability.actual_effort || '');
                    }}
                    disabled={submitting}
                    className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          )}

          {activeTab === 'timeline' && renderTimeline()}
        </div>

        {/* Comments Section (always visible at bottom) */}
        <div className="border-t border-gray-200 p-6 bg-gray-50">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Comments</h3>

          <form onSubmit={handleAddComment} className="mb-4">
            <textarea
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              rows={3}
              className="block w-full rounded-md border-gray-300 shadow-sm mb-2"
              placeholder="Add a comment..."
            />
            <button
              type="submit"
              disabled={submitting || !newComment.trim()}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300"
            >
              {submitting ? 'Adding...' : 'Add Comment'}
            </button>
          </form>

          <div className="space-y-4">
            {detail.comments.length === 0 ? (
              <p className="text-gray-500 text-center py-4">No comments yet</p>
            ) : (
              detail.comments.map((comment) => (
                <div key={comment.id} className="bg-white rounded-lg p-4">
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-medium text-gray-900">{comment.username}</div>
                    <div className="text-sm text-gray-500">
                      {new Date(comment.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="text-gray-700 whitespace-pre-wrap">{comment.comment}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default VulnerabilityDetail;
```

## Usage Example

To use the Remediation Board in your dashboard:

```typescript
import RemediationBoard from '../components/vulnerabilities/RemediationBoard';

// In your component:
<RemediationBoard scanId={currentScanId} />
```
