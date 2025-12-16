# Analytics Dashboard Backend API Implementation

This document describes the analytics backend API implementation for HeroForge.

## Overview

Implemented a comprehensive analytics system that aggregates data from scan results to provide insights into scan activity, host discoveries, vulnerabilities, and service distributions.

## Files Created/Modified

### 1. Database Models (`src/db/models.rs`)

Added new analytics model structs:

- **AnalyticsSummary**: Overall statistics including total scans, hosts, ports, vulnerabilities (by severity), and recent scan counts
- **TimeSeriesPoint**: Generic time-series data point for charts (date + value)
- **ServiceCount**: Service name and occurrence count for top services
- **VulnerabilityTrend**: Daily vulnerability counts broken down by severity (critical, high, medium, low)

### 2. Database Analytics Module (`src/db/analytics.rs`)

Created new module with 5 analytics aggregation functions:

#### `get_analytics_summary(pool, user_id, days)`
Returns comprehensive summary statistics:
- Total scans in date range
- Total hosts discovered
- Total open ports found
- Total vulnerabilities (with breakdown by severity: critical, high, medium, low)
- Scans in the last week
- Scans in the last month

Parses JSON scan results from the `scan_results` table and aggregates data across all completed scans.

#### `get_hosts_over_time(pool, user_id, days)`
Returns time-series data of host discoveries grouped by date.

- Aggregates host counts per day
- Useful for trending charts showing discovery patterns

#### `get_vulnerabilities_over_time(pool, user_id, days)`
Returns vulnerability trends with severity breakdown over time.

- Daily counts for each severity level (critical, high, medium, low)
- Enables multi-series charts showing vulnerability patterns

#### `get_top_services(pool, user_id, limit)`
Returns the most frequently discovered services across all scans.

- Aggregates service names from all port scan results
- Sorted by occurrence count (descending)
- Configurable limit (default: top 10)

#### `get_scan_frequency(pool, user_id, days)`
Returns scan frequency data (number of scans per day).

- Shows user activity patterns
- Useful for understanding scan cadence

### 3. Analytics API Endpoints (`src/web/api/analytics.rs`)

Created 5 REST API endpoints, all requiring JWT authentication:

#### GET `/api/analytics/summary?days=30`
- **Query Param**: `days` (default: 30) - time range in days
- **Returns**: `AnalyticsSummary` JSON object
- **Use Case**: Dashboard summary cards

#### GET `/api/analytics/hosts?days=30`
- **Query Param**: `days` (default: 30) - time range in days
- **Returns**: Array of `TimeSeriesPoint` objects
- **Use Case**: Hosts discovered over time chart

#### GET `/api/analytics/vulnerabilities?days=30`
- **Query Param**: `days` (default: 30) - time range in days
- **Returns**: Array of `VulnerabilityTrend` objects
- **Use Case**: Stacked area/line chart of vulnerabilities by severity

#### GET `/api/analytics/services?limit=10`
- **Query Param**: `limit` (default: 10) - number of top services
- **Returns**: Array of `ServiceCount` objects
- **Use Case**: Bar chart or pie chart of most common services

#### GET `/api/analytics/frequency?days=30`
- **Query Param**: `days` (default: 30) - time range in days
- **Returns**: Array of `TimeSeriesPoint` objects
- **Use Case**: Activity heatmap or frequency chart

### 4. Module Registration

- Added `pub mod analytics;` to `src/db/mod.rs`
- Re-exported analytics functions from db module for easy access
- Added `pub mod analytics;` to `src/web/api/mod.rs`
- Registered 5 analytics routes in `src/web/mod.rs` under the authenticated API scope

## Architecture Details

### Data Aggregation Strategy

All analytics functions follow a consistent pattern:

1. **Query Scans**: Fetch completed scans for the user within the specified date range
2. **Parse JSON Results**: Deserialize the `results` field from `scan_results` table into `Vec<HostInfo>`
3. **Aggregate Data**: Use HashMaps to group and count data by date, service, severity, etc.
4. **Transform Output**: Convert aggregated data into response models
5. **Sort Results**: Ensure time-series data is chronologically ordered

### Security & Authentication

- All endpoints require JWT authentication via `web::ReqData<auth::Claims>`
- Enforced via the `JwtMiddleware` wrapper in the protected API scope
- Each endpoint filters data by `user_id` from JWT claims (ensures users only see their own data)
- Rate-limited at 100 requests/minute per IP (via API-level rate limiter)

### Error Handling

All endpoints use consistent error handling:
- Database errors are logged with `log::error!`
- Returns HTTP 500 with user-friendly error messages
- Uses Actix-web's `ErrorInternalServerError` for proper error responses

### Performance Considerations

- Queries filter by `user_id` and `status = 'completed'` to avoid incomplete scans
- Date filtering reduces dataset size
- Aggregation happens in Rust (not SQL) for flexibility with JSON parsing
- Future optimization: Consider caching frequently-requested analytics data

## Data Flow Example

For `GET /api/analytics/summary?days=30`:

1. Client sends authenticated request with JWT token
2. `JwtMiddleware` validates token and extracts user_id
3. Handler calls `db::get_analytics_summary(pool, user_id, 30)`
4. Function queries all completed scans in last 30 days
5. Parses JSON results to extract hosts, ports, vulnerabilities
6. Counts and categorizes data
7. Returns `AnalyticsSummary` struct
8. Handler serializes to JSON and returns HTTP 200

## Example API Responses

### Summary Response
```json
{
  "total_scans": 15,
  "total_hosts": 45,
  "total_ports": 234,
  "total_vulnerabilities": 12,
  "critical_vulns": 2,
  "high_vulns": 3,
  "medium_vulns": 5,
  "low_vulns": 2,
  "scans_this_week": 3,
  "scans_this_month": 8
}
```

### Hosts Over Time Response
```json
[
  { "date": "2025-01-01", "value": 10 },
  { "date": "2025-01-02", "value": 15 },
  { "date": "2025-01-03", "value": 8 }
]
```

### Vulnerability Trend Response
```json
[
  {
    "date": "2025-01-01",
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1
  },
  {
    "date": "2025-01-02",
    "critical": 0,
    "high": 1,
    "medium": 4,
    "low": 2
  }
]
```

### Top Services Response
```json
[
  { "service": "http", "count": 45 },
  { "service": "ssh", "count": 38 },
  { "service": "https", "count": 32 },
  { "service": "mysql", "count": 12 }
]
```

## Testing

Compilation verified with `cargo check`:
- ✅ All analytics models compile
- ✅ All database functions compile
- ✅ All API endpoints compile
- ✅ Proper JWT authentication integration
- ✅ Correct Actix-web handler signatures

## Next Steps (Frontend Integration)

The frontend should create:
1. Analytics Dashboard page/tab
2. Chart components using a library like Recharts or Chart.js
3. Summary cards for quick stats
4. Date range selector (7 days, 30 days, 90 days)
5. Interactive charts:
   - Line chart for hosts over time
   - Stacked area chart for vulnerability trends
   - Bar chart for top services
   - Heatmap for scan frequency

## Notes

- All analytics are user-scoped (users only see their own data)
- Handles missing or incomplete scan results gracefully
- Time-series data is returned in ascending chronological order
- Empty results return empty arrays (no errors)
- Severity matching uses Rust enum variants (not string comparison)
