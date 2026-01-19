# HeroForge Status Page

A simple, static status page for communicating service availability to users.

## Deployment Options

### Option 1: GitHub Pages (Recommended)

1. Create a new repository named `heroforge-status` or use a branch in this repo
2. Copy `index.html` to the repository root
3. Enable GitHub Pages in repository Settings > Pages
4. The status page will be available at `https://yourusername.github.io/heroforge-status/`

### Option 2: Serve from Main Application

The status page can be served directly from the HeroForge application by placing it in the frontend's public directory.

### Option 3: Standalone Web Server

Host the `index.html` file on any static file server (Nginx, Apache, Cloudflare Pages, Netlify, etc.).

## Updating Status

### Manual Updates

Edit `index.html` directly to update service status:

1. **Overall Status Banner**: Update the `overall-status` class:
   - `status-operational` (green) - All systems working
   - `status-degraded` (yellow) - Some issues
   - `status-outage` (red) - Major outage

2. **Individual Services**: Update each service's indicator class:
   - `indicator-operational` (green)
   - `indicator-degraded` (yellow)
   - `indicator-outage` (red)

3. **Incidents**: Uncomment and modify the incident template in the HTML.

### Example: Reporting an Incident

```html
<div class="incident">
    <div class="incident-title">Database Performance Issues</div>
    <div class="incident-date">January 19, 2026 - Investigating</div>
    <div class="incident-update">
        <strong>Investigating:</strong> We are investigating reports of slow
        database queries affecting scan performance.
    </div>
</div>
```

### Example: Resolving an Incident

```html
<div class="incident incident-resolved">
    <div class="incident-title">Database Performance Issues</div>
    <div class="incident-date">January 19, 2026 - Resolved</div>
    <div class="incident-update">
        <strong>Resolved:</strong> The issue has been identified and resolved.
        A database index was missing and has been added.
    </div>
    <div class="incident-update">
        <strong>Investigating:</strong> We are investigating reports of slow
        database queries affecting scan performance.
    </div>
</div>
```

## Integration with Monitoring

This status page works well with UptimeRobot or similar monitoring services:

1. Set up monitors for each service endpoint:
   - Web App: `https://heroforge.genialarchitect.io`
   - API Health: `https://heroforge.genialarchitect.io/health/ready`
   - Liveness: `https://heroforge.genialarchitect.io/health/live`

2. Configure alerts to notify you of downtime

3. Update the status page when incidents occur

## Future Enhancements

For automated status updates, consider:

- **Statuspage.io** - Full-featured incident management
- **Cachet** - Self-hosted status page with API
- **Upptime** - GitHub-powered uptime monitor and status page
- **Custom automation** - Script to update based on UptimeRobot API
