# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the frontend for HeroForge, a network reconnaissance and triage tool. It's a React 18 + TypeScript + Vite application with TailwindCSS styling.

For full project documentation including backend architecture, deployment, and CLI usage, see the parent `../CLAUDE.md`.

## Commands

```bash
npm install                  # Install dependencies
npm run dev                  # Development server at localhost:3000 (proxies /api to :8080)
npm run build                # Production build to dist/
npm run build:check          # TypeScript check + production build
npm run lint                 # ESLint with strict warnings
```

After changes, rebuild and redeploy:
```bash
npm run build
cd /root && docker compose build heroforge && docker compose up -d heroforge
```

## Architecture

### State Management

Two state systems work together:

**Zustand stores** (`src/store/`) - Client-side global state:
- `authStore.ts` - User authentication, JWT token, role checks (`isAdmin()`, `hasRole()`)
- `scanStore.ts` - Active scan data, real-time results from WebSocket, live updates

**React Query** (`@tanstack/react-query`) - Server state for API data caching and refetching.

### API Layer

All API calls go through `src/services/api.ts` which:
- Uses axios with `/api` base URL
- Automatically attaches JWT Bearer token from localStorage
- Exports domain-specific API objects: `authAPI`, `scanAPI`, `adminAPI`, `vulnerabilityAPI`, `complianceAPI`, `crmAPI`, etc.

Separate portal API in `src/services/portalApi.ts` for customer portal authentication.

### Route Protection

Three route wrappers in `App.tsx`:
- `ProtectedRoute` - Requires authentication (checks `authStore.isAuthenticated`)
- `AdminRoute` - Requires admin role (checks `authStore.isAdmin()`)
- `PortalProtectedRoute` - Customer portal auth (checks `portalAuthAPI.isAuthenticated()`)

### Component Organization

```
src/components/
├── admin/          # User/scan/system management
├── auth/           # Login forms
├── compliance/     # Framework analysis, manual assessments
├── crm/            # Customer relationship management
├── dashboard/      # Customizable dashboard widgets
├── layout/         # Header, navigation
├── portal/         # Customer portal components
├── results/        # Scan results display
├── scan/           # Scan creation forms
├── settings/       # User settings tabs
├── ui/             # Reusable primitives (Button, Badge, Checkbox, Tooltip)
└── vulnerabilities/ # Vulnerability list/detail views
```

### Real-time Updates

Scans use WebSocket connections for live progress:
1. `useScanStore` holds `liveUpdates` Map for real-time messages
2. WebSocket connects to `/api/ws/scans/{id}?token=JWT`
3. Updates include: `host_discovered`, `port_discovered`, `service_detected`, `vulnerability_found`, `progress_update`, `scan_complete`

### Lazy Loading

Less-used pages are lazy-loaded via `React.lazy()` in `App.tsx` (AdminPage, SettingsPage, CompliancePage, etc.) with a `PageLoader` fallback.

## Key Patterns

**Types:** All types in `src/types/index.ts`. Import from `'../types'`.

**Styling:** TailwindCSS with dark theme (`bg-gray-900`, `text-gray-*`). Color scheme uses cyan for primary actions.

**Toasts:** Use `react-toastify` with dark theme. Import `toast` from `'react-toastify'`.

**Icons:** Lucide React (`lucide-react`). Import individual icons: `import { Shield, Search } from 'lucide-react'`.

**Charts:** Recharts for analytics (`recharts`). Heavy library - code-split into `vendor-charts` chunk.

## Build Configuration

Vite config (`vite.config.ts`) includes:
- Dev server proxy: `/api` → `http://localhost:8080`
- Manual chunks for code splitting: `vendor-react`, `vendor-ui`, `vendor-state`, `vendor-charts`
- Chunk size limit: 600KB
