# HeroForge Web Application Setup

## Overview

HeroForge now includes a web application with:
- **Backend**: Actix-web REST API with JWT authentication
- **Frontend**: React + TypeScript with Vite
- **Database**: SQLite for user and scan management
- **Real-time**: WebSocket support for live scan progress

## Quick Start

### 1. Build the Backend

```bash
cd /root/Development/HeroForge
cargo build --release
```

### 2. Start the Web Server

```bash
./target/release/heroforge serve
```

The server will start at `http://0.0.0.0:8080`

### 3. Set Up Frontend (First Time Only)

```bash
cd frontend
npm install
```

### 4. Run Frontend Development Server

```bash
cd frontend
npm run dev
```

The frontend will start at `http://localhost:3000` with API proxy to backend.

### 5. Build Frontend for Production

```bash
cd frontend
npm run build
```

This creates optimized files in `frontend/dist/` which are served by the Actix backend.

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token
- `GET /api/auth/me` - Get current user info (requires auth)

### Scans
- `POST /api/scans` - Create new scan (requires auth)
- `GET /api/scans` - Get all user's scans (requires auth)
- `GET /api/scans/{id}` - Get specific scan (requires auth)
- `GET /api/scans/{id}/results` - Get scan results (requires auth)

### WebSocket
- `WS /api/ws/scans/{id}` - Real-time scan progress updates

## Frontend Structure

```
frontend/
├── src/
│   ├── components/     # Reusable UI components
│   ├── pages/          # Page components (Login, Dashboard, etc.)
│   ├── services/       # API services
│   ├── hooks/          # Custom React hooks
│   ├── types/          # TypeScript interfaces
│   └── styles/         # CSS/styling files
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## Database

The SQLite database is automatically created on first run. Default location: `heroforge.db`

### Tables
- **users**: User accounts with bcrypt password hashing
- **scan_results**: Scan configurations and results

## Development Workflow

### Backend Development
```bash
# Run in watch mode (requires cargo-watch)
cargo watch -x 'run -- serve'
```

### Frontend Development
```bash
cd frontend
npm run dev
```

The Vite dev server includes:
- Hot Module Replacement (HMR)
- Proxy to backend API
- TypeScript type checking

## Security Notes

1. **JWT Secret**: Change `JWT_SECRET` in `src/web/auth/jwt.rs` for production
2. **CORS**: Configure allowed origins in `src/web/mod.rs`
3. **HTTPS**: Use a reverse proxy (nginx/Caddy) for TLS in production
4. **Database**: Use PostgreSQL for production instead of SQLite

## Production Deployment

### 1. Build Everything
```bash
# Build backend
cargo build --release

# Build frontend
cd frontend
npm run build
cd ..
```

### 2. Run Production Server
```bash
./target/release/heroforge serve --bind 0.0.0.0:8080 --database sqlite://heroforge.db
```

### 3. Use Reverse Proxy (Recommended)

Example nginx configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Environment Variables

```bash
# Optional: Customize database location
DATABASE_URL=sqlite://custom.db

# Optional: Custom bind address
BIND_ADDRESS=127.0.0.1:3000
```

## Troubleshooting

### Frontend can't connect to backend
- Ensure backend is running on port 8080
- Check Vite proxy configuration in `vite.config.ts`
- Verify CORS settings in backend

### Database errors
- Delete `heroforge.db` and restart to recreate schema
- Check file permissions

### WebSocket connection fails
- Ensure `/api/ws/` route is not blocked by proxy
- Check browser console for errors

## Next Steps for Frontend Development

The frontend starter includes:
1. TypeScript types for all API responses
2. Axios-based API service layer
3. Basic project structure

### To Complete:
1. Create Login/Register pages
2. Build Dashboard with react-grid-layout
3. Implement Scan creation form
4. Add Scan results viewer
5. Integrate WebSocket for real-time updates
6. Style with Tailwind CSS

### Recommended Libraries (Already in package.json):
- **react-router-dom**: Routing
- **react-grid-layout**: Draggable dashboard tiles
- **recharts**: Data visualization
- **@tanstack/react-query**: Data fetching
- **zustand**: State management
- **react-toastify**: Notifications
- **lucide-react**: Icons

## CLI Mode Still Available

All CLI commands still work:
```bash
# Network scan
./target/release/heroforge scan 192.168.1.0/24

# Host discovery
./target/release/heroforge discover 192.168.1.0/24

# Port scan
./target/release/heroforge portscan 192.168.1.100 -p 1-1000
```

## Support

For issues or questions:
- Check logs: Backend outputs to stdout/stderr
- Frontend console: Browser DevTools
- Database: Use sqlite3 CLI to inspect
