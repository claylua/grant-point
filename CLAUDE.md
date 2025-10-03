# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands for Development

### Client (React/Vite Frontend)
```bash
cd client
npm run dev        # Start development server
npm run build      # Build for production
npm run preview    # Preview production build
```

### Server (Express.js Backend)
```bash
cd server
npm run dev        # Start development server with nodemon
npm start          # Start production server
```

### Docker
```bash
docker-compose up  # Start backend service
```

### Database Operations
```bash
# Database setup (PostgreSQL required)
createdb setel
psql setel -f server/scripts/schema.sql

# Check processing status
psql setel -c "SELECT status, COUNT(*) FROM grant_requests GROUP BY status;"
```

## Architecture Overview

This is a full-stack web application for processing Mesra grant CSV files against Setel APIs.

### High-Level Structure
- **Monorepo**: Client and server are separate but related applications
- **Client**: React SPA built with Vite, handles file uploads and monitoring
- **Server**: Express.js API with PostgreSQL backend for data persistence
- **Processing**: Background processor that handles CSV records in configurable chunks

### Key Components

#### Authentication & Authorization
- Session-based authentication using `express-session` with PostgreSQL store
- Role-based access control: `admin` and `user` roles
- Special permissions for user "clay" (audit log access)
- Admin-only operations: user management, data deletion, processing controls

#### Data Flow
1. **Upload**: CSV files are parsed and stored in `grant_requests` table
2. **Processing**: Background processor sends records to Setel APIs in chunks
3. **Results**: Success/error status persisted to database and CSV log files
4. **Monitoring**: Real-time status updates and error reporting

#### Core Modules (server/src/)
- `index.js`: Main Express application with API routes
- `processor.js`: Background processing logic with chunked API calls
- `db.js`: Database connection and transaction utilities
- `audit.js`: User action logging for compliance
- `config.js`: Environment configuration and API endpoints

#### Processing Features
- **Resumable**: Can recover from crashes and resume pending records
- **Configurable**: Chunk size and delay between chunks are adjustable
- **Environment-aware**: Supports staging and production Setel endpoints
- **Audit trail**: Comprehensive logging of all user actions

### Database Schema
- `grant_batches`: Tracks CSV upload sessions
- `grant_requests`: Individual CSV records with processing status
- `app_users`: User accounts and roles
- `audit_events`: User action logging
- `session`: Express session storage

### Environment Configuration

#### Required Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `SETEL_IDENTIFIER`: API authentication identifier
- `SETEL_PASSWORD`: API authentication password
- `SESSION_SECRET`: Express session encryption key

#### Optional Variables
- `PORT`: Server port (default: 4000)
- `LOG_DIRECTORY`: CSV log file location
- `CORS_ALLOWED_ORIGINS`: Comma-separated allowed origins
- `HTTPS_*`: HTTPS certificate configuration

### Deployment Notes
- Client can be deployed to static hosting (Cloudflare Pages)
- Server requires Node.js runtime with PostgreSQL access
- Docker support available via docker-compose
- External network access required for Setel API endpoints

### Security Considerations
- Production processing requires explicit confirmation
- Sensitive credentials handled via environment variables
- Session-based authentication with CSRF protection
- Role-based access control for administrative functions