# Grant Mesra With Membership Tier – Web Processor

This project extends the original Mesra grant script into a full-stack tool with a PostgreSQL backend, an Express.js API, and a Vite + React front-end. It lets you upload Mesra grant CSV files, process them against Setel staging or production endpoints, track progress, review errors, and resume failed runs safely.

## Key Features
- Secure login with session-based auth (initial admin configured at startup).
- Upload Mesra CSV files and persist records in PostgreSQL (`setel` database).
- Enforce one active dataset at a time (must delete before re-uploading, admin only).
- Start or resume processing with either **staging** or **production** URLs, including a production safety prompt.
- Stream results to both the database (per-row status, logs) and a CSV log file stored under `logs/`.
- Resume partially processed batches automatically after a crash or restart.
- Download the generated result CSV and review errored rows directly in the UI.
- Admin console to create, update, reset, or delete user accounts (non-admins cannot manage users or wipe data).

## Project Structure
```
server/   # Express API, CSV ingestion, processing worker
client/   # Vite + React front-end
logs/     # GrantPointResult-<batch>.csv files (created at runtime)
server/scripts/schema.sql  # Database schema
grantMesraWithMembershipTier.js  # Original standalone script (still available)
```

## Prerequisites
- Node.js 18+
- PostgreSQL 14+ (Homebrew install already configured in this environment)
- `admin/admin` PostgreSQL superuser (created earlier)

## Database Setup
```bash
# Ensure the database exists (created previously)
createdb setel

# Apply schema (creates grant_batches + grant_requests tables, triggers)
psql setel -f server/scripts/schema.sql
```

## Backend (Express) Setup
```bash
cd server
npm install
npm run dev   # or npm start for production mode
```

For development, copy the sample environment file and adjust values as needed:

```bash
cd server
cp .env.example .env
```

Use `.env` (or per-environment overrides like `.env.production`) to provide different `SESSION_SECRET` and `CORS_ALLOWED_ORIGINS` values for local development vs production. In production hosting, set the same variables via your process manager/container secrets instead of committing them to source control.

Required variables for the backend:
- `DATABASE_URL`
- `SETEL_IDENTIFIER`
- `SETEL_PASSWORD`
- `SESSION_SECRET`

Optional overrides include `LOG_DIRECTORY`, `CORS_ALLOWED_ORIGINS`, and the service credential defaults shown in `server/.env.example`.

Environment variables (optional) – defaults are suitable for local use:
- `DATABASE_URL` (default: `postgres://admin:admin@localhost:5432/setel`)
- `SETEL_IDENTIFIER` and `SETEL_PASSWORD` to override the hard-coded service credentials
- `LOG_DIRECTORY` to customise where CSV logs are stored
- `SESSION_SECRET` to override the Express session secret (set this in production)
- `CORS_ALLOWED_ORIGINS` (comma-separated list) when hosting the UI separately, e.g. `https://your-pages-domain.pages.dev`
- `PORT` (default: `4000`)

## Front-end (Vite + React) Setup
```bash
cd client
npm install
npm run dev
```
The Vite dev server proxies `/api` to `http://localhost:4000`. Build output can be served statically if desired.

### Cloudflare Pages Deployment
1. Copy `client/.env.example` to `client/.env.production` (or configure Pages project variables) and set `VITE_API_BASE_URL` to your public Express backend URL (e.g. `https://setel-api.example.com`).
2. In your Cloudflare Pages project, set:
   - **Build command**: `npm run build`
   - **Build output directory**: `dist`
   - **Root directory**: `client`
3. Ensure the backend enables CORS (allowing the Pages origin) and accepts session cookies (`Access-Control-Allow-Credentials: true`).
4. For local builds: `cd client && npm run build`, then deploy the contents of `client/dist/`.

## Usage Flow
1. Visit the Vite interface (default `http://localhost:5173`).
2. Upload a CSV containing the columns used by the original script (`referenceId`, `title`, `cardNumber`, `adjustmentType`, `amount`, `merchantId`, `remarks`, `basePoints`, `bonusPoints`).
3. Choose **Staging** or **Production** as the target environment. Production requires an extra confirmation.
4. Choose **Staging** or **Production**, then click **Start / Continue** to process pending rows.
5. Monitor progress, review errors, and download the latest `GrantPointResult-<batch>.csv`.
6. When finished (or before uploading a new file), click **Delete current data** (admin only) to truncate tables and remove log files.

### Authentication & User Management
- On first run, log in with the initial admin credentials configured for the environment.
- Admins can add, update (role/password), or delete other users from the **User Management** section.
- Non-admin users may upload CSVs and process batches but cannot manage users or delete existing data.
- Sessions are stored in Postgres via `connect-pg-simple`; the Express API enforces authentication/authorization on every route.

### Processing Guarantees
- Each row is stored with a `status` (`pending`, `success`, `error`).
- Success/error details are persisted (`response_status`, `error_message`, `raw_error`).
- If the server stops mid-run, restarting the Express app and pressing **Start / Continue** resumes from rows still marked `pending`.
- Result CSV logging mirrors the legacy script while also storing logs in the database.

## API Overview
- `POST /api/upload` – Upload CSV (multipart) and populate the tables. Fails if existing data is present.
- `POST /api/process` – Start/resume processing. Requires body `{ environment: 'staging' | 'production', confirmProduction?: boolean }`.
- `GET /api/status` – Counts by status, batch metadata, and processor state.
- `GET /api/errors?limit=200` – Paginated error rows.
- `GET /api/log-file` – Download the latest GrantPointResult CSV.
- `DELETE /api/data?confirm=true` – Truncate tables and remove log files.

## Original Script
The original Node script (`grantMesraWithMembershipTier.js`) still exists if you need the single-run CLI utility:
```bash
node grantMesraWithMembershipTier.js inputFile
```
It continues to read `inputFile.csv` and write `GrantPointResult-inputFile.csv` using the production endpoints.

## Troubleshooting
- **Upload blocked**: Ensure you removed existing data (`DELETE /api/data?confirm=true`).
- **Processing refuses to start**: Check that `grant_requests` has `pending` rows (`SELECT status, COUNT(*) FROM grant_requests GROUP BY status;`).
- **Production prompt**: API rejects production unless `confirmProduction: true` is sent (UI handles this with a confirmation dialog).
- **CSV log missing**: Logs are created on first processing run under `logs/GrantPointResult-<batch>.csv`.
- **Resuming after crash**: Restart the Express server and click **Start / Continue**; pending rows resume automatically.

## Notes on Credentials
Authentication uses the `enterprise-ops` service credentials embedded in the legacy script. Use environment variables if you need to override them. Treat production access carefully; the UI adds an explicit warning and confirmation step, and the API enforces the confirmation flag.

---

**Happy processing!**
