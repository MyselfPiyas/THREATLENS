# THREATLENS

THREATLENS is an AI-powered web threat detection and digital trust intelligence platform. It includes the application foundation, Supabase authentication and RLS schema, a bounded URL investigation service, message and QR analysis, and evidence-backed Threat Intelligence and Scam DNA views.

## Technology stack

- Next.js App Router, React, TypeScript strict mode
- Tailwind CSS v4, shadcn/ui component setup, Lucide icons
- FastAPI, Pydantic Settings, Uvicorn, bounded standard-library HTTP inspection
- Supabase PostgreSQL, Supabase Auth, `@supabase/ssr`
- SQL migrations and pgTAP security checks under `supabase/`

## Project layout

```text
frontend/       Next.js app, auth screens, protected workspace and Supabase SSR clients
backend/        FastAPI application, Supabase JWT validation and ownership dependencies
supabase/       Local CLI configuration, database migrations and RLS tests
contracts/      Shared API contract documentation
docs/           Project architecture and local development notes
```

## Requirements

- Node.js 20.19 or later and npm
- Python 3.10 or later
- A Supabase project or the local Supabase CLI stack for Auth and database integration
- Docker Desktop or a compatible container runtime for the local Supabase stack

## Environment

Copy `frontend/.env.example` to `frontend/.env.local` and `backend/.env.example` to `backend/.env`. The root `.env.example` shows both sets together.

| Variable | Service | Purpose |
| --- | --- | --- |
| `NEXT_PUBLIC_SITE_URL` | Frontend | Public app origin used in Auth email redirects; local default is `http://localhost:3000` |
| `NEXT_PUBLIC_API_URL` | Frontend | FastAPI base URL; defaults to `http://127.0.0.1:8000/api/v1` |
| `NEXT_PUBLIC_SUPABASE_URL` | Frontend | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Frontend | Browser-safe Supabase key; `NEXT_PUBLIC_SUPABASE_ANON_KEY` is accepted for legacy projects |
| `APP_NAME` | Backend | FastAPI title and startup log name |
| `APP_ENV` | Backend | Environment label used in startup logs |
| `LOG_LEVEL` | Backend | Python logging level |
| `FRONTEND_ALLOWED_ORIGINS` | Backend | Comma-separated exact HTTP(S) origins permitted by CORS |
| `SUPABASE_URL` | Backend | Supabase project URL |
| `SUPABASE_PUBLISHABLE_KEY` | Backend | Public API key used with caller JWTs; `SUPABASE_ANON_KEY` is accepted for legacy projects |
| `SUPABASE_SECRET_KEY` | Backend only | Required for scanner writes and threat-indicator access; never sent to the browser |
| `SUPABASE_SERVICE_ROLE_KEY` | Backend only | Optional legacy fallback for `SUPABASE_SECRET_KEY` |
| `OPENROUTER_API_KEY` | Backend only | OpenRouter secret; never expose it to the browser |
| `OPENROUTER_BASE_URL` | Backend only | OpenRouter API base URL, normally `https://openrouter.ai/api/v1` |
| `OPENROUTER_MODEL` | Backend only | Model ID supported by the OpenRouter account |
| `OPENROUTER_SITE_URL` / `OPENROUTER_APP_NAME` | Backend only | Optional OpenRouter attribution headers |
| `LLM_REQUEST_TIMEOUT_SECONDS` | Backend only | Bounded provider request timeout |
| `URL_SCAN_*` | Backend only | URL length, timeouts, redirect/response limits, scoring thresholds and signal weights; see `backend/.env.example` |

Never put `SUPABASE_SECRET_KEY` or `SUPABASE_SERVICE_ROLE_KEY` in a frontend environment file. The frontend uses only the publishable key; Row Level Security controls its data access.

URL scan persistence requires `SUPABASE_SECRET_KEY` in `backend/.env` because authenticated users cannot write scan results under the database policies. This key is never sent to the browser. The URL scanner uses the configured exact threat indicator records in `threat_indicators`; only an exact match from a configured trusted source with confidence at or above `URL_SCAN_CONFIRMED_MIN_CONFIDENCE` can produce `CONFIRMED_MALICIOUS`. No registrar/WHOIS provider is configured, so domain registration age is reported as unavailable.

## Database and Auth setup

### Local Supabase stack

Install the [Supabase CLI](https://supabase.com/docs/guides/local-development/cli/getting-started) and Docker Desktop. This repository includes `supabase/config.toml`; do not run `supabase init` over it.

From the repository root:

```powershell
supabase start
supabase status
```

The local stack applies migrations on first startup. If you add migrations later and want a fresh local database, `supabase db reset` recreates the local database and reapplies every migration. This reset is destructive to local Supabase data only.

Use the local API URL and publishable key printed by `supabase status` in both frontend and backend environment files. Keep the local secret key in `backend/.env` only if a trusted backend operation needs elevated access. Local Auth email messages can be inspected in the Mailpit URL printed by the CLI.

### Hosted Supabase project

Set `NEXT_PUBLIC_SITE_URL` to the deployed app origin and add the exact callback URL `<site-origin>/auth/callback` to the project's Auth redirect allow-list. For local development, `supabase/config.toml` allows `http://localhost:3000/auth/callback`.

To deploy migrations after reviewing them, install and authenticate the CLI, then link and push:

```powershell
supabase login
supabase link --project-ref <your-project-ref>
supabase db push --remote
```

Review the target project and pending migrations before running `db push --remote`. The migration is also available in the Supabase Dashboard SQL Editor if you prefer to apply it there.

### Schema and access rules

The migration creates `profiles`, `scans`, `scan_findings`, `threat_indicators`, `scan_events`, `trust_passports`, and `scan_relationships`.

Trust Passports (Part 9) store a canonical report snapshot and deterministic
off-chain SHA-256 digest for a completed scan. Apply
`supabase/migrations/20261108020000_trust_passport_integrity.sql` followed by
`supabase/migrations/20261108030000_offchain_passport_reports.sql`. Verification
re-hashes the original snapshot and reports `OFFCHAIN_VERIFIED`,
`INTEGRITY_MISMATCH`, or `INVALID_REPORT`; it never regenerates its reference.
Owners can download JSON/PDF reports and enable or revoke public metadata-only
verification links. This detects application-level tampering but does not
protect against a privileged database operator changing both the report and
hash. Part 9 does not use a blockchain, wallet, RPC, contract, or gas.

The complete end-to-end checklist is in `docs/PASSPORT_VERIFICATION.md`; hosted
deployment guidance is in `docs/PRODUCTION_DEPLOYMENT.md`. Failed or queued
scans cannot generate official passports.

The follow-up `20261107000100_url_scan_risk_labels.sql` migration adds the URL scanner classifications while retaining the earlier labels for existing rows. Apply it before running the scanner against a hosted project (`supabase db push --remote`) or recreate the local database with `supabase db reset`.

- New Auth users receive a profile row through a database trigger.
- Every table has Row Level Security enabled.
- Authenticated users can read only their own scan data and update their own profile.
- Users cannot directly create or edit scan results. Trusted backend operations use the backend-only secret key.
- `threat_indicators` has no grants for `anon` or `authenticated`; only trusted backend access is granted.
- Scan ownership is checked through FastAPI with the caller's JWT and enforced again by PostgreSQL RLS.
- Passport storage retains legacy chain-reference columns for compatibility, but the current workflow does not write to a blockchain. Passport access remains owner-scoped through RLS; public sharing uses revocable random tokens and returns metadata only.

Every scan-specific FastAPI route uses `require_scan_owner`; list queries are also filtered by the authenticated user ID and run with the caller JWT. Scan creation and result writes use the backend-only key. The in-process scan queue is bounded (64 queued items and 2 workers); queued jobs are not durable across a backend restart.

## URL scanning

Authenticated endpoints are available under `/api/v1`:

- `POST /scans/url` — accept a URL and return a queued scan ID.
- `GET /scans` — list the caller's scans.
- `GET /scans/{scan_id}` — read one owned scan.
- `GET /scans/{scan_id}/findings` and `/events` — read its findings and chronological investigation timeline.
- `GET /scans/{scan_id}/status` — poll progress.

The scanner accepts only HTTP(S) on standard ports, rejects credential-bearing URLs and private/reserved destinations, validates and pins every DNS result per connection, and validates each redirect before following it. It sends no cookies or credentials to targets, verifies TLS certificates, bounds DNS/connect/request/job timeouts and response headers, and never reads, saves, renders, or executes a response body. Pattern scores are configurable in `backend/.env`; weak heuristic signals cannot confirm maliciousness. A low-risk result explicitly is not a safety guarantee.

To enable actual scans after a fresh local install, put the Supabase URL and publishable key in `backend/.env`, and the same public credentials in `frontend/.env.local`. Add the Supabase secret key only to `backend/.env`, apply the migrations, and restart FastAPI. If the backend-only key is absent, scan submission returns HTTP 503 and does not create a partial record.

## Authentication screens

- `/auth/sign-up` — creates an account and sends an email confirmation when enabled.
- `/auth/login` — signs in using Supabase Auth.
- `/auth/forgot-password` — requests a reset email without revealing whether an address is registered.
- `/auth/reset-password` — accepts a new password only with a valid Auth session from the reset link.
- `/profile` — protected profile view and update.
- `/dashboard` — protected workspace and RLS-scoped recent scan history.

The auth callback exchanges Supabase's one-time code for a cookie-backed session. Protected routes verify claims on the server and in Next.js Proxy. The FastAPI `/api/v1/auth/me` endpoint validates bearer tokens with Supabase Auth.

## Install and run locally

Open separate terminals from the repository root.

### FastAPI

```powershell
cd .\backend
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health checks:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/api/v1/health`
- Authenticated identity: `GET http://127.0.0.1:8000/api/v1/auth/me` with `Authorization: Bearer <access-token>`

### Next.js

```powershell
cd .\frontend
if (-not (Test-Path .env.local)) { Copy-Item .env.example .env.local }
npm install
npm run dev
```

Open `http://localhost:3000`. Without valid Supabase credentials, the public readiness page and auth screens still load, while protected routes redirect to sign-in and auth forms explain that configuration is required.

## Checks

```powershell
cd .\frontend
npm run lint
npm run typecheck
npm run build
```

In another terminal:

```powershell
cd .\backend
.\.venv\Scripts\Activate.ps1
python -m pytest
```

With the Supabase CLI and Docker running, validate the migrations and RLS policy checks locally:

```powershell
supabase db reset
supabase test db
```

## Architecture notes

- Browser and server Supabase Auth clients use cookie-based sessions from `@supabase/ssr`.
- Server-side route guards verify claims; the database RLS policies remain the data authorization boundary.
- FastAPI validates the caller's access token with Supabase Auth and queries scan ownership using the caller JWT, never the backend secret key.
- `get_supabase_admin_client()` reads the optional privileged key only from backend environment settings and disables auth-session persistence.
- CORS is limited to exact origins from `FRONTEND_ALLOWED_ORIGINS`; local defaults permit `http://localhost:3000` and `http://127.0.0.1:3000`.
- API and provider errors shown to users do not include tokens, stack traces, or raw provider payloads.

## Website identity analysis

Authenticated clients can compare a URL with the configured reference brand catalog:

- `POST /api/v1/analyze/identity` with `{ "url": "https://example.com", "claimed_brand": "Google", "scan_id": "optional-owned-scan-id" }`
- `GET /api/v1/brands` returns the configured reference brands.
- `GET /api/v1/scans/{scan_id}/identity` returns the saved identity evidence for an owned scan.

Identity analysis reports similarity, Unicode or punycode signals, substitutions, suspicious subdomains, and sensitive paths. Similarity alone is never treated as proof of impersonation; saved results include evidence and a capped confidence score for review.

## Message and QR analysis

Authenticated clients can submit untrusted message text or an image:

- `POST /api/v1/analyze/message` with `{ "content": "..." }`
- `GET /api/v1/analyze/message/{analysis_id}`
- `POST /api/v1/analyze/qr` as multipart form field `file` (PNG, JPEG, or WEBP, maximum 5 MB)
- `GET /api/v1/analyze/qr/{analysis_id}`

Message analysis uses transparent rules and, only when `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` are configured and the user opts in for that submission, an optional OpenRouter structured-JSON review. The centralized backend service calls `OPENROUTER_BASE_URL/chat/completions` and uses the configured model; it never silently switches providers or models. Free models have provider quotas and may fall back to the deterministic rules when unavailable. Email addresses and phone numbers are redacted before provider submission. Raw message content and QR bytes are never persisted; derived indicators are stored in the user's analysis record. Provider failures fall back to the rule assessment, and the model cannot lower the baseline risk. QR URLs are queued through the same bounded URL scanner and are never visited by the browser automatically. Apply the `20261108000000_message_qr_analyses.sql` migration before using hosted persistence.
