# Production deployment checklist

## Free-tier hosting layout

Use Vercel for the Next.js frontend and Render's free Web Service for FastAPI.
The API runs a persistent background scan queue, so it must not be deployed as
a short-lived serverless function. Render's free service may sleep after
inactivity; the first request after sleep can take around a minute. This is a
free-tier availability limitation, not a scan-data issue.

### Deploy the FastAPI service on Render

1. Push the project to the public `MyselfPiyas/THREATLENS` GitHub repository.
2. In Render, choose **New + → Blueprint**, connect that repository, and let
   Render read the root `render.yaml`. The Blueprint defines a free Python web
   service rooted at `backend` with `/health` as its health check.
3. Enter the requested backend environment values in Render's protected
   environment form. Required backend values are listed below. Do not put any
   secret in the repository or a `NEXT_PUBLIC_` variable.
4. Deploy and wait for Render to report the `/health` check as healthy. Copy the
   assigned HTTPS service origin (for example, `https://<service>.onrender.com`).

The Blueprint intentionally leaves credentials as `sync: false`: they must be
entered in Render's secret environment settings and cannot safely be guessed
or copied into source control.

## Vercel frontend

Create or update a Vercel project from this repository with **Root Directory**
set to `frontend`. Vercel detects Next.js automatically; use the repository's
normal `npm install` and `npm run build` commands. Configure only these
browser-safe variables in Vercel:

- `NEXT_PUBLIC_SITE_URL` — the deployed Vercel origin
- `NEXT_PUBLIC_API_URL` — the HTTPS URL of the deployed FastAPI service,
  including `/api/v1`
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`

Set `NEXT_PUBLIC_API_URL` to the Render HTTPS service origin followed by
`/api/v1` (for example, `https://<service>.onrender.com/api/v1`). Redeploy the
Vercel frontend after changing environment variables. If the existing Vercel
deployment came from a folder upload, import the GitHub repository to enable
repeatable deployments from source; set its root directory to `frontend`.

Never add `SUPABASE_SECRET_KEY`, `SUPABASE_SERVICE_ROLE_KEY`,
`OPENROUTER_API_KEY`, or any wallet/RPC/private-key variable to Vercel.

Set `FRONTEND_ALLOWED_ORIGINS` in Render to the exact Vercel production origin,
without a trailing slash. If Vercel preview deployments need access, add only
the specific preview origins that should be allowed; do not use `*`.

## Backend

Configure these as backend-only secrets/environment variables:

- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY` (or legacy `SUPABASE_ANON_KEY`)
- `SUPABASE_SECRET_KEY` (or legacy service-role key, never in frontend)
- `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, and `OPENROUTER_MODEL`
- `FRONTEND_ALLOWED_ORIGINS` with exact deployed origins only

`OPENROUTER_SITE_URL` is optional; `OPENROUTER_APP_NAME` is set by the
Blueprint. If OpenRouter credentials are absent or the provider is unavailable,
AI explanations are unavailable but deterministic analysis and passport
integrity operations should remain usable.

Run migrations in order, including
`20261108020000_trust_passport_integrity.sql` and
`20261108030000_offchain_passport_reports.sql`. Review the hosted project before
using `supabase db push --remote`.

## Frontend

Set `NEXT_PUBLIC_SITE_URL`, `NEXT_PUBLIC_API_URL`,
`NEXT_PUBLIC_SUPABASE_URL`, and the publishable Supabase key. Never use a
`NEXT_PUBLIC_` prefix for a secret or OpenRouter key.

## Verification smoke test

1. Sign in and complete a URL scan.
2. Open Trust Passports and create a passport from the completed scan.
3. Download JSON and PDF, then upload the JSON to verify it.
4. Enable a public link and verify it in a private browser window.
5. Revoke the link and confirm the public endpoint returns 404.
6. Modify a downloaded report and confirm verification returns
   `INTEGRITY_MISMATCH`.

The passport hash and verification status are deterministic backend decisions.
OpenRouter is optional explanatory text only; an outage must not prevent report
creation, hashing, downloads, or verification. THREATLENS uses no blockchain,
wallet, RPC, contract, or transaction service.
