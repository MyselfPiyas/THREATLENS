# Production deployment checklist

## Vercel frontend

Create a Vercel project from this repository with **Root Directory** set to
`frontend`. Vercel detects Next.js automatically; use the repository's normal
`npm install` and `npm run build` commands. Configure only these browser-safe
variables in Vercel:

- `NEXT_PUBLIC_SITE_URL` — the deployed Vercel origin
- `NEXT_PUBLIC_API_URL` — the HTTPS URL of the deployed FastAPI service,
  including `/api/v1`
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`

Never add `SUPABASE_SECRET_KEY`, `SUPABASE_SERVICE_ROLE_KEY`,
`OPENROUTER_API_KEY`, or any wallet/RPC/private-key variable to Vercel.

The FastAPI service must be deployed separately on a provider that supports a
persistent Python web process. Set its start command to
`uvicorn app.main:app --host 0.0.0.0 --port $PORT` from the `backend` directory,
and add the Vercel origin exactly to `FRONTEND_ALLOWED_ORIGINS`.

## Backend

Configure these as backend-only secrets/environment variables:

- `SUPABASE_URL`
- `SUPABASE_PUBLISHABLE_KEY` (or legacy `SUPABASE_ANON_KEY`)
- `SUPABASE_SECRET_KEY` (or legacy service-role key, never in frontend)
- `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, and `OPENROUTER_MODEL`
- `FRONTEND_ALLOWED_ORIGINS` with exact deployed origins only

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
