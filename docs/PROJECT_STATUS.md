# THREATLENS project status

## Provider configuration

The optional LLM provider is OpenRouter, using its OpenAI-compatible chat completions API. Provider calls are centralized in `backend/app/services/llm_service.py` and are backend-only.

Required backend variables:

- `OPENROUTER_API_KEY`
- `OPENROUTER_BASE_URL` (normally `https://openrouter.ai/api/v1`)
- `OPENROUTER_MODEL`

Optional attribution variables:

- `OPENROUTER_SITE_URL`
- `OPENROUTER_APP_NAME` (defaults to `THREATLENS`)

`OPENROUTER_API_KEY` must never use a `NEXT_PUBLIC_` prefix or appear in frontend code, logs, tests, or API responses. Provider errors, rate limits, timeouts, unavailable models, and malformed JSON are handled without exposing credentials. Message analysis falls back to deterministic rules so URL scanning and other non-AI features remain operational.

## Permanent architecture rule

OpenRouter is the exclusive LLM provider for THREATLENS. Every future LLM-powered feature must call `backend/app/services/llm_service.py`; feature modules must not create provider clients, import an OpenAI SDK, or hardcode a model identifier. Deterministic validation, DNS, TLS, reputation, hashing, authorization, persistence, and other security decisions remain independent of the LLM. User content and external content are untrusted data, and OpenRouter unavailability must disable only the AI enhancement while preserving deterministic functionality.

## Threat intelligence feed

The protected FastAPI API can refresh the OpenPhish Community Feed through
`POST /api/v1/intelligence/refresh`. It imports and persists source-attributed
phishing URLs in `threat_indicators`; it never visits the listed destinations.
The community feed is refreshed no more than once every 12 hours per running
backend process. OpenPhish does not publish a numeric confidence value, so the
stored confidence is an internal source-based indicator and is not shown as a
provider-assigned score. Feed failures are reported as unavailable, not as a
clean reputation result. The feed is provided under OpenPhish's published
community-feed terms: https://www.openphish.com/phishing_feeds.html.

## Part 9: Trust Passports — off-chain only

Passport creation snapshots persisted scan, finding, and timeline evidence into
`trust_passports.canonical_report`, then stores a deterministic SHA-256 digest.
Verification hashes that original snapshot; it does not rebuild the report
from mutable scan rows or replace the original reference. JSON/PDF downloads
are owner-only. Public verification uses an unguessable owner-controlled share
token that can be revoked, and returns integrity metadata only. Optional
OpenRouter explanation uses the centralized backend service and cannot change
the canonical report, digest, or verification state.

No blockchain, wallet, RPC, chain ID, contract, signer, or gas setup is part of
Part 9. `OFFCHAIN_VERIFIED` means the digest matches the stored report; it does
not protect against a privileged database operator changing both the report
and digest, and does not prove a website is safe. Apply
`supabase/migrations/20261108020000_trust_passport_integrity.sql` followed by
`supabase/migrations/20261108030000_offchain_passport_reports.sql` before using
the updated passport API against hosted Supabase.

## Part 10 integration status

The off-chain passport workflow is integrated with completed URL investigations,
persisted findings/events, scan history, owner-scoped Supabase access, downloads,
tamper detection, and revocable metadata-only public verification. Failed scans
are intentionally excluded from passport creation. No blockchain or wallet
dependency remains in the application workflow. See
`docs/PASSPORT_VERIFICATION.md` and `docs/PRODUCTION_DEPLOYMENT.md` for the
verification and deployment checklists. Deterministic passport tests and live
health/build checks pass; a full authenticated Supabase end-to-end run remains
environment-dependent and must be completed before declaring the milestone
fully verified.
