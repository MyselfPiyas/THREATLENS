# Trust Passport API (Part 9)

All owner endpoints below require a valid Supabase bearer access token. The API
checks ownership and the database's RLS policy independently. The public
verification route requires an unguessable share token created by the owner;
it does not expose scan contents or ownership data.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/passports` | Snapshot a completed owned scan and create an off-chain SHA-256 passport (`{"scan_id":"UUID"}`). |
| `GET` | `/api/v1/passports?limit=50&offset=0` | List the caller's passports, paginated. |
| `GET` | `/api/v1/passports/{passport_id}` | Get owner-visible metadata. |
| `GET` | `/api/v1/passports/{passport_id}/proof` | Get the canonical report and current integrity comparison. |
| `GET` | `/api/v1/passports/{passport_id}/download?format=json` | Download the original report as JSON or PDF. |
| `POST` | `/api/v1/passports/{passport_id}/verify` | Re-hash the originally stored report and persist the result/time. |
| `POST` | `/api/v1/passports/{passport_id}/verify-upload` | Multipart `file` JSON upload comparison; maximum 1 MiB. Does not replace the original report. |
| `GET` | `/api/v1/passports/{passport_id}/status` | Get the latest persisted status. |
| `POST` | `/api/v1/passports/{passport_id}/share` | Create/rotate a revocable public share token. |
| `DELETE` | `/api/v1/passports/{passport_id}/share` | Revoke the public token. |
| `GET` | `/api/v1/public/passports/{public_token}/verify` | Verify the shared report's saved canonical report and return only intended integrity metadata. |
| `POST` | `/api/v1/passports/{passport_id}/explain` | Optional OpenRouter explanation via centralized `llm_service.py`; deterministic workflow does not depend on it. |

Statuses include `OFFCHAIN_VERIFIED`, `INTEGRITY_MISMATCH`, and
`INVALID_REPORT`. A matching digest verifies consistency with the saved report,
not the safety of the scanned site and not resistance to privileged database
tampering. No blockchain transaction or on-chain proof is produced.

## Hosted Supabase migration

Apply the migrations in order from the Supabase SQL Editor or Supabase CLI:

1. `20261108020000_trust_passport_integrity.sql`
2. `20261108030000_offchain_passport_reports.sql`

The second migration adds the canonical report snapshot, ownership field,
algorithm/version metadata, verification timestamp, and revocable share token.
