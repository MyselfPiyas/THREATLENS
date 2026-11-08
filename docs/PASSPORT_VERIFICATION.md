# THREATLENS off-chain passport verification

Trust Passports are deterministic, off-chain integrity records. A passport can
be created only for a persisted URL investigation whose status is `completed`
or `complete`; failed and queued scans are never eligible.

## Workflow

1. The backend reads the owned scan, findings, and investigation events from
   Supabase.
2. It creates a versioned canonical JSON snapshot. Object keys are sorted,
   Unicode is normalized to NFC, timestamps are normalized to UTC, and array
   ordering is deterministic.
3. SHA-256 is calculated over the snapshot (excluding only the envelope's
   `generated_at` value) and the snapshot plus digest are stored together.
4. Verification re-hashes the stored snapshot and compares it to the original
   digest. The original digest is never replaced by a verification request.
5. JSON and PDF downloads are available only to the owning authenticated user.

`OFFCHAIN_VERIFIED` means only that the digest matches the stored snapshot. It
does not prove that a website is safe and cannot protect against a privileged
database operator changing both values.

## Public verification

An owner may create a random, revocable share token. Public verification accepts
only that token and returns the passport ID, hash algorithm, report version,
digest, timestamp, and integrity status. It never returns the target, findings,
events, user ID, or canonical report. Deleting the share immediately invalidates
the token.

## API checks

- `POST /api/v1/passports` creates a passport from a completed scan.
- `GET /api/v1/passports/{id}/proof` returns the owner-only canonical snapshot
  and a recalculated digest.
- `POST /api/v1/passports/{id}/verify` persists the latest deterministic status.
- `POST /api/v1/passports/{id}/verify-upload` checks a downloaded JSON report
  without modifying the stored passport.
- `GET /api/v1/passports/{id}/download?format=json|pdf` downloads the report.
- `POST` and `DELETE /api/v1/passports/{id}/share` enable or revoke sharing.
- `GET /api/v1/public/passports/{token}/verify` performs metadata-only public
  verification.

No wallet, smart contract, RPC provider, transaction, gas, or blockchain
dependency is used.
