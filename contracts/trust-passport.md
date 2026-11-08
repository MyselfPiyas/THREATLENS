# THREATLENS Trust Passport integrity contract

Part 9 is implemented with off-chain canonical JSON and SHA-256 only. No smart
contract, chain RPC, wallet, gas payment, or blockchain receipt is used.

The API snapshots persisted scan, finding, and event evidence in
`trust_passports.canonical_report`, then hashes it with UTF-8 JSON serialization,
sorted keys, compact separators, NFC-normalized strings, UTC timestamps, and a
fixed array order. `generated_at` is metadata excluded from the hash. The
passport's original canonical report and digest are retained; verification
never silently replaces either reference.

`OFFCHAIN_VERIFIED` means the digest matches the stored report. It detects
accidental or application-level report changes but cannot protect against a
privileged database operator changing both the report and digest. Public
verification is available only through a random owner-controlled share token;
the token can be revoked. Public results exclude scan ownership and private
report content. Downloads are available as JSON and PDF to the authenticated
owner. JSON preserves Unicode content; the compact PDF rendering is a readable
summary.

The optional OpenRouter explanation uses only the centralized backend LLM
service, cites IDs supplied by the stored report, and cannot change the report,
digest, verification status, or evidence. If OpenRouter is unavailable, the
deterministic integrity workflow still functions.

Passwords, API keys, private messages, and other sensitive user data are not
stored in reports unless the scan evidence itself legitimately contains it;
callers should avoid submitting such data to scanners.
