# API contracts

The initial health contract is `GET /api/v1/health`:

```json
{
  "status": "ok",
  "service": "threatlens-api",
  "supabase_configured": false
}
```

`supabase_configured` indicates that the backend has a project URL and anon key
in its environment. It is not a remote availability check.

## Trust Passport registry

The active Trust Passport workflow is off-chain only. It stores a canonical
report and SHA-256 digest in Supabase, then re-hashes that saved snapshot during
verification. Public verification requires an owner-created, revocable,
unguessable share token and reveals integrity metadata only. No wallet, RPC,
contract, gas, or signing key is used. Solidity and blockchain code are not
part of this implementation.
