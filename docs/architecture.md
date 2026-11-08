# THREATLENS architecture

## Application services

Browser and Next.js App Router
- Cookie-based Supabase Auth sessions
- Protected dashboard and profile routes
- Central FastAPI API client

FastAPI
- Supabase Auth bearer-token validation
- Request-scoped scan ownership dependency
- Supabase user-scoped and backend-admin clients

Supabase
- Auth users and profile-provisioning trigger
- PostgreSQL tables protected by Row Level Security
- Threat-indicator corpus restricted to backend access

## Authentication and authorization

- Signup, password login, reset requests, and password updates use Next.js Server Actions. Inputs are validated on the server.
- Supabase SSR clients store sessions in cookies. Next.js Proxy performs early route redirects; protected layouts independently verify claims.
- The /auth/callback route exchanges one-time PKCE codes before redirecting to a validated internal path.
- FastAPI validates access tokens against Supabase Auth. It never accepts a user ID from request input as proof of identity.
- Every scan-specific FastAPI route uses the require_scan_owner dependency. It queries scans using the verified user JWT; PostgreSQL RLS applies as a second ownership boundary.
- The backend-only get_supabase_admin_client function and scan persistence adapter require a backend-only secret key. Scan result writes and threat-indicator lookups never use a browser key.
- URL requests enter a bounded in-process queue with two workers. Jobs are not durable across backend restarts.
- Outbound HTTP connections use validated, pinned public IP addresses. Redirects are followed manually, each with a fresh DNS check. The scanner reads only bounded response headers.
- Trusted exact threat-indicator matches can confirm a malicious result only when the source is allowlisted and confidence meets the configured threshold. URL-pattern signals are never sufficient to confirm.

## Database controls

- Migration 20261107000000_threatlens_database.sql creates the seven Part 2 tables, constraints, indexes, auth profile trigger, RLS grants, and policies.
- Every public table has RLS enabled.
- End users can read only their own scan rows and associated findings, events, passports, and relationships. Relationships are visible only when both scans belong to the user.
- Users can update only their own profile. Profile rows are inserted by the Auth trigger.
- Scan result writes are reserved for trusted backend operations. Threat indicators have no grants for anon or authenticated.
- Migration 20261107000100_url_scan_risk_labels.sql adds the URL scanner classifications while preserving legacy values.
- Passport records contain a report hash and chain references; private user data and credentials are never placed on-chain.

The URL scanner UI polls authenticated API status and then loads the saved scan, findings, and chronological events. Message and QR analysis remain explicitly marked as preview-only.
