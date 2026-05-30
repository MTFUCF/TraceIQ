# TraceIQ — Security Hardening Guide

Author: **Matthew Faber**

TraceIQ in its current form is a take-home **functional prototype**. It
makes deliberate trade-offs in favor of speed-of-demo over
production-grade security. This document is the inventory of those
trade-offs and the concrete steps to harden each one before any real
customer data touches the system.

For each item the **Current state** is what's deployed today; **Risk** is
the worst-case impact; **Hardening** is the concrete action.

---

## 🔴 Critical — must fix before any production use

### 1. Secrets are stored as Container App secrets, not Key Vault

- **Current state:** `foundry-key`, `db-url`, `jwt-secret`,
  `storage-conn`, `seed-admin-password` live as Container App secrets,
  passed in via `--parameters` at deploy time. They're encrypted at rest
  by Azure but visible to anyone with `Microsoft.App/containerApps/read`
  permission.
- **Risk:** Over-privileged developers or stolen RBAC roles → cleartext
  Foundry key, DB password, JWT signing secret.
- **Hardening:**
  1. Provision an Azure Key Vault in the resource group.
  2. Move all secret values into Key Vault.
  3. Reference each from the Container App as a Key Vault secret
     reference (already enabled in `infra/modules/core.bicep` via the
     `keyVaultUrl` syntax — just swap the bicep `secrets` block).
  4. Grant the user-assigned managed identity `Key Vault Secrets User`
     on the vault. Remove direct secret values from the bicep deploy.

### 2. PostgreSQL is publicly reachable (firewall allows all Azure)

- **Current state:** `AllowAzureServices` firewall rule (start `0.0.0.0`
  end `0.0.0.0`) — every Azure tenant can reach the port, only the
  password gates access.
- **Risk:** Online password spray attacks; collateral risk from any
  other Azure-resident attacker.
- **Hardening:**
  1. Enable **Private Endpoint** on the Flexible Server.
  2. Attach the Container Apps environment to a VNet (`workloadProfile`
     networking).
  3. Place Postgres + Blob + Key Vault on private endpoints in the same
     VNet. Disable public network access on all of them.

### 3. Storage account is connection-string auth

- **Current state:** `AZURE_STORAGE_CONNECTION_STRING` env var carries
  the account key. Anyone who can read the api Container App config can
  read/write the entire storage account.
- **Risk:** Stolen storage account → exfiltrate every uploaded log; the
  key has full data plane permissions.
- **Hardening:**
  1. Switch the api to `DefaultAzureCredential` from
     `@azure/identity` + `BlobServiceClient(url, credential)`.
  2. Grant the UAMI `Storage Blob Data Contributor` only on the `logs`
     container (not the whole account).
  3. Delete the storage account keys (`az storage account keys rotate`
     until both keys are unused, then `allowSharedKeyAccess: false`).

### 4. Postgres also uses password auth

- **Current state:** `DATABASE_URL` carries a username + password.
- **Risk:** Same as #3 — credential leakage exposes the DB.
- **Hardening:** Enable **Entra authentication** on the Flexible Server.
  Grant the UAMI an `aad_user` role with `LOGIN`. In code, use
  `pg.defaults` + `DefaultAzureCredential` to fetch an access token for
  every connection.

### 5. JWT secret is shared across all replicas, never rotated

- **Current state:** Single HS256 secret set at deploy. Token expiry is
  12 hours. No rotation, no revocation list.
- **Risk:** Secret leak → forge any user's session for 12h. Once stolen
  the only mitigation is rolling the secret (which invalidates EVERY
  live session).
- **Hardening:**
  1. Move JWT signing to **asymmetric** (RS256) with the private key in
     Key Vault, public key cached on the api.
  2. Add a `kid` (key id) header to enable rotation: api accepts two
     keys at a time during a rotation window.
  3. Add a `jti` (token id) blacklist in Postgres for revoked tokens.

---

## 🟠 High — fix before exposing to untrusted users

### 6. JWT lives in `localStorage` — XSS-vulnerable

- **Current state:** Frontend stores the token in `localStorage` and
  reads it on every request. Any XSS turns into a session-takeover.
- **Risk:** Any reflected/stored XSS = total compromise of the affected
  user (and admin access if they're the admin user).
- **Hardening:**
  1. Switch to an **httpOnly + Secure + SameSite=Strict** cookie set by
     the API on login.
  2. Add a CSRF token (double-submit cookie pattern) for mutating
     endpoints.
  3. Add a strict **Content Security Policy** (`script-src 'self'`,
     `connect-src 'self' https://api-url`, etc.) emitted by Next.js as a
     `next.config.js` `headers()` callback.

### 7. CORS is wide open

- **Current state:** `app.use(cors())` on the api (allows any origin).
  The api Container App's ingress also has `allowedOrigins: ['*']`.
- **Risk:** Once auth #6 is fixed (cookies), any site can attempt
  same-origin attacks because CORS allows them. Today the bearer token
  in localStorage isn't auto-sent, but #6 will change that.
- **Hardening:** Lock CORS to exactly the web origin:
  `origin: ['https://traceiq.matthew-faber.com']`.

### 8. No rate limiting

- **Current state:** `/auth/login` will accept unlimited attempts.
  `/uploads` will accept unlimited 25 MB POSTs.
- **Risk:** Credential stuffing on login; bandwidth-burning upload
  flood; potential bill amplification via Foundry token spend.
- **Hardening:**
  1. Add `express-rate-limit` to `/auth/login` (e.g., 10/min per IP).
  2. Add per-user upload quota (e.g., 100 MB/day) checked in the
     uploads route.
  3. Add a Foundry token budget check before each LLM call.
  4. In Azure: enable Front Door or App Gateway WAF in front of the web
     app to absorb volumetric attacks.

### 9. No registration / no password policy / no MFA

- **Current state:** Only a seeded admin user. Password is whatever was
  passed at deploy time. No complexity check, no lockout, no MFA.
- **Risk:** Operational — accounts can't be added without redeploying.
  Security — no defense beyond the single password.
- **Hardening:**
  1. Replace the in-DB user table with **Entra External ID (CIAM)** as
     the IdP. Use OIDC code flow from the web app.
  2. Make MFA mandatory in the Entra External ID tenant.
  3. Drop the `users` and `password_hash` tables entirely.

---

## 🟡 Medium — fix during normal hardening pass

### 10. No structured logging / no Application Insights

- **Current state:** `console.log` + Container Apps default stdout
  capture to Log Analytics. No correlation IDs, no per-request tracing,
  no Foundry token tracking.
- **Risk:** Limited visibility during an incident. Hard to attribute a
  bad request to a specific user.
- **Hardening:**
  1. Wire `@azure/monitor-opentelemetry` into both api and web.
  2. Tag every span with `userId`, `uploadId`, route, latency, token
     count (for Foundry calls).
  3. Add a 200ms-latency SLO dashboard in Azure Monitor.

### 11. No input validation on upload contents

- **Current state:** We accept any file up to 25 MB. The parser tolerates
  bad lines but doesn't reject suspicious input (very long lines,
  embedded shell metacharacters in `details`).
- **Risk:** Database bloat; dashboard XSS if `raw_line` is rendered
  unescaped anywhere. (Today it isn't, but watch this.)
- **Hardening:**
  1. Cap individual log line length (e.g., 64 KB) — drop oversized lines
     with an audit message.
  2. Strict file-extension check (`.log`, `.json`, `.ndjson`, `.txt`).
  3. Magic-byte sniff to reject obvious non-text uploads (PE headers,
     PDFs, etc.).

### 12. No row-level isolation on shared deployments

- **Current state:** Authorization is enforced by `WHERE user_id = $1`
  in every query. Correct but fragile — a missing WHERE clause in any
  new endpoint would leak across tenants.
- **Risk:** A future bug = total cross-tenant leak.
- **Hardening:** Enable Postgres **Row Level Security**. Add a
  `SET app.current_user_id = …` at the start of each connection (via
  `pool.on('connect')`) and `CREATE POLICY` on every table.

### 13. Schema runs on every container start

- **Current state:** `apps/api/src/index.ts` runs the schema +
  bcrypt-seeds the admin user on every container start. Idempotent, but
  spends a DB roundtrip per cold start, and seeds passwords from env
  vars.
- **Risk:** Concurrency — two replicas booting at the same time both
  run `INSERT` on first deploy; race resolves correctly (`ON CONFLICT
  DO NOTHING`-ish via existence check), but it's brittle.
- **Hardening:** Move migrations to a Container Apps **Job** that runs
  once per deploy. Web tier stops booting if it can't connect — let the
  job own DB schema.

### 14. Image tags are `:latest`

- **Current state:** ACR holds `traceiq-api:latest` and
  `traceiq-web:latest`. Each deploy overwrites the tag.
- **Risk:** Can't roll back by tag; can't audit which commit is running.
- **Hardening:** Tag every image with `:<git-sha>` (and optionally
  `:latest`). Use `--image $ACR/api:<sha>` in `az containerapp update`.

### 15. No retention policy on Blob storage

- **Current state:** Every uploaded file stays in `logs/` forever.
- **Risk:** Cost creep + GDPR / privacy headache (uploaded logs may
  contain personal data).
- **Hardening:** Add a Storage Lifecycle Management rule:
  `Move logs/* to cool after 30 days, delete after 365 days`.

---

## 🟢 Low — nice-to-haves

### 16. No SBOM / no vulnerability scanning on images

- **Hardening:** Add `docker scout cves` or **Microsoft Defender for
  Containers** to ACR. Block deploys on `High` CVEs.

### 17. No automated test coverage

- **Hardening:** Vitest for the parsers + detectors + correlator (pure
  functions, easy wins). Playwright for the dashboard + correlation
  flow. Gate `azd up` on `npm test`.

### 18. Logs contain user emails

- **Hardening:** Scrub `user_name`/`recipient`/`principal` in
  `console.log` calls before they hit Log Analytics. Use a logger
  middleware that hashes PII fields.

### 19. No CSP/HSTS/security headers

- **Hardening:** In `next.config.js` `headers()` callback:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### 20. CI uses a long-lived service principal

- **Current state:** `.github/workflows/deploy.yml` template uses OIDC
  federated credentials (already good). Make sure you actually used
  federated credentials and NOT a generated client secret when running
  `az ad sp create-for-rbac`.
- **Hardening:** Audit `az ad app federated-credential list` to confirm
  the only credential is a GitHub OIDC one — no client secrets.

---

## Quick win checklist (one-day hardening sprint)

If you only have a day before showing this to a real customer:

- [ ] **#1** — Move secrets to Key Vault (1h)
- [ ] **#3** — Switch Blob to managed identity (1h)
- [ ] **#6** — httpOnly cookies + CSRF (3h)
- [ ] **#7** — Lock CORS to the actual web origin (5 min)
- [ ] **#8** — Add `express-rate-limit` on `/auth/login` (15 min)
- [ ] **#14** — Image tagging with git sha (15 min)
- [ ] **#15** — Blob lifecycle rule, delete after 90 days (10 min)
- [ ] **#19** — Security headers via next.config.js (15 min)

The remaining items are essential for **multi-tenant production** but
can wait if this stays an internal demo.
