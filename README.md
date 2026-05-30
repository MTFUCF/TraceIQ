# loginsight

**A SOC log analysis platform: upload web proxy logs, get a triage-ready dashboard with statistical + AI-powered anomaly detection.**

Author: **Matthew Faber**
Stack: Next.js 15 + Express + PostgreSQL + Azure Container Apps + Azure AI Foundry
Live demo: *(filled in after first deploy — `https://loginsight.matthew-faber.com`)*

---

## Table of contents

1. [What this is](#what-this-is)
2. [Architecture](#architecture)
3. [Repository layout](#repository-layout)
4. [Local setup](#local-setup)
5. [Sample data](#sample-data)
6. [How anomaly detection works](#how-anomaly-detection-works)
7. [Where AI is used (Azure AI Foundry)](#where-ai-is-used-azure-ai-foundry)
8. [API reference](#api-reference)
9. [Database schema](#database-schema)
10. [Deploying to Azure](#deploying-to-azure)
11. [Custom domain (matthew-faber.com)](#custom-domain-matthew-fabercom)
12. [CI/CD](#cicd)
13. [Trade-offs and things I'd change for production](#trade-offs-and-things-id-change-for-production)

---

## What this is

loginsight is a small full-stack app that helps a tier-1 SOC analyst triage a
proxy log file in **minutes instead of hours**. The user signs in, uploads a
ZScaler-style JSON-Lines log file, and gets:

- **Summary stats** — total / allowed / blocked / unique IPs / unique users.
- **Per-minute event timeline** with anomalies overlaid in red.
- **Top talkers** — most active client IPs and target hosts.
- **Anomaly panel** — each flagged event with rule, reason, confidence,
  severity, and (for the top 5) an LLM-written analyst narrative.
- **Events table** — first 500 events with a "show only anomalies" toggle.

The goal of the take-home is **functional**, not production-grade: I've
deliberately picked the smallest possible component for each role so the
whole system fits in a couple of files per concern and can be explained
end-to-end in a 60-minute interview.

## Architecture

```
                     ┌────────────────────────────────────────────┐
                     │              browser (you)                 │
                     └────────────────────────────────────────────┘
                                  │ HTTPS + JWT
                                  ▼
        ┌─────────────────────────────────────────────────────────┐
        │   Container App: web   (Next.js 15, port 3000)          │
        │   - login / dashboard / analysis pages                  │
        │   - Recharts visualisations                             │
        └──────────────────┬──────────────────────────────────────┘
                           │ fetch (NEXT_PUBLIC_API_URL)
                           ▼
        ┌─────────────────────────────────────────────────────────┐
        │   Container App: api   (Express + TS, port 4000)        │
        │   - /auth/login, /uploads, /uploads/:id/*               │
        │   - Parser, anomaly detector, Foundry enrichment        │
        └─┬──────────────┬──────────────┬──────────────┬──────────┘
          │              │              │              │
          ▼              ▼              ▼              ▼
   ┌─────────────┐ ┌───────────┐ ┌──────────────┐ ┌──────────────┐
   │ PostgreSQL  │ │ Blob (logs│ │ Azure AI     │ │ Key Vault    │
   │ Flexible    │ │ container)│ │ Foundry      │ │ (secrets via │
   │ Server B1ms │ │           │ │ gpt-4o-mini  │ │ Managed Id.) │
   └─────────────┘ └───────────┘ └──────────────┘ └──────────────┘
```

The two services are independent Docker images deployed to the same Azure
Container Apps environment. They share an Azure Container Registry and a
user-assigned managed identity (used for `AcrPull` and Key Vault reads).

## Repository layout

```
loginsight/
├── apps/
│   ├── api/                 # Express + TS REST API
│   │   ├── src/
│   │   │   ├── config.ts            # validated env-var loader
│   │   │   ├── db/
│   │   │   │   ├── client.ts        # pg pool
│   │   │   │   ├── schema.sql       # tables (users, uploads, events, anomalies)
│   │   │   │   └── migrate.ts       # idempotent schema runner + admin seed
│   │   │   ├── middleware/auth.ts   # JWT verify, signing
│   │   │   ├── routes/
│   │   │   │   ├── auth.ts          # POST /auth/login, GET /auth/me
│   │   │   │   └── uploads.ts       # upload + parse + analyze + queries
│   │   │   ├── services/
│   │   │   │   ├── storage.ts       # Azure Blob wrapper
│   │   │   │   ├── parser.ts        # ZScaler JSON-Lines parser
│   │   │   │   ├── anomaly.ts       # 5 deterministic detection rules
│   │   │   │   └── foundry.ts       # Azure AI Foundry enrichment
│   │   │   └── index.ts             # Express bootstrap + inline migrations
│   │   └── Dockerfile
│   └── web/                  # Next.js 15 (App Router) frontend
│       ├── src/
│       │   ├── app/
│       │   │   ├── layout.tsx       # global shell
│       │   │   ├── login/page.tsx
│       │   │   ├── dashboard/page.tsx
│       │   │   └── analysis/[id]/page.tsx   # timeline + anomalies + table
│       │   ├── components/AuthGate.tsx
│       │   └── lib/api.ts            # typed fetch wrapper
│       └── Dockerfile
├── infra/
│   ├── main.bicep            # subscription-scope entry
│   ├── modules/core.bicep    # RG, ACR, Postgres, Storage, KV, ACA env, apps
│   └── main.parameters.json
├── samples/
│   ├── generate.js
│   ├── sample-benign.log     # ~300 normal events
│   └── sample-suspicious.log # ~400 events with planted anomalies (all rules)
├── azure.yaml                # azd config (services -> Container Apps)
├── docker-compose.yml        # local Postgres + Azurite
├── package.json              # npm workspaces root
└── README.md
```

## Local setup

### Prerequisites
- **Node 22+** and **npm 10+**
- **Docker** (for the local Postgres + Azurite)
- *(Optional, for deploy)* **Azure CLI** + **Azure Developer CLI (azd)**

### Steps

```bash
# 1. Install all workspaces
npm install

# 2. Start Postgres + Azurite locally
npm run db:up
# (waits ~5s for Postgres to be ready)

# 3. Copy env template (you can leave Foundry blank locally — the LLM
#    enrichment step will be silently skipped if the keys aren't set)
cp .env.example .env

# 4. Run the schema migration + seed the admin user
npm run -w @loginsight/api migrate

# 5. Start both apps in dev mode
npm run dev
```

Open **http://localhost:3000** and sign in with the credentials from `.env`
(`admin@loginsight.local` / `ChangeMe123!` by default). Upload one of the
files from `samples/` to exercise the full pipeline.

### Stopping
```bash
npm run db:down
```

## Sample data

The `samples/` folder contains two pre-generated files:

| File | Events | Purpose |
|---|---|---|
| `sample-benign.log`     | ~300 | Boring, normal traffic. Anomaly count should be 0–1. |
| `sample-suspicious.log` | ~400 | Same baseline plus planted attacks that trigger **every** rule (burst, high-block-ratio probing, malware category, rare scanner UA, large data exfil). |

Re-generate them anytime with `node samples/generate.js`.

## How anomaly detection works

The detector lives in [`apps/api/src/services/anomaly.ts`](apps/api/src/services/anomaly.ts).
It's a **deterministic rules engine** that runs five checks. Each emits an
`Anomaly` with a rule id, a human-readable `reason`, a `confidence` in
`[0,1]`, and a `severity` of `low | medium | high`.

| ID | Rule                | What it flags                                                                                          |
|----|---------------------|---------------------------------------------------------------------------------------------------------|
| R1 | `burst_from_ip`     | One client IP whose request count in a single minute is > 3 standard deviations above its own baseline and ≥ 20 requests. Catches port-scanning bots, credential stuffing, scrapers. |
| R2 | `high_block_ratio`  | A client IP with ≥ 10 requests and ≥ 50% of them blocked. Suggests a compromised host or someone probing policy boundaries. |
| R3 | `malicious_category`| Any request whose ZScaler `urlcategory` is in `{Malware, Phishing, Botnet, Spyware, C2, ...}`. |
| R4 | `rare_user_agent`   | A User-Agent string that appears exactly once in the file *and* the request returned 4xx/5xx. Pattern for bespoke scanners (`sqlmap`, `nikto`, custom implants). |
| R5 | `large_exfil`       | Any single request with `bytesout ≥ 10 MB`. Possible data exfiltration. |

### Why rules first, AI second?
- **Explainability.** A SOC analyst can act on "IP X made 60 requests in 1
  minute (baseline 12)". They cannot act on "the model thinks it's bad".
- **Determinism.** Same file in, same anomalies out. Easy to test; easy to
  demo; auditable.
- **Cost & latency.** Rules run over the whole file in milliseconds with no
  external calls. We only spend LLM tokens on the **top 5** by confidence.
- **Bounded blast radius.** If the LLM API is down or misconfigured, the
  app still returns full results — the AI explanation field is just
  `null`. The detector NEVER blocks on Foundry.

## Where AI is used (Azure AI Foundry)

There is exactly **one** AI touchpoint in loginsight:
[`apps/api/src/services/foundry.ts`](apps/api/src/services/foundry.ts) —
the function `enrichTopAnomalies` takes the top 5 anomalies (by
confidence) and asks a model to write a 2-3 sentence analyst narrative for
each one: what likely happened, what to check next, and how severe it is.

### Why Azure AI Foundry (and not direct Azure OpenAI)?

Azure AI Foundry is Microsoft's unified model platform. A Foundry **project**
gives you:

- **One endpoint, many models.** The same `@azure-rest/ai-inference` SDK
  talks to OpenAI, Phi, Llama, Mistral, etc. — swapping models is a config
  change (`AZURE_AI_FOUNDRY_DEPLOYMENT`), not a code change.
- **Project-level governance.** Quota, content safety, evaluation, and
  observability are scoped to the project rather than to one model.
- **Future-proof.** As Microsoft adds new model families to Foundry,
  loginsight can switch with zero refactor.

We deploy **`gpt-4o-mini`** inside the Foundry project because it's fast,
cheap, and the outputs we need are short and structured.

### How the call is shaped

The prompt template (also see comments in `foundry.ts`):

```
SYSTEM:
You are a SOC analyst assistant. Given a structured anomaly detected in a
web proxy log, write a 2-3 sentence narrative for a tier-1 analyst. Cover:
(1) what the activity looks like, (2) what threat it could indicate,
(3) one concrete next step. Be concise, factual, and avoid jargon the
analyst already knows.

USER:
Anomaly:
{ "rule": "...", "severity": "...", "confidence": 0.92,
  "reason": "...", "metadata": { ... } }
Write the analyst narrative now.
```

Parameters: `temperature: 0.2` (we want stable wording), `max_tokens: 220`
(enough for 3 sentences, capped for cost).

### How to set up Foundry for loginsight

1. In the Azure portal, go to **Azure AI Foundry** → create a project (or
   reuse one). Pick a region with model availability (e.g. `eastus2`).
2. Inside the project, **Deployments → + Deploy model → gpt-4o-mini**. Give
   it a deployment name like `gpt-4o-mini`.
3. **Project settings → Keys and endpoint** → copy:
   - Endpoint (looks like `https://<project>.services.ai.azure.com/models`)
   - Key
4. Put them in your `.env` (locally) and in azd env vars (Azure):
   ```
   AZURE_AI_FOUNDRY_ENDPOINT=https://<project>.services.ai.azure.com/models
   AZURE_AI_FOUNDRY_API_KEY=<key>
   AZURE_AI_FOUNDRY_DEPLOYMENT=gpt-4o-mini
   ```

If you skip this step, loginsight still works — every anomaly still gets
a rule-based reason and confidence; only the AI narrative field will be
empty.

## API reference

All requests require `Authorization: Bearer <token>` except `POST /auth/login`.

| Method | Path                          | Description                                  |
|--------|-------------------------------|----------------------------------------------|
| POST   | `/auth/login`                 | `{ email, password }` → `{ token, user }`   |
| GET    | `/auth/me`                    | Current user                                 |
| POST   | `/uploads`                    | `multipart` `file` → parsed + analyzed       |
| GET    | `/uploads`                    | List the user's uploads                      |
| GET    | `/uploads/:id`                | Metadata + summary stats + top IPs / hosts   |
| GET    | `/uploads/:id/events`         | Paginated events (`?limit&offset`)           |
| GET    | `/uploads/:id/anomalies`      | All anomalies for the upload                 |
| GET    | `/uploads/:id/timeline`       | Per-minute buckets for the chart             |
| DELETE | `/uploads/:id`                | Delete upload + cascade events / anomalies   |
| GET    | `/health`                     | Liveness probe                               |

## Database schema

Four tables. See [`apps/api/src/db/schema.sql`](apps/api/src/db/schema.sql).

- **`users`** — id, email (unique), password_hash (bcrypt), created_at.
- **`uploads`** — id, user_id (FK), filename, blob_path, size_bytes,
  status (`pending|parsing|analyzing|done|error`), error, event_count,
  anomaly_count, created_at, completed_at.
- **`events`** — id (bigserial), upload_id (FK), line_number, occurred_at,
  user_name, client_ip, action, url, host, url_category, status_code,
  bytes_out, bytes_in, user_agent, raw_line.
- **`anomalies`** — id (bigserial), upload_id (FK), event_id (FK, nullable),
  rule, reason, confidence, severity, ai_explanation (nullable), metadata
  (jsonb).

Indexed on the columns you actually query: `(upload_id)`,
`(upload_id, occurred_at)`, `(upload_id, client_ip)`.

## Deploying to Azure

You'll need: an Azure subscription, **Azure CLI**, **Azure Developer CLI
(`azd`)**, and **Docker** (`azd` builds the images locally).

```bash
# 1. Authenticate
az login --tenant 549e0345-48a7-474e-9f8b-48610087dcac
az account set --subscription c152612b-c239-4f41-9ca4-7ffc733084da
azd auth login

# 2. Initialise an azd environment in this repo
azd env new loginsight-dev
azd env set AZURE_LOCATION eastus2
azd env set AZURE_AI_FOUNDRY_ENDPOINT "https://<project>.services.ai.azure.com/models"
azd env set AZURE_AI_FOUNDRY_API_KEY "<key>"
azd env set AZURE_AI_FOUNDRY_DEPLOYMENT "gpt-4o-mini"

# Strong random passwords / secrets
azd env set DB_ADMIN_PASSWORD       "$(openssl rand -base64 24)"
azd env set JWT_SECRET              "$(openssl rand -base64 32)"
azd env set SEED_ADMIN_PASSWORD     "$(openssl rand -base64 16)"

# 3. Provision + build + deploy
azd up
```

When `azd up` finishes it prints the URLs:
```
SERVICE_WEB_URI: https://ca-loginsight-web-xxxxx.<region>.azurecontainerapps.io
SERVICE_API_URI: https://ca-loginsight-api-xxxxx.<region>.azurecontainerapps.io
```

> **One caveat:** because `NEXT_PUBLIC_API_URL` is baked into the web build
> at image-build time, the first `azd up` defaults to `http://localhost:4000`.
> After the first deploy, grab the API URL, set `NEXT_PUBLIC_API_URL` in
> your azd env, then re-run `azd deploy web` so the web image is rebuilt
> against the right API origin. (For production you'd put both apps behind
> a single domain and a reverse proxy and avoid this dance.)

## Custom domain (matthew-faber.com)

Once `azd up` is done, bind a subdomain:

```bash
# Grab the FQDN of the web app
WEB_FQDN=$(az containerapp show -n ca-loginsight-web-<suffix> -g rg-loginsight-dev \
  --query "properties.configuration.ingress.fqdn" -o tsv)

# Add these two records at your DNS host for matthew-faber.com:
#   CNAME  loginsight  -> $WEB_FQDN
#   TXT    asuid.loginsight -> <verification id from the next command>
az containerapp hostname add \
  --name ca-loginsight-web-<suffix> \
  --resource-group rg-loginsight-dev \
  --hostname loginsight.matthew-faber.com

# Then issue + bind a free managed certificate:
az containerapp hostname bind \
  --name ca-loginsight-web-<suffix> \
  --resource-group rg-loginsight-dev \
  --hostname loginsight.matthew-faber.com \
  --environment cae-loginsight-<suffix> \
  --validation-method CNAME
```

After ~5 minutes, `https://loginsight.matthew-faber.com` will resolve with
a valid Microsoft-managed TLS certificate.

## CI/CD

`.github/workflows/deploy.yml` does a `azd deploy` on every push to `main`
using OIDC federated credentials (no long-lived secrets). To enable:

1. Create a service principal with federated credentials for the repo:
   ```
   az ad sp create-for-rbac --name loginsight-ci \
     --role contributor \
     --scopes /subscriptions/c152612b-c239-4f41-9ca4-7ffc733084da
   ```
2. Add three GitHub Actions secrets:
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`     (`549e0345-48a7-474e-9f8b-48610087dcac`)
   - `AZURE_SUBSCRIPTION_ID` (`c152612b-c239-4f41-9ca4-7ffc733084da`)

## Trade-offs and things I'd change for production

This is a deliberately small functional prototype. If we were taking it to
production, these are the next things I'd do, in order:

1. **Asynchronous processing.** Upload returns immediately; a worker
   (Azure Functions or a Container Apps Job) does the parse + analyze.
   The UI polls for status.
2. **Streaming parser.** Right now we load the whole file into memory.
   Replace with `readline` + per-line insert to handle multi-GB uploads.
3. **Move from key-based to Managed-Identity auth** for Postgres, Blob,
   and Foundry. Container Apps already has the UAMI — wire it through.
4. **httpOnly cookies + CSRF tokens** instead of `localStorage` JWT
   (mitigates XSS).
5. **Private endpoints + VNet integration** for Postgres and Blob
   (currently `AllowAzureServices`).
6. **Bigger anomaly toolkit** — periodic beaconing detection, DGA domain
   detection, JA3/JA4 fingerprint clustering, user-baseline learning.
7. **Foundry observability** — wire Application Insights into the
   Container Apps so token usage and latency are visible.
8. **Tests.** Vitest for the parser + detector (pure functions, easy
   wins), Playwright for the dashboard.

---

**Author:** Matthew Faber
**Submission contact:** `venkata@tenex.ai`
