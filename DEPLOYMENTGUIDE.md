# TraceIQ — Deployment Guide

Author: **Matthew Faber**

This guide covers two paths: **local development** (Docker Compose) and
**production deployment to Azure**. Each is fully reproducible with no
hand-edits.

---

## 1. Local development

### Prerequisites

| Tool | Version | Why |
|---|---|---|
| Node.js | 22+ | Both apps run on Node 22 |
| npm | 10+ | npm workspaces |
| Docker Desktop | any recent | Postgres + Azurite (Blob emulator) |
| (optional) Azure AI Foundry endpoint + key | — | For AI narratives. Without it the app still works, narrative fields are empty |

### Steps

```bash
# 1. clone + install
git clone https://github.com/MTFUCF/traceiq.git
cd traceiq
npm install

# 2. local services
npm run db:up          # postgres on :5432, azurite on :10000

# 3. env
cp .env.example .env   # then fill AZURE_AI_FOUNDRY_* if you want AI

# 4. schema + seeded admin user
npm run -w @traceiq/api migrate

# 5. run both apps
npm run dev            # api on :4000, web on :3000
```

Open **http://localhost:3000**, sign in with the credentials from `.env`
(`admin@traceiq.local` / `ChangeMe123!` by default), upload a sample
from `samples/`, and click **🔗 Correlate** after uploading two or more.

### Stopping

```bash
npm run db:down        # also wipes the local volumes
```

---

## 2. Azure deployment

### Prerequisites

| Tool | Why |
|---|---|
| Azure CLI (`az`) | Resource provisioning + Container App updates |
| Bicep CLI | Compile `infra/main.bicep` → ARM JSON |
| Docker Desktop | Build images locally before pushing to ACR |
| (`azd` is optional) | The Azure Developer CLI works on most networks but its bicep download fails on restrictive corporate networks. The `az`-only path below always works. |

### 2.1 Authenticate

```bash
az login --tenant <YOUR_TENANT_GUID>
az account set --subscription <YOUR_SUBSCRIPTION_GUID>
```

### 2.2 Configure Azure AI Foundry

1. Portal → **Azure AI Foundry** → create a project (region: `eastus2`,
   `eastus`, or `westus3` — any region with `gpt-4o-mini` availability).
2. Inside the project: **Deployments → + Deploy model → gpt-4o-mini**.
3. Project → **Keys and endpoint** → copy the endpoint
   (`https://<project>.services.ai.azure.com/models`) and a key.

Keep these handy — you'll pass them to bicep as parameters.

### 2.3 Compile bicep

If the bicep CLI isn't installed:

```bash
# Option A: az tries to download
az bicep install

# Option B: direct download from GitHub releases (works on networks
# that block downloads.bicep.azure.com)
curl -L -o ~/.azure/bin/bicep.exe \
  https://github.com/Azure/bicep/releases/latest/download/bicep-win-x64.exe
```

Then compile:

```bash
bicep build infra/main.bicep --outfile infra/main.json
```

### 2.4 Provision infrastructure

> **Subscription region restriction:** Many Visual Studio Enterprise
> subscriptions have PostgreSQL Flexible Server restricted to specific
> regions. If your first `az deployment` returns `LocationIsOfferRestricted`,
> try a different `location` (we landed on `westus3`).

```bash
# Generate strong secrets
DB_PASS=$(openssl rand -base64 24)
JWT_SECRET=$(openssl rand -base64 32)
ADMIN_PASS=$(openssl rand -base64 16)

# Deploy at subscription scope (creates rg-traceiq-{env})
az deployment sub create \
  --name traceiq-001 \
  --location westus3 \
  --template-file infra/main.json \
  --parameters \
    appName=traceiq \
    environmentName=live \
    location=westus3 \
    dbAdminLogin=traceiqadmin \
    dbAdminPassword="$DB_PASS" \
    jwtSecret="$JWT_SECRET" \
    seedAdminEmail=admin@traceiq.local \
    seedAdminPassword="$ADMIN_PASS" \
    foundryEndpoint="https://<project>.services.ai.azure.com/models" \
    foundryApiKey="<key from step 2.2>" \
    foundryDeployment=gpt-4o-mini
```

Save the outputs:

```bash
az deployment sub show --name traceiq-001 \
  --query "properties.outputs" -o json
```

You'll get:
- `AZURE_RESOURCE_GROUP` → `rg-traceiq-live`
- `AZURE_CONTAINER_REGISTRY_ENDPOINT` → `acrtraceiq{suffix}.azurecr.io`
- `SERVICE_API_URI`, `SERVICE_WEB_URI`

### 2.5 Enable required Postgres extension

The schema uses `pgcrypto`. Flexible Server requires it to be explicitly
allowed:

```bash
RG=rg-traceiq-live
PG=$(az postgres flexible-server list -g $RG --query "[0].name" -o tsv)
az postgres flexible-server parameter set \
  -g $RG -s $PG \
  --name azure.extensions --value pgcrypto
```

### 2.6 Build + push images

```bash
ACR=acrtraceiq{suffix}.azurecr.io        # from outputs
ACR_NAME=acrtraceiq{suffix}              # without .azurecr.io
API_URL=https://ca-traceiq-api-{suffix}.{...}.azurecontainerapps.io

az acr login --name $ACR_NAME

# API
docker build -f apps/api/Dockerfile -t $ACR/traceiq-api:latest .
docker push $ACR/traceiq-api:latest

# Web — API URL is baked at build time
docker build -f apps/web/Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=$API_URL \
  -t $ACR/traceiq-web:latest .
docker push $ACR/traceiq-web:latest
```

### 2.7 Roll the Container Apps to the new images

```bash
az containerapp update -n ca-traceiq-api-{suffix} -g $RG \
  --image $ACR/traceiq-api:latest

az containerapp update -n ca-traceiq-web-{suffix} -g $RG \
  --image $ACR/traceiq-web:latest
```

Wait 30-60s for the new revision to come up. The API will run the schema
migration + seed admin user on first start.

### 2.8 Bind a custom domain (`traceiq.matthew-faber.com`)

```bash
WEB=ca-traceiq-web-{suffix}
ENV=cae-traceiq-{suffix}
HOST=traceiq.matthew-faber.com

# Get the DNS verification ID
VER_ID=$(az containerapp env show -n $ENV -g $RG \
  --query "properties.customDomainConfiguration.customDomainVerificationId" -o tsv)

# Get the FQDN your CNAME must point at
WEB_FQDN=$(az containerapp show -n $WEB -g $RG \
  --query "properties.configuration.ingress.fqdn" -o tsv)

echo "Add at your DNS host:"
echo "  CNAME  traceiq        -> $WEB_FQDN"
echo "  TXT    asuid.traceiq  -> $VER_ID"
```

Add those two records at your domain registrar. After ~5 minutes:

```bash
az containerapp hostname add  -n $WEB -g $RG --hostname $HOST
az containerapp hostname bind -n $WEB -g $RG --hostname $HOST \
  --environment $ENV --validation-method CNAME
```

A free Microsoft-managed TLS cert is provisioned and bound automatically.

### 2.9 First sign-in

URL: `https://traceiq.matthew-faber.com`
Email: `admin@traceiq.local`
Password: the `ADMIN_PASS` you generated in 2.4

To upload the "alice gets phished" demo, drop all three sample files in
`samples/sample-{email-phishing,endpoint-edr,cloud-azuread}.log` then
click **🔗 Correlate**.

---

## 3. Updating after a code change

```bash
# rebuild
docker build -f apps/api/Dockerfile -t $ACR/traceiq-api:latest .
docker push $ACR/traceiq-api:latest

# roll
az containerapp update -n ca-traceiq-api-{suffix} -g $RG \
  --image $ACR/traceiq-api:latest --revision-suffix $(date +%s)
```

The `--revision-suffix` forces a new revision even if the image tag
didn't change (`:latest` is reused).

---

## 4. Rotating the Foundry key

```bash
az containerapp secret set -n ca-traceiq-api-{suffix} -g $RG \
  --secrets foundry-key=<NEW_KEY>
# the secret is already referenced as AZURE_AI_FOUNDRY_API_KEY env var,
# but you need to roll a new revision so the env var picks up the new value:
az containerapp update -n ca-traceiq-api-{suffix} -g $RG \
  --revision-suffix rot$(date +%s)
```

---

## 5. Tear down

```bash
az group delete --name rg-traceiq-live --yes --no-wait
```

This deletes everything — Container Apps, Postgres, Blob, ACR, Log
Analytics. The custom domain and its DNS records at your registrar are
not affected; manually remove the CNAME + TXT if you don't plan to
redeploy.
