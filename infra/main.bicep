// =====================================================================
// loginsight — main Bicep entrypoint (subscription scope).
// Author: Matthew Faber
// =====================================================================
// This file is the single source of truth for everything `azd up` creates
// in Azure. We deploy at the subscription scope so we own the resource
// group itself — that makes `azd down` a clean teardown.
//
// What we provision:
//   - Resource group
//   - Log Analytics workspace      (Container Apps env requirement)
//   - Container Apps environment   (shared compute for api + web)
//   - Container Registry           (private image hosting)
//   - Azure Database for PostgreSQL Flexible Server (Burstable B1ms)
//   - Storage account + "logs" container (uploaded log files)
//   - Key Vault                    (secrets accessible via Managed Identity)
//   - User-assigned Managed Identity (granted on KV, ACR, Storage)
//   - Two Container Apps           (api + web) — created EMPTY at first;
//     `azd` then builds images, pushes them to ACR, and updates each app
//     to point at the new image tag.
//
// Why no Azure AI Foundry resources in here? Foundry projects are created
// in the Foundry portal (you choose region + project name + which models
// to deploy). The endpoint + key are passed in as parameters and stored
// as Container App secrets so the code can talk to them.
// =====================================================================
targetScope = 'subscription'

@description('Short app name; resource names are derived from this.')
param appName string = 'loginsight'

@description('Azure region for all resources.')
param location string = 'eastus2'

@description('Environment tag (e.g. dev, prod).')
param environmentName string = 'dev'

@description('PostgreSQL admin login name.')
param dbAdminLogin string = 'loginsightadmin'

@secure()
@description('PostgreSQL admin password. Generate a strong random value.')
param dbAdminPassword string

@secure()
@description('JWT signing secret. 32+ random characters.')
param jwtSecret string

@description('Email for the initial seeded admin user.')
param seedAdminEmail string = 'admin@loginsight.local'

@secure()
@description('Initial seeded admin password.')
param seedAdminPassword string

@description('Azure AI Foundry inference endpoint (from your Foundry project).')
param foundryEndpoint string = ''

@secure()
@description('Azure AI Foundry API key.')
param foundryApiKey string = ''

@description('Deployment name of the model inside your Foundry project.')
param foundryDeployment string = 'gpt-4o-mini'

// Deterministic suffix so repeated deploys reuse the same names.
var suffix = uniqueString(subscription().id, appName, environmentName)
var rgName = 'rg-${appName}-${environmentName}'

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: rgName
  location: location
  tags: {
    app: appName
    env: environmentName
    owner: 'Matthew Faber'
  }
}

module core 'modules/core.bicep' = {
  name: 'core'
  scope: rg
  params: {
    appName: appName
    location: location
    suffix: suffix
    dbAdminLogin: dbAdminLogin
    dbAdminPassword: dbAdminPassword
    jwtSecret: jwtSecret
    seedAdminEmail: seedAdminEmail
    seedAdminPassword: seedAdminPassword
    foundryEndpoint: foundryEndpoint
    foundryApiKey: foundryApiKey
    foundryDeployment: foundryDeployment
  }
}

output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_LOCATION string = location
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = core.outputs.acrLoginServer
output AZURE_CONTAINER_REGISTRY_NAME string = core.outputs.acrName
output SERVICE_API_NAME string = core.outputs.apiName
output SERVICE_WEB_NAME string = core.outputs.webName
output SERVICE_API_URI string = core.outputs.apiFqdn
output SERVICE_WEB_URI string = core.outputs.webFqdn
