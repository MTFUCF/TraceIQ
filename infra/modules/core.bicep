// =====================================================================
// traceiq — core resources (resource-group scope).
// Author: Matthew Faber
// =====================================================================
// Everything in this module deploys into the resource group created by
// main.bicep. Kept as a single module (not micro-modules) so a reader can
// trace the topology top-to-bottom without jumping files.
// =====================================================================
targetScope = 'resourceGroup'

param appName string
param location string
param suffix string
param dbAdminLogin string
@secure()
param dbAdminPassword string
@secure()
param jwtSecret string
param seedAdminEmail string
@secure()
param seedAdminPassword string
param foundryEndpoint string
@secure()
param foundryApiKey string
param foundryDeployment string

var tags = { app: appName, owner: 'Matthew Faber' }

// =========================
// Identity (UAMI)
// =========================
// One identity attached to both Container Apps and granted on KV, ACR, and
// Storage. Container Apps will use it to pull images and read secrets.
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${appName}-${suffix}'
  location: location
  tags: tags
}

// =========================
// Log Analytics
// =========================
resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${appName}-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// =========================
// Container Registry
// =========================
// Basic SKU is cheapest and plenty for two images.
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: 'acr${appName}${suffix}'
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
  }
}

// AcrPull for the UAMI so Container Apps can pull images without admin creds.
resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, uami.id, 'AcrPull')
  scope: acr
  properties: {
    principalId: uami.properties.principalId
    principalType: 'ServicePrincipal'
    // AcrPull
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '7f951dda-4ed3-4680-a7ca-43fe172d538d'
    )
  }
}

// =========================
// Storage (uploaded logs)
// =========================
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st${appName}${suffix}'
  location: location
  tags: tags
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource logsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'logs'
}

// =========================
// PostgreSQL Flexible Server
// =========================
// Smallest tier — Burstable B1ms — costs ~$15/mo and fits this workload.
resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: 'pg-${appName}-${suffix}'
  location: location
  tags: tags
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: dbAdminLogin
    administratorLoginPassword: dbAdminPassword
    storage: { storageSizeGB: 32 }
    backup: { backupRetentionDays: 7, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    network: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// Allow all Azure services (incl. Container Apps egress IPs) to reach the DB.
// For a take-home this is fine; production would use a private endpoint.
resource pgFwAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: pg
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

resource pgDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: pg
  name: 'traceiq'
  properties: { charset: 'UTF8', collation: 'en_US.utf8' }
}

// =========================
// Container Apps environment
// =========================
resource cae 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${appName}-${suffix}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
  }
}

// =========================
// Connection strings
// =========================
var dbConn = 'postgresql://${dbAdminLogin}:${dbAdminPassword}@${pg.properties.fullyQualifiedDomainName}:5432/traceiq?sslmode=require'
var storageConn = 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${storage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'

// =========================
// Container App: API
// =========================
resource apiApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-${appName}-api-${suffix}'
  location: location
  tags: union(tags, { 'azd-service-name': 'api' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${uami.id}': {} }
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 4000
        transport: 'auto'
        corsPolicy: {
          allowedOrigins: [ '*' ]
          allowedMethods: [ 'GET', 'POST', 'DELETE', 'OPTIONS' ]
          allowedHeaders: [ '*' ]
        }
      }
      registries: [
        { server: acr.properties.loginServer, identity: uami.id }
      ]
      secrets: [
        { name: 'db-url', value: dbConn }
        { name: 'jwt-secret', value: jwtSecret }
        { name: 'storage-conn', value: storageConn }
        { name: 'seed-admin-password', value: seedAdminPassword }
        { name: 'foundry-key', value: empty(foundryApiKey) ? 'unset' : foundryApiKey }
      ]
    }
    template: {
      // azd swaps in the real built image on first deploy. The placeholder
      // here lets the resource provision in a single pass.
      containers: [
        {
          name: 'api'
          image: 'mcr.microsoft.com/k8se/quickstart:latest'
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'NODE_ENV', value: 'production' }
            { name: 'PORT', value: '4000' }
            { name: 'DATABASE_URL', secretRef: 'db-url' }
            { name: 'JWT_SECRET', secretRef: 'jwt-secret' }
            { name: 'AZURE_STORAGE_CONNECTION_STRING', secretRef: 'storage-conn' }
            { name: 'AZURE_STORAGE_CONTAINER', value: 'logs' }
            { name: 'SEED_ADMIN_EMAIL', value: seedAdminEmail }
            { name: 'SEED_ADMIN_PASSWORD', secretRef: 'seed-admin-password' }
            { name: 'AZURE_AI_FOUNDRY_ENDPOINT', value: foundryEndpoint }
            { name: 'AZURE_AI_FOUNDRY_API_KEY', secretRef: 'foundry-key' }
            { name: 'AZURE_AI_FOUNDRY_DEPLOYMENT', value: foundryDeployment }
          ]
        }
      ]
      scale: { minReplicas: 0, maxReplicas: 2 }
    }
  }
  dependsOn: [ acrPullRole ]
}

// =========================
// Container App: WEB
// =========================
resource webApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-${appName}-web-${suffix}'
  location: location
  tags: union(tags, { 'azd-service-name': 'web' })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${uami.id}': {} }
  }
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
      }
      registries: [
        { server: acr.properties.loginServer, identity: uami.id }
      ]
    }
    template: {
      containers: [
        {
          name: 'web'
          image: 'mcr.microsoft.com/k8se/quickstart:latest'
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: [
            { name: 'NODE_ENV', value: 'production' }
            { name: 'PORT', value: '3000' }
            // Note: NEXT_PUBLIC_API_URL is baked at image build time. azd
            // passes it as a Docker build-arg from main.parameters.json or
            // the environment, so the API URL is already in the JS bundle.
          ]
        }
      ]
      scale: { minReplicas: 0, maxReplicas: 2 }
    }
  }
  dependsOn: [ acrPullRole ]
}

output acrLoginServer string = acr.properties.loginServer
output acrName string = acr.name
output apiName string = apiApp.name
output webName string = webApp.name
output apiFqdn string = 'https://${apiApp.properties.configuration.ingress.fqdn}'
output webFqdn string = 'https://${webApp.properties.configuration.ingress.fqdn}'
