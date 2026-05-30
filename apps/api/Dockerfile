# Multi-stage Dockerfile for the loginsight API.
# Author: Matthew Faber
#
# Why multi-stage? Builder installs ALL deps (incl. dev) to compile TS -> JS.
# Runner is slim, with only production deps + the compiled output. This keeps
# the prod image small and removes tsx, @types/*, etc. from the attack surface.

# ---------- Builder ----------
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
COPY apps/api/package.json apps/api/

# Install the api workspace only (and its hoisted deps at root).
RUN npm install --workspace=@loginsight/api --include-workspace-root

COPY tsconfig.base.json ./
COPY apps/api ./apps/api
RUN npm run build --workspace=@loginsight/api

# ---------- Runner ----------
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json* ./
COPY apps/api/package.json apps/api/
RUN npm install --workspace=@loginsight/api --omit=dev --include-workspace-root

COPY --from=builder /app/apps/api/dist ./apps/api/dist

ENV PORT=4000
EXPOSE 4000

# Direct node invocation = proper signal handling for graceful shutdown.
CMD ["node", "apps/api/dist/index.js"]
