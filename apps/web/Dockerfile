# Build for the loginsight Next.js frontend.
# Author: Matthew Faber
#
# We use Next.js's `output: "standalone"` mode (configured in next.config.js).
# That mode emits .next/standalone which contains a tiny server.js plus only
# the node_modules actually needed at runtime. The resulting image is small
# (~150 MB vs ~600 MB for a full node_modules copy).
#
# The API URL is baked in at build time because Next.js inlines
# NEXT_PUBLIC_* variables. We pass it as a build-arg so the same Dockerfile
# is reused across local/dev/prod.

# ---------- Builder ----------
FROM node:22-alpine AS builder
WORKDIR /app

ARG NEXT_PUBLIC_API_URL=http://localhost:4000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

COPY package.json package-lock.json* ./
COPY apps/web/package.json apps/web/
RUN npm install --workspace=@loginsight/web --include-workspace-root

COPY tsconfig.base.json ./
COPY apps/web ./apps/web
RUN npm run build --workspace=@loginsight/web

# ---------- Runner ----------
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# The standalone output bundles its own server.js + minimal deps.
COPY --from=builder /app/apps/web/.next/standalone ./
COPY --from=builder /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder /app/apps/web/public ./apps/web/public

EXPOSE 3000
CMD ["node", "apps/web/server.js"]
