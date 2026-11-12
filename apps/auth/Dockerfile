# syntax=docker/dockerfile:1
# Build with the repository root as context:
# docker build -f apps/auth/Dockerfile -t allauth-auth .
FROM node:22.22.3-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS build-input
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV NEXT_TELEMETRY_DISABLED=1
ENV TURBO_TELEMETRY_DISABLED=1
ENV LEFTHOOK=0
ENV AUTH_RUNTIME=node
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@11.1.1 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig*.json LICENSE.md ./
COPY patches ./patches
COPY packages ./packages
RUN pnpm install --frozen-lockfile --store-dir=/pnpm/store \
    --filter @better-auth/root \
    --filter better-auth... \
    --filter @better-auth/api-key... \
    --filter @better-auth/oauth-provider... \
    --filter @better-auth/passkey... \
    --filter @better-auth/scim... \
    --filter @better-auth/sso... \
    --filter @better-auth/i18n... \
    --filter @better-auth/cimd... \
    --filter @better-auth/stripe... \
    --filter @better-auth/mcp...
RUN pnpm exec turbo run build \
    --filter=better-auth... \
    --filter=@better-auth/api-key... \
    --filter=@better-auth/oauth-provider... \
    --filter=@better-auth/passkey... \
    --filter=@better-auth/scim... \
    --filter=@better-auth/sso... \
    --filter=@better-auth/i18n... \
    --filter=@better-auth/cimd... \
    --filter=@better-auth/stripe... \
    --filter=@better-auth/mcp...

COPY apps/auth/package.json apps/auth/pnpm-lock.yaml apps/auth/pnpm-workspace.yaml ./apps/auth/
COPY apps/auth/patches ./apps/auth/patches
WORKDIR /app/apps/auth
RUN pnpm install --frozen-lockfile --store-dir=/pnpm/store
COPY apps/auth ./

FROM build-input AS build
# Runtime variables are read by dynamic server routes, never passed to this build.
RUN NODE_OPTIONS=--max-old-space-size=4096 pnpm run build
RUN pnpm --dir /app/packages/better-auth exec tsdown --config /app/apps/auth/scripts/avatar-cleanup.build.mjs
RUN pnpm --dir /app/packages/better-auth exec tsdown --config /app/apps/auth/scripts/self-host-bootstrap.build.mjs

FROM build-input AS rehearsal-build
RUN cp scripts/rehearsal/project-engine-selection.ts lib/projects/project-engine-rehearsal-selection.ts
RUN NODE_OPTIONS=--max-old-space-size=4096 pnpm run build

FROM node:22.22.3-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS runtime-base
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV AUTH_RUNTIME=node
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
WORKDIR /app/apps/auth

COPY --from=build-input --chown=node:node /app/apps/auth/public ./public
COPY --from=build-input --chown=node:node /app/apps/auth/migrations ./migrations
COPY --from=build-input --chown=node:node /app/apps/auth/scripts/database.mjs ./scripts/database.mjs
COPY --from=build-input --chown=node:node /app/LICENSE.md /app/LICENSE.md
USER node
EXPOSE 3000
CMD ["node", "server.js"]

# This target is only for disposable project-engine rehearsals.
FROM runtime-base AS project-engine-rehearsal
COPY --from=rehearsal-build --chown=node:node /app/apps/auth/.next/standalone /app/
COPY --from=rehearsal-build --chown=node:node /app/apps/auth/.next/static ./.next/static

FROM runtime-base AS runtime
# Preserve the tracing root so links to the official package tree stay valid.
COPY --from=build --chown=node:node /app/apps/auth/.next/standalone /app/
COPY --from=build --chown=node:node /app/apps/auth/.next/static ./.next/static
COPY --from=build --chown=node:node /app/apps/auth/.next/avatar-cleanup ./scripts/avatar-cleanup
COPY --from=build --chown=node:node /app/apps/auth/.next/self-host ./scripts/self-host
