# syntax=docker/dockerfile:1
#
# cogos-api runtime image — security posture
# ------------------------------------------
# Runtime stage uses Google's distroless nodejs20 image:
#   - No shell (no /bin/sh, /bin/bash) — eliminates a whole class of
#     post-exploitation tradecraft (no `sh -c`, no curl pipe-to-shell).
#   - No package manager (no apk/apt) — attacker cannot install tools
#     in a compromised container.
#   - Runs as the built-in `nonroot` user (uid 65532), never root.
#   - Read-only-root-filesystem ready: only /app/data needs to be
#     writable, and it is intended to be a mounted volume in prod
#     (run with `--read-only --tmpfs /tmp -v cogos-data:/app/data`).
# The builder stage uses Microsoft's devcontainers Node image to avoid
# Docker Hub's unauthenticated pull rate limit, which is shared across
# all `az acr build` traffic and caused repeated deploy failures in
# May 2026. MCR has no rate limit on authenticated Azure builds.
# That stage is discarded and never reaches prod, so the size doesn't
# matter — only that it has npm + a shell to run `npm ci`.

FROM mcr.microsoft.com/devcontainers/javascript-node:20-bookworm AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev \
 && mkdir -p /app/data

FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app
COPY --from=deps --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=deps --chown=nonroot:nonroot /app/data ./data
COPY --chown=nonroot:nonroot src ./src
COPY --chown=nonroot:nonroot scripts ./scripts
COPY --chown=nonroot:nonroot package.json ./
ENV NODE_ENV=production \
    PORT=4444
EXPOSE 4444
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node","-e","require('http').get('http://127.0.0.1:4444/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
CMD ["src/index.js"]
