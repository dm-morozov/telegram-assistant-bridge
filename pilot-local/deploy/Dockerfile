ARG NODE_BASE
FROM ${NODE_BASE}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY pilot-local/package.json pilot-local/package-lock.json ./pilot-local/
RUN npm ci --prefix pilot-local --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY --chown=node:node pilot-local/pilot.mjs pilot-local/verifier.mjs pilot-local/jwks-snapshot.mjs pilot-local/http-pilot.mjs pilot-local/owner-config.mjs pilot-local/container-main.mjs pilot-local/bounded-deadline.mjs ./pilot-local/
USER node
CMD ["node", "pilot-local/container-main.mjs", "--container", "--owner-config", "/run/bridge-owner/owner.local.json", "--jwks-snapshot", "/run/bridge-jwks/jwks.snapshot.json"]
