ARG NODE_BASE=node:24-bookworm-slim
FROM ${NODE_BASE}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY --chown=node:node src ./src
USER node
CMD ["node", "src/main.mjs", "--container"]
