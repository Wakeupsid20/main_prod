# This image contains the verifier and public proving artifacts, never holder secrets.
FROM node:24-bookworm-slim AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY frontend ./frontend
COPY scripts ./scripts
COPY index.html ./
COPY build/session/manifest.json ./build/session/manifest.json
COPY build/session/final.zkey ./build/session/final.zkey
COPY build/session/verification_key.json ./build/session/verification_key.json
COPY build/session/auth_session_js/auth_session.wasm ./build/session/auth_session_js/auth_session.wasm
RUN npm run build:cloud && npm prune --omit=dev

FROM python:3.11-slim-bookworm
COPY --from=web /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY requirements-cloud.txt ./
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements-cloud.txt
COPY --from=web /app/node_modules ./node_modules
COPY --from=web /app/dist ./dist
COPY --from=web /app/build/session ./build/session
COPY backend ./backend
COPY zk.cjs auth_session.circom ./
COPY scripts/cloud-entrypoint.py ./scripts/cloud-entrypoint.py
RUN useradd --create-home --uid 10001 veil && mkdir /var/data && chown veil:veil /var/data
ENV ZKP_CLOUD=1 ZKP_DB=/var/data/registry.db PORT=10000 PYTHONUNBUFFERED=1
EXPOSE 10000
# One process owns the SQLite volume. Do not horizontally scale this service.
CMD ["python", "scripts/cloud-entrypoint.py"]
