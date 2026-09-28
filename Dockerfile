# TunnelScope public demo image (owner 2026-09-28, Railway). Analyses uploaded captures only: the server runs with
# TUNNELSCOPE_PUBLIC_DEMO=1, which refuses fixing, drafting, live capture and site views (tunnelscope/api/server.py).
# A normal install does not use this image; it runs `tunnelscope serve` on 127.0.0.1.

FROM node:22-slim AS dashboard
WORKDIR /src/fleet-dashboard
COPY fleet-dashboard/package.json fleet-dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY fleet-dashboard/ ./
RUN npm run build

FROM python:3.11-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# tshark reads the captures; no setuid capture group is needed (the demo never captures live)
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY tunnelscope/ tunnelscope/
RUN pip install --no-cache-dir .
COPY --from=dashboard /src/fleet-dashboard/dist /app/dashboard
RUN useradd --create-home --uid 10001 tunnelscope
USER tunnelscope
ENV TUNNELSCOPE_PUBLIC_DEMO=1 \
    TUNNELSCOPE_NETWORK=on \
    TUNNELSCOPE_DASHBOARD_DIR=/app/dashboard \
    PORT=8765
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health',timeout=4)"
CMD ["tunnelscope", "serve", "--no-browser"]
