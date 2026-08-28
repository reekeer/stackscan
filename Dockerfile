# stackscan runner image — a panel worker that claims jobs, scans, and reports.
#
# Build:  docker build -t stackscan:latest .
# Tag:    docker tag stackscan:latest ghcr.io/reekeer/stackscan:v2.7.0
# Run:    docker run --rm -e STACKSCAN_RUNNER=1 \
#             -e STACKSCAN_BACKEND_URL=http://panel:8787 \
#             -e STACKSCAN_WORKER_TOKEN=... stackscan:latest
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STACKSCAN_RUNNER=1

WORKDIR /app

# nmap powers optional port scanning; keep it available even though the runner
# profile leaves ports off by default.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first for better layer caching, then the package itself.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[geo]"

# Non-root runtime.
RUN useradd --create-home --uid 10001 runner
USER runner

# STACKSCAN_RUNNER=1 makes the entrypoint select runner mode; extra flags
# (e.g. --backend, --batch) can still be appended.
ENTRYPOINT ["stackscan"]
CMD ["--runner"]
