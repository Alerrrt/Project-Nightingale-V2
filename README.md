## Project Nightingale V2 — Security Scanner

A modern web security scanning platform with robust concurrency, safe HTTP policies, and real-time updates.

### Highlights

- Scanners run concurrently with adaptive limits and circuit breakers
- Shared HTTP client with retries, exponential backoff + jitter, per‑host throttling, optional SSRF guard, host allow/deny lists, and response size caps
- Structured logging and runtime metrics (HTTP and concurrency) exposed via API
- Snapshotting and partial results for resilience
- FastAPI backend with WebSocket updates; React + Tailwind frontend

### Quick start (Docker)

1) From repo root:
```bash
docker compose up --build
```

2) Backend API: `http://localhost:9000`
- Docs: `http://localhost:9000/docs`
- Health: `GET /health`
- Scans: `POST /api/scans/start`, `GET /api/scans/{scan_id}`
- Metrics: `GET /api/metrics/http-client`, `GET /api/metrics/concurrency`

3) Frontend: `http://localhost:3002`

### Local dev (backend)

```bash
python -m venv .venv
. .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 9000 --reload
```

### Core APIs

- Start scan
```bash
curl -sX POST http://localhost:9000/api/scans/start \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.com","scan_type":"full","options":{}}'
```

- Scan status
```bash
curl -s http://localhost:9000/api/scans/{scan_id}
```

- Results (compact)
```bash
curl -s http://localhost:9000/api/scans/{scan_id}/results
```

- Reports
```bash
curl -s http://localhost:9000/api/reports/scans/{scan_id}/results
```

### Network safety and HTTP resilience

Environment variables (set in `.env` or docker‑compose):
- `BLOCK_PRIVATE_NETWORKS` (bool): block private/loopback by default
- `HTTP_MAX_RETRIES` (int), `HTTP_BACKOFF_BASE_SECONDS` (float), `HTTP_BACKOFF_MAX_SECONDS` (float)
- `HTTP_PER_HOST_MIN_INTERVAL_MS` (int): min interval between requests to same host
- `HTTP_ALLOWED_HOSTS` (list[str]): allowlist; if non‑empty, other hosts are blocked
- `HTTP_BLOCKED_HOSTS` (list[str]): blocklist
- `HTTP_MAX_RESPONSE_BYTES` (int): truncate response content above limit (0 disables)
- `HTTP_ACCEPT_LANGUAGE` (str): default Accept‑Language

### Concurrency and stability

- Priority scheduling, adaptive concurrency by memory pressure
- Per‑scanner circuit breaker and global breaker
- Queue fairness and immediate start when capacity exists

### Metrics

- HTTP client: cache size, active requests, retries, throttle waits, SSRF blocks
  - `GET /api/metrics/http-client`
- Concurrency manager: active/queued/completed/failed, avg exec time, memory usage, circuit breaker status
  - `GET /api/metrics/concurrency`

### Testing

Run targeted backend tests:
```bash
python -m pytest -q backend/tests
```

### Repository layout

- `backend/` FastAPI app, scanners, engine, utils
- `frontend/` React app
- `docker-compose.yml` local dev stack

### License

MIT
