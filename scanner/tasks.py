"""
Celery tasks for malware scanning.

Concurrency strategy
--------------------
The challenge: requests from the *same* tenant must be processed sequentially,
while requests from *different* tenants run in parallel.

Solution: Redis-based per-tenant mutex (distributed lock).

  - Each task acquires a Redis lock keyed by `tenant_lock:<tenant_id>`.
  - The lock is held for the duration of the YARA scan.
  - If the lock is already taken (another task for the same tenant is running),
    the task retries with a short countdown rather than blocking the worker
    thread indefinitely (which would starve other work).
  - Different tenants have independent locks → full parallelism across tenants.

Why not Celery's rate_limit or canvas chords?
  - rate_limit is per-task-type, not per-tenant.
  - Building per-tenant chains would require dynamic routing logic and
    persistent chain state — more complex with no real benefit at this scale.
  - A simple Redis lock is explicit, easy to reason about, and observable.
"""
import logging
import time

import redis as redis_client
from celery import shared_task

from django.conf import settings

logger = logging.getLogger(__name__)

# How long (seconds) to hold the lock at most (safety net against crashed workers)
LOCK_TIMEOUT = 60
# How long (seconds) to wait before retrying when lock is contended
RETRY_COUNTDOWN = 2
# Maximum number of retries
MAX_RETRIES = 30


def _get_redis():
    return redis_client.from_url(settings.REDIS_URL, decode_responses=True)


@shared_task(bind=True, max_retries=MAX_RETRIES, default_retry_delay=RETRY_COUNTDOWN)
def scan_payload(self, scan_result_id: int, tenant_id: str, payload_text: str):
    """
    Scan a payload with YARA rules.

    Steps:
    1. Acquire a per-tenant Redis lock.
    2. Run YARA scan using the pre-compiled rules.
    3. Persist results via Django ORM.
    4. Release the lock.
    """
    from scanner.celery_app import get_compiled_rules
    from scanner.models import ScanResult

    lock_key = f"tenant_lock:{tenant_id}"
    r = _get_redis()

    # Attempt to acquire the lock (SET NX EX — atomic)
    acquired = r.set(lock_key, self.request.id, nx=True, ex=LOCK_TIMEOUT)

    if not acquired:
        # Another task for the same tenant is running; retry later.
        logger.info(
            "[tenant=%s] Lock contended for scan_result_id=%s, retrying in %ss",
            tenant_id,
            scan_result_id,
            RETRY_COUNTDOWN,
        )
        raise self.retry(countdown=RETRY_COUNTDOWN)

    logger.info(
        "[tenant=%s] Lock acquired, starting scan for scan_result_id=%s",
        tenant_id,
        scan_result_id,
    )

    try:
        rules = get_compiled_rules()
        matched_rule_names = []

        if rules is not None:
            matches = rules.match(data=payload_text.encode("utf-8", errors="replace"))
            matched_rule_names = [m.rule for m in matches]
        else:
            logger.warning("No compiled YARA rules available; skipping scan.")

        status = (
            ScanResult.Status.MATCHED if matched_rule_names else ScanResult.Status.CLEAN
        )

        ScanResult.objects.filter(pk=scan_result_id).update(
            status=status,
            matched_rules=matched_rule_names,
        )

        logger.info(
            "[tenant=%s] Scan complete for scan_result_id=%s — status=%s, matched=%s",
            tenant_id,
            scan_result_id,
            status,
            matched_rule_names,
        )

    except Exception as exc:
        logger.exception(
            "[tenant=%s] Scan error for scan_result_id=%s: %s",
            tenant_id,
            scan_result_id,
            exc,
        )
        ScanResult.objects.filter(pk=scan_result_id).update(
            status=ScanResult.Status.ERROR,
            error_message=str(exc),
        )

    finally:
        # Only release the lock if we still own it
        current = r.get(lock_key)
        if current == self.request.id:
            r.delete(lock_key)
            logger.info(
                "[tenant=%s] Lock released for scan_result_id=%s",
                tenant_id,
                scan_result_id,
            )
