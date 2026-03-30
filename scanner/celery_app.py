"""
Celery application factory.

Key design decision: YARA rules are compiled ONCE when the worker process
starts (via the worker_process_init signal) and stored as a module-level
singleton. This avoids the expensive re-compilation on every task call.
"""
import logging
import os

import django
from celery import Celery
from celery.signals import worker_process_init

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "scanner.settings")
django.setup()

from django.conf import settings  # noqa: E402 — must come after django.setup()

logger = logging.getLogger(__name__)

app = Celery("scanner")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks(["scanner"])

# ---------------------------------------------------------------------------
# Module-level YARA rules cache (per worker process)
# ---------------------------------------------------------------------------
_compiled_rules = None


def get_compiled_rules():
    """Return the cached compiled YARA rules (compiled once per process)."""
    return _compiled_rules


@worker_process_init.connect
def compile_yara_rules(**kwargs):
    """
    Called once per worker *process* at startup.
    Compiles all .yar / .yara files in YARA_RULES_DIR into a single
    yara.Rules object and caches it globally for the lifetime of the process.
    """
    global _compiled_rules
    import yara

    rules_dir = settings.YARA_RULES_DIR
    rule_files = {}

    if os.path.isdir(rules_dir):
        for fname in os.listdir(rules_dir):
            if fname.endswith((".yar", ".yara")):
                namespace = os.path.splitext(fname)[0]
                rule_files[namespace] = os.path.join(rules_dir, fname)

    if rule_files:
        try:
            _compiled_rules = yara.compile(filepaths=rule_files)
            logger.info(
                "YARA rules compiled at worker startup: %s",
                list(rule_files.keys()),
            )
        except yara.SyntaxError as exc:
            logger.error("YARA compilation failed: %s", exc)
            _compiled_rules = None
    else:
        logger.warning("No YARA rule files found in %s", rules_dir)
        _compiled_rules = None
