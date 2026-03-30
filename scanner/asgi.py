"""
ASGI entry point.

Django's setup() must be called before any model imports.
We do it here, once, before the FastAPI application object is referenced.
"""
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "scanner.settings")

import django  # noqa: E402
django.setup()

from scanner.api import api as fastapi_app  # noqa: E402 — after django.setup()

# Uvicorn is pointed at `scanner.asgi:fastapi_app`
