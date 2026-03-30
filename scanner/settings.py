"""
Django settings for the scanner project.
FastAPI and Celery share this settings module via DJANGO_SETTINGS_MODULE.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-in-prod")
DEBUG = os.environ.get("DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "scanner",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "scanner",
        "USER": "scanner",
        "PASSWORD": "scanner",
        "HOST": os.environ.get("DB_HOST", "db"),
        "PORT": "5432",
    }
}

# Override with DATABASE_URL if provided
_db_url = os.environ.get("DATABASE_URL")
if _db_url:
    # Simple parser for postgres://user:pass@host:port/db
    import re
    m = re.match(r"postgresql?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", _db_url)
    if m:
        DATABASES["default"].update({
            "USER": m.group(1),
            "PASSWORD": m.group(2),
            "HOST": m.group(3),
            "PORT": m.group(4),
            "NAME": m.group(5),
        })

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Celery
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "amqp://guest:guest@localhost:5672/")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"

# Redis (for distributed locks)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# YARA rules directory
YARA_RULES_DIR = os.path.join(BASE_DIR, "rules")

USE_TZ = True
CELERY_TASK_DEFAULT_QUEUE = "default"