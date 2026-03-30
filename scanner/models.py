from django.db import models


class ScanResult(models.Model):
    """Persists the result of a YARA scan for a given tenant payload."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        CLEAN = "clean", "Clean"
        MATCHED = "matched", "Matched"
        ERROR = "error", "Error"

    tenant_id = models.CharField(max_length=255, db_index=True)
    payload_text = models.TextField()
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    matched_rules = models.JSONField(default=list)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "scanner"
        ordering = ["-created_at"]

    def __str__(self):
        return f"ScanResult(tenant={self.tenant_id}, status={self.status})"
