import logging
import os

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

api = FastAPI(title="CyberUltron Malware Scanner", version="1.0.0")

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class ScanRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=255)
    payload_text: str = Field(..., min_length=1)


class ScanResponse(BaseModel):
    scan_result_id: int
    tenant_id: str
    status: str
    message: str


@api.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(os.path.join(TEMPLATE_DIR, "dashboard.html"))


@api.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit a payload for malware scanning",
)
async def submit_scan(request: ScanRequest):
    from scanner.models import ScanResult
    from scanner.tasks import scan_payload

    try:
        result = await _create_scan_result(request.tenant_id, request.payload_text)
    except Exception as exc:
        logger.exception("DB write failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to persist scan request")

    try:
        scan_payload.delay(result.id, request.tenant_id, request.payload_text)
    except Exception as exc:
        logger.exception("Failed to enqueue task: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to enqueue scan task")

    logger.info("Scan enqueued — tenant=%s scan_result_id=%s", request.tenant_id, result.id)

    return ScanResponse(
        scan_result_id=result.id,
        tenant_id=request.tenant_id,
        status=result.status,
        message="Scan enqueued successfully",
    )


@api.get("/scan/{scan_result_id}", summary="Poll the result of a scan")
async def get_scan_result(scan_result_id: int):
    from scanner.models import ScanResult

    try:
        result = await _get_result(scan_result_id)
    except ScanResult.DoesNotExist:
        raise HTTPException(status_code=404, detail="Scan result not found")

    return {
        "scan_result_id": result.id,
        "tenant_id": result.tenant_id,
        "status": result.status,
        "matched_rules": result.matched_rules,
        "error_message": result.error_message,
        "created_at": result.created_at.isoformat(),
        "updated_at": result.updated_at.isoformat(),
    }


@api.get("/health", summary="Health check")
async def health():
    return {"status": "ok"}


import asyncio
from functools import partial


async def _create_scan_result(tenant_id: str, payload_text: str):
    from scanner.models import ScanResult
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        partial(ScanResult.objects.create, tenant_id=tenant_id, payload_text=payload_text, status=ScanResult.Status.PENDING),
    )


async def _get_result(scan_result_id: int):
    from scanner.models import ScanResult
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(ScanResult.objects.get, pk=scan_result_id))
