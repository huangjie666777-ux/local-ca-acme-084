"""FastAPI HTTP layer for the local test CA."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from . import policy
from .acme.api import PROBLEM_JSON, create_acme_router
from .acme.errors import AcmeError
from .acme.service import AcmeService
from .service import CAService
from .storage import (
    CertificateNotFound,
    IdempotencyConflict,
    RevocationReasonConflict,
)

TEXT_PEM = "application/x-pem-file"


class IssueRequest(BaseModel):
    csr: str = Field(description="PEM-encoded PKCS#10 certificate request")
    # Strict mode: bool and string values are rejected, not coerced.
    days: int = Field(strict=True)
    idempotency_key: str


class RevokeRequest(BaseModel):
    reason: str


def create_app(service: CAService, acme: AcmeService | None = None) -> FastAPI:
    app = FastAPI(title="Local Test CA")

    @app.middleware("http")
    async def acme_replay_nonce(request: Request, call_next):
        response = await call_next(request)
        if (
            acme is not None
            and request.url.path.startswith("/acme/")
            and "replay-nonce" not in response.headers
        ):
            response.headers["Replay-Nonce"] = acme.new_nonce()
        return response

    @app.exception_handler(policy.PolicyError)
    async def policy_error_handler(request: Request, exc: policy.PolicyError):
        return PlainTextResponse(str(exc), status_code=422)

    @app.exception_handler(CertificateNotFound)
    async def not_found_handler(request: Request, exc: CertificateNotFound):
        return PlainTextResponse(str(exc), status_code=404)

    @app.exception_handler(IdempotencyConflict)
    async def idempotency_conflict_handler(
        request: Request, exc: IdempotencyConflict
    ):
        return PlainTextResponse(
            f"{exc} (existing serial: {exc.serial_hex})", status_code=409
        )

    @app.exception_handler(RevocationReasonConflict)
    async def reason_conflict_handler(
        request: Request, exc: RevocationReasonConflict
    ):
        return PlainTextResponse(str(exc), status_code=409)

    @app.exception_handler(AcmeError)
    async def acme_error_handler(request: Request, exc: AcmeError):
        body = {
            "type": f"urn:ietf:params:acme:error:{exc.acme_type}",
            "status": exc.status,
            "detail": exc.detail,
        }
        headers = {}
        if acme is not None and exc.acme_type == "badNonce":
            # A bad nonce consumes nothing; hand out a fresh one.
            headers["Replay-Nonce"] = acme.new_nonce()
        return JSONResponse(
            content=body,
            status_code=exc.status,
            headers=headers,
            media_type=PROBLEM_JSON,
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ca/certificate", response_class=Response)
    def download_ca_certificate():
        return Response(
            content=service.ca.cert_pem,
            media_type=TEXT_PEM,
            headers={
                "Content-Disposition": "attachment; filename=ca_cert.pem"
            },
        )

    @app.post("/certificates")
    def issue_certificate(payload: IssueRequest):
        record, replayed = service.issue(
            csr_pem=payload.csr.encode("utf-8"),
            days=payload.days,
            idempotency_key=payload.idempotency_key,
        )
        return {
            "serial": record.serial_hex,
            "certificate": record.cert_pem,
            "san": record.san,
            "days": record.days,
            "not_before": record.not_before,
            "not_after": record.not_after,
            "status": record.status,
            "replayed": replayed,
        }

    @app.get("/certificates/{serial_hex}")
    def get_certificate(serial_hex: str):
        record = service.get_certificate(serial_hex)
        return {
            "serial": record.serial_hex,
            "certificate": record.cert_pem,
            "san": record.san,
            "not_before": record.not_before,
            "not_after": record.not_after,
            "status": record.status,
            "revoked_at": record.revoked_at,
            "revocation_reason": record.reason,
        }

    @app.get("/certificates/{serial_hex}/pem", response_class=Response)
    def get_certificate_pem(serial_hex: str):
        record = service.get_certificate(serial_hex)
        return Response(content=record.cert_pem, media_type=TEXT_PEM)

    @app.post("/certificates/{serial_hex}/revoke")
    def revoke_certificate(serial_hex: str, payload: RevokeRequest):
        record, changed = service.revoke(serial_hex, payload.reason)
        return {
            "serial": record.serial_hex,
            "status": record.status,
            "revoked_at": record.revoked_at,
            "revocation_reason": record.reason,
            "replayed": not changed,
        }

    @app.post("/crl/publish")
    def publish_crl():
        crl_pem, number = service.publish_crl()
        return {"crl_number": number, "crl": crl_pem}

    @app.get("/crl/current")
    def current_crl():
        crl_pem, number = service.current_crl()
        return {"crl_number": number, "crl": crl_pem}

    @app.get("/crl/current.pem", response_class=Response)
    def current_crl_pem():
        crl_pem, number = service.current_crl()
        return Response(
            content=crl_pem,
            media_type=TEXT_PEM,
            headers={"X-CRL-Number": str(number)},
        )

    if acme is not None:
        app.include_router(create_acme_router(acme))

    return app
