"""ACME HTTP endpoints (RFC 8555 subset).

All POST endpoints consume a JWS (``application/jose+json``). New-account
requests authenticate with a JWK; everything else uses a kid. Query-style
operations (account lookup, order/authz/certificate fetch) are POST-as-GET.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from ..storage import AcmeAccountRecord
from .errors import AcmeError
from .jws import b64url_decode, verify_jws
from .service import AcmeService, CHALLENGE_TYPE

JOSE_JSON = "application/jose+json"
PROBLEM_JSON = "application/problem+json"


def create_acme_router(acme: AcmeService) -> APIRouter:
    """Build the ACME router. Problem documents (AcmeError) are rendered by
    the app-level exception handler registered in ``app.api.create_app``."""
    router = APIRouter(prefix="/acme")

    def base_url(request: Request) -> str:
        return str(request.base_url).rstrip("/")

    async def read_jws(request: Request) -> tuple[dict, bytes, object]:
        content_type = request.headers.get("content-type", "")
        if not content_type.lower().startswith(JOSE_JSON):
            raise AcmeError(
                415,
                "malformed",
                f"Content-Type must be {JOSE_JSON}",
            )
        body = await request.body()
        return verify_jws(
            body,
            request_url=str(request.url),
            nonce_validator=acme.consume_nonce,
            account_lookup=acme.account_by_kid,
        )

    def require_account(account: object) -> AcmeAccountRecord:
        if not isinstance(account, AcmeAccountRecord):
            raise AcmeError(
                403,
                "accountDoesNotExist",
                "this operation requires a registered account",
            )
        return account

    def require_empty_payload(payload: bytes) -> None:
        if payload != b"":
            raise AcmeError(
                400, "malformed", "POST-as-GET request must have an empty payload"
            )

    def json_object(payload: bytes) -> dict:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AcmeError(400, "malformed", "payload must be a JSON object")
        if not isinstance(value, dict):
            raise AcmeError(400, "malformed", "payload must be a JSON object")
        return value

    def account_url(request: Request, account: AcmeAccountRecord) -> str:
        return f"{base_url(request)}/acme/acct/{account.id}"

    def account_dict(account: AcmeAccountRecord) -> dict:
        try:
            contact = json.loads(account.contact)
        except json.JSONDecodeError:
            contact = []
        return {
            "status": account.status,
            "contact": contact,
            "createdAt": account.created_at,
        }

    def order_url(request: Request, order_id: int) -> str:
        return f"{base_url(request)}/acme/order/{order_id}"

    def authz_url(request: Request, authz_id: int) -> str:
        return f"{base_url(request)}/acme/authz/{authz_id}"

    def challenge_url(request: Request, authz_id: int) -> str:
        return f"{base_url(request)}/acme/authz/{authz_id}/chall/{CHALLENGE_TYPE}"

    def order_dict(request: Request, account: AcmeAccountRecord, order) -> dict:
        authz = acme.get_authz_for_order(account, order.id)
        result = {
            "status": order.status,
            "expires": order.expires,
            "identifiers": [{"type": "dns", "value": order.domain}],
            "authorizations": [authz_url(request, authz.id)],
            "finalize": f"{order_url(request, order.id)}/finalize",
        }
        if order.status == "valid":
            result["certificate"] = f"{order_url(request, order.id)}/cert"
        return result

    def authz_dict(request: Request, authz) -> dict:
        return {
            "status": authz.status,
            "expires": authz.expires,
            "identifier": {"type": "dns", "value": authz.domain},
            "challenges": [
                {
                    "type": CHALLENGE_TYPE,
                    "url": challenge_url(request, authz.id),
                    "token": authz.token,
                    "status": authz.chall_status,
                }
            ],
        }

    @router.get("/directory")
    def directory(request: Request):
        root = base_url(request)
        return {
            "newNonce": f"{root}/acme/new-nonce",
            "newAccount": f"{root}/acme/new-account",
            "newOrder": f"{root}/acme/new-order",
            "meta": {"externalAccountRequired": False},
        }

    @router.api_route("/new-nonce", methods=["GET", "HEAD"])
    def new_nonce():
        return Response(
            status_code=204,
            headers={"Replay-Nonce": acme.new_nonce()},
        )

    @router.post("/new-account")
    async def new_account(request: Request):
        _protected, payload, account = await read_jws(request)
        if account is not None:
            # Re-using a registered key: 200 OK with the account location.
            return JSONResponse(
                content=account_dict(account),
                status_code=200,
                headers={"Location": account_url(request, account)},
            )
        data = json_object(payload)
        contact = data.get("contact")
        account, created = acme.new_account(_protected["jwk"], contact)
        return JSONResponse(
            content=account_dict(account),
            status_code=201 if created else 200,
            headers={"Location": account_url(request, account)},
        )

    @router.post("/new-order")
    async def new_order(request: Request):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        data = json_object(payload)
        order = acme.new_order(account, data.get("identifiers"))
        return JSONResponse(
            content=order_dict(request, account, order),
            status_code=201,
            headers={"Location": order_url(request, order.id)},
        )

    @router.post("/acct/{account_id}")
    async def get_account(request: Request, account_id: int):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        require_empty_payload(payload)
        if account.id != account_id:
            raise AcmeError(403, "accountDoesNotExist", "account mismatch")
        return JSONResponse(
            content=account_dict(account),
            status_code=200,
            headers={"Location": account_url(request, account)},
        )

    @router.post("/order/{order_id}")
    async def get_order(request: Request, order_id: int):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        require_empty_payload(payload)
        order = acme.get_order(account, order_id)
        return JSONResponse(
            content=order_dict(request, account, order), status_code=200
        )

    @router.post("/order/{order_id}/finalize")
    async def finalize_order(request: Request, order_id: int):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        data = json_object(payload)
        csr_b64 = data.get("csr")
        if not isinstance(csr_b64, str):
            raise AcmeError(400, "malformed", "payload must contain a csr string")
        try:
            csr_der = b64url_decode(csr_b64)
        except AcmeError:
            raise AcmeError(400, "badCSR", "csr is not valid base64url DER")
        order = acme.finalize(account, order_id, csr_der)
        return JSONResponse(
            content=order_dict(request, account, order), status_code=200
        )

    @router.post("/order/{order_id}/cert")
    async def download_certificate(request: Request, order_id: int):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        require_empty_payload(payload)
        pem_chain = acme.get_certificate_pem(account, order_id)
        return Response(
            content=pem_chain,
            status_code=200,
            media_type="application/pem-certificate-chain",
        )

    @router.post("/authz/{authz_id}")
    async def get_authz(request: Request, authz_id: int):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        require_empty_payload(payload)
        authz = acme.get_authz(account, authz_id)
        return JSONResponse(content=authz_dict(request, authz), status_code=200)

    @router.post("/authz/{authz_id}/chall/{chall_id}")
    async def post_challenge(request: Request, authz_id: int, chall_id: str):
        _protected, payload, account = await read_jws(request)
        account = require_account(account)
        if chall_id != CHALLENGE_TYPE:
            raise AcmeError(404, "malformed", "unknown challenge type")
        # RFC 8555 allows an empty object or an empty payload here.
        if payload != b"":
            json_object(payload)
        authz = acme.post_challenge(account, authz_id)
        return JSONResponse(content=authz_dict(request, authz), status_code=200)

    return router
