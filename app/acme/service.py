"""ACME service: accounts, orders, HTTP-01 authorizations and finalize.

Orders are single-identifier (one lab.test domain, no wildcards) and expire
after 10 minutes. Finalize reuses the main CA issuance policy with a fixed
7-day lifetime. All state lives in the shared SQLite database, so a process
restart continues pending orders.
"""

from __future__ import annotations

import datetime as dt
import hmac
import json
import secrets
import threading
import time
from urllib.parse import urlparse

from cryptography import x509

from .. import policy
from ..service import CAService
from ..storage import (
    AcmeAccountRecord,
    AcmeAuthzRecord,
    AcmeOrderRecord,
    CAStore,
    IdempotencyConflict,
)
from . import jws
from .challenge import ChallengeError, fetch_http01
from .errors import AcmeError

NONCE_TTL_SECONDS = 300  # nonces are valid for 5 minutes (RFC 8555 §6.5)
ORDER_TTL_SECONDS = 600  # orders and authorizations expire after 10 minutes
FINALIZE_DAYS = 7
CHALLENGE_TYPE = "http-01"


class _NonceStore:
    """One-time nonces with a bounded lifetime. Replay succeeds at most once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}

    def issue(self) -> str:
        nonce = secrets.token_urlsafe(16)
        with self._lock:
            self._purge_locked()
            self._nonces[nonce] = time.monotonic() + NONCE_TTL_SECONDS
        return nonce

    def consume(self, nonce: object) -> None:
        if not isinstance(nonce, str) or not nonce:
            raise AcmeError(400, "badNonce", "missing or invalid nonce")
        with self._lock:
            self._purge_locked()
            expires_at = self._nonces.pop(nonce, None)
        if expires_at is None:
            raise AcmeError(400, "badNonce", "nonce is unknown or already used")

    def _purge_locked(self) -> None:
        now = time.monotonic()
        for stale in [n for n, exp in self._nonces.items() if exp <= now]:
            del self._nonces[stale]


def _parse_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


def _is_expired(expires_iso: str, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    return _parse_iso(expires_iso) <= now


class AcmeService:
    def __init__(
        self,
        store: CAStore,
        ca_service: CAService,
        challenge_port: int,
    ):
        self._store = store
        self._ca = ca_service
        self._challenge_port = challenge_port
        self._nonces = _NonceStore()

    # ------------------------------------------------------------------
    # Nonces
    # ------------------------------------------------------------------

    def new_nonce(self) -> str:
        return self._nonces.issue()

    def consume_nonce(self, nonce: object) -> None:
        self._nonces.consume(nonce)

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    def account_by_kid(self, kid: object) -> AcmeAccountRecord | None:
        """Resolve a kid URL to an account, or None for an unknown kid."""
        if not isinstance(kid, str):
            return None
        try:
            path = urlparse(kid).path.rstrip("/")
            account_id = int(path.rsplit("/", 1)[-1])
        except (ValueError, IndexError):
            return None
        return self._store.acme_get_account(account_id)

    def new_account(
        self, jwk: dict, contact: object
    ) -> tuple[AcmeAccountRecord, bool]:
        """Register a key, or reuse the account if the key is known."""
        thumbprint = jws.jwk_thumbprint(jwk)
        existing = self._store.acme_get_account_by_thumbprint(thumbprint)
        if existing is not None:
            return existing, False
        contact_json = json.dumps(contact if isinstance(contact, list) else [])
        now_iso = dt.datetime.now(dt.timezone.utc).isoformat()
        account = self._store.acme_create_account(
            thumbprint, json.dumps(jwk), contact_json, now_iso
        )
        return account, True

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------

    def new_order(
        self, account: AcmeAccountRecord, identifiers: object
    ) -> AcmeOrderRecord:
        if not isinstance(identifiers, list) or len(identifiers) != 1:
            raise AcmeError(
                400,
                "malformed",
                "exactly one order identifier is required",
            )
        identifier = identifiers[0]
        if (
            not isinstance(identifier, dict)
            or identifier.get("type") != "dns"
            or not isinstance(identifier.get("value"), str)
        ):
            raise AcmeError(
                400,
                "rejectedIdentifier",
                "only DNS identifiers are supported",
            )
        try:
            domain = policy.normalize_dns_name(identifier["value"])
        except policy.PolicyError as exc:
            raise AcmeError(400, "rejectedIdentifier", str(exc))

        now = dt.datetime.now(dt.timezone.utc)
        expires = now + dt.timedelta(seconds=ORDER_TTL_SECONDS)
        token = secrets.token_urlsafe(16)
        order, _authz = self._store.acme_create_order(
            account.id, domain, expires.isoformat(), now.isoformat(), token
        )
        return order

    def _load_order(
        self, account: AcmeAccountRecord, order_id: int
    ) -> AcmeOrderRecord:
        order = self._store.acme_get_order(order_id)
        if order is None or order.account_id != account.id:
            # Do not reveal whether the resource exists.
            raise AcmeError(404, "malformed", "order not found")
        if order.status == "pending" and _is_expired(order.expires):
            self._store.acme_mark_order_invalid(order_id)
            order = self._store.acme_get_order(order_id)
        return order

    def _load_authz(
        self, account: AcmeAccountRecord, authz_id: int
    ) -> AcmeAuthzRecord:
        authz = self._store.acme_get_authz(authz_id)
        if authz is None or authz.account_id != account.id:
            raise AcmeError(404, "malformed", "authorization not found")
        if authz.status == "pending" and _is_expired(authz.expires):
            self._store.acme_mark_authz_invalid(authz_id)
            authz = self._store.acme_get_authz(authz_id)
        return authz

    def get_order(
        self, account: AcmeAccountRecord, order_id: int
    ) -> AcmeOrderRecord:
        return self._load_order(account, order_id)

    def get_authz(
        self, account: AcmeAccountRecord, authz_id: int
    ) -> AcmeAuthzRecord:
        return self._load_authz(account, authz_id)

    def get_authz_for_order(
        self, account: AcmeAccountRecord, order_id: int
    ) -> AcmeAuthzRecord:
        order = self._load_order(account, order_id)
        authz = self._store.acme_get_authz_by_order(order.id)
        if authz is None or authz.account_id != account.id:
            raise AcmeError(404, "malformed", "authorization not found")
        return authz

    # ------------------------------------------------------------------
    # Challenge
    # ------------------------------------------------------------------

    def post_challenge(
        self, account: AcmeAccountRecord, authz_id: int
    ) -> AcmeAuthzRecord:
        authz = self._load_authz(account, authz_id)
        if authz.status != "pending":
            # Re-posting is idempotent; validation is never re-attempted.
            return authz

        order = self._store.acme_get_order(authz.order_id)
        if order is None or _is_expired(order.expires):
            self._store.acme_mark_authz_invalid(authz_id)
            return self._store.acme_get_authz(authz_id)

        try:
            body = fetch_http01(authz.domain, authz.token, self._challenge_port)
        except ChallengeError:
            self._store.acme_mark_challenge_invalid(authz_id)
            return self._store.acme_get_authz(authz_id)

        jwk = json.loads(account.jwk_json)
        expected = f"{authz.token}.{jws.jwk_thumbprint(jwk)}"
        if hmac.compare_digest(body, expected):
            now_iso = dt.datetime.now(dt.timezone.utc).isoformat()
            self._store.acme_mark_challenge_valid(authz_id, now_iso)
        else:
            self._store.acme_mark_challenge_invalid(authz_id)
        return self._store.acme_get_authz(authz_id)

    # ------------------------------------------------------------------
    # Finalize and certificate download
    # ------------------------------------------------------------------

    def finalize(
        self, account: AcmeAccountRecord, order_id: int, csr_der: bytes
    ) -> AcmeOrderRecord:
        order = self._load_order(account, order_id)
        if order.status == "valid":
            if order.csr_der is not None and order.csr_der != csr_der:
                raise AcmeError(
                    409,
                    "badCSR",
                    "CSR does not match the CSR already submitted for this order",
                )
            return order
        if order.status in ("invalid", "processing"):
            raise AcmeError(
                403,
                "orderNotReady",
                f"order is {order.status}; finalize is not possible",
            )

        authz = self._store.acme_get_authz_by_order(order.id)
        if authz is None or authz.status != "valid":
            raise AcmeError(
                403, "orderNotReady", "authorization has not succeeded"
            )

        try:
            csr = x509.load_der_x509_csr(csr_der)
        except (ValueError, TypeError):
            raise AcmeError(400, "badCSR", "CSR is not valid DER")
        try:
            sans = policy.validate_csr(csr)
        except policy.PolicyError as exc:
            raise AcmeError(400, "badCSR", str(exc))
        if sans != [order.domain]:
            raise AcmeError(
                400,
                "badCSR",
                "CSR subjectAltName must equal the order identifier",
            )

        if not self._store.acme_mark_order_processing(order.id):
            # A concurrent finalize already claimed this order.
            raise AcmeError(
                403, "orderNotReady", "finalize is already in progress"
            )
        try:
            record, _replayed = self._ca.issue_der(
                csr_der,
                days=FINALIZE_DAYS,
                idempotency_key=f"acme-order-{order.id}",
            )
        except IdempotencyConflict:
            self._store.acme_mark_order_pending(order.id)
            raise AcmeError(
                409,
                "badCSR",
                "CSR does not match the CSR already submitted for this order",
            )
        except Exception:
            self._store.acme_mark_order_pending(order.id)
            raise
        self._store.acme_mark_order_valid(order.id, csr_der, record.serial_hex)
        return self._store.acme_get_order(order.id)

    def get_certificate_pem(
        self, account: AcmeAccountRecord, order_id: int
    ) -> bytes:
        order = self._load_order(account, order_id)
        if order.status != "valid" or not order.cert_serial:
            raise AcmeError(
                403, "orderNotReady", "certificate has not been issued"
            )
        record = self._store.get_certificate(order.cert_serial)
        # Chain: leaf certificate followed by the CA certificate.
        return record.cert_pem.encode("ascii") + self._ca.ca.cert_pem
