"""SQLite persistence for certificates, idempotency keys and CRL state."""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import random_serial_number

DB_FILE = "ca.sqlite3"
STATUS_VALID = "valid"
STATUS_REVOKED = "revoked"


class StoreError(RuntimeError):
    pass


class IdempotencyConflict(StoreError):
    def __init__(self, serial_hex: str):
        super().__init__("idempotency key was already used with different input")
        self.serial_hex = serial_hex


class CertificateNotFound(StoreError):
    pass


class RevocationReasonConflict(StoreError):
    def __init__(self, existing_reason: str, new_reason: str):
        super().__init__(
            f"certificate already revoked with reason {existing_reason!r}, "
            f"cannot change to {new_reason!r}"
        )
        self.existing_reason = existing_reason
        self.new_reason = new_reason


@dataclass(frozen=True)
class CertificateRecord:
    serial_hex: str
    cert_pem: str
    csr_der: bytes
    days: int
    san: list[str]
    not_before: str
    not_after: str
    status: str
    revoked_at: str | None
    reason: str | None


@dataclass(frozen=True)
class RevokedRecord:
    serial: int
    revoked_at: str
    reason: str


@dataclass(frozen=True)
class IssueResult:
    record: CertificateRecord
    replayed: bool


@dataclass(frozen=True)
class AcmeAccountRecord:
    id: int
    thumbprint: str
    jwk_json: str
    contact: str
    status: str
    created_at: str


@dataclass(frozen=True)
class AcmeOrderRecord:
    id: int
    account_id: int
    status: str
    domain: str
    expires: str
    created_at: str
    csr_der: bytes | None
    cert_serial: str | None


@dataclass(frozen=True)
class AcmeAuthzRecord:
    id: int
    order_id: int
    account_id: int
    domain: str
    status: str
    expires: str
    token: str
    chall_status: str
    validated_at: str | None


SignCallback = Callable[[int], tuple[str, list[str], str, str]]
BuildCrlCallback = Callable[[list[RevokedRecord], int, str], str]


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    serial_hex TEXT PRIMARY KEY,
    csr_der BLOB NOT NULL,
    days INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    san TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'valid',
    revoked_at TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS idempotency (
    idempotency_key TEXT PRIMARY KEY,
    serial_hex TEXT NOT NULL,
    csr_der BLOB NOT NULL,
    days INTEGER NOT NULL,
    FOREIGN KEY (serial_hex) REFERENCES certificates(serial_hex)
);
CREATE TABLE crl_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    number INTEGER NOT NULL,
    crl_pem TEXT NOT NULL,
    published_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thumbprint TEXT NOT NULL UNIQUE,
    jwk_json TEXT NOT NULL,
    contact TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'valid',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acme_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES acme_accounts(id),
    status TEXT NOT NULL,
    domain TEXT NOT NULL,
    expires TEXT NOT NULL,
    created_at TEXT NOT NULL,
    csr_der BLOB,
    cert_serial TEXT
);
CREATE TABLE IF NOT EXISTS acme_authz (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL UNIQUE REFERENCES acme_orders(id),
    account_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    expires TEXT NOT NULL,
    token TEXT NOT NULL,
    chall_status TEXT NOT NULL,
    validated_at TEXT
);
"""


class CAStore:
    def __init__(self, data_dir: str):
        self._db_path = os.path.join(data_dir, DB_FILE)
        self._lock = threading.RLock()

    def _ensure_dir(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

    def exists(self) -> bool:
        return os.path.exists(self._db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def initialize(self, ca: object) -> None:
        """Create schema and bind the database to the given CA certificate."""
        fingerprint = ca.cert.fingerprint(hashes.SHA256())  # type: ignore[attr-defined]
        self._ensure_dir()
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)",
                ("ca_sha256_fingerprint", fingerprint),
            )

    def load_ca_fingerprint(self) -> bytes:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'ca_sha256_fingerprint'"
            ).fetchone()
        if row is None:
            raise StoreError("database is missing the CA fingerprint")
        return bytes(row["value"])

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CertificateRecord:
        return CertificateRecord(
            serial_hex=row["serial_hex"],
            cert_pem=row["cert_pem"],
            csr_der=bytes(row["csr_der"]),
            days=row["days"],
            san=[part for part in row["san"].split(",") if part],
            not_before=row["not_before"],
            not_after=row["not_after"],
            status=row["status"],
            revoked_at=row["revoked_at"],
            reason=row["reason"],
        )

    def get_certificate(self, serial_hex: str) -> CertificateRecord:
        normalized = serial_hex.lower().strip()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?",
                (normalized,),
            ).fetchone()
        if row is None:
            raise CertificateNotFound(f"unknown certificate serial: {serial_hex}")
        return self._row_to_record(row)

    def issue_certificate(
        self,
        idempotency_key: str,
        csr_der: bytes,
        days: int,
        sign: SignCallback,
    ) -> IssueResult:
        """Idempotently persist a certificate.

        Same key + same CSR DER + same days replays the original certificate;
        same key with different content raises IdempotencyConflict.
        A process-wide lock plus one transaction guarantees one record even
        under concurrent retries; a signing/insert failure leaves nothing.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT * FROM idempotency WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    if (
                        bytes(existing["csr_der"]) == csr_der
                        and existing["days"] == days
                    ):
                        row = conn.execute(
                            "SELECT * FROM certificates WHERE serial_hex = ?",
                            (existing["serial_hex"],),
                        ).fetchone()
                        return IssueResult(self._row_to_record(row), replayed=True)
                    raise IdempotencyConflict(existing["serial_hex"])

                for _ in range(5):
                    serial = random_serial_number()
                    serial_hex = format(serial, "x")
                    cert_pem, san, not_before, not_after = sign(serial)
                    try:
                        conn.execute(
                            "INSERT INTO certificates("
                            "serial_hex, csr_der, days, cert_pem, san, "
                            "not_before, not_after) VALUES(?,?,?,?,?,?,?)",
                            (
                                serial_hex,
                                csr_der,
                                days,
                                cert_pem,
                                ",".join(san),
                                not_before,
                                not_after,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        # Vanishingly unlikely serial collision: try again.
                        continue
                    conn.execute(
                        "INSERT INTO idempotency("
                        "idempotency_key, serial_hex, csr_der, days) "
                        "VALUES(?,?,?,?)",
                        (
                            idempotency_key,
                            serial_hex,
                            csr_der,
                            days,
                        ),
                    )
                    conn.execute("COMMIT")
                    row = conn.execute(
                        "SELECT * FROM certificates WHERE serial_hex = ?",
                        (serial_hex,),
                    ).fetchone()
                    return IssueResult(self._row_to_record(row), replayed=False)
                conn.execute("ROLLBACK")
                raise StoreError("could not allocate a unique certificate serial")
            except BaseException:
                # Roll back unless the transaction already ended (commit error).
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def revoke(
        self, serial_hex: str, reason: str, now_iso: str
    ) -> tuple[CertificateRecord, bool]:
        """Revoke a certificate. Returns (record, changed_now).

        First revocation time/reason are preserved forever. Repeating with
        the same reason is idempotent; a different reason raises a conflict.
        """
        normalized = serial_hex.lower().strip()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM certificates WHERE serial_hex = ?",
                    (normalized,),
                ).fetchone()
                if row is None:
                    raise CertificateNotFound(
                        f"unknown certificate serial: {serial_hex}"
                    )
                if row["status"] == STATUS_REVOKED:
                    if row["reason"] != reason:
                        raise RevocationReasonConflict(row["reason"], reason)
                    record = self._row_to_record(row)
                    return record, False
                conn.execute(
                    "UPDATE certificates SET status = ?, revoked_at = ?, "
                    "reason = ? WHERE serial_hex = ?",
                    (STATUS_REVOKED, now_iso, reason, normalized),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            row = conn.execute(
                "SELECT * FROM certificates WHERE serial_hex = ?", (normalized,)
            ).fetchone()
            return self._row_to_record(row), True

    def list_revoked(self) -> list[RevokedRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT serial_hex, revoked_at, reason FROM certificates "
                "WHERE status = ? ORDER BY revoked_at",
                (STATUS_REVOKED,),
            ).fetchall()
        return [
            RevokedRecord(
                serial=int(row["serial_hex"], 16),
                revoked_at=row["revoked_at"],
                reason=row["reason"],
            )
            for row in rows
        ]

    def publish_crl(self, build: BuildCrlCallback) -> tuple[str, int]:
        """Atomically bump the persisted CRL number and store the new CRL."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT number FROM crl_state WHERE id = 1"
                ).fetchone()
                number = (row["number"] if row is not None else 0) + 1
                now_iso = _utcnow_iso()
                entries = [
                    RevokedRecord(
                        serial=int(r["serial_hex"], 16),
                        revoked_at=r["revoked_at"],
                        reason=r["reason"],
                    )
                    for r in conn.execute(
                        "SELECT serial_hex, revoked_at, reason FROM certificates "
                        "WHERE status = ? ORDER BY revoked_at",
                        (STATUS_REVOKED,),
                    ).fetchall()
                ]
                crl_pem = build(entries, number, now_iso)
                conn.execute(
                    "INSERT INTO crl_state(id, number, crl_pem, published_at) "
                    "VALUES(1, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET number = excluded.number, "
                    "crl_pem = excluded.crl_pem, "
                    "published_at = excluded.published_at",
                    (number, crl_pem, now_iso),
                )
                conn.execute("COMMIT")
                return crl_pem, number
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def get_current_crl(self) -> tuple[str, int] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT crl_pem, number FROM crl_state WHERE id = 1"
            ).fetchone()
        if row is None:
            return None
        return row["crl_pem"], row["number"]

    # ------------------------------------------------------------------
    # ACME (RFC 8555 subset) persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_acme_account(row: sqlite3.Row) -> AcmeAccountRecord:
        return AcmeAccountRecord(
            id=row["id"],
            thumbprint=row["thumbprint"],
            jwk_json=row["jwk_json"],
            contact=row["contact"],
            status=row["status"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _row_to_acme_order(row: sqlite3.Row) -> AcmeOrderRecord:
        return AcmeOrderRecord(
            id=row["id"],
            account_id=row["account_id"],
            status=row["status"],
            domain=row["domain"],
            expires=row["expires"],
            created_at=row["created_at"],
            csr_der=bytes(row["csr_der"]) if row["csr_der"] is not None else None,
            cert_serial=row["cert_serial"],
        )

    @staticmethod
    def _row_to_acme_authz(row: sqlite3.Row) -> AcmeAuthzRecord:
        return AcmeAuthzRecord(
            id=row["id"],
            order_id=row["order_id"],
            account_id=row["account_id"],
            domain=row["domain"],
            status=row["status"],
            expires=row["expires"],
            token=row["token"],
            chall_status=row["chall_status"],
            validated_at=row["validated_at"],
        )

    def acme_create_account(
        self, thumbprint: str, jwk_json: str, contact_json: str, now_iso: str
    ) -> AcmeAccountRecord:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO acme_accounts(thumbprint, jwk_json, contact, "
                "status, created_at) VALUES(?,?,?,?,?)",
                (thumbprint, jwk_json, contact_json, "valid", now_iso),
            )
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE thumbprint = ?", (thumbprint,)
            ).fetchone()
            return self._row_to_acme_account(row)

    def acme_get_account_by_thumbprint(
        self, thumbprint: str
    ) -> AcmeAccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE thumbprint = ?", (thumbprint,)
            ).fetchone()
        return self._row_to_acme_account(row) if row is not None else None

    def acme_get_account(self, account_id: int) -> AcmeAccountRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_accounts WHERE id = ?", (account_id,)
            ).fetchone()
        return self._row_to_acme_account(row) if row is not None else None

    def acme_create_order(
        self,
        account_id: int,
        domain: str,
        expires_iso: str,
        now_iso: str,
        token: str,
    ) -> tuple[AcmeOrderRecord, AcmeAuthzRecord]:
        """Create an order plus its single pending authorization atomically."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "INSERT INTO acme_orders(account_id, status, domain, "
                    "expires, created_at) VALUES(?,?,?,?,?)",
                    (account_id, "pending", domain, expires_iso, now_iso),
                )
                order_id = cur.lastrowid
                conn.execute(
                    "INSERT INTO acme_authz(order_id, account_id, domain, "
                    "status, expires, token, chall_status) VALUES(?,?,?,?,?,?,?)",
                    (
                        order_id,
                        account_id,
                        domain,
                        "pending",
                        expires_iso,
                        token,
                        "pending",
                    ),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            order_row = conn.execute(
                "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
            ).fetchone()
            authz_row = conn.execute(
                "SELECT * FROM acme_authz WHERE order_id = ?", (order_id,)
            ).fetchone()
            return (
                self._row_to_acme_order(order_row),
                self._row_to_acme_authz(authz_row),
            )

    def acme_get_order(self, order_id: int) -> AcmeOrderRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_orders WHERE id = ?", (order_id,)
            ).fetchone()
        return self._row_to_acme_order(row) if row is not None else None

    def acme_get_authz(self, authz_id: int) -> AcmeAuthzRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_authz WHERE id = ?", (authz_id,)
            ).fetchone()
        return self._row_to_acme_authz(row) if row is not None else None

    def acme_get_authz_by_order(self, order_id: int) -> AcmeAuthzRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM acme_authz WHERE order_id = ?", (order_id,)
            ).fetchone()
        return self._row_to_acme_authz(row) if row is not None else None

    def acme_mark_challenge_valid(self, authz_id: int, now_iso: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_authz SET status = 'valid', chall_status = 'valid', "
                "validated_at = ? WHERE id = ? AND status = 'pending'",
                (now_iso, authz_id),
            )

    def acme_mark_challenge_invalid(self, authz_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_authz SET status = 'invalid', chall_status = 'invalid' "
                "WHERE id = ? AND status = 'pending'",
                (authz_id,),
            )

    def acme_mark_order_invalid(self, order_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_orders SET status = 'invalid' "
                "WHERE id = ? AND status = 'pending'",
                (order_id,),
            )

    def acme_mark_authz_invalid(self, authz_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_authz SET status = 'invalid', chall_status = 'invalid' "
                "WHERE id = ? AND status = 'pending'",
                (authz_id,),
            )

    def acme_mark_order_processing(self, order_id: int) -> bool:
        """Transition pending -> processing. Returns False if already claimed."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE acme_orders SET status = 'processing' "
                "WHERE id = ? AND status = 'pending'",
                (order_id,),
            )
            return cur.rowcount == 1

    def acme_mark_order_pending(self, order_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_orders SET status = 'pending' "
                "WHERE id = ? AND status = 'processing'",
                (order_id,),
            )

    def acme_mark_order_valid(
        self, order_id: int, csr_der: bytes, cert_serial: str
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_orders SET status = 'valid', csr_der = ?, "
                "cert_serial = ? WHERE id = ?",
                (csr_der, cert_serial, order_id),
            )

    def acme_force_expire(self, order_id: int, expires_iso: str) -> None:
        """Test helper: push an order's expiry into the past."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE acme_orders SET expires = ? WHERE id = ?",
                (expires_iso, order_id),
            )
            conn.execute(
                "UPDATE acme_authz SET expires = ? WHERE order_id = ?",
                (expires_iso, order_id),
            )


def _utcnow_iso() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat()
