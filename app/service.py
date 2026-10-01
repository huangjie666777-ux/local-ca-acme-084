"""Certificate issuance/revocation/CRL orchestration between CA and storage."""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ReasonFlags

from . import policy
from .ca import CertificateAuthority
from .storage import CAStore, CertificateRecord, RevokedRecord

_REASON_MAP = {
    "unspecified": ReasonFlags.unspecified,
    "key_compromise": ReasonFlags.key_compromise,
    "ca_compromise": ReasonFlags.ca_compromise,
    "affiliation_changed": ReasonFlags.affiliation_changed,
    "superseded": ReasonFlags.superseded,
    "cessation_of_operation": ReasonFlags.cessation_of_operation,
    "certificate_hold": ReasonFlags.certificate_hold,
    "privilege_withdrawn": ReasonFlags.privilege_withdrawn,
    "aa_compromise": ReasonFlags.aa_compromise,
}


def parse_csr(pem_bytes: bytes) -> x509.CertificateSigningRequest:
    try:
        return x509.load_pem_x509_csr(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise policy.PolicyError(f"invalid PEM CSR: {exc}") from exc


class CAService:
    def __init__(self, ca: CertificateAuthority, store: CAStore):
        self._ca = ca
        self._store = store

    @property
    def ca(self) -> CertificateAuthority:
        return self._ca

    def issue(
        self, csr_pem: bytes, days: int, idempotency_key: str
    ) -> tuple[CertificateRecord, bool]:
        csr = parse_csr(csr_pem)
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        return self.issue_der(csr_der, days, idempotency_key)

    def issue_der(
        self, csr_der: bytes, days: int, idempotency_key: str
    ) -> tuple[CertificateRecord, bool]:
        """Issue from a DER-encoded CSR, reusing the shared policy."""
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except (ValueError, TypeError) as exc:
            raise policy.PolicyError(f"invalid DER CSR: {exc}") from exc
        policy.validate_days(days)
        key = policy.validate_idempotency_key(idempotency_key)
        dns_names = policy.validate_csr(csr)

        now = dt.datetime.now(dt.timezone.utc)
        not_before = now - dt.timedelta(minutes=1)
        requested_after = now + dt.timedelta(days=days)
        # Validity must never cross the CA's own expiry.
        not_after = min(requested_after, self._ca.not_after())
        if not_after <= not_before:
            raise policy.PolicyError(
                "CA validity period is too short to issue this certificate"
            )

        def sign(serial: int) -> tuple[str, list[str], str, str]:
            cert = self._ca.issue_cert(
                csr=csr,
                dns_names=dns_names,
                serial_number=serial,
                not_before=not_before,
                not_after=not_after,
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            return (
                cert_pem,
                dns_names,
                not_before.isoformat(),
                not_after.isoformat(),
            )

        result = self._store.issue_certificate(
            idempotency_key=key,
            csr_der=csr_der,
            days=days,
            sign=sign,
        )
        return result.record, result.replayed

    def get_certificate(self, serial_hex: str) -> CertificateRecord:
        return self._store.get_certificate(serial_hex)

    def revoke(self, serial_hex: str, reason: str) -> tuple[CertificateRecord, bool]:
        reason = policy.validate_reason(reason)
        now_iso = dt.datetime.now(dt.timezone.utc).isoformat()
        return self._store.revoke(serial_hex, reason, now_iso)

    def _build_crl(
        self, entries: list[RevokedRecord], number: int, now_iso: str
    ) -> str:
        now = dt.datetime.fromisoformat(now_iso)
        revoked_certs = []
        for entry in entries:
            revoked_at = dt.datetime.fromisoformat(entry.revoked_at)
            builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry.serial)
                .revocation_date(revoked_at)
                .add_extension(
                    x509.CRLReason(_REASON_MAP[entry.reason]),
                    critical=False,
                )
            )
            revoked_certs.append(builder.build())
        crl = self._ca.build_crl(revoked_certs, number, now)
        return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def publish_crl(self) -> tuple[str, int]:
        return self._store.publish_crl(self._build_crl)

    def current_crl(self) -> tuple[str, int]:
        current = self._store.get_current_crl()
        if current is not None:
            return current
        # Database created by an older build without an initial CRL: publish
        # CRL number 1 rather than exposing an uninitialized state.
        return self.publish_crl()
