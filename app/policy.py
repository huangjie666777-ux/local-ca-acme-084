"""Certificate policy: CSR and request validation, SAN normalization."""

from __future__ import annotations

import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

MIN_RSA_KEY_SIZE = 2048
MIN_DAYS = 1
MAX_DAYS = 30
MAX_IDEMPOTENCY_KEY_LEN = 128

# lab.test plus any non-empty sub-domain label chain.
_ROOT_LABELS = ("lab", "test")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class PolicyError(ValueError):
    """Raised when a CSR or issuance request violates the local policy."""


def validate_days(days: object) -> int:
    if isinstance(days, bool) or not isinstance(days, int):
        raise PolicyError("days must be an integer")
    if not (MIN_DAYS <= days <= MAX_DAYS):
        raise PolicyError(f"days must be between {MIN_DAYS} and {MAX_DAYS}")
    return days


def validate_idempotency_key(key: object) -> str:
    if not isinstance(key, str) or not key.strip():
        raise PolicyError("idempotency_key must be a non-empty string")
    key = key.strip()
    if len(key) > MAX_IDEMPOTENCY_KEY_LEN:
        raise PolicyError(
            f"idempotency_key must be at most {MAX_IDEMPOTENCY_KEY_LEN} characters"
        )
    return key


def normalize_dns_name(raw: object) -> str:
    """Validate and normalize one DNS name. Rejects wildcards and non-lab.test."""
    if not isinstance(raw, str) or not raw:
        raise PolicyError("SAN contains an empty DNS name")
    name = raw.strip().lower().rstrip(".")
    if "*" in name:
        raise PolicyError("wildcard DNS names are not allowed")
    if not name or len(name) > 253:
        raise PolicyError("invalid DNS name length")
    labels = name.split(".")
    if any(_LABEL_RE.match(label) is None for label in labels):
        raise PolicyError(f"invalid DNS name: {raw!r}")
    if labels != list(_ROOT_LABELS) and (
        len(labels) <= 2 or labels[-2:] != list(_ROOT_LABELS)
    ):
        raise PolicyError("only lab.test and its sub-domains are allowed")
    return name


# Backwards-compatible alias.
_normalize_dns_name = normalize_dns_name


def validate_csr(csr: x509.CertificateSigningRequest) -> list[str]:
    """Validate CSR signature/key/SAN. Returns de-duplicated, sorted DNS SANs."""
    try:
        signature_valid = csr.is_signature_valid
    except UnsupportedAlgorithm as exc:
        raise PolicyError(f"unsupported CSR signature algorithm: {exc}") from exc
    if not signature_valid:
        raise PolicyError("CSR signature is invalid")

    public_key = csr.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PolicyError("only RSA public keys are supported")
    if public_key.key_size < MIN_RSA_KEY_SIZE:
        raise PolicyError(
            f"RSA key must be at least {MIN_RSA_KEY_SIZE} bits, "
            f"got {public_key.key_size}"
        )

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        # CN must never be used as a SAN substitute.
        raise PolicyError("CSR must include a non-empty subjectAltName extension")

    general_names = list(san_ext.value)
    if not general_names:
        raise PolicyError("subjectAltName must be non-empty")

    normalized: set[str] = set()
    for general_name in general_names:
        # Only DNS names are permitted: no IP, URI, email, directoryName, etc.
        if not isinstance(general_name, x509.DNSName):
            raise PolicyError("subjectAltName may only contain DNS names")
        normalized.add(_normalize_dns_name(general_name.value))

    return sorted(normalized)


# Allowed RFC 5280 CRL revocation reasons. remove_from_crl is excluded because
# revocation is irreversible for this service.
ALLOWED_REVOCATION_REASONS = frozenset(
    {
        "unspecified",
        "key_compromise",
        "ca_compromise",
        "affiliation_changed",
        "superseded",
        "cessation_of_operation",
        "certificate_hold",
        "privilege_withdrawn",
        "aa_compromise",
    }
)


def validate_reason(reason: object) -> str:
    if not isinstance(reason, str) or reason not in ALLOWED_REVOCATION_REASONS:
        allowed = ", ".join(sorted(ALLOWED_REVOCATION_REASONS))
        raise PolicyError(f"reason must be one of: {allowed}")
    return reason
