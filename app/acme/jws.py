"""JWS verification and JWK handling for ACME (RFC 8555 §6, RFC 7638).

Only RS256 (RSA PKCS#1 v1.5 with SHA-256) is accepted. New-account requests
authenticate with a JWK; every other request authenticates with a kid that
names a previously registered account.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import AcmeError

MIN_RSA_KEY_SIZE = 2048

NonceValidator = Callable[[str], None]
AccountLookup = Callable[[str], object]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str):
        raise AcmeError(400, "malformed", "base64url field must be a string")
    try:
        padding_len = -len(data) % 4
        return base64.urlsafe_b64decode(data + ("=" * padding_len))
    except (ValueError, TypeError) as exc:
        raise AcmeError(400, "malformed", f"invalid base64url encoding: {exc}")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint of an RSA public JWK."""
    canonical = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b64url_encode(hashlib.sha256(canonical).digest())


def jwk_to_public_key(jwk: object) -> rsa.RSAPublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise AcmeError(400, "badPublicKey", "only RSA public keys are supported")
    try:
        modulus = int.from_bytes(b64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(b64url_decode(jwk["e"]), "big")
    except (KeyError, TypeError, ValueError):
        raise AcmeError(400, "badPublicKey", "invalid RSA JWK")
    if modulus.bit_length() < MIN_RSA_KEY_SIZE:
        raise AcmeError(
            400,
            "badPublicKey",
            f"RSA key must be at least {MIN_RSA_KEY_SIZE} bits, "
            f"got {modulus.bit_length()}",
        )
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def _url_matches(protected_url: object, request_url: str) -> bool:
    if not isinstance(protected_url, str) or not protected_url:
        return False
    from urllib.parse import urlparse

    protected, request = urlparse(protected_url), urlparse(request_url)
    if protected.path != request.path:
        return False
    # When the client sends an absolute URL, the host must match too.
    if protected.netloc and protected.netloc != request.netloc:
        return False
    return True


def verify_jws(
    body: bytes,
    *,
    request_url: str,
    nonce_validator: NonceValidator,
    account_lookup: AccountLookup,
) -> tuple[dict, bytes, object | None]:
    """Verify a JWS-signed ACME request body.

    Returns ``(protected_header, payload_bytes, account_or_None)``. The account
    is ``None`` only for JWK-authenticated new-account requests.
    """
    try:
        document = json.loads(body)
        protected_b64 = document["protected"]
        payload_b64 = document["payload"]
        signature_b64 = document["signature"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AcmeError(400, "malformed", f"invalid JWS object: {exc}")

    try:
        protected = json.loads(b64url_decode(protected_b64))
        payload = b64url_decode(payload_b64)
        signature = b64url_decode(signature_b64)
    except AcmeError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AcmeError(400, "malformed", f"invalid JWS encoding: {exc}")

    if not isinstance(protected, dict):
        raise AcmeError(400, "malformed", "protected header must be a JSON object")
    if protected.get("alg") != "RS256":
        raise AcmeError(
            400, "badSignatureAlgorithm", "only RS256 signatures are supported"
        )
    if not _url_matches(protected.get("url"), request_url):
        raise AcmeError(400, "malformed", "protected url does not match the request")
    nonce = protected.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise AcmeError(400, "badNonce", "JWS protected header is missing a nonce")
    # Validator raises badNonce for unknown/expired/replayed nonces.
    nonce_validator(nonce)

    has_jwk = "jwk" in protected
    has_kid = "kid" in protected
    if has_jwk == has_kid:
        raise AcmeError(
            400, "malformed", "JWS must carry exactly one of jwk or kid"
        )

    if has_jwk:
        jwk = protected["jwk"]
        key = jwk_to_public_key(jwk)
        account = None
    else:
        kid = protected["kid"]
        account = account_lookup(kid)
        if account is None:
            raise AcmeError(
                403,
                "accountDoesNotExist",
                "kid does not identify a registered account",
            )
        jwk = json.loads(account.jwk_json)
        key = jwk_to_public_key(jwk)

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    try:
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise AcmeError(400, "badSignature", "JWS signature is invalid")

    return protected, payload, account
