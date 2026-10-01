"""Helpers for ACME end-to-end tests: JWS signing and an HTTP-01 responder."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_for(key: rsa.RSAPrivateKey) -> dict:
    nums = key.public_key().public_numbers()

    def encode_int(value: int) -> str:
        return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {"kty": "RSA", "n": encode_int(nums.n), "e": encode_int(nums.e)}


def thumbprint(jwk: dict) -> str:
    canonical = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b64url(hashlib.sha256(canonical).digest())


class AcmeUser:
    """An ACME account key with a small JWS-signing client."""

    def __init__(self, client, key: rsa.RSAPrivateKey | None = None):
        self.client = client
        self.key = key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.jwk = jwk_for(self.key)
        self.account_url: str | None = None
        self._nonce: str | None = None

    def _fresh_nonce(self) -> str:
        response = self.client.get("/acme/new-nonce")
        assert response.status_code == 204
        return response.headers["replay-nonce"]

    def post(
        self,
        url: str,
        payload: dict | None = None,
        *,
        use_jwk: bool = False,
        kid: str | None = None,
        nonce: str | None = None,
        corrupt_signature: bool = False,
        wrong_url: str | None = None,
        content_type: str = "application/jose+json",
    ):
        protected = {"alg": "RS256", "url": wrong_url or url, "nonce": nonce or self._fresh_nonce()}
        if use_jwk:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = kid or self.account_url
        protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode())
        if payload is None:
            payload_bytes = b""
        else:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        signing_input = f"{protected_b64}.{b64url(payload_bytes)}".encode("ascii")
        signature = self.key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        if corrupt_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])
        body = {
            "protected": protected_b64,
            "payload": b64url(payload_bytes),
            "signature": b64url(signature),
        }
        response = self.client.post(
            url, json=body, headers={"Content-Type": content_type}
        )
        if "replay-nonce" in response.headers:
            self._nonce = response.headers["replay-nonce"]
        return response

    def register(self, **kwargs):
        directory = self.client.get("/acme/directory").json()
        response = self.post(
            directory["newAccount"],
            {"contact": ["mailto:ops@lab.test"], "termsOfServiceAgreed": True},
            use_jwk=True,
            **kwargs,
        )
        if response.status_code in (200, 201):
            self.account_url = response.headers["location"]
        return response


class _ChallengeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.path.rsplit("/", 1)[-1]
        body = self.server.tokens.get(token)  # type: ignore[attr-defined]
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class ChallengeServer:
    """A minimal HTTP responder for HTTP-01 challenges on 127.0.0.1."""

    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _ChallengeHandler)
        self.server.tokens = {}  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self._thread.start()

    def set_response(self, token: str, key_authorization: str) -> None:
        self.server.tokens[token] = key_authorization  # type: ignore[attr-defined]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
