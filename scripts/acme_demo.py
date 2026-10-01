#!/usr/bin/env python3
"""ACME HTTP-01 demo client for the local test CA.

Drives the full RFC 8555 flow against a running local test CA:
directory -> newNonce -> newAccount -> newOrder -> http-01 challenge ->
finalize -> certificate download. Uses only the Python standard library plus
cryptography.

Usage:
  # 1. Start the CA with the challenge port the responder will use:
  ACME_CHALLENGE_PORT=8099 .venv/bin/python -m uvicorn app.main:app \\
      --host 127.0.0.1 --port 8000

  # 2. Start the challenge responder (serves webroot/.well-known/acme-challenge):
  .venv/bin/python scripts/http01_responder.py --port 8099 --webroot ./webroot

  # 3. Run the demo:
  .venv/bin/python scripts/acme_demo.py --server http://127.0.0.1:8000 \\
      --domain api.lab.test --webroot ./webroot
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def make_csr_der(domain: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


class AcmeClient:
    def __init__(self, server: str):
        self.server = server.rstrip("/")
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = self.key.public_key().public_numbers()

        def encode_int(value: int) -> str:
            return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

        self.jwk = {"kty": "RSA", "n": encode_int(nums.n), "e": encode_int(nums.e)}
        canonical = json.dumps(
            {"e": self.jwk["e"], "kty": "RSA", "n": self.jwk["n"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.thumbprint = b64url(hashlib.sha256(canonical).digest())
        self.account_url: str | None = None
        self._nonce: str | None = None

    def _request(self, method: str, url: str, body: bytes | None = None,
                 headers: dict | None = None):
        request = urllib.request.Request(
            url, data=body, method=method, headers=headers or {}
        )
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as exc:
            response = exc
        return response.status, dict(response.headers), response.read()

    def _get_nonce(self) -> str:
        status, headers, _ = self._request("GET", self.server + "/acme/new-nonce")
        assert status == 204, (status, _)
        return headers["Replay-Nonce"]

    def _post(self, url: str, payload: dict | None = None, *, use_jwk: bool = False):
        nonce = self._nonce or self._get_nonce()
        self._nonce = None
        protected = {"alg": "RS256", "url": url, "nonce": nonce}
        if use_jwk:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.account_url
        protected_b64 = b64url_json(protected)
        payload_bytes = b"" if payload is None else json.dumps(
            payload, separators=(",", ":")
        ).encode("utf-8")
        signing_input = f"{protected_b64}.{b64url(payload_bytes)}".encode("ascii")
        signature = self.key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        body = json.dumps(
            {
                "protected": protected_b64,
                "payload": b64url(payload_bytes),
                "signature": b64url(signature),
            }
        ).encode("utf-8")
        status, headers, data = self._request(
            "POST",
            url,
            body,
            {"Content-Type": "application/jose+json"},
        )
        if "Replay-Nonce" in headers:
            self._nonce = headers["Replay-Nonce"]
        return status, headers, data

    def directory(self) -> dict:
        _, _, data = self._request("GET", self.server + "/acme/directory")
        return json.loads(data)

    def register(self, directory: dict) -> str:
        status, headers, data = self._post(
            directory["newAccount"],
            {"termsOfServiceAgreed": True},
            use_jwk=True,
        )
        assert status in (200, 201), (status, data)
        self.account_url = headers["Location"]
        return self.account_url

    def new_order(self, directory: dict, domain: str):
        status, headers, data = self._post(
            directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": domain}]},
        )
        assert status == 201, (status, data)
        return json.loads(data), headers["Location"]

    def post_as_get(self, url: str) -> dict:
        status, _, data = self._post(url)
        assert status == 200, (status, data)
        return json.loads(data)

    def post_challenge(self, url: str) -> dict:
        status, _, data = self._post(url, {})
        assert status == 200, (status, data)
        return json.loads(data)

    def finalize(self, url: str, csr_der: bytes) -> dict:
        status, _, data = self._post(url, {"csr": b64url(csr_der)})
        assert status == 200, (status, data)
        return json.loads(data)

    def get_certificate(self, url: str) -> bytes:
        status, _, data = self._post(url)
        assert status == 200, (status, data)
        return data


def main() -> None:
    parser = argparse.ArgumentParser(description="ACME HTTP-01 demo client")
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--domain", default="api.lab.test")
    parser.add_argument("--webroot", default="./webroot")
    parser.add_argument("--out", default="./issued")
    args = parser.parse_args()

    acme_dir = os.path.join(args.webroot, ".well-known", "acme-challenge")
    os.makedirs(acme_dir, exist_ok=True)
    os.makedirs(args.out, exist_ok=True)

    client = AcmeClient(args.server)
    directory = client.directory()
    print(f"[1/6] directory: {directory['newAccount']}")

    client.register(directory)
    print(f"[2/6] account registered: {client.account_url}")

    order, _order_url = client.new_order(directory, args.domain)
    print(f"[3/6] order created: status={order['status']}")

    authz = client.post_as_get(order["authorizations"][0])
    challenge = authz["challenges"][0]
    token = challenge["token"]
    key_authorization = f"{token}.{client.thumbprint}"
    with open(os.path.join(acme_dir, token), "w", encoding="utf-8") as handle:
        handle.write(key_authorization)
    print(f"[4/6] challenge token written; posting challenge...")
    result = client.post_challenge(challenge["url"])
    print(f"      authorization status: {result['status']}")
    assert result["status"] == "valid", "challenge did not validate"

    csr_der = make_csr_der(args.domain)
    finalized = client.finalize(order["finalize"], csr_der)
    print(f"[5/6] order status: {finalized['status']}")
    assert finalized["status"] == "valid", "order did not finalize"

    cert_pem = client.get_certificate(finalized["certificate"])
    cert_path = os.path.join(args.out, f"{args.domain}.pem")
    with open(cert_path, "wb") as handle:
        handle.write(cert_pem)
    print(f"[6/6] certificate saved to {cert_path}")
    print(
        f"      verify: openssl verify -CAfile "
        f"<(curl -s {args.server}/ca/certificate) {cert_path}"
    )


if __name__ == "__main__":
    main()
