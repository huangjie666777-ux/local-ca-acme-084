"""End-to-end tests for the RFC 8555 subset."""

from __future__ import annotations

import datetime as dt
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.acme.service import AcmeService
from app.api import create_app
from app.ca import load_or_create_ca
from app.service import CAService
from app.storage import CAStore
from tests.acme_helpers import AcmeUser, ChallengeServer, b64url, thumbprint
from tests.conftest import make_csr_pem


@pytest.fixture()
def env(tmp_path):
    data_dir = str(tmp_path / "data")
    ca = load_or_create_ca(data_dir)
    store = CAStore(data_dir)
    ca_service = CAService(ca, store)
    ca_service.publish_crl()
    challenge = ChallengeServer()
    acme = AcmeService(store, ca_service, challenge_port=challenge.port)
    app = create_app(ca_service, acme)
    with TestClient(app) as client:
        yield type(
            "Env",
            (),
            {
                "data_dir": data_dir,
                "ca": ca,
                "store": store,
                "ca_service": ca_service,
                "acme": acme,
                "client": client,
                "challenge": challenge,
            },
        )()
    challenge.stop()


def _directory(env) -> dict:
    return env.client.get("/acme/directory").json()


def _csr_der(domain: str) -> bytes:
    pem = make_csr_pem(cn=domain, dns_names=[domain])
    return x509.load_pem_x509_csr(pem).public_bytes(serialization.Encoding.DER)


def _order(env, user: AcmeUser, domain: str = "api.lab.test") -> dict:
    directory = _directory(env)
    response = user.post(
        directory["newOrder"],
        {"identifiers": [{"type": "dns", "value": domain}]},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _fulfill_challenge(env, user: AcmeUser, order: dict) -> dict:
    authz_url = order["authorizations"][0]
    authz = user.post(authz_url).json()
    challenge = authz["challenges"][0]
    assert challenge["type"] == "http-01"
    env.challenge.set_response(
        challenge["token"], f"{challenge['token']}.{thumbprint(user.jwk)}"
    )
    response = user.post(challenge["url"], {})
    assert response.status_code == 200, response.text
    return response.json()


def _finalize(
    env, user: AcmeUser, order: dict, domain: str = "api.lab.test"
) -> tuple[dict, bytes]:
    csr_der = _csr_der(domain)
    response = user.post(order["finalize"], {"csr": b64url(csr_der)})
    assert response.status_code == 200, response.text
    return response.json(), csr_der


# ---------------------------------------------------------------------------
# Directory / nonce / account registration
# ---------------------------------------------------------------------------

def test_directory_lists_implemented_endpoints(env):
    directory = _directory(env)
    assert set(directory) == {"newNonce", "newAccount", "newOrder", "meta"}
    assert directory["newNonce"].endswith("/acme/new-nonce")
    assert directory["newAccount"].endswith("/acme/new-account")
    assert directory["newOrder"].endswith("/acme/new-order")


def test_new_nonce_header(env):
    response = env.client.get("/acme/new-nonce")
    assert response.status_code == 204
    assert response.headers["replay-nonce"]
    head = env.client.head("/acme/new-nonce")
    assert head.status_code == 204
    assert head.headers["replay-nonce"]


def test_new_account_registration_and_reuse(env):
    user = AcmeUser(env.client)
    directory = _directory(env)

    first = user.post(
        directory["newAccount"],
        {"contact": ["mailto:ops@lab.test"], "termsOfServiceAgreed": True},
        use_jwk=True,
    )
    assert first.status_code == 201
    assert first.headers["location"].endswith("/acme/acct/1")
    assert first.json()["status"] == "valid"
    assert first.json()["contact"] == ["mailto:ops@lab.test"]
    user.account_url = first.headers["location"]

    # Same key reuses the account: 200 with the same Location.
    second = user.post(
        directory["newAccount"],
        {"contact": ["mailto:other@lab.test"]},
        use_jwk=True,
    )
    assert second.status_code == 200
    assert second.headers["location"] == first.headers["location"]

    # A different key gets a different account.
    other = AcmeUser(env.client)
    registered = other.register()
    assert registered.status_code == 201
    assert registered.headers["location"] != first.headers["location"]


def test_new_account_rejects_small_key(env):
    user = AcmeUser(env.client, key=rsa.generate_private_key(65537, 1024))
    response = user.register()
    assert response.status_code == 400
    assert response.json()["type"].endswith("badPublicKey")


def test_jws_rejects_bad_signature(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    response = user.post(
        directory["newAccount"],
        {"termsOfServiceAgreed": True},
        use_jwk=True,
        corrupt_signature=True,
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("badSignature")


def test_jws_rejects_wrong_url(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    response = user.post(
        directory["newAccount"],
        {"termsOfServiceAgreed": True},
        use_jwk=True,
        wrong_url="http://testserver/acme/new-order",
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("malformed")


def test_jws_rejects_bad_nonce(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    response = user.post(
        directory["newAccount"],
        {"termsOfServiceAgreed": True},
        use_jwk=True,
        nonce="not-a-valid-nonce",
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("badNonce")
    assert response.headers["replay-nonce"]


def test_nonce_replay_succeeds_at_most_once(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    # Grab one nonce and use it for two concurrent registrations.
    nonce = env.client.get("/acme/new-nonce").headers["replay-nonce"]
    user._nonce = nonce
    responses = []

    def worker():
        responses.append(
            user.post(
                directory["newAccount"],
                {"termsOfServiceAgreed": True},
                use_jwk=True,
                nonce=nonce,
            )
        )

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == 1
    assert statuses.count(400) == 3
    assert all(
        r.json()["type"].endswith("badNonce") for r in responses if r.status_code == 400
    )


def test_unknown_kid_rejected(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    response = user.post(
        directory["newOrder"],
        {"identifiers": [{"type": "dns", "value": "api.lab.test"}]},
        kid="http://testserver/acme/acct/999",
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("accountDoesNotExist")


def test_post_requires_jose_content_type(env):
    user = AcmeUser(env.client)
    directory = _directory(env)
    response = user.post(
        directory["newAccount"],
        {"termsOfServiceAgreed": True},
        use_jwk=True,
        content_type="application/json",
    )
    assert response.status_code == 415


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------

def test_new_order_shape(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    assert order["status"] == "pending"
    assert order["identifiers"] == [{"type": "dns", "value": "api.lab.test"}]
    assert len(order["authorizations"]) == 1
    assert order["finalize"].endswith("/finalize")
    # 10-minute expiry.
    expires = dt.datetime.fromisoformat(order["expires"])
    assert expires > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=9)


def test_new_order_rejects_foreign_wildcard_multiple(env):
    user = AcmeUser(env.client)
    user.register()
    directory = _directory(env)

    bad_identifiers = [
        [{"type": "dns", "value": "evil.com"}],
        [{"type": "dns", "value": "*.lab.test"}],
        [{"type": "dns", "value": "api.lab.test"}, {"type": "dns", "value": "lab.test"}],
        [{"type": "ip", "value": "127.0.0.1"}],
    ]
    for identifiers in bad_identifiers:
        response = user.post(
            directory["newOrder"], {"identifiers": identifiers}
        )
        assert response.status_code == 400, (identifiers, response.text)
        assert response.json()["type"].endswith(
            ("rejectedIdentifier", "malformed")
        )


def test_post_as_get_requires_empty_payload(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    response = user.post(order["authorizations"][0], {"unexpected": True})
    assert response.status_code == 400
    assert response.json()["type"].endswith("malformed")


# ---------------------------------------------------------------------------
# HTTP-01 challenge
# ---------------------------------------------------------------------------

def test_http01_challenge_valid(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    authz = _fulfill_challenge(env, user, order)
    assert authz["status"] == "valid"
    assert authz["challenges"][0]["status"] == "valid"
    assert authz["identifier"] == {"type": "dns", "value": "api.lab.test"}


def test_http01_challenge_wrong_authorization_invalid(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    authz_url = order["authorizations"][0]
    authz = user.post(authz_url).json()
    challenge = authz["challenges"][0]
    # Serve the wrong keyAuthorization.
    env.challenge.set_response(challenge["token"], f"{challenge['token']}.wrongthumb")
    response = user.post(challenge["url"], {})
    assert response.status_code == 200
    assert response.json()["status"] == "invalid"
    assert response.json()["challenges"][0]["status"] == "invalid"


def test_http01_challenge_responder_down(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    authz = user.post(order["authorizations"][0]).json()
    challenge = authz["challenges"][0]
    # Nothing served on the challenge port: validation fails, not 500s.
    response = user.post(challenge["url"], {})
    assert response.status_code == 200
    assert response.json()["status"] == "invalid"


def test_challenge_post_is_idempotent(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    authz = _fulfill_challenge(env, user, order)
    challenge_url = authz["challenges"][0]["url"]
    again = user.post(challenge_url, {})
    assert again.json()["status"] == "valid"


# ---------------------------------------------------------------------------
# Finalize and certificate download
# ---------------------------------------------------------------------------

def test_finalize_requires_valid_authorization(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    response = user.post(order["finalize"], {"csr": b64url(_csr_der("api.lab.test"))})
    assert response.status_code == 403
    assert response.json()["type"].endswith("orderNotReady")


def test_finalize_success_and_certificate_download(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    finalized, _csr = _finalize(env, user, order)
    assert finalized["status"] == "valid"
    assert finalized["certificate"].endswith("/cert")

    response = user.post(finalized["certificate"])
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pem-certificate-chain"
    chain = response.content
    leaf = x509.load_pem_x509_certificate(chain)
    assert leaf.issuer == env.ca.cert.subject
    san = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert san == ["api.lab.test"]
    # Fixed 7-day lifetime.
    assert 6 <= (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 7
    # Chain verifies against the downloaded CA.
    env.ca.cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )
    # The CA certificate follows the leaf in the chain.
    assert chain.count(b"BEGIN CERTIFICATE") == 2


def test_finalize_san_mismatch(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user, domain="api.lab.test")
    _fulfill_challenge(env, user, order)
    response = user.post(
        order["finalize"], {"csr": b64url(_csr_der("other.lab.test"))}
    )
    assert response.status_code == 400
    assert response.json()["type"].endswith("badCSR")


def test_finalize_wildcard_csr(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    pem = make_csr_pem(cn="*.lab.test", dns_names=["*.lab.test"])
    csr_der = x509.load_pem_x509_csr(pem).public_bytes(serialization.Encoding.DER)
    response = user.post(order["finalize"], {"csr": b64url(csr_der)})
    assert response.status_code == 400
    assert response.json()["type"].endswith("badCSR")


def test_finalize_garbage_csr(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    response = user.post(order["finalize"], {"csr": b64url(b"not a csr")})
    assert response.status_code == 400
    assert response.json()["type"].endswith("badCSR")


def test_finalize_different_csr_conflicts(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    _finalize(env, user, order)
    other = _csr_der("api.lab.test")
    response = user.post(order["finalize"], {"csr": b64url(other)})
    assert response.status_code == 409
    assert response.json()["type"].endswith("badCSR")


def test_concurrent_finalize_same_csr_single_cert(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    csr_der = _csr_der("api.lab.test")
    results: list = []
    errors: list = []

    def worker():
        try:
            results.append(
                user.post(order["finalize"], {"csr": b64url(csr_der)}).json()
            )
        except BaseException as exc:  # pragma: no cover - diagnostic only
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 6
    assert {r["status"] for r in results} == {"valid"}
    assert len({r["certificate"] for r in results}) == 1


def test_certificate_download_before_finalize(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    response = user.post(
        order["finalize"].replace("/finalize", "/cert"),
    )
    assert response.status_code == 403
    assert response.json()["type"].endswith("orderNotReady")


# ---------------------------------------------------------------------------
# Isolation, expiry, restart
# ---------------------------------------------------------------------------

def test_accounts_cannot_access_each_others_orders(env):
    alice = AcmeUser(env.client)
    alice.register()
    order = _order(env, alice)

    bob = AcmeUser(env.client)
    bob.register()
    response = bob.post(order["authorizations"][0])
    assert response.status_code == 404
    # POST-as-GET on the order itself is also denied.
    response = bob.post(order["finalize"].removesuffix("/finalize"))
    assert response.status_code == 404


def test_expired_order_rejected(env):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    # Push the order into the past.
    env.store.acme_force_expire(
        int(order["finalize"].rsplit("/", 2)[-2]),
        (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat(),
    )
    response = user.post(order["finalize"], {"csr": b64url(_csr_der("api.lab.test"))})
    assert response.status_code == 403
    assert response.json()["type"].endswith("orderNotReady")


def test_restart_continues_accounts_and_orders(env, tmp_path):
    user = AcmeUser(env.client)
    user.register()
    order = _order(env, user)
    _fulfill_challenge(env, user, order)
    finalized, csr_der = _finalize(env, user, order)

    # Simulate a full process restart: new service objects on the same data.
    data_dir = env.data_dir
    ca2 = load_or_create_ca(data_dir)
    store2 = CAStore(data_dir)
    ca_service2 = CAService(ca2, store2)
    acme2 = AcmeService(store2, ca_service2, challenge_port=env.challenge.port)
    app2 = create_app(ca_service2, acme2)
    with TestClient(app2) as client2:
        restarted = AcmeUser(client2, key=user.key)
        directory = _directory(type("E", (), {"client": client2})())
        # Same key reuses the account.
        again = restarted.post(
            directory["newAccount"], {"termsOfServiceAgreed": True}, use_jwk=True
        )
        assert again.status_code == 200
        assert again.headers["location"] == user.account_url
        restarted.account_url = user.account_url
        # The order and its certificate are still reachable; re-finalizing the
        # same CSR replays the certificate.
        got = restarted.post(order["finalize"], {"csr": b64url(csr_der)})
        assert got.status_code == 200
        assert got.json()["status"] == "valid"
        cert = restarted.post(finalized["certificate"])
        assert cert.status_code == 200
        assert cert.headers["content-type"] == "application/pem-certificate-chain"


def test_old_api_rejects_bool_and_string_days(env):
    csr_pem = make_csr_pem(dns_names=["days.lab.test"])
    for bad_days in (True, False, "7", 7.0):
        response = env.client.post(
            "/certificates",
            json={"csr": csr_pem.decode(), "days": bad_days, "idempotency_key": "d"},
        )
        assert response.status_code == 422, (bad_days, response.text)
