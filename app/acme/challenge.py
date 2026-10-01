"""HTTP-01 challenge responder fetch (RFC 8555 §8.3).

The responder is always contacted on the local machine (127.0.0.1) on a
configurable port, while the HTTP Host header carries the target domain so
the local web server can select the right vhost. Redirects are forbidden and
the response is bounded in size and time.
"""

from __future__ import annotations

import httpx

CHALLENGE_PATH = "/.well-known/acme-challenge/"
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5.0


class ChallengeError(Exception):
    """Raised when the challenge responder cannot be read or is malformed."""


def fetch_http01(domain: str, token: str, port: int) -> str:
    """Fetch the keyAuthorization for ``token`` from the local responder."""
    url = f"http://127.0.0.1:{port}{CHALLENGE_PATH}{token}"
    try:
        with httpx.Client(trust_env=False) as client:
            with client.stream(
                "GET",
                url,
                headers={"Host": domain},
                follow_redirects=False,
                timeout=TIMEOUT_SECONDS,
            ) as response:
                if response.status_code != 200:
                    raise ChallengeError(
                        f"challenge responder returned HTTP {response.status_code}"
                    )
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise ChallengeError("challenge response too large")
                    chunks.append(chunk)
    except ChallengeError:
        raise
    except httpx.HTTPError as exc:
        raise ChallengeError(f"challenge responder request failed: {exc}")

    body = b"".join(chunks)
    # A trailing newline written by hand is harmless; the token itself has none.
    return body.decode("utf-8", errors="replace").strip()
