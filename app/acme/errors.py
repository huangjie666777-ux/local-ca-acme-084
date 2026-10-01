"""ACME problem-document error (RFC 8555 §6.7)."""

from __future__ import annotations


class AcmeError(Exception):
    """An error that maps to an ``application/problem+json`` response.

    ``acme_type`` is the short name (e.g. ``"malformed"``) and is rendered as
    ``urn:ietf:params:acme:error:<acme_type>``.
    """

    def __init__(self, status: int, acme_type: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.acme_type = acme_type
        self.detail = detail
