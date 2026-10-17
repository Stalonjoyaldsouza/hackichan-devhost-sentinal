"""Identity registry. Callers prove identity with an opaque credential; actor IDs supplied in a
request are never trusted. Only credential hashes are stored."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from enum import StrEnum


class PrincipalKind(StrEnum):
    AGENT = "agent"
    HUMAN = "human"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: PrincipalKind
    roles: tuple[str, ...]


class AuthenticationError(Exception):
    pass


def _h(credential: str) -> str:
    return hashlib.sha256(credential.encode()).hexdigest()


class IdentityRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_hash: dict[str, Principal] = {}
        self._ids: set[str] = set()

    def register(self, principal_id: str, kind: PrincipalKind, roles: tuple[str, ...] = ()) -> str:
        with self._lock:
            if principal_id in self._ids:
                raise ValueError(f"principal {principal_id!r} already registered")
            credential = secrets.token_urlsafe(32)
            self._by_hash[_h(credential)] = Principal(principal_id, kind, tuple(roles))
            self._ids.add(principal_id)
            return credential

    def authenticate(self, credential: str) -> Principal:
        if not isinstance(credential, str) or not credential:
            raise AuthenticationError("missing credential")
        digest = _h(credential)
        with self._lock:
            for known, principal in self._by_hash.items():
                if hmac.compare_digest(known, digest):
                    return principal
        raise AuthenticationError("invalid credential")
