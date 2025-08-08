"""
Temporary relay state storage for bridging OAuth redirects.

This module allows our server to act as the registered redirect URI with Google
while still notifying a local OAuth client (e.g., Cursor/VSCode) that expects
to receive the authorization code on a loopback address.

Flow:
- Client hits our /oauth2/authorize with its own redirect_uri and optional state
- We create a relay entry mapping a short relay_id -> (client_redirect_uri, client_state)
- We send Google a state like "relay:<relay_id>" and force redirect_uri to our server callback
- When Google calls /oauth2callback with ?code=...&state=relay:<relay_id>, we look up the
  original client redirect and 302 the browser to that local URI with ?code=...&state=<client_state>

Security notes:
- Only loopback client redirect URIs are allowed (localhost/127.0.0.1)
- Entries expire quickly and are single-use
"""

import time
import secrets
import threading
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse


RELAY_STATE_PREFIX = "relay:"
DEFAULT_TTL_SECONDS = 600  # 10 minutes


@dataclass
class RelayEntry:
    client_redirect_uri: str
    client_state: Optional[str]
    created_at: float
    ttl_seconds: int

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


class OAuthRelayStateStore:
    def __init__(self) -> None:
        self._entries: Dict[str, RelayEntry] = {}
        self._code_entries: Dict[str, float] = {}
        self._lock = threading.RLock()

    def _is_loopback_uri(self, uri: str) -> bool:
        try:
            parsed = urlparse(uri)
            if parsed.scheme != "http":
                return False
            host = (parsed.hostname or "").lower()
            return host in {"localhost", "127.0.0.1"}
        except Exception:
            return False

    def create(self, client_redirect_uri: str, client_state: Optional[str], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
        if not self._is_loopback_uri(client_redirect_uri):
            raise ValueError("Client redirect URI must be loopback (http://localhost or http://127.0.0.1)")

        relay_id = secrets.token_hex(16)
        entry = RelayEntry(
            client_redirect_uri=client_redirect_uri,
            client_state=client_state,
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
        )
        with self._lock:
            self._entries[relay_id] = entry
        return RELAY_STATE_PREFIX + relay_id

    def consume(self, relay_state: str) -> Optional[Tuple[str, Optional[str]]]:
        if not relay_state.startswith(RELAY_STATE_PREFIX):
            return None
        relay_id = relay_state[len(RELAY_STATE_PREFIX):]
        with self._lock:
            entry = self._entries.pop(relay_id, None)
        if not entry:
            return None
        if entry.is_expired():
            return None
        return entry.client_redirect_uri, entry.client_state

    def register_code_for_relay(self, code: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        now = time.time()
        with self._lock:
            # Clean old codes
            expired = [c for c, t in self._code_entries.items() if (now - t) > ttl_seconds]
            for c in expired:
                self._code_entries.pop(c, None)
            self._code_entries[code] = now

    def is_code_relay(self, code: Optional[str], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> bool:
        if not code:
            return False
        now = time.time()
        with self._lock:
            ts = self._code_entries.get(code)
            if ts is None:
                return False
            if (now - ts) > ttl_seconds:
                # Expired
                self._code_entries.pop(code, None)
                return False
            return True


_global_store = OAuthRelayStateStore()


def create_relay_state(client_redirect_uri: str, client_state: Optional[str]) -> str:
    return _global_store.create(client_redirect_uri, client_state)


def consume_relay_state(relay_state: str) -> Optional[Tuple[str, Optional[str]]]:
    return _global_store.consume(relay_state)


def is_relay_state(state: Optional[str]) -> bool:
    return bool(state and state.startswith(RELAY_STATE_PREFIX))


def register_code_for_relay(code: str) -> None:
    _global_store.register_code_for_relay(code)


def is_code_relay(code: Optional[str]) -> bool:
    return _global_store.is_code_relay(code)
