"""Enterprise decision events to a SIEM over syslog TLS (RFC 5424 / RFC 5425).

The payload is the decision, the tool name, and digests. It does not include
raw arguments, the proposal text, or any ledger key. A send failure is reported
and does not change the decision.
"""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def message(event: dict[str, Any]) -> bytes:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    body = json.dumps(event, sort_keys=True, separators=(",", ":"))
    # local0.info. Structured data is unused; the JSON is the message.
    return f"<134>1 {ts} two-key two-key - - - {body}\n".encode("utf-8")


def send(host: str, port: int, event: dict[str, Any], *, timeout: float = 5.0,
         cafile: str | None = None) -> bool:
    """Send one event. Returns False if the SIEM cannot be reached or rejects the TLS handshake."""
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(message(event))
        return True
    except (OSError, ssl.SSLError, TimeoutError):
        return False
