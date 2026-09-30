"""Ledger anchoring: INTERFACE AND STUBS ONLY. Nothing is published publicly.

Spec 5.6 says production "writes the root to a public log on a schedule"
(for example a transparency log, blockchain, or notary). That is not
implemented. Which public log to use, how often, and the privacy trade-offs
are decisions for Stephan. ``LocalFileAnchor`` exists so the hook can be
exercised in tests; it only appends to a local file.
"""

from __future__ import annotations

import abc
import json
import time
from pathlib import Path


class Anchor(abc.ABC):
    @abc.abstractmethod
    def publish(self, signed_head: dict) -> dict:
        """Publish a signed ledger head. Return a receipt (JSON-serializable)."""


class NullAnchor(Anchor):
    def publish(self, signed_head: dict) -> dict:
        return {"anchor": "null", "published": False, "note": "no anchoring configured"}


class LocalFileAnchor(Anchor):
    """Appends signed heads to a local file. NOT a public transparency log."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def publish(self, signed_head: dict) -> dict:
        rec = {"anchored_at": time.time(), "signed_head": signed_head}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return {"anchor": "local-file", "published": False, "path": str(self.path),
                "size": signed_head.get("size"), "note": "local stub, not public"}
