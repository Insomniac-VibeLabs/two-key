"""Path B judges: the abstract interface and adapters (connectors are added in judges/*.py)."""

from .base import Ballot, Judge

__all__ = ["Ballot", "Judge"]
