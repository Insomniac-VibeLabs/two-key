"""Two-Key: dual-path authorization for AI agents.

A tool call runs only if Path A (policy VM) and Path B (judge quorum) both
allow. It has no scanning engine of its own: from 0.6.0 ``two_key.scan`` calls
the operator's antivirus or DLP product. It is not a SIEM either: from 0.7.0
``two_key.siem`` copies allowlisted ledger fields to the operator's collector.
"""

__version__ = "0.7.2"

from .core import Decision, TwoKey

__all__ = ["Decision", "TwoKey", "__version__"]
