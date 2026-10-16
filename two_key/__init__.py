"""Two-Key: dual-path authorization for AI agents.

A tool call runs only if Path A (policy VM) and Path B (judge quorum) both
allow. It has no scanning, antivirus, or DLP hooks.
"""

__version__ = "0.6.0"

from .core import Decision, TwoKey

__all__ = ["Decision", "TwoKey", "__version__"]
