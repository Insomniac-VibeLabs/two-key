"""Two-Key concept: dual-path authorization for AI agents.

A tool call runs only if Path A (policy VM) and Path B (judge quorum) both
allow. This package is the initial concept. It has no scanning, antivirus,
or DLP hooks.
"""

__version__ = "0.3.1"

from .core import Decision, TwoKey

__all__ = ["Decision", "TwoKey", "__version__"]
