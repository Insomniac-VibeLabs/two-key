"""A Python scanner hook for tests/test_scanners.py: ``scan_hook_fixture:inspect``."""

from two_key.scan import ScanResult

label = "fixture"


def inspect(request):
    if any(b"FAKE-SECRET" in part.data for part in request.parts):
        return ScanResult.flagged("secret")
    return ScanResult.clean()
