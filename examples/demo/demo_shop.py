# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Demo Shop: a pretend payments server for the Two-Key demo. Nothing real is paid."""

import json
import time
from pathlib import Path
from typing import Annotated

from pydantic import Field

from mcp.server.mcpserver import MCPServer

BOOK = Path.home() / "demo-shop-payments.txt"
server = MCPServer("demo-shop")


@server.tool()
def pay_vendor(
    vendor: Annotated[str, Field(description="Vendor id: one lower-case word, such as acme. No display name.")],
    amount: Annotated[float, Field(description="Amount in US dollars, a number such as 25.50.")],
    memo: Annotated[str, Field(description="What the payment is for.")] = "",
) -> str:
    """Pay a vendor an amount in US dollars."""
    line = json.dumps({"time": time.strftime("%H:%M:%S"), "vendor": vendor, "amount": amount, "memo": memo})
    with BOOK.open("a", encoding="utf-8") as book:
        book.write(line + "\n")
    return f"Paid {vendor} ${amount:.2f} (pretend money)."


@server.tool()
def delete_all_records() -> str:
    """Delete every payment record."""
    BOOK.unlink(missing_ok=True)
    return "Deleted every record."


if __name__ == "__main__":
    server.run()
