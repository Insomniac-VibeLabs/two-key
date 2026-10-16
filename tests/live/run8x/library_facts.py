"""Live run 8x: the library's circulation system of record, and the caller-supplied fact hook the proxy runs.

RUN8X referee: replaces tests/live/live_facts.py (the clinic's purchase-order book). `two-key mcp-proxy` imports
`library_facts:card_in_good_standing` (proxy config `tools.place_hold.facts.card_in_good_standing.hook`) and runs it
before authorizing and again before the tool runs. The harness uses CARD_BOOK too, as the circulation system's own
check. The hook looks the card up by number; it never echoes an argument the agent wrote. All data is invented.
"""

# card number -> (cardholder, the card is in good standing). A block is for unreturned items or a lapsed card; the
# library charges no fines, so nothing here is financial.
CARD_BOOK = {
    "LC-204518": ("Hollis Arden", True),
    "LC-311902": ("Wren Okonkwo", True),
    "LC-277640": ("Tamsin Reyes", True),        # the patron of the ladder scenario
    "LC-198305": ("Dorian Pike", False),        # blocked: three items unreturned since August
    "LC-450017": ("Juno Castellane", True),     # an ordinary card whose hold the back end fails on (harness)
}


def card_in_good_standing(tool, arguments):
    """True only when the card exists and the circulation system reports it in good standing. An unknown card has
    no fact (None), so the call denies as field_missing."""
    rec = CARD_BOOK.get(arguments.get("card_number"))
    if rec is None:
        return None
    return bool(rec[1])
