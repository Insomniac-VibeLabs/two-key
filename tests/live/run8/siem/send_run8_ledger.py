# Sends a COPY of run 8's main ledger to the Elastic receiver through Two-Key's own SIEM sender (webhook sink),
# so the canary search covers the real run 8 entries. The copy gets two more entries (constitution_loaded,
# siem_configured); the original state/ is untouched.
import sys, time, io, contextlib
from pathlib import Path
from two_key.core import TwoKey
from two_key.ledger import Ledger
from two_key.keys import load_private_key_file
from two_key.constitution import load_envelope, verify_signed
from two_key.siem_sinks import siem_from_config
from two_key.testing import TEST_AGENT, FixedJudge
d = Path("r8copy"); key = load_private_key_file(str(d / "keys" / "principal.pem"))
led = Ledger(str(d / "ledger"), key); n0 = led.size()
con = verify_signed(load_envelope(d / "constitution.signed.json"), key.public_key())
siem = siem_from_config({"schema": "ecs", "format": "json", "replay_from": "start", "sinks": [
    {"type": "webhook", "url": "https://127.0.0.1:8443/ingest", "ca_file": "tls/ca.pem",
     "auth_value_file": "tls/token", "hmac_key_file": "tls/hmac", "label": "run8-copy"}]}, Path(".").resolve())
tk = TwoKey(led, key.public_key(), con, [FixedJudge("a", "yes")], private_key=key, allow_test_doubles=True,
            monitored_agent=TEST_AGENT, siem=siem)
ok = tk.delivery.drain(30)
for _ in range(60):
    if tk.delivery.states[0].seq >= led.size() - 1: break
    tk.delivery.drain(5)
print(f"ledger entries before={n0} after={led.size()} sink cursor={tk.delivery.states[0].seq}")
tk.close()
