import sys, time, statistics, json
from pathlib import Path
from two_key.core import TwoKey
from two_key.ledger import Ledger
from two_key.keys import load_private_key_file, generate_private_key
from two_key.constitution import sign_constitution, verify_signed
from two_key.siem_sinks import siem_from_config
from two_key.strict import load_file_strict
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge
from cryptography.hazmat.primitives import serialization
yaml_path, d, phase, n = sys.argv[1], Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
d.mkdir(exist_ok=True)
kp = d / "principal.pem"
if not kp.exists():
    k = generate_private_key()
    kp.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())); kp.chmod(0o600)
key = load_private_key_file(str(kp))
rules = [{"id": "tools", "allow_only_tools": ["search", "email_draft"]}, {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}}]
specs = {"search": {"irreversible": False, "data_class_floor": "public"},
         "email_draft": {"irreversible": False, "data_class_floor": "public", "counterparties": [{"json_path": "to", "allow": ["ada@example"]}]}}
con = verify_signed(sign_constitution("Never wire money. Drafts are allowed.", rules, key, specs), key.public_key())
block = load_file_strict(yaml_path); block = block.get("siem", block); block = dict(block); block["replay_from"] = "cursor"
siem = siem_from_config(block, Path(yaml_path).resolve().parent)
led = Ledger(str(d / "ledger"), key); n0 = led.size()
t0 = time.perf_counter()
tk = TwoKey(led, key.public_key(), con, [FixedJudge("a", "yes", provider="p", maker="m"), FixedJudge("b", "yes", provider="q", maker="n")],
            private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT, siem=siem)
start_ms = (time.perf_counter() - t0) * 1000
ms = []
for i in range(n):
    t = time.perf_counter()
    if i % 2: r = tk.authorize({"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True}, {}, "wire")
    else: r = tk.authorize({"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False}, {"to": "ada@example"}, "draft")
    ms.append((time.perf_counter() - t) * 1000)
time.sleep(float(sys.argv[5]) if len(sys.argv) > 5 else 3.0)
st = tk.delivery.states[0]
out = {"phase": phase, "ledger_before": n0, "ledger_after": led.size(), "start_ms": round(start_ms, 1), "calls": n,
       "sink_cursor_before_close": st.seq, "failing": st.failed_at is not None}
if ms: out.update({"median_ms": round(statistics.median(ms), 2), "max_ms": round(max(ms), 2)})
tk.close()
print(json.dumps(out))
