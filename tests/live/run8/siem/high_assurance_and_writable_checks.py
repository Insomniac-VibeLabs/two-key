import sys, os, io, contextlib, tempfile, json
from pathlib import Path
from unittest import mock
sys.path.insert(0, "/workspace/tk-run8"); sys.path.insert(0, "/workspace/tk-run8/tests")
import test_siem as T
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.quorum import QuorumPolicy
from two_key.siem_sinks import siem_from_config
from two_key.ledger import Ledger
d = Path(tempfile.mkdtemp())
key = T.generate_private_key()
con = T.verify_signed(T.sign_constitution("Searching is fine. Paying needs care.", T.RULES, key, T.SPECS, fields=T.FIELDS), key.public_key())
def start(name, **kw):
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            tk = TwoKey(Ledger(d / name, key), key.public_key(), con, kw.pop("judges", [T.FixedJudge("a","yes")]),
                        private_key=key, allow_test_doubles=True, monitored_agent=T.TEST_AGENT, **kw)
        tk.close(); res = "STARTED"
    except TwoKeyConfigError as e:
        res = "REFUSED: " + str(e)[:220]
    led = d / name
    size = sum(1 for _ in open(led)) if led.exists() and led.is_file() else "n/a"
    print(f"[{name}] {res} | stderr: {' / '.join(l[:160] for l in err.getvalue().splitlines() if 'WARN' in l or 'writable' in l.lower())[:400]} | ledger lines: {size}")
HA = lambda: QuorumPolicy.high_assurance(required_yes=2, timeout_seconds=10)
for transport, port in (("udp", 5514), ("tcp", 5514)):
    plain = siem_from_config({"sinks": [{"type": "syslog", "host": "127.0.0.1", "transport": transport, "port": port}]}, d)
    start(f"ha_plain_{transport}_machine", judges=T.HIGH, quorum=HA(), siem=plain)
    with mock.patch("two_key.writable.runtime_targets", return_value=[]):
        start(f"ha_plain_{transport}_nomachine", judges=T.HIGH, quorum=HA(), siem=plain)
webhook = siem_from_config({"sinks": [{"type": "webhook", "url": "http://127.0.0.1:8099/ingest"}]}, d)
with mock.patch("two_key.writable.runtime_targets", return_value=[]):
    start("ha_plain_http_webhook", judges=T.HIGH, quorum=HA(), siem=webhook)
    start("default_plain_udp_warns", siem=siem_from_config({"sinks": [{"type": "syslog", "host": "127.0.0.1", "transport": "udp", "port": 5514}]}, d))
# writable paths
ww = d / "settings.yaml"; ww.write_text("x: 1\n"); os.chmod(ww, 0o666)
safe = d / "safe.yaml"; safe.write_text("x: 1\n"); os.chmod(safe, 0o600)
wwdir = d / "wwdir"; wwdir.mkdir(); os.chmod(wwdir, 0o777)
with mock.patch("two_key.writable.runtime_targets", return_value=[]):
    start("writable_default_warn", check_paths=[str(ww)])
    start("writable_refuse_file", on_writable_paths="refuse", check_paths=[str(ww)])
    start("writable_refuse_folder", on_writable_paths="refuse", check_paths=[str(wwdir)])
    start("writable_refuse_safe_file", on_writable_paths="refuse", check_paths=[str(safe)])
    start("ha_writable_default", judges=T.HIGH, quorum=HA(), check_paths=[str(ww)])
    start("ha_writable_warn", judges=T.HIGH, quorum=HA(), on_writable_paths="warn", check_paths=[str(ww)])
    start("ha_safe_only", judges=T.HIGH, quorum=HA(), check_paths=[str(safe)])
start("ha_real_machine_no_paths", judges=T.HIGH, quorum=HA())
start("refuse_real_machine_no_paths", on_writable_paths="refuse")
