"""RUN8X referee: the step-4 fixtures of live run 8x (PLAN8x step 4). Harness-only code, every line of it.

Nothing here changes Two-Key or reaches inside it. The product is driven only through its documented surface:
`two-key mcp-proxy` over stdio (a small JSON-RPC client, so the harness owns the close and the process id),
`siem-export` and `siem-verify`, and, for the two token cases, `TwoKey(...).gateway()` built the way
`two-key demo` builds it (two_key/cli.py `_demo`: FixedJudge with allow_test_doubles=True, a real ledger).
The fixtures gather evidence only; report.py applies the documented rule to it.

Bound to the harness module at import (`bind(sys.modules["__main__"])`), as it uses the harness's STATE, cli(),
write_proxy(), the scripted judges, and the throwaway CA of tests/tls.py. Ports: 18497 the collector under test
(a fault, or a bad certificate), 18498 a redirect target that must stay empty, 18499 a spare collector.

Content-filter rule: no antivirus test string is written to disk here, nothing logs a payload or an attachment
body, and the collectors keep events in memory (the run's own siem_events.jsonl is unchanged)."""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import queue
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

H = None                                  # the harness module
FAULT_PORT, REDIRECT_PORT, SPARE_PORT = 18497, 18498, 18499
WIRED = {"icap_drip", "icap_truncated", "icap_infected_clean", "icap_always_204", "icap_200_unchanged",
         "icap_encrypted_policy", "icap_limits", "judge_time_swap", "fifo", "cursor_first_start",
         "cert_wrong_name", "cert_untrusted", "cert_expired", "collector_tls_stall", "collector_http_500",
         "collector_redirect_302", "collector_redirect_307", "collector_retry_after_429", "collector_drip",
         "gateway_python"}
SINK_TIMEOUT = 2          # seconds, the documented `timeout_seconds` of a sink: keeps a fault case short
FIFO_WAIT = 30            # seconds before the FIFO watchdog opens the write end (a hung read is a FAIL)


def bind(harness):
    global H
    H = harness


def log(event, **kw):
    H.log(event, **kw)


# =============================================================== ICAP: the extra answers (SCANNERS.md mapping)
def _reply(status: bytes, extra: bytes = b""):
    return lambda tag: b"ICAP/1.0 " + status + b"\r\n" + tag + extra + b"Encapsulated: null-body=0\r\n\r\n"


def _icap_unchanged(sock, tag, sent, req_hdr):
    """A 200 that hands back the request exactly as sent: the same HTTP header block and the same body."""
    body = sent or b""
    chunked = (b"%x\r\n%s\r\n" % (len(body), body) if body else b"") + b"0\r\n\r\n"
    sock.sendall(b"ICAP/1.0 200 OK\r\n" + tag + b"Encapsulated: req-hdr=0, req-body=%d\r\n\r\n" % len(req_hdr)
                 + req_hdr + chunked)


def _icap_drip(sock, tag, _sent, _req_hdr):
    """A valid 204, one byte a second: the whole answer takes far longer than the scan timeout (3 s)."""
    for i in range(len(reply := _reply(b"204 No Content")(tag))):
        try:
            sock.sendall(reply[i:i + 1])
        except OSError:
            return
        time.sleep(1)


def _icap_truncated(sock, tag, _sent, _req_hdr):
    """The status line and half a header, then the connection closes."""
    sock.sendall(b"ICAP/1.0 200 OK\r\n" + tag + b"X-Infection-Fo")
    sock.shutdown(socket.SHUT_RDWR)


def _simple(status, extra=b""):
    make = _reply(status, extra)
    return lambda sock, tag, _s, _h: sock.sendall(make(tag))


ICAP_SOCKET = {
    "icap_drip": _icap_drip,
    "icap_truncated": _icap_truncated,
    # an infection header on a part the toy scanner finds clean
    "icap_infected_clean": _simple(b"200 OK", b"X-Infection-Found: Type=0; Resolution=2; Threat=Toy.FalsePositive;\r\n"),
    "icap_always_204": _simple(b"204 No Content"),           # whatever the part holds
    "icap_200_unchanged": _icap_unchanged,
    # encrypted and a policy violation in one answer: encrypted_pass must not wave the violation through
    "icap_encrypted_policy": _simple(b"200 OK", b"X-Virus-ID: Heuristics.Encrypted.Zip\r\nX-Violations-Found: 1\r\n"),
    # ClamAV's "scan limits exceeded" heuristic, named in an infection header
    "icap_limits": _simple(b"200 OK", b"X-Infection-Found: Type=0; Resolution=2; Threat=Heuristics.Limits.Exceeded;\r\n"),
}


def icap_answer(mode, sock, tag, sent, req_hdr, case, part):
    """Called by ToyIcap after it read a whole request. True when this module answered it."""
    if mode not in ICAP_SOCKET:
        return False
    log("scanner_request", case=case, part=part, served=mode)
    try:
        ICAP_SOCKET[mode](sock, tag, sent, req_hdr)
    except OSError:
        pass
    return True


# =============================================================== the file swap while the judges deliberate
SWAP_TEXT = "Story time moves to 10:30 on Saturdays.\n"
SWAPPED: dict = {}        # case id -> what was done, once per case


def swap_reset():
    """swap-me.txt as write_outbox_files made it, before each swap case (a case before may have changed it)."""
    p = H.OUTBOX / "swap-me.txt"
    if p.is_symlink() or p.exists():
        p.unlink()
    p.write_text(SWAP_TEXT, encoding="utf-8", newline="\n")


def maybe_swap(case_id):
    """Called by the scripted judge endpoint: the scan read the file before the judges were asked, and the
    gateway hashes it again after they answer, so this is the window a time-of-check/time-of-use swap uses."""
    how = (H.case_by_id(case_id) or {}).get("swap")
    if not how:
        return
    with H.LOCK:
        if case_id in SWAPPED:
            return
        SWAPPED[case_id] = how
    p = H.OUTBOX / "swap-me.txt"
    if how == "rewrite":                          # same length, different bytes
        p.write_text("Story time moves to 11:15 on Saturdays.\n", encoding="utf-8", newline="\n")
    elif how == "grow":                           # past the 4096-byte cap
        p.write_text("Story time moves to 10:30 on Saturdays.\n" * 120, encoding="utf-8", newline="\n")
    elif how == "to_symlink":                     # a link, to a file inside the folder
        p.unlink()
        os.symlink(H.OUTBOX / "closure-notice.txt", p)
    elif how == "delete":
        p.unlink()
    log("fixture_swap", case=case_id, swap=how)


# =============================================================== a FIFO in the outbox
class FifoGuard:
    """pipe.txt is a named pipe for the length of one case. If the call has not come back after FIFO_WAIT
    seconds, the watchdog opens the write end (and closes it), so a reader blocked in open() gets end of file and
    the pass goes on. That the watchdog had to do it is recorded: a read that blocks is a finding."""

    def __init__(self):
        self.path = H.OUTBOX / "pipe.txt"
        self.done = threading.Event()
        self.released = False

    def __enter__(self):
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        os.mkfifo(self.path, 0o600)
        threading.Thread(target=self._watch, daemon=True).start()
        return self

    def _watch(self):
        if self.done.wait(FIFO_WAIT):
            return
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)   # ENXIO when nobody has it open to read
            os.close(fd)
            self.released = True
        except OSError:
            pass

    def __exit__(self, *exc):
        self.done.set()
        try:
            self.path.unlink()
        except OSError:
            pass
        return False


# =============================================================== certificates (our own CA; tests/tls.py's key is private)
def _x509():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    return x509, hashes, serialization, ec, NameOID, ExtendedKeyUsageOID


def _authority(common):
    x509, hashes, _s, ec, NameOID, _e = _x509()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=60))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _leaf(ca_key, ca_cert, *, ip=True, dns=None, days=(-1, 30)):
    x509, hashes, _s, ec, NameOID, EKU = _x509()
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = ([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))] if ip else []) + ([x509.DNSName(dns)] if dns else [])
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns or "127.0.0.1")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now + datetime.timedelta(days=days[0])).not_valid_after(now + datetime.timedelta(days=days[1]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


CERTS: dict = {}


def cert_set():
    """ca.pem (the CA the sink trusts), and one server certificate per mode: good (the control), wrong_name (signed
    by that CA, for wrong-name.invalid only), untrusted (127.0.0.1, signed by another CA), expired (127.0.0.1, that
    CA, ended yesterday). Keys stay under state/ with mode 0600."""
    if CERTS:
        return CERTS
    _x, _h, ser, _ec, _n, _e = _x509()
    d = H.STATE / "siem_certs8x"
    d.mkdir(mode=0o700, exist_ok=True)
    ca_key, ca = _authority("run8x referee CA")
    other_key, other = _authority("run8x other CA")
    leaves = {"good": _leaf(ca_key, ca), "wrong_name": _leaf(ca_key, ca, ip=False, dns="wrong-name.invalid"),
              "untrusted": _leaf(other_key, other), "expired": _leaf(ca_key, ca, days=(-30, -1))}

    def write(path, data):
        path.write_bytes(data)
        os.chmod(path, 0o600)
    write(d / "ca.pem", ca.public_bytes(ser.Encoding.PEM))
    CERTS["ca"] = d / "ca.pem"
    for mode, (key, cert) in leaves.items():
        write(d / f"{mode}.pem", cert.public_bytes(ser.Encoding.PEM))
        write(d / f"{mode}.key", key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        CERTS[mode] = (d / f"{mode}.pem", d / f"{mode}.key")
    return CERTS


def server_ctx(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def probe(port, ca_file):
    """Our own TLS client, as strict as a sink: the CA, the hostname 127.0.0.1. "ok" or the error class."""
    ctx = ssl.create_default_context(cafile=str(ca_file))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                ctx.wrap_socket(raw, server_hostname="127.0.0.1"):
            return "ok"
    except ssl.SSLCertVerificationError as e:
        return f"verify_failed:{e.verify_message}"
    except (OSError, ssl.SSLError) as e:
        return type(e).__name__


# =============================================================== collectors on 127.0.0.1
class Listener:
    """A TCP listener whose connections are handled in threads; stop() closes it and every open connection."""

    def __init__(self, port):
        self.port, self.stopped, self.conns = port, threading.Event(), []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.sock.settimeout(0.2)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.conns.append(conn)
            threading.Thread(target=self._safe, args=(conn,), daemon=True).start()

    def _safe(self, conn):
        try:
            self.handle(conn)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def drop_connections(self):
        for c in list(self.conns):
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.conns.clear()

    def stop(self):
        self.stopped.set()
        self.drop_connections()
        try:
            self.sock.close()
        except OSError:
            pass
        time.sleep(0.3)

    def handle(self, conn):
        raise NotImplementedError


class TlsOnly(Listener):
    """Presents a certificate and does nothing else: the start-up check of a sink sees it, or refuses it."""

    def __init__(self, port, cert, key):
        self.ctx = server_ctx(cert, key)
        self.handshakes = {"ok": 0, "failed": 0}
        super().__init__(port)

    def handle(self, conn):
        conn.settimeout(5)
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            self.handshakes["failed"] += 1
            return
        self.handshakes["ok"] += 1
        while not self.stopped.is_set() and tls.recv(4096):
            pass


class Collector(Listener):
    """Records native events in memory. mode is switched by the scenario while connections stay open."""

    def __init__(self, port, mode="ok"):
        self.mode, self.events, self.unparseable, self.requests = mode, [], 0, {}
        self.lock = threading.Lock()
        certs = H.SIEM_TLS["certs"]                 # tests/tls.py: a server certificate for 127.0.0.1
        self.ctx = server_ctx(certs.server_cert, certs.server_key)
        super().__init__(port)

    def count(self, what):
        with self.lock:
            self.requests[what] = self.requests.get(what, 0) + 1

    def record(self, text):
        try:
            ev = json.loads(text)
        except ValueError:
            with self.lock:
                self.unparseable += 1
            return
        with self.lock:
            self.events.append(ev)


class SyslogCollector(Collector):
    """Syslog over TLS, octet counting (the Elastic example's reader). tls_stall: a connection accepted while
    stalling is held without a TLS handshake until the mode changes; switching to it drops the open connections,
    so the sender has to reconnect into the stall."""

    def set_mode(self, mode):
        self.mode = mode
        if mode == "tls_stall":
            self.drop_connections()

    def handle(self, conn):
        counted = False
        while self.mode == "tls_stall" and not self.stopped.is_set():
            if not counted:
                self.count("stalled_connection")
                counted = True
            time.sleep(0.1)
        conn.settimeout(30)
        tls = self.ctx.wrap_socket(conn, server_side=True)
        recv, buffer = H.receiver_module(), b""
        while not self.stopped.is_set():
            chunk = tls.recv(65536)
            if not chunk:
                return
            buffer += chunk
            messages, buffer = recv.frames(buffer)
            for raw in messages:
                _kind, body = recv.message_of(raw.decode("utf-8", "replace"))
                self.record(body)


class WebhookCollector(Collector):
    """HTTPS, application/x-ndjson. Modes: ok, http_500, redirect_302, redirect_307 (to REDIRECT_PORT),
    retry_after_429 (Retry-After: 999999, as the case says), drip (a 200 sent one byte a second). Only "ok" keeps the events."""

    def set_mode(self, mode):
        self.mode = mode

    def handle(self, conn):
        conn.settimeout(30)
        tls = self.ctx.wrap_socket(conn, server_side=True)
        f = tls.makefile("rb")
        while not self.stopped.is_set():
            line = f.readline(65537)
            if not line:
                return
            headers = {}
            while True:
                h = f.readline(65537)
                if h in (b"\r\n", b"\n", b""):
                    break
                k, _, v = h.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
            body = f.read(int(headers.get("content-length", "0") or 0))
            mode = self.mode
            self.count(mode)
            if mode == "ok":
                for ln in body.decode("utf-8", "replace").splitlines():
                    if ln.strip():
                        self.record(ln)
                out = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            elif mode == "http_500":
                out = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
            elif mode in ("redirect_302", "redirect_307"):
                out = (b"HTTP/1.1 %s Found\r\nLocation: https://127.0.0.1:%d/ingest\r\nContent-Length: 0\r\n\r\n"
                       % (mode[-3:].encode(), REDIRECT_PORT))
            elif mode == "retry_after_429":
                out = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 999999\r\nContent-Length: 0\r\n\r\n"
            else:                                               # drip
                out = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                for i in range(len(out)):
                    if self.mode != "drip" or self.stopped.is_set():
                        return                                  # recovery: close, the sender retries
                    tls.sendall(out[i:i + 1])
                    time.sleep(1)
                continue
            tls.sendall(out)


def collector(kind, port, mode="ok"):
    return SyslogCollector(port, mode) if kind == "syslog_tls" else WebhookCollector(port, mode)


def sink(kind, port):
    ca = str(H.SIEM_TLS["certs"].ca_file)
    if kind == "syslog_tls":
        return {"type": "syslog", "host": "127.0.0.1", "port": port, "ca_file": ca, "timeout_seconds": SINK_TIMEOUT}
    return {"type": "webhook", "url": f"https://127.0.0.1:{port}/ingest", "ca_file": ca,
            "timeout_seconds": SINK_TIMEOUT}


# =============================================================== a proxy the harness drives itself
class RawProxy:
    """`two-key mcp-proxy` over stdio with a minimal JSON-RPC client: initialize, tools/call, and a clean close
    (stdin closed, then wait for the proxy to exit by itself; never a terminate). The harness keeps the pid, so a
    kill -9 is the proxy's own process and no other."""

    def __init__(self, config: Path):
        self.config, self.p, self.q, self.id = config, None, queue.Queue(), 0

    def start(self):
        self.err = (self.config.parent / "proxy.stderr").open("a")
        self.p = subprocess.Popen([sys.executable, "-m", "two_key", "mcp-proxy", "--config", str(self.config)],  # nosec
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                  env=H.base_env(), cwd=str(H.REPO))
        threading.Thread(target=self._read, daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                    "clientInfo": {"name": "run8x-referee", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def _read(self):
        for line in self.p.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                continue
        self.q.put(None)

    def _send(self, obj):
        self.p.stdin.write((json.dumps(obj) + "\n").encode())
        self.p.stdin.flush()

    def request(self, method, params, timeout=90):
        self.id += 1
        rid = self.id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        end = time.monotonic() + timeout
        while True:
            msg = self.q.get(timeout=max(0.1, end - time.monotonic()))
            if msg is None:
                raise EOFError("proxy closed stdout")
            if msg.get("id") == rid:
                return msg

    def call(self, tool, arguments):
        t0 = time.monotonic()
        msg = self.request("tools/call", {"name": tool, "arguments": arguments})
        return time.monotonic() - t0, msg

    def close(self, timeout=90):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            rc = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            rc = "hung_on_close"
        self.err.close()
        return rc

    def kill9(self):
        os.kill(self.p.pid, signal.SIGKILL)
        self.p.wait()
        self.err.close()


def burst(px, cid, n, start=0, latencies=None):
    """n catalog searches. The scripted judges of a siem case both say no, so each call is a ledgered deny and no
    tool back end is asked."""
    out = latencies if latencies is not None else []
    for i in range(start, start + n):
        dt, _msg = px.call("catalog_search", {"query": f"run8x {cid} search {i}"})
        out.append(dt)
    return out


def p95(xs):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(0.95 * len(xs)))], 4) if xs else None


def scenario_dir(cid, digest, sink_cfg, *, suffix=""):
    """proxy.json for the first start (replay_from: start, so the copy can be checked from seq 0), and
    proxy.cursor.json, the same with the default replay_from: cursor, for every later start. Under `start` every
    start re-sends the whole ledger (seen in the step-4 selftest; SIEM.md says the cursor decides after the first),
    so a later start on `start` would hide what the cursor does."""
    d = H.STATE / f"siem_{cid}{suffix}"
    d.mkdir()
    for name in ("keys", "constitution.signed.json", "judges.yaml"):
        os.symlink(H.STATE / name, d / name)
    for name, replay_from in (("proxy.json", "start"), ("proxy.cursor.json", "cursor")):
        H.write_proxy(d / name, digest, siem={"schema": "native", "replay_from": replay_from,
                                              "sinks": [dict(sink_cfg, label="collector")]})
    return d


def later(d):
    return d / "proxy.cursor.json"


def cursor_path(d):
    return d / "ledger.siem" / "cursor.json"


def export(d, name="export.jsonl", ledger=None):
    """siem-export of a ledger: the entries it holds, as native events, and the signed summary line."""
    out = d / name
    if out.exists():
        out.unlink()
    r = H.cli("siem-export", "--key", str(H.STATE / "keys" / "principal.pem"), "--ledger", str(ledger or d / "ledger"),
              "--out", str(out))
    if r.returncode:
        return None, r.returncode
    lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
    return lines, 0


def verify(d, events, name, ledger=None):
    f = d / name
    f.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events))
    r = H.cli("siem-verify", "--key", str(H.STATE / "keys" / "principal.pem"), "--ledger", str(ledger or d / "ledger"),
              "--events", str(f), "--require-complete")
    return r.returncode, (r.stdout + r.stderr)[-400:]


def completeness(d, col):
    lines, rc = export(d)
    if lines is None:
        return {"export_rc": rc}
    ledger = {e["entry_hash"] for e in lines if e.get("kind") != "siem_export_summary" and e.get("entry_hash")}
    hashes = [e.get("entry_hash") for e in col.events if e.get("entry_hash")]
    gone = sorted((e["seq"], e.get("kind")) for e in lines if e.get("entry_hash") in ledger - set(hashes))
    return {"missing_detail": gone[:12], "ledger_head_seq": max((e.get("seq", -1) for e in lines
                                                                 if e.get("kind") != "siem_export_summary"), default=-1),
            "ledger_entries": len(ledger), "delivered": len(hashes), "delivered_unique": len(set(hashes)),
            "missing": len(ledger - set(hashes)), "repeats": len(hashes) - len(set(hashes)),
            "foreign": len(set(hashes) - ledger), "unparseable": col.unparseable,
            "replay_marked": sum(1 for e in col.events if e.get("replay") is True)}


def recover(d, col, wait=4):
    """The documented catch-up: the collector is back, so the next start sends what the cursor has not."""
    px = RawProxy(later(d)).start()
    time.sleep(wait)
    rc = px.close()
    time.sleep(2)
    return rc


# =============================================================== the scenarios
def sc_verify_tamper(case, digest, shared):
    """siem-export of the main pass's ledger, a baseline siem-verify (must exit 0), then the same file with one
    field changed (must not)."""
    d = H.STATE / f"siem_{case['id']}"
    d.mkdir()
    lines, rc = export(d, ledger=H.STATE / "ledger")
    if lines is None:
        return {"fixture_error": f"siem-export of the main ledger exited {rc}"}
    clean_rc, _ = verify(d, lines, "clean.jsonl", ledger=H.STATE / "ledger")
    tamper, applied, where = case["tamper"], False, None
    bad = json.loads(json.dumps(lines))
    if tamper == "summary_count":
        for e in bad:
            if e.get("kind") == "siem_export_summary" and isinstance(e.get("count"), int):
                e["count"] += 1
                applied, where = True, "summary"
    else:
        for e in bad:
            if e.get("kind") == "siem_export_summary" or tamper not in e:
                continue
            v = e[tamper]
            if tamper == "prev" and isinstance(v, str) and v:
                e[tamper] = v[:-1] + ("0" if v[-1] != "0" else "1")
            elif tamper == "severity" and isinstance(v, int) and not isinstance(v, bool):
                e[tamper] = 6 if v != 6 else 4
            elif tamper == "severity" and isinstance(v, str):
                e[tamper] = "informational" if v != "informational" else "warning"
            else:
                continue
            applied, where = True, e.get("seq")
            break
    tampered_rc, tail = verify(d, bad, f"tampered-{tamper}.jsonl", ledger=H.STATE / "ledger")
    return {"siem": {"tamper": tamper, "applied": applied, "at_seq": where, "events": len(lines),
                     "clean_rc": clean_rc, "tampered_rc": tampered_rc, "verify_says": tail[-200:]}}


def sc_close_after_n(case, digest, shared):
    col = collector(case["sink"], FAULT_PORT)
    try:
        d = scenario_dir(case["id"], digest, sink(case["sink"], FAULT_PORT))
        px = RawProxy(d / "proxy.json").start()
        burst(px, case["id"], case["n"])
        rc = px.close()                                     # at once: the last pass is the proxy's own
        time.sleep(3)
        got = completeness(d, col)
        got.update(demo_tail(d, col))                       # finding 2's own vehicle, `two-key demo --siem`
    finally:
        col.stop()
    return {"siem": dict(got, close_rc=rc, calls=case["n"])}


def demo_tail(d, syslog_col):
    """Run 8 finding 2 was seen with `two-key demo --siem` over syslog TLS. The demo's ledger is temporary, so its
    size is taken from a control run of the same demo to an HTTPS webhook; the syslog run must deliver as many
    ledgered events, seq 0 to the same last seq."""
    def run(sink_cfg, col, name):
        f = d / name
        f.write_text(json.dumps({"siem": {"schema": "native", "replay_from": "start",
                                          "sinks": [dict(sink_cfg, label="demo")]}}))
        n0 = len(col.events)
        r = H.cli("demo", "--siem", str(f))
        time.sleep(3)
        seqs = sorted(e.get("seq") for e in col.events[n0:] if e.get("ledgered") is not False)
        return r.returncode, len(seqs), (seqs[-1] if seqs else None)
    web = WebhookCollector(SPARE_PORT)
    try:
        wrc, wn, wlast = run(sink("webhook", SPARE_PORT), web, "demo-webhook.json")
    finally:
        web.stop()
    src, sn, slast = run(sink("syslog_tls", FAULT_PORT), syslog_col, "demo-syslog.json")
    return {"demo_control_rc": wrc, "demo_control_ledgered": wn, "demo_control_last_seq": wlast,
            "demo_syslog_rc": src, "demo_syslog_ledgered": sn, "demo_syslog_last_seq": slast}


def sc_verify_collected(case, digest, shared):
    col = collector("webhook", FAULT_PORT)
    try:
        d = scenario_dir(case["id"], digest, sink("webhook", FAULT_PORT))
        px = RawProxy(d / "proxy.json").start()
        for i in range(10):         # the control canaries' shape: a search whose words must never leave
            px.call("catalog_search", {"query": f"SIEMCANARY8X-verify-{i} large print mysteries"})
        rc = px.close()
        time.sleep(3)
    finally:
        col.stop()
    vrc, tail = verify(d, col.events, "collected.jsonl")
    text = json.dumps(col.events)
    return {"siem": dict(completeness(d, col), close_rc=rc, verify_rc=vrc, verify_says=tail[-200:],
                         canary_in_events="SIEMCANARY8X" in text)}


def sc_collector_mode(case, digest, shared):
    mode, kind, n = case["mode"], case["sink"], case["n"]
    col = collector(kind, FAULT_PORT)
    target = WebhookCollector(REDIRECT_PORT) if mode.startswith("redirect") else None
    lat_base, lat_fault, starts = [], [], 0
    try:
        d = scenario_dir(case["id"], digest, sink(kind, FAULT_PORT))
        px = RawProxy(d / "proxy.json").start()
        burst(px, case["id"], 10, 0, lat_base)              # healthy: the baseline
        col.set_mode(mode)
        burst(px, case["id"], n, 10, lat_fault)             # under the fault
        col.set_mode("ok")
        time.sleep(6)                                       # the sender's own retry, while running
        rc = px.close()
        time.sleep(2)
        got = completeness(d, col)
        while got.get("missing") and starts < 2:            # the documented catch-up on the next start
            recover(d, col)
            starts += 1
            got = completeness(d, col)
    finally:
        col.stop()
        if target:
            target.stop()
    return {"siem": dict(got, mode=mode, close_rc=rc, baseline_p95=p95(lat_base), fault_p95=p95(lat_fault),
                         fault_max=round(max(lat_fault), 4), recovery_starts=starts, fault_requests=dict(col.requests),
                         redirect_target_events=len(target.events) if target else None)}


def sc_collector_restart(case, digest, shared):
    """The collector goes away for outage_seconds in the middle of a burst, then comes back on the same port."""
    n, out = case["n"], case["outage_seconds"]
    holder = {"col": collector("webhook", FAULT_PORT)}
    events = holder["col"].events
    lat_before, lat_during, lat_after, starts = [], [], [], 0
    try:
        d = scenario_dir(case["id"], digest, sink("webhook", FAULT_PORT))
        px = RawProxy(d / "proxy.json").start()
        burst(px, case["id"], n // 4, 0, lat_before)
        holder["col"].stop()
        t_back = time.monotonic() + out
        i = n // 4
        while time.monotonic() < t_back and i < n:
            lat_during.append(px.call("catalog_search", {"query": f"run8x {case['id']} search {i}"})[0])
            i += 1
        while time.monotonic() < t_back:
            time.sleep(0.05)
        new = WebhookCollector(FAULT_PORT)
        new.events = events                                  # one record across the restart
        holder["col"] = new
        if i < n:
            burst(px, case["id"], n - i, i, lat_after)
        time.sleep(6)
        rc = px.close()
        time.sleep(2)
        got = completeness(d, holder["col"])
        while got.get("missing") and starts < 2:
            recover(d, holder["col"])
            starts += 1
            got = completeness(d, holder["col"])
    finally:
        holder["col"].stop()
    return {"siem": dict(got, close_rc=rc, baseline_p95=p95(lat_before), fault_p95=p95(lat_during),
                         calls_during_outage=len(lat_during), recovery_starts=starts)}


CRASH_REFUSALS = ("signed head does not match the chain", "the last record does not decrypt")


def start_after_crash(d, notes):
    """A start after a kill -9. If the ledger refuses with one of the two messages HOWTO names for a process killed
    between an append and the checkpoint, the operator's documented step is `two-key recover`, then start again."""
    err = d / "proxy.stderr"
    mark = err.stat().st_size if err.exists() else 0
    try:
        return RawProxy(later(d) if notes is not None and (d / "ledger").exists() else d / "proxy.json").start()
    except (EOFError, queue.Empty, OSError):
        said = err.read_text(errors="replace")[mark:] if err.exists() else ""
        why = next((m for m in CRASH_REFUSALS if m in said), None)
        if why is None:
            raise
        r = H.cli("recover", "--key", str(H.STATE / "keys" / "principal.pem"), "--ledger", str(d / "ledger"))
        notes.append({"refused": why, "recover_rc": r.returncode})
        if r.returncode:
            raise
        return RawProxy(later(d)).start()


def sc_kill9(case, digest, shared):
    """kill -9 of the proxy at each time in kills (seconds into a burst), a fresh start after each, then a clean
    catch-up start. Repeats are allowed (the cursor may lag the kill); a missing entry or a ledger that no longer
    opens is not."""
    col = collector("webhook", FAULT_PORT)
    starts_ok, start_errors, calls_made, recovers = 0, [], 0, []
    try:
        d = scenario_dir(case["id"], digest, sink("webhook", FAULT_PORT))
        for k, t in enumerate(case["kills"]):
            try:
                px = start_after_crash(d, recovers)
                starts_ok += 1
            except (EOFError, queue.Empty, OSError) as e:
                start_errors.append(f"start {k}: {type(e).__name__}")
                break
            done = []

            def run(px=px, k=k):
                try:
                    burst(px, case["id"], case["n"], k * case["n"], done)
                except (EOFError, queue.Empty, OSError, ValueError):
                    pass
            th = threading.Thread(target=run, daemon=True)
            th.start()
            time.sleep(t)
            px.kill9()
            th.join(10)
            calls_made += len(done)
        try:
            px = start_after_crash(d, recovers)          # the clean catch-up start
            time.sleep(10)
            rc = px.close()
            time.sleep(2)
        except (EOFError, queue.Empty, OSError) as e:
            start_errors.append(f"recovery start: {type(e).__name__}")
            rc = None
        got = completeness(d, col)
        if got.get("missing"):
            recover(d, col, wait=10)
            got = completeness(d, col)
    finally:
        col.stop()
    stderr_tail = (d / "proxy.stderr").read_text(errors="replace")[-300:] if (d / "proxy.stderr").exists() else ""
    return {"siem": dict(got, kills=case["kills"], starts_ok=starts_ok, start_errors=start_errors,
                         calls_before_kills=calls_made, close_rc=rc, recovers=recovers,
                         stderr_tail=stderr_tail if start_errors else "")}


def sc_cursor_tamper(case, digest, shared):
    """Two runs on one ledger (replay_from: start, so the first start sends it all; the cursor decides after).
    Between them the cursor is deleted, rolled back to an older copy, replaced by a longer ledger's cursor, or
    overwritten with garbage. Its format is not documented, so it is only ever deleted, copied, or overwritten."""
    cid, n, variant = case["id"], case["n"], case["variant"]
    col = collector("webhook", FAULT_PORT)
    tampered = False
    try:
        d = scenario_dir(cid, digest, sink("webhook", FAULT_PORT))
        cur = cursor_path(d)
        px = RawProxy(d / "proxy.json").start()
        burst(px, cid, n // 2)
        px.close()
        time.sleep(1)
        older = d / "cursor.older.json"
        if cur.exists():
            shutil.copyfile(cur, older)
        px = RawProxy(later(d)).start()
        burst(px, cid, n // 2 - 5, n // 2)
        col.set_mode("http_500")                       # a backlog: the last five calls are not delivered
        burst(px, cid, 5, n - 5)
        px.close()
        col.set_mode("ok")
        time.sleep(1)
        if variant == "deleted" and cur.exists():
            cur.unlink()
            tampered = True
        elif variant == "rolled_back" and older.exists() and cur.exists() and older.read_bytes() != cur.read_bytes():
            shutil.copyfile(older, cur)
            tampered = True
        elif variant == "ahead":
            other_col = collector("webhook", SPARE_PORT)
            try:                                        # a longer ledger, the same sink label, its own collector
                dx = scenario_dir(cid, digest, sink("webhook", SPARE_PORT), suffix="_longer")
                pxx = RawProxy(dx / "proxy.json").start()
                burst(pxx, cid + "x", 4 * n)
                pxx.close()
                time.sleep(1)
            finally:
                other_col.stop()
            if cursor_path(dx).exists() and cur.exists():
                shutil.copyfile(cursor_path(dx), cur)
                tampered = True
        elif variant == "garbage" and cur.exists():
            cur.write_text("not a cursor {{{ \u202e ]]\n", encoding="utf-8")
            tampered = True
        px = RawProxy(later(d)).start()
        burst(px, cid, n // 2, n)
        time.sleep(4)
        rc = px.close()
        time.sleep(2)
    finally:
        col.stop()
    vrc, tail = verify(d, col.events, "collected.jsonl")
    got = completeness(d, col)
    return {"siem": dict(got, variant=variant, tampered=tampered, verify_rc=vrc, verify_says=tail[-200:],
                         close_rc=rc, cursor_after=("missing" if not cursor_path(d).exists() else
                                                    "symlink" if cursor_path(d).is_symlink() else "file"))}


def _demo_twokey(d, sink_cfg):
    """`two-key demo`'s TwoKey, on a ledger that stays (d/ledger) and with this case's siem block."""
    from two_key.constitution import sign_constitution, verify_signed
    from two_key.core import TwoKey
    from two_key.keys import generate_private_key
    from two_key.ledger import Ledger
    from two_key.quorum import QuorumPolicy
    from two_key.siem_sinks import siem_from_config
    from two_key.testing import TEST_AGENT, FixedJudge
    key = generate_private_key()
    rules = [{"id": "tools", "allow_only_tools": ["search", "email_draft"]}]
    specs = {"search": {"irreversible": False, "data_class_floor": "public"},
             "email_draft": {"irreversible": False, "data_class_floor": "public",
                             "counterparties": [{"json_path": "to", "allow": ["ada@example"]}]}}
    envelope = sign_constitution("Drafts are allowed. Search is allowed.", rules, key, specs)
    siem = siem_from_config({"schema": "native", "replay_from": "start", "sinks": [dict(sink_cfg, label="collector")]}, d)
    judges = [FixedJudge("a", "yes", provider="local-a", maker="local", local_weights=True),
              FixedJudge("b", "yes", provider="cloud-b", maker="other")]
    return TwoKey(Ledger(d / "ledger", key), key.public_key(), verify_signed(envelope, key.public_key()), judges,
                  private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True,
                  monitored_agent=TEST_AGENT, siem=siem)


def sc_refused_tokens(case, digest, shared):
    d = H.STATE / f"siem_{case['id']}"
    d.mkdir()
    col = collector("webhook", FAULT_PORT)
    probes = [f"run8x-not-a-token-{i:04d}" for i in range(case["n"])]
    try:
        tk = _demo_twokey(d, sink("webhook", FAULT_PORT))
        gw = tk.gateway(tools={"email_draft": lambda a: {"drafted": a.get("to")}})
        before = tk.ledger.size()
        refused = sum(1 for t in probes if not gw.invoke(t, "email_draft", {"to": "ada@example"}).allowed)
        growth = tk.ledger.size() - before
        tk.close()
        time.sleep(3)
    finally:
        col.stop()
    counts = [e for e in col.events if e.get("kind") == "gateway_token_refused"]
    text = json.dumps(col.events)
    return {"siem": {"refused": refused, "ledger_growth": growth, "refused_events": len(counts),
                     "all_unledgered": all(e.get("ledgered") is False and e.get("seq") == -1 for e in counts),
                     "token_text_in_events": any(t in text for t in probes),
                     "counts_reported": [e.get("counts") for e in counts][:3]}}


def sc_token_replay(case, digest, shared):
    d = H.STATE / f"siem_{case['id']}"
    d.mkdir()
    col = collector("webhook", FAULT_PORT)
    try:
        tk = _demo_twokey(d, sink("webhook", FAULT_PORT))
        allowed = tk.authorize({"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                               {"to": "ada@example"}, "draft a note")
        gw = tk.gateway(tools={"email_draft": lambda a: {"drafted": a.get("to")}})
        before = tk.ledger.size()
        outcomes = {}
        for _ in range(case["n"]):
            r = gw.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
            key = "allowed" if r is not None and r.allowed else str(getattr(r, "reason", None))[:40]
            outcomes[key] = outcomes.get(key, 0) + 1
        kinds = {}
        for e in tk.ledger.entries[before:]:
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
        tk.close()
        time.sleep(2)
    finally:
        col.stop()
    return {"siem": {"token_issued": bool(allowed.token), "outcomes": outcomes, "ledger_kinds_after": kinds,
                     "invokes": case["n"]}}


SCENARIOS = {"verify_tamper": sc_verify_tamper, "close_after_n": sc_close_after_n,
             "verify_collected": sc_verify_collected, "collector_mode": sc_collector_mode,
             "collector_restart": sc_collector_restart, "kill9": sc_kill9, "cursor_tamper": sc_cursor_tamper,
             "refused_tokens": sc_refused_tokens, "token_replay": sc_token_replay}


def run_siem_cases(cases, results, digest):
    """Every kind:siem case, after the MCP passes (verify_tamper reads the main ledger, so it must be closed)."""
    shared: dict = {}
    for case in cases:
        if case["kind"] != "siem":
            continue
        cid = case["id"]
        H.CURRENT["case"], H.CURRENT["step"] = cid, 0
        log("case_start", case=cid, case_kind="siem", scenario=case.get("scenario"))
        if case.get("fixture") and case["fixture"] not in WIRED:
            results[cid] = {"not_applicable": f"not exercisable: fixture {case['fixture']}"}
        else:
            t0 = time.monotonic()
            try:
                results[cid] = SCENARIOS[case["scenario"]](case, digest, shared)
            except Exception as e:                  # a broken fixture is never a verdict on Two-Key
                results[cid] = {"fixture_error": f"{type(e).__name__}: {str(e)[:200]}"}
            results[cid]["seconds"] = round(time.monotonic() - t0, 1)
        log("case_result", case=cid, **results[cid])
    H.CURRENT["case"] = None


# =============================================================== config cases: certificates and the cursor
class ConfigFixture:
    """Set up before a config case's measured start, torn down after. Returns the siem block and any extra
    top-level proxy keys, and records what the fixture itself checked (so a broken fixture is not a PASS)."""

    def __init__(self, case, d, digest):
        self.case, self.d, self.digest, self.atk = case, d, digest, case["attack"]
        self.siem, self.extra, self.check, self.stop = None, {}, {}, []

    def __enter__(self):
        atk = self.atk
        if atk.startswith("siem_cert_"):
            mode = atk[len("siem_cert_"):]
            certs = cert_set()
            good = TlsOnly(SPARE_PORT, *certs["good"])           # the control: our CA, our client, a good cert
            self.check["control"] = probe(SPARE_PORT, certs["ca"])
            good.stop()
            bad = TlsOnly(FAULT_PORT, *certs[mode])
            self.stop.append(bad)
            self.check["probe"] = probe(FAULT_PORT, certs["ca"])
            self.siem = {"schema": "native", "replay_from": "start",
                         "sinks": [{"type": "syslog", "host": "127.0.0.1", "port": FAULT_PORT,
                                    "ca_file": str(certs["ca"]), "label": f"cert-{mode.replace('_', '-')}"}]}
        elif atk.startswith("siem_cursor_"):
            col = SyslogCollector(FAULT_PORT)
            self.stop.append(col)
            self.siem = {"schema": "native", "replay_from": "start",
                         "sinks": [dict(sink("syslog_tls", FAULT_PORT), label="cursor")]}
            H.write_proxy(self.d / "proxy.json", self.digest, siem=self.siem)
            r = H.cli("mcp-proxy", "--config", str(self.d / "proxy.json"), env=H.base_env(), stdin=subprocess.DEVNULL)
            cur = cursor_path(self.d)
            self.check.update(first_rc=r.returncode, cursor_created=cur.is_file(),
                              baseline_writable=r.stderr.count("writable_path:"))
            if cur.is_file():
                if atk in ("siem_cursor_writable", "siem_cursor_writable_refuse"):
                    os.chmod(cur.parent, 0o755)             # traversable, so the file's own mode decides
                    os.chmod(cur, 0o666)                    # nosec B103 - the point of the case
                    self.check["cursor_mode"] = "0666 in a 0755 folder"
                if atk == "siem_cursor_writable_refuse":
                    self.extra["on_writable_paths"] = "refuse"
                if atk == "siem_cursor_symlink":
                    elsewhere = self.d / "elsewhere"
                    elsewhere.mkdir(mode=0o700)
                    target = elsewhere / "cursor-target.json"
                    shutil.copyfile(cur, target)
                    self.check["target_sha_before"] = H.sha(target.read_text())[:12]
                    cur.unlink()
                    os.symlink(target, cur)
                    self.target = target
        return self

    def observe_after(self, res):
        """For the symlink case: what the measured start (and its close) did to the link and its target."""
        if self.atk != "siem_cursor_symlink" or not hasattr(self, "target"):
            return
        cur = cursor_path(self.d)
        res["observed"] = {
            "rc": res.get("rc"), "cursor_is_symlink_after": cur.is_symlink(),
            "target_changed": H.sha(self.target.read_text())[:12] != self.check.get("target_sha_before"),
            "stderr_mentions_cursor": "cursor" in (res.get("stderr") or ""),
            "writable_or_link_warning": [ln[:160] for ln in (res.get("stderr") or "").splitlines()
                                         if "cursor" in ln or "symlink" in ln or "link" in ln][:3]}

    def __exit__(self, *exc):
        for s in self.stop:
            s.stop()
        return False
