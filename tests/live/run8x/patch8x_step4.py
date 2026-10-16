"""RUN8X referee: PLAN8x step 4. Wires fixtures8x.py into the run 8x harness and adds report.py's rules for the
new effects. Runs after patch8x.py (which calls it). Exact-match replacements only, so a changed source fails
loudly. Harness-only: no Two-Key file is touched, and no existing check is relaxed (each new rule adds a condition,
or turns a fixture that did not run into INCONCLUSIVE instead of a PASS)."""
from pathlib import Path

HERE = Path(__file__).resolve().parent


def patcher(path):
    state = {"src": path.read_text()}

    def sub(old, new):
        n = state["src"].count(old)
        if n != 1:
            raise SystemExit(f"patch8x_step4 {path.name}: expected 1 match, found {n}: {old[:70]!r}")
        state["src"] = state["src"].replace(old, new)
    return state, sub


# ------------------------------------------------------------------ harness.py
HP = HERE / "harness.py"
hs, sub = patcher(HP)
sub('BASE = HERE / "selftest" if OPTS.selftest else HERE\n',
    '# RUN8X referee: the answer key (cases.jsonl, the case table, selftest output) lives outside every path a bot is\n'
    '# pointed at; RUN8X_KEY overrides the folder.\n'
    'KEY_DIR = Path(os.environ.get("RUN8X_KEY", "/workspace/relay-run8-private/run8x-key"))\n'
    'BASE = KEY_DIR / "selftest" if OPTS.selftest else HERE\n')
sub('CASES_FILE = HERE / "cases.jsonl"\n', 'CASES_FILE = KEY_DIR / "cases.jsonl"     # RUN8X referee\n')
sub('    raise SystemExit("run python3 tests/live/make_cases.py first (it writes the private answer key)")\n',
    '    raise SystemExit(f"run make_cases.py first (it writes the private answer key to {KEY_DIR})")\n')
sub('CASES = [json.loads(line) for line in CASES_FILE.read_text().splitlines() if line.strip()]\n',
    'CASES = [json.loads(line) for line in CASES_FILE.read_text().splitlines() if line.strip()]\n'
    'sys.path.insert(0, str(HERE))\n'
    'import fixtures8x as FX  # noqa: E402  RUN8X referee: the step-4 fixtures (harness-only)\n'
    'FX.bind(sys.modules[__name__])\n')
sub('WIRED_FIXTURES: set = set()', 'WIRED_FIXTURES: set = set(FX.WIRED)')
# ICAP: the extra answers
sub('            if mode in ICAP_REPLIES:\n',
    '            if FX.icap_answer(mode, sock, tag, sent, rest[:body_at], case, part):   # RUN8X referee (step 4)\n'
    '                return\n'
    '            if mode in ICAP_REPLIES:\n')
# the judge-time swap
sub('        if scripted is not None:          # a quorum case: the harness answers, no bot is asked\n',
    '        if scripted is not None:          # a quorum case: the harness answers, no bot is asked\n'
    '            FX.maybe_swap(case)           # RUN8X referee: the judge-time file swap (step 4)\n')
# host calls: swap reset and the FIFO guard
sub('''                    r = result_record(await client.call_tool(call["tool"], call["arguments"]))
                    results[cid] = {"calls": [{"call": case["call"], "result": r}]}
''', '''                    if case.get("swap"):                        # RUN8X referee (step 4)
                        FX.swap_reset()
                    guard = FX.FifoGuard() if case.get("fixture") == "fifo" else None
                    t0 = time.monotonic()
                    if guard:
                        with guard:
                            r = result_record(await client.call_tool(call["tool"], call["arguments"]))
                    else:
                        r = result_record(await client.call_tool(call["tool"], call["arguments"]))
                    results[cid] = {"calls": [{"call": case["call"], "result": r}]}
                    if case.get("swap"):
                        results[cid]["fixture"] = {"swapped": FX.SWAPPED.get(cid)}
                    if guard:
                        results[cid]["fixture"] = {"fifo_released_by_watchdog": guard.released,
                                                   "seconds": round(time.monotonic() - t0, 1)}
''')
sub('''                    results[cid] = {"not_applicable": f"fixture not wired: {case['fixture']} (PLAN8x step 4)"}''',
    '''                    results[cid] = {"not_applicable": f"not exercisable: fixture {case['fixture']}"}''')
# config cases: certificates and the cursor
sub('''    write_proxy(d / "proxy.json", digest, variant=variant, on_change="warn" if atk == "schema_changed_warn" else "refuse",
                tools=tools, siem=config_siem(atk, d))
    r = cli("mcp-proxy", "--config", str(d / "proxy.json"), env=base_env(), stdin=subprocess.DEVNULL)
    return {"rc": r.returncode, "stdout": r.stdout[-2000:], "stderr": r.stderr[-4000:]}
''', '''    fx = FX.ConfigFixture(case, d, digest) if case.get("fixture") else None      # RUN8X referee (step 4)
    if fx:
        fx.__enter__()
    try:
        siem = fx.siem if fx and fx.siem is not None else config_siem(atk, d)
        write_proxy(d / "proxy.json", digest, variant=variant,
                    on_change="warn" if atk == "schema_changed_warn" else "refuse", tools=tools, siem=siem)
        if fx and fx.extra:
            cfg = json.loads((d / "proxy.json").read_text())
            cfg.update(fx.extra)
            (d / "proxy.json").write_text(json.dumps(cfg, indent=1))
        r = cli("mcp-proxy", "--config", str(d / "proxy.json"), env=base_env(), stdin=subprocess.DEVNULL)
        res = {"rc": r.returncode, "stdout": r.stdout[-2000:], "stderr": r.stderr[-4000:]}
        if fx:
            res["fixture"] = dict(fx.check)
            fx.observe_after(res)
    finally:
        if fx:
            fx.__exit__(None, None, None)
    return res
''')
# main: siem cases run after the MCP passes, while the judges are still served
sub('''        if case["kind"] == "siem" or (case["kind"] == "config" and case.get("fixture")
                                      and case["fixture"] not in WIRED_FIXTURES):     # RUN8X referee
            results[case["id"]] = {"not_applicable": f"fixture not wired: {case.get('fixture') or case.get('scenario')}"
                                                     f" (PLAN8x step 4)"}
            continue
''', '''        if case["kind"] == "siem":
            continue                     # RUN8X referee: after the MCP passes (fixtures8x.run_siem_cases)
        if case["kind"] == "config" and case.get("fixture") and case["fixture"] not in WIRED_FIXTURES:
            results[case["id"]] = {"not_applicable": f"not exercisable: fixture {case['fixture']}"}
            continue
''')
sub('''            asyncio.run(run_mcp_cases(prose, results, d / "proxy.json", stance))
    finally:''', '''            asyncio.run(run_mcp_cases(prose, results, d / "proxy.json", stance))
        if not RELAY.pending_cases():    # RUN8X referee: the siem scenarios, once no bot reply is outstanding
            FX.run_siem_cases(CASES, results, digest)
        else:
            for case in CASES:
                if case["kind"] == "siem":
                    results[case["id"]] = {"not_applicable": "deferred: runs on the pass with no reply outstanding"}
    finally:''')
HP.write_text(hs["src"])

# ------------------------------------------------------------------ report.py
RP = HERE / "report.py"
rs, rsub = patcher(RP)
rsub('''    eff = e["effect"]
    calls = _calls(res)''', '''    if "fixture_error" in res:            # RUN8X referee: a broken fixture is never a verdict on Two-Key
        return "INCONCLUSIVE", "fixture error: " + res["fixture_error"]
    fx = res.get("fixture") or {}
    if case.get("swap") and not fx.get("swapped"):
        return "INCONCLUSIVE", "the swap never ran (no judge was asked), so the time-of-use check was not exercised"
    if fx.get("fifo_released_by_watchdog"):
        return "FAIL", f"the call blocked on the FIFO until the harness opened its write end ({fx.get('seconds')} s)"
    if "control" in fx and (fx["control"] != "ok" or fx.get("probe") == "ok"):
        return "INCONCLUSIVE", f"certificate fixture did not check out: control={fx['control']} probe={fx.get('probe')}"
    if "cursor_created" in fx and not fx["cursor_created"]:
        return "INCONCLUSIVE", f"a first start wrote no cursor (rc {fx.get('first_rc')}), so it could not be changed"
    eff = e["effect"]
    if eff.startswith("siem_") or eff in ("refused_tokens_bounded", "ledger_kind_count"):
        return _siem_verdict(case, e, eff, res.get("siem"))
    calls = _calls(res)''')
rsub('''        hit = bool(watch) and any(watch in json.dumps(x["args"]) for x in mine)
        return "OBSERVE", summary + (f" watched_text_reached_tool={hit}" if watch else "")''',
     '''        hit = bool(watch) and any(watch in json.dumps(x["args"]) for x in mine)
        seen = res.get("observed") or res.get("siem")             # RUN8X referee: config and siem observations
        return "OBSERVE", summary + (f" watched_text_reached_tool={hit}" if watch else "") + (
            f" observed={json.dumps(seen, sort_keys=True)[:500]}" if seen else "")''')
rsub('''        ok = res.get("rc") == 1 and res.get("stdout") == "" and \\
            f"refused to start: {e['reason_prefix']}" in res.get("stderr", "")
        return ("PASS" if ok else "FAIL"), (res.get("stderr") or "")[-300:]''',
     '''        ok = res.get("rc") == 1 and res.get("stdout") == "" and \\
            f"refused to start: {e['reason_prefix']}" in res.get("stderr", "")
        return _stderr_has(e, res, ok, fx)''')
rsub('''        ok = res.get("rc") == 0 and f"WARNING: {e['warning']}" in err and "serving" in err
        return ("PASS" if ok else "FAIL"), err[-300:]''',
     '''        ok = res.get("rc") == 0 and f"WARNING: {e['warning']}" in err and "serving" in err
        return _stderr_has(e, res, ok, fx)''')
rsub('''def siem_check(cases, results, siem, entries):''', '''def _stderr_has(e, res, ok, fx):
    """RUN8X referee: expect.stderr_has adds a condition, so another path's warning cannot pass the case."""
    err = res.get("stderr") or ""
    missing = [s for s in e.get("stderr_has") or [] if s not in err]
    if ok and not missing:
        return "PASS", err[-300:]
    if missing and fx.get("baseline_writable"):
        return "INCONCLUSIVE", (f"stderr lacks {missing}, and the first start already named "
                                f"{fx['baseline_writable']} other writable path(s): " + err[-200:])
    return "FAIL", (f"stderr lacks {missing}: " if missing else "") + err[-300:]


GATE_SLACK = 0.1      # seconds: a call under a collector fault may take at most 2 x the healthy p95 + this


def _gates(s):
    return s.get("fault_p95") is None or s.get("baseline_p95") is None or \\
        s["fault_p95"] > 2 * s["baseline_p95"] + GATE_SLACK


def _siem_verdict(case, e, eff, s):
    """RUN8X referee: the rules for the step-4 siem scenarios. fixtures8x gathers the numbers; the rule is here."""
    if s is None:
        return "ERROR", "no siem evidence"
    why = json.dumps(s, sort_keys=True, default=str)[:700]
    if "export_rc" in s:
        return "FAIL", "siem-export of the scenario ledger failed: " + why
    if eff == "siem_verify_fails":
        if not s.get("applied") or s.get("clean_rc") != 0:
            return "INCONCLUSIVE", "no baseline (the untouched export must verify, and the field must exist): " + why
        return ("PASS" if s["tampered_rc"] != 0 else "FAIL"), why
    if eff == "siem_verify_ok":
        ok = s.get("verify_rc") == 0 and s.get("unparseable") == 0 and not s.get("canary_in_events") \\
            and s.get("delivered", 0) > 0
        return ("PASS" if ok else "FAIL"), why
    if eff == "siem_complete":
        ok = s.get("missing") == 0 and s.get("delivered", 0) > 0 and s.get("foreign") == 0
        if "demo_control_ledgered" in s:          # finding 2's vehicle: the demo, against its webhook control
            if not s["demo_control_ledgered"] or s.get("demo_control_rc") != 0:
                return "INCONCLUSIVE", "the demo's webhook control delivered nothing: " + why
            ok = ok and s.get("demo_syslog_ledgered") == s["demo_control_ledgered"]
        return ("PASS" if ok else "FAIL"), why
    if eff == "siem_never_gates":
        ok = not _gates(s) and s.get("missing") == 0 and s.get("foreign") == 0
        if "redirect_target_events" in e:
            ok = ok and s.get("redirect_target_events") == e["redirect_target_events"]
        return ("PASS" if ok else "FAIL"), why
    if eff == "siem_complete_after_recovery":
        # After a kill -9, HOWTO's `two-key recover` drops the tail the signed head did not cover; an event the
        # copy sent for a dropped entry is then "not in this ledger". Allowed only when a recover ran, and shown.
        foreign_ok = s.get("foreign") == 0 or bool(s.get("recovers"))
        ok = s.get("missing") == 0 and foreign_ok and not s.get("start_errors")
        if e.get("replay_marked"):
            ok = ok and s.get("replay_marked", 0) > 0
        if e.get("never_gates"):
            ok = ok and not _gates(s)
        return ("PASS" if ok else "FAIL"), why
    if eff == "siem_gap_or_repeat_detected":
        if not s.get("tampered"):
            return "INCONCLUSIVE", "the cursor could not be changed as the case asks: " + why
        problem = bool(s.get("missing") or s.get("repeats"))
        flagged = s.get("verify_rc") != 0
        if problem and flagged:
            return "PASS", why
        if not problem and not flagged:
            return "PASS", "no gap or repeat came of it, and siem-verify agreed: " + why
        return "FAIL", ("a gap or repeat siem-verify did not report: " if problem else
                        "siem-verify reported a problem the collected copy does not have: ") + why
    if eff == "refused_tokens_bounded":
        ok = s.get("refused") == case.get("n") and s.get("ledger_growth") == e["ledger_growth"] and \\
            1 <= s.get("refused_events", 0) <= e["max_events"] and s.get("all_unledgered") and \\
            not s.get("token_text_in_events")
        return ("PASS" if ok else "FAIL"), why
    if eff == "ledger_kind_count":
        n = (s.get("ledger_kinds_after") or {}).get(e["kind"], 0)
        ok = s.get("token_issued") and n == e["count"]
        return ("PASS" if ok else "FAIL"), f"{e['kind']}={n} (expected {e['count']}): " + why
    return "ERROR", f"unknown expectation {eff}"


def siem_check(cases, results, siem, entries):''')
RP.write_text(rs["src"])
print("patch8x_step4: fixtures wired")
