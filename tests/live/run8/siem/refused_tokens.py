import sys, json, time
sys.argv=[sys.argv[0]]
exec(open("/workspace/run8-manual/outage.py").read().split("t0 = time.perf_counter()")[0].replace("yaml_path, d, phase, n = sys.argv[1], Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])","yaml_path, d, phase, n = 'siem_webhook.yaml', Path('outage/refused'), 'refused', 0"))
tk = TwoKey(led, key.public_key(), con, [FixedJudge("a","yes",provider="p",maker="m"), FixedJudge("b","yes",provider="q",maker="n")], private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT, siem=siem)
gw = tk.gateway(tools={"email_draft": lambda a: {"drafted": a.get("to")}})
before = led.size()
results = [gw.invoke(t, "email_draft", {"to": "ada@example"}).reason for t in ("not.a.token", "aaaa.bbbb.cccc", "x"*50)]
after = led.size()
tk.close()
print(json.dumps({"ledger_before_refusals": before, "ledger_after_refusals": after, "reasons": results}))
