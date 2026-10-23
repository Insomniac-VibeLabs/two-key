# Run 9s notes

- Not covered: everything ran on one machine, over loopback, as one OS account (proxies used `on_agent_access: warn` and `allow_unresolved_identity: true` in the throwaway serial deployments). A monitored agent connecting from another machine is still untested; that is the open gap before 1.0.
- Scanners: DeepSource (Python, Secrets) and SonarCloud were checked on GitHub, not by us. Per the brief, every check on 8b3fd76 is green, including the SonarCloud gate. We did not re-run or verify them.
- Cyber's Scorecard check was not run.
- Step 7 (the live relay pass) ran: 165 PASS / 10 INCONCLUSIVE / 0 FAIL, C129 and C170 PASS live. Relay incidents: transport truncation at r10/r12, file-path delivery from r13, Cyber freeze/remake at r18, toned-down Cyber attacks from r18. See LIVE_SUMMARY.md.
- The serial scripts were rebuilt, not the 9y/9z originals (see SERIAL.md). T1 is an in-process differential test, not CLI.
- Not committed: state/, selftest/, cases.jsonl, keys, *.pem, ledgers, tls/, relay payloads, the serial scripts and their deployments.
