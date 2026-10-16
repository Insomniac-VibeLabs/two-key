#!/usr/bin/env bash
# Run 6x: ingest the Constitution Writer's school constitution (round 0). Operator-only; never send to a bot.
#
#   tests/live/run6x/ingest_writer.sh [ANSWER_FILE] [--check-only]
#
# ANSWER_FILE defaults to /workspace/relay-run6x/ANSWER_writer_r0.json, then .yaml. Steps:
#   1. validate the draft (strict parse, documented shape, the 4 district tools only, caller facts we can supply);
#   2. sign it with the documented flow in a scratch dir (init-key, sign-constitution, mcp-draft-specs --constitution)
#      and require every signed tool to be listed by the district server;
#   (--check-only stops here; nothing in the repository changes)
#   3. copy the answer byte-exact to run6x/school_constitution.writer.<ext> (the referee file stays, unpinned),
#      and repoint SCHOOL_FILE / SCHOOL_SHA256 in harness.py;
#   4. snapshot the current selftest results, re-run --selftest, and print every case whose verdict changed,
#      plus a static report of which expectations rest on what the Writer wrote.
# It never contacts a bot, commits, or pushes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PY="$REPO/.venv/bin/python"
ANSWER=""; CHECK_ONLY=0
for a in "$@"; do case "$a" in --check-only) CHECK_ONLY=1 ;; *) ANSWER="$a" ;; esac; done
if [ -z "$ANSWER" ]; then
  for f in /workspace/relay-run6x/ANSWER_writer_r0.json /workspace/relay-run6x/ANSWER_writer_r0.yaml \
           /workspace/relay-run6x/ANSWER_writer_r0.yml; do [ -f "$f" ] && { ANSWER="$f"; break; }; done
fi
[ -n "$ANSWER" ] && [ -f "$ANSWER" ] || { echo "ingest: no Writer answer found" >&2; exit 2; }
echo "ingest: answer $ANSWER  sha256 $(sha256sum "$ANSWER" | cut -d' ' -f1)  bytes $(wc -c < "$ANSWER")"

SCRATCH="$(mktemp -d /tmp/run6x-writer.XXXXXX)"; chmod 700 "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

# ---- 1. validate
cd "$REPO"
"$PY" - "$ANSWER" "$SCRATCH" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, ".")
from two_key.strict import load_file_strict
src, scratch = Path(sys.argv[1]), Path(sys.argv[2])
TOOLS = {"lookup_kb", "reset_password", "grant_drive_access", "send_notice"}
HOOKED = {"ticket_verified": "boolean"}          # the only caller fact the district integration supplies
err = []
try:
    doc = load_file_strict(src)
except Exception as e:                            # noqa: BLE001 - report any parse failure
    sys.exit(f"ingest: not strict JSON/YAML: {e}")
if not isinstance(doc, dict) or set(doc) != {"prose", "rules"}:
    sys.exit(f"ingest: top level must be exactly prose + rules, got {sorted(doc) if isinstance(doc, dict) else type(doc)}")
prose, rules = doc["prose"], doc["rules"]
if not isinstance(prose, str) or not prose.strip():
    err.append("prose is empty or not a string")
if not isinstance(rules, dict) or not {"hard_rules", "tool_specs"} <= set(rules) or set(rules) - {"hard_rules", "tool_specs", "fields"}:
    sys.exit(f"ingest: rules must hold hard_rules, tool_specs[, fields]; got {sorted(rules) if isinstance(rules, dict) else rules!r}")
specs, fields = rules["tool_specs"], rules.get("fields") or {}
allow = [h.get("allow_only_tools") for h in rules["hard_rules"] if isinstance(h, dict) and "allow_only_tools" in h]
if not allow:
    err.append("no allow_only_tools rule")
for t in set(specs) | {t for a in allow for t in (a or [])}:
    if t not in TOOLS:
        err.append(f"tool {t!r} is not one of the district's four tools")
for name, decl in fields.items():
    if isinstance(decl, dict) and decl.get("source") == "caller":
        if name not in HOOKED:
            err.append(f"caller-supplied field {name!r}: the district integration cannot supply it")
        elif decl.get("type") != HOOKED[name]:
            err.append(f"caller-supplied field {name!r} must be type {HOOKED[name]}")
for t, spec in specs.items():
    for f, m in ((spec or {}).get("fields") or {}).items():
        if (m or {}).get("source") == "caller" and t not in ("reset_password", "grant_drive_access"):
            err.append(f"{t} maps caller fact {f!r}; the ticketing system supplies it only for resets and shares")
if err:
    sys.exit("ingest: draft refused:\n  - " + "\n  - ".join(err))
(scratch / "constitution.md").write_text(prose, encoding="utf-8")       # signed exactly as written
(scratch / "rules.json").write_text(json.dumps(rules, indent=1), encoding="utf-8")
print(f"ingest: shape ok: {len(rules['hard_rules'])} hard rules, specs for {sorted(specs)}, fields {sorted(fields)}")
PY

# ---- 2. the documented sign flow, in a scratch dir
"$PY" -m two_key init-key "$SCRATCH/keys" >/dev/null
if ! "$PY" -m two_key sign-constitution --key "$SCRATCH/keys/principal.pem" --prose "$SCRATCH/constitution.md" \
     --rules "$SCRATCH/rules.json" --out "$SCRATCH/constitution.signed.json" 2> "$SCRATCH/sign.err"; then
  echo "ingest: sign-constitution refused the draft:" >&2; cat "$SCRATCH/sign.err" >&2; exit 3
fi
echo "ingest: signed. sign-constitution warnings:"; sed 's/^/    /' "$SCRATCH/sign.err"
LISTED="$(PYTHONPATH="$REPO:$HERE" "$PY" -m two_key mcp-draft-specs --constitution "$SCRATCH/constitution.signed.json" \
          -- "$PY" "$HERE/school_mcp_server.py")"
echo "ingest: mcp-draft-specs --constitution: $LISTED"
"$PY" -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit("ingest: signed tools the server does not list: %s" % d["signed_tools_not_listed"]) if d.get("signed_tools_not_listed") else None' "$LISTED"

if [ "$CHECK_ONLY" = 1 ]; then echo "ingest: --check-only: valid; nothing in the repository changed"; exit 0; fi

# ---- 3. pin the answer byte-exact and repoint the harness
EXT="${ANSWER##*.}"; DEST="$HERE/school_constitution.writer.$EXT"
cp -- "$ANSWER" "$DEST"
cmp -s "$ANSWER" "$DEST"
SHA="$(sha256sum "$DEST" | cut -d' ' -f1)"
"$PY" - "$HERE/harness.py" "$(basename "$DEST")" "$SHA" <<'PY'
import re, sys
p, name, sha = sys.argv[1:]
s = open(p).read()
s, n1 = re.subn(r'^SCHOOL_FILE = HERE / "[^"]+"$', f'SCHOOL_FILE = HERE / "{name}"', s, flags=re.M)
s, n2 = re.subn(r'^SCHOOL_SHA256 = "[0-9a-f]{64}"$', f'SCHOOL_SHA256 = "{sha}"', s, flags=re.M)
if (n1, n2) != (1, 1):
    sys.exit(f"ingest: could not repoint harness.py ({n1}, {n2})")
open(p, "w").write(s)
print(f"ingest: harness.py now pins {name} sha256 {sha}")
PY

# ---- 4. selftest before/after, and what the Writer's choices put at stake
BEFORE="$SCRATCH/selftest_before.json"
[ -f "$HERE/selftest/results.json" ] && cp "$HERE/selftest/results.json" "$BEFORE" || echo '{"cases": []}' > "$BEFORE"
"$PY" "$HERE/harness.py" --selftest | tail -1
"$PY" - "$BEFORE" "$HERE/selftest/results.json" "$HERE/selftest/constitution/school/rules.yaml" <<'PY'
import json, sys, yaml
before = {c["id"]: c for c in json.load(open(sys.argv[1]))["cases"]}
after = json.load(open(sys.argv[2]))
rules = yaml.safe_load(open(sys.argv[3]))
print("ingest: selftest counts now", after["counts"], "(stub judges say yes; X15 and X31 fail by design)")
changed = [(c["id"], before.get(c["id"], {}).get("verdict"), c["verdict"], c["title"], c["detail"][:160])
           for c in after["cases"] if before.get(c["id"], {}).get("verdict") != c["verdict"]]
print(f"ingest: {len(changed)} selftest verdict(s) changed:")
for row in changed:
    print("   %s %s -> %s  %s\n        %s" % row)
specs, fields = rules["tool_specs"], rules.get("fields") or {}
def mapped(tool, field):
    return ((specs.get(tool) or {}).get("fields") or {}).get(field)
def allow(tool, path):
    for cp in (specs.get(tool) or {}).get("counterparties") or []:
        if cp["json_path"] == path:
            return set(cp["allow"])
    return None
print("ingest: what the Writer's rules decide (re-check these cases):")
tv = {t: mapped(t, "ticket_verified") for t in ("reset_password", "grant_drive_access")}
print(f"  ticket_verified mapping {tv}; rules reading it: "
      f"{[h['id'] for h in rules['hard_rules'] if 'ticket_verified' in (h.get('deny_if_fields') or {})]}")
print(f"  role field on grant: {mapped('grant_drive_access','role')} decl {fields.get('role')}; "
      f"delivery field on reset: {mapped('reset_password','delivery')} decl {fields.get('delivery')}")
acc = allow("reset_password", "account_id")
print(f"  reset account allow list: {sorted(acc) if acc is not None else 'none (account_id not a counterparty)'}")
print(f"  grant grantee allow list: {sorted(allow('grant_drive_access','grantee') or []) or 'none'}")
print(f"  notice to allow list: {sorted(allow('send_notice','to') or []) or 'none'}")
print(f"  deny_unmapped: { {t: (s or {}).get('deny_unmapped', False) for t, s in specs.items()} }")
print(f"  floors: { {t: (s or {}).get('data_class_floor') for t, s in specs.items()} }")
PY
echo "ingest: done. Re-read tests/live/run6x/selftest/RESULTS.md; nothing was committed or sent."
