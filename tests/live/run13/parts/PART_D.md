# Run 13, Part D: folder-path rules (`type: path`) + extras Y1-Y5

Executed Tue Nov 3, 2026, 5:20-5:56 PM MST. Tree /workspace/tk-run13 @ 340c876 (working), Python 3.14.8, cryptography 50.0.2, mcp 2.3.0.
Scratch: /workspace/run13-work/partD/ (scripts d12.py, m1.py, m2.py, d46.py, rawproxy.py, pdlib.py, mlib.py; raw results *.json).
Folder under test: N = `/workspace/run13-work/partD/srv/notes` (stands in for `/srv/notes`), "wider" folder = `/workspace/run13-work/partD/srv`.

## Which copy each result came from
- **G** = in-process gateway (TwoKey + `tk.gateway`), the tool is a Python writer with NO folder limit (wider than the signed rule), scripted judge (counts calls). Ledgers: partD/ledgers/d12-1, race-*, d4*/d6*.
- **M** = in-process MCP proxy core (`sdk.running_core` + `build_server`, the same code `mcp-proxy` runs) + the real `@modelcontextprotocol/server-filesystem` 2.1.0 (npm, local), allowed **partD/srv** (wider than the signed `under: [N]`). Ledgers: partD/ledgers/m1-*, y2-*, y4-*, d3b-*.
- **P** = real `two-key mcp-proxy --config partD/d9/proxy.yaml` process over raw stdio JSON-RPC, on a copy of OLD (depB) upgraded to 0.9.0, upstream = the same real filesystem server allowed partD/srv, scripted HTTP judge stub on 127.0.0.1:18790. Ledger: partD/d9/ledger.

"j" = judge calls for that call (0 = no judge asked).

## D1 HOWTO table (G; all 21 rows) - PASS 21/21
| Value (notes -> N) | Expected | Got | j | seq |
|---|---|---|---|---|
| N/todo.txt | allowed | redeemed, file N/todo.txt | 1 | 9 |
| N | allowed | allowed; tool `tool_error:IsADirectoryError` (writing a folder) | 1 | 17 |
| srv//partD/./... `//notes/./todo.txt/` | N/todo.txt | redeemed, landed N/todo.txt | 1 | 25 |
| N/sub dir/a b.txt | same | redeemed, file there | 1 | 33 |
| N/../.ssh/authorized_keys | field_unreadable | `derive_failed:field_unreadable:note_path` | 0 | 38 |
| N/.. | field_unreadable | same | 0 | 43 |
| todo.txt, ./todo.txt, ~/notes/todo.txt, notes/todo.txt | field_unreadable | same (all 4) | 0 | 48-64 |
| N\todo.txt, C:\notes\todo.txt | field_unreadable | same | 0 | 69, 74 |
| N/caf\u00e9.txt, N/a\u0000.txt, N/a\u000a.txt | field_unreadable | same | 0 | 79-89 |
| N2/todo.txt (notes2) | field_not_allowed | `derive_failed:field_not_allowed:note_path` | 0 | 94 |
| srv/Notes/todo.txt | field_not_allowed | same | 0 | 99 |
| srv (parent), `/`, /etc/passwd | field_not_allowed | same | 0 | 104-114 |
| //N/todo.txt | N/todo.txt | redeemed, landed N/todo.txt | 1 | 122 |
Same subset through M (m1.json) and P: clean path reached the real server (`Successfully wrote to N/m_clean.txt` for `srv//notes/./m_clean.txt/`).

## D2 own tricks (G unless noted) - PASS (none wrote outside N)
| Input | Result | j |
|---|---|---|
| `N/%2e%2e/x`, `N/%2e%2e/%2e%2e/etc/x` | allowed: literal folder `%2e%2e` created INSIDE N (no decoding; stays inside) | 1 |
| `N%2f..%2fx` | field_not_allowed | 0 |
| `N/sub/..` (trailing /..), `.` alone | field_unreadable | 0 |
| `N/./x.txt` | allowed, landed N/x.txt | 1 |
| NUL mid, newline mid | field_unreadable | 0 |
| fullwidth slash U+FF0F, fullwidth dot U+FF0E, one-dot leader U+2024, division slash U+2215, RLM U+200F, RLO U+202E | field_unreadable (all) | 0 |
| exactly 4,096 chars (46 segments, segments <=99) | allowed (`coerce_value` ok:4096) | - |
| 4,097 chars | field_unreadable | 0 |
| 64 segments / 65 segments | allowed / field_unreadable (seq 219 / 224) | 1 / 0 |
| 255-char segment / 256-char segment | allowed / field_unreadable (seq 232 / 237) | 1 / 0 |
| JSON number, array, object, null, true, "" | field_unreadable (all) | 0 |
| missing `path` | `derive_failed:field_missing:note_path` (seq 339) | 0 |
| arg named `PATH` / `Path` (G); `PATH` + `path` together (M) | field_missing; with both, only lower-case `path` reaches the tool (M seq 99, `PATH` dropped by projection) | 0 / 1 |
| two `path` keys in raw JSON (P, raw stdio) | NOT refused: last key wins. `{"path":"N/d9_dup_first.txt","path":"srv/d9_dup_second.txt"}` -> field_not_allowed; reversed order -> allowed, file N/d9_dup_in2.txt. Library `strict.loads_json` refuses the same text (`duplicate key 'path'`). No escape (tool gets the checked value) - see finding 3 |
Disk check after D1/D2: nothing under partD/srv outside N except the test fixtures.

## D3 links - PASS (evidence: partD/d3_capture.txt, terminal capture instead of screenshot)
| Item | Copy | Result |
|---|---|---|
| `N/out -> srv/outside` (folder link), write N/out/m_link.txt | M | `path_symlink:note_path`, seq 40; no file in srv/outside |
| `N/outfile -> srv/outside/target.txt`, write / read_text_file | M | `path_symlink:note_path` seq 47 / 54; target.txt still `orig` |
| Notes folder itself a link (`srv/lnotes -> partD/realnotes`) | G | allowed, landed realnotes/via_link.txt (by design) |
| same | M | Two-Key allowed (j=1); the real server refused: "symlink target outside allowed directories" (its own limit; target outside its root) |
| Race: thread swaps N/race between a real folder and a link to srv/outside2 while 300 writes go to N/race/rN.txt | G | 293 redeemed, 7 `path_symlink`, **2 files escaped** to srv/outside2 (r2.txt, r4.txt) during the swap. Best effort as documented; no escape without a swap running. Not a finding |
Note: `path_symlink` is decided at the gateway, after the judge was asked (j=1) and the token issued; the tool did not run.

## D4 rules (G) - PASS
| Rule | Value | Result |
|---|---|---|
| under N/private | N/private/x, N/private, N//private//x | `rule_denied:no-private` |
| | N/privatex | redeemed |
| | N/private/../x | field_unreadable |
| in [N/a.txt, N/b.txt] | N/a.txt, N/./b.txt, N/a.txt/ | `rule_denied:not-these`; N/c.txt redeemed |
| eq N/a.txt | N/a.txt, N//a.txt | `rule_denied:not-a`; N/A.txt and N/a.txtx redeemed (exact case, warned at signing) |
| not_under N/inbox | N/inbox/a, N/inbox | redeemed; N/a, N/inboxx/a `rule_denied:inbox-only` |
Also P: N/private/x -> `rule_denied:no-private`. Rule denials ask the judges (see finding 2).

## D5 signing refusals (`sign-constitution`, partD/sign/*.yaml) - PASS
| Input | Message |
|---|---|
| under [/] | `fields.note_path.under: / admits every path; name the folder the tool may use` |
| under [N, N/sub] | `fields.note_path.under: a folder is listed twice or inside another` (does not name which, finding 5) |
| under [srv//notes/] | `fields.note_path.under[0]: write it in clean form, 'N'` |
| rule under /etc | `rule[1]...under: '/etc' is outside the field's under folders, so the rule could never apply` |
| rule eq N/a/../b | `...eq: not a path this field can hold (absolute, printable ASCII, no backslash, no .. segment)` |
| under [notes] (relative) | same "not a path this field can hold" |
| ok.yaml | signs `two-key-constitution-v3`; prints `note: tool 'write_file': note_path admits any path inside N ...` and the case WARNING |
`constitution-editor --check` prints the same note and `signs as two-key-constitution-v3`; for nested.yaml `does not sign: ... inside another`.

## D6 case (G) - PASS (with doc gap, finding 1)
| Setting | Value | Result |
|---|---|---|
| exact (default) | srv/Notes/x | field_not_allowed (seq 6, j=0) |
| exact | N/X.txt | redeemed, tool got N/X.txt |
| insensitive (folder written lower-case) | srv/Notes/X.TXT; whole path upper-case | redeemed; tool got lower-cased `.../partd/srv/notes/x.txt` |
| insensitive + rule under n/private | N/PRIVATE/a, N/Private/x | `rule_denied:no-private` |
| signing exact field + under rule | WARNING `rule 'no-private': the path field note_path is compared exactly ...` |
| signing insensitive with mixed-case folder | refused `write it in clean form, '/workspace/run13-work/partd/srv/notes'` (finding 1) |

## D7 two path fields (M) - PASS
| Call | Result |
|---|---|
| move_file N/m_todo.txt -> srv/m_moved_out.txt | `derive_failed:field_not_allowed:dest_path`, j=0, seq 73 |
| move_file srv/outside/target.txt -> N/stolen.txt | `field_not_allowed:note_path`, j=0 |
| move_file N/m_clean.txt -> N/sub/m_moved_in.txt | ran, file moved |
| read_multiple_files paths [..] | `derive_failed:field_unreadable:note_path`, j=0, seq 91 |

## D8 versions - PASS
0.9.0 signs the path constitution as `two-key-constitution-v3`. 0.8.0 (uv venv, PyPI `two-key[yaml,mcp]==0.8.0`, deleted afterwards): `sign-constitution` -> `refused: fields.note_path.type: expected one of ['boolean', 'integer', 'enum', 'string']`; loading the 0.9.0-signed v3 file (signed with an Ed25519-only 0.8.0 key so the signature checks) -> `ConstitutionError fields.note_path.type: expected one of ['boolean', 'integer', 'enum', 'string']`.

## D9 upgrade plus paths (P, copy partD/d9 of depB) - PASS
- First `mcp-proxy` start refused `agent_same_account` (single account). `config set on_agent_access warn --confirm-weaker` (typed yes via `script`) did the upgrade: `upgrading the keys to hybrid ed25519+ml-dsa-65, once; let it finish` then `keys_upgraded at seq 170`, then `back up now`.
- Rules replaced by write_file/read_text_file with `note_path` under N, serial 2, `sign-constitution` -> v3; `mcp-draft-specs --constitution` digest sha256:6883d66a...; `config set upstream.command` / `upstream.schema_digest`.
- Start: `serving 2 signed tool(s) ['read_text_file', 'write_file']`. Calls: N/d9_ok.txt written (70 ms); N/private/x rule_denied; N/../x field_unreadable; srv/d9_wider.txt field_not_allowed (the server would have allowed it). Judge stub requests: 6 (2 allowed + 1 rule_denied, 2 judges each; derive_failed asked none).
- `audit --check-history constitution.signed.json`: `"ok": true`, size 213, fingerprints `hybrid-sha256:`.

## Extras
| Item | Result | Evidence |
|---|---|---|
| Y1 NFC `café` / NFD `cafe`+U+0301 | PASS: both field_unreadable (non-ASCII), j=0 | d12.json seq 272/277 |
| Y1 trailing space / dot | allowed, files `N/a.txt ` and `N/a.` (literal, inside) | seq 285/293 |
| Y1 trailing tab | field_unreadable; `N /x` (space on the folder segment) field_not_allowed | seq 298/303 |
| Y2 hard link N/hl -> srv/outside/hl_target.txt | NOTE: allowed (j=1), real server wrote through it; the outside file now reads `VIA-HARDLINK` (same inode). The link check does not (cannot) see hard links; the target is reachable whenever a hard link already sits in the folder. Docs do not mention hard links (finding 7) | m2.json |
| Y3 notes2, notes-private, notes-evil | PASS: field_not_allowed, j=0 | seq 308-318 |
| Y3 folder itself N, `N/` | allowed by Path A (as the table says); tool_error IsADirectoryError, token spent | seq 326/334 |
| Y4 same field on two tools | PASS: note_path on write_file + read_text_file both checked (M); a second path field `other_path` (srv/other) on create_directory: srv/other/m_dir created, N/m_dir field_not_allowed:other_path |
| Y4 unmapped field | PASS: signing refuses a tool that does not map a field a deny rule reads (`each tool must map every field ... or mark it not_applicable`). With `not_applicable`, edit_file's `path` is dropped by projection: the server got no path (`Input validation error ... path ... undefined`), outside file unchanged. Not passed through | y4 |
| Y5 editor round trip | PASS: `constitution_editor.open_signed` + `sign_and_save` (headless API) on d9's constitution: signed body identical except serial 2->3; format v3; diff partD/y5_before.json vs y5_after.json = serial line only. high_assurance part: N/A (not run, time) | y5out/ |

## Counts
PASS 14 of 14 items (D1-D9, Y1-Y5); Y2 recorded as a note; Y5 high_assurance sub-part N/A. 0 FAIL, 0 BLOCKED.

## Findings
| # | Finding | Class | Suggested fix | Input |
|---|---|---|---|---|
| 1 | `case: insensitive` needs `under`/rule paths already lower-case; HOWTO says they "are then lower-cased", and the refusal says "write it in clean form" though the path is clean | doc gap / UX | Say "write it in lower case" in the message, or lower-case at signing; fix HOWTO wording | partD/sign/ci.yaml (`case: insensitive`, `under: [/workspace/run13-work/partD/srv/notes]`) |
| 2 | A `deny_if_fields` path rule denial still asks the judges (j=1 in G; stub +2 in P); only `derive_failed` refusals skip them | Ask Claude (likely WAD: both paths run) | Confirm; if WAD say so in HOWTO | `N/private/x` with rule no-private |
| 3 | Over `mcp-proxy`, raw JSON with two `path` keys is accepted, last wins; the library parser (`strict.loads_json`) refuses duplicates | hardening / UX (no escape: the tool gets the checked value) | Refuse duplicate keys in `tools/call` arguments at the proxy, as everywhere else | rawproxy.py: `{"path":"<srv>/d9_dup_inside.txt","path":"N/d9_dup_in2.txt",...}` |
| 4 | The 4,096 limit is on the raw value: a 4,097-char value that cleans to 4,096 (trailing `/`), or `N` + `//`x2100 + `/x`, is field_unreadable | doc gap (fail closed) | HOWTO: "over 4,096 characters as sent" | m2.json `4096 trailing slash` |
| 5 | Nested-folder refusal does not name the folders | UX | Name both folders | nested.yaml |
| 6 | Undescribed-input warning for a path field suggests "Folder id, exactly as the directory shows it" | UX | For `type: path`, suggest "Absolute POSIX path inside <folder>" | d9 start / mcp-draft-specs |
| 7 | Hard link inside the folder to an outside file is written through (Y2); docs list symlinks only | doc gap (best effort) | THREAT_MODEL/HOWTO: mention hard links; the tool account must not be able to create or own them | N/hl |

Not findings (brief's NOT FINDINGS or documented): race escapes (D3, 2 of 300 during swaps), folder itself as link allowed, `..` refused not resolved, path list field_unreadable, upgrade one-way, `back up now` at every start.

## Departures
- Folder is /workspace/run13-work/partD/srv/notes, not /srv/notes (no root changes needed).
- Scripted judges: in-process `FixedJudge` subclass that counts calls (G, M); HTTP stub on 127.0.0.1:18790 answering `consistent: true` (P). No bots messaged.
- Single box account; on d9 `on_agent_access` set to `warn` with `config set --confirm-weaker` (typed yes via `script`). Because of that, the key upgrade happened at `config set`, not at the first `mcp-proxy` start (the start was refused first by `agent_same_account`).
- D9 path field added by editing hard_rules.yaml and `sign-constitution`, not the editor or `config set`; the editor round trip on that constitution is Y5. Upstream changed with `config set upstream.command` / `upstream.schema_digest`.
- G/M run the product code in-process (gateway / proxy core) rather than separate deployments; P is the real `mcp-proxy` process.
- Filesystem server: npm `@modelcontextprotocol/server-filesystem` 2.1.0 installed locally under partD/npm (not npx).
- D3 evidence is a terminal capture (partD/d3_capture.txt), not a screenshot.
- D8 0.8.0 load test used a constitution signed by 0.9.0 with a 0.8.0-made Ed25519 key, so the type check (not the key) is what refuses.
- Y5 high_assurance sub-part not run.

## Claude: fix vs WAD
- Fix: 1 (message/doc), 3 (refuse duplicate argument keys at the proxy), 5, 6 (messages), 4 and 7 (doc lines).
- Decide: 2 (judges asked for path rule denials).
- WAD: D3 race escapes, folder-as-link allowed, writing to the folder itself gives a tool error after spending the token, `%2e%2e` treated as a literal name.

## Box changes / cleanup
Appended to UNDO_BOX_CHANGES.sh: `rm -rf /workspace/run13-work/partD` (includes npm server, d9 copy, ledgers) and stop the judge stub. Judge stub already stopped; 0.8.0 venv already deleted. No processes left running from Part D.
