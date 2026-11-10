<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Set up Two-Key with the windows: an illustrated walkthrough (0.9.1)

This walkthrough takes one proxy deployment from nothing to an audited ledger on Two-Key 0.9.1, with a
screenshot of every step. Most of it happens in windows: the setup window writes the deployment, the
constitution editor makes the rules your own and signs them, the agent makes a few calls, and the ledger view
shows what happened. Then the ledger rolls over and the ledger view shows its archive, and the last part moves
an existing 0.9.0 deployment to 0.9.1.

The reference for each window is in [SETUP](SETUP.md), [CONSTITUTION_EDITOR](CONSTITUTION_EDITOR.md) and
[LEDGER_VIEW](LEDGER_VIEW.md); this page only shows one run through them.

## Contents

<!-- toc -->
- [Before you start](#before-you-start)
- [Part 1: Answer the setup questions in the setup window](#part-1-answer-the-setup-questions-in-the-setup-window)
- [Part 2: Make the rules your own in the constitution editor](#part-2-make-the-rules-your-own-in-the-constitution-editor)
- [Part 3: Check the config and let the agent call](#part-3-check-the-config-and-let-the-agent-call)
- [Part 4: Audit what happened in the ledger view](#part-4-audit-what-happened-in-the-ledger-view)
- [Part 5: Roll the ledger over and see the archive](#part-5-roll-the-ledger-over-and-see-the-archive)
- [Already set up on 0.9.0? Moving to 0.9.1](#already-set-up-on-090-moving-to-091)
- [Next steps](#next-steps)
<!-- /toc -->

## Before you start

**You need** Two-Key 0.9.1 with the `mcp` extra (`pip install "two-key[yaml,mcp]==0.9.1"`), Python with
tkinter (on Debian and Ubuntu, `apt install python3-tk`), and three accounts: Two-Key's own (here `ubuntu`),
the monitored agent's (here `agent`), and root for the one sudo rule that lets the agent start the proxy.

**How the screenshots were made.** Every picture is a screen capture from one live run on 2026-11-10 of the
0.9.1 code, in a Linux container with a virtual display. The windows are the real windows: a small script
filled in each field and pressed each button through the window's own code, so every check, warning and
result on screen is Two-Key's. The terminal parts ran in a real xterm. Nothing is drawn or mocked up. The
upstream MCP server is Two-Key's test billing server (`tests/fixtures/fake_mcp_server.py`), and the two
judges are local models answered by a small stand-in server on loopback, so no real money or API key was
involved. The stand-in votes no when the call's own amount is over 1000, and yes otherwise. The shell ran with
the usual umask 022, to show that setup makes its files owner-only by itself.

## Part 1: Answer the setup questions in the setup window

`two-key setup --window` asks the same questions as the terminal wizard, one page per group, and runs the
same code: same files, same checks, same ledger entry. The terminal wizard still works, and the window can save
an answers file for a server with no screen (`two-key setup --answers`). The line at the bottom of the window
always says what is still missing.

1. Log in as Two-Key's own account (never root, never the agent's account) and start the window with a folder
   that does not exist yet:

   ```bash
   two-key setup --dir ~/deploy/billing --window
   ```

2. **Deployment.** The folder is filled in from `--dir`. Keep the `proxy` route, and give the absolute path of
   a passphrase file only this account can read, so the principal key is stored encrypted.

   ![The Deployment page, filled in](images/gui-walkthrough/01-setup-deployment.png)

3. **High assurance (optional).** Ticking the switch shows, grayed out, what the `high_assurance` profile sets
   and the window will not let you change: the tool check on every tool behind the proxy, a signed agent
   roster, a yes from a judge on this machine, refusing to start on writable paths or agent access, no
   plaintext SIEM sinks, checked upstream files, and holding a tool that keeps leaving calls unanswered. Under
   it, each quorum number can only go up. This run unticked it again and uses the default profile.

   ![High assurance switched on, with the settings it locks](images/gui-walkthrough/02-setup-high-assurance.png)

   When an answers file you open says `unanswered_hold: false` and the switch is on, the box says so: high
   assurance always holds, so setup writes `true`. The Proxy page and the Review page say the same, the
   Review page under "Changed by high assurance". The picture is that case, opened from an answers file; the
   red line shows what high assurance still needs before it sets up (here a tool check on `pay_vendor`).

   ![The lock box naming the unanswered_hold the answers file asked for](images/gui-walkthrough/03-setup-ha-override.png)

4. **Judges.** For each judge fill in id, type, model, base URL and maker, then press **Add**. The API key is
   named by its environment variable (*auth env*), never typed; leave it blank for a local model with no key.
   Fill in *upstream* only when the address and model do not say who serves the judge. Here both judges are
   local models on the same host, from two makers.

   ![Two judges added](images/gui-walkthrough/04-setup-judges.png)

5. **Quorum.** These are the profile's numbers for these judges. Keeping or raising them needs nothing more;
   here `min_makers` was raised to 2. Only a number lowered below the profile is weaker and asks for a typed
   yes on the last page.

   The warning under the numbers is about providers, not makers. Both judges are `openai_compatible` with no
   `provider:`, so both count as the type's default provider, `openai-compatible`: one service answering every
   ballot, whoever trained the models. If different services or machines run them, give each judge its own
   `provider:` (in `judges.yaml`, or with `two-key config set`) and set `min_distinct_providers: 2`. Here one
   stand-in answers both, so the warning is right and stays.

   ![The quorum numbers, min_makers raised to 2](images/gui-walkthrough/05-setup-quorum.png)

6. **Agent and history.** Describe the monitored agent and name the variable that holds its credential. Fill in
   *upstream* too (who serves the agent's model) when the address does not say: without it the Review page
   warns `unresolved_identity` and the proxy would refuse to start. Give the account the agent runs as (here
   `agent`): setup then signs an agent roster with this agent first, and the proxy serves it only when that
   account starts it ([AGENT_ROSTER](AGENT_ROSTER.md)). The table below adds more agents, each with its own
   account, or a shared group; this run has one agent. Keep the judge-history defaults.

   ![The monitored agent with its account, the roster table, and the judge-history defaults](images/gui-walkthrough/06-setup-agent-history.png)

7. **Rules and prose.** Leave both files blank to get the starter rules and prose. Add each tool to allow with
   its lowest data class, whether a call can be undone, and the agents that may call it (blank or `any` is
   every agent on the roster). A new row starts with **a call cannot be undone** ticked and the NUL box
   unticked, the safer choice of each; untick what does not apply. Here `pay_vendor` cannot be undone and
   `read_report` can, and both name `billing-agent`.

   The *tool check* column turns on the receipt check for an MCP server that checks its own calls: put a
   receipt key's `hybrid-sha256:` fingerprint there (from `two-key tool-key new`), `exempt`, or leave it blank
   for off ([TOOL_CHECK](TOOL_CHECK.md)). It is off here. The last box lets a NUL character through in the
   tool's arguments. Leave it unticked unless a tool truly needs one: a tool that reads C strings may act on
   less text than the judges read, so ticking it is weaker and asks for the typed yes
   ([HOWTO, "Characters a tool call may not carry"](HOWTO.md)).

   ![pay_vendor and read_report as starter tools, with the form's defaults](images/gui-walkthrough/07-setup-rules-tools.png)

8. **Proxy.** Give the command that starts the upstream MCP server and leave the schema digest blank so setup
   reads it from the server. The agent-session variable is only needed when a judge runs in the cloud. Keep
   *one proxy at a time* on. The unanswered-hold box is off by default; high assurance turns it on.

   ![The upstream server command](images/gui-walkthrough/08-setup-proxy.png)

9. **Review and set up.** Every answer is shown with its warnings: here only the single-provider warning from
   step 5. Nothing is weaker than the profile, so no typed yes is needed. **Save answers file...** writes these
   answers for `two-key setup --answers` on another machine.

   ![The Review page before Set up](images/gui-walkthrough/09-setup-review.png)

10. Press **Set up**. The page now shows what setup did instead of the answers: the `config check` of the new
    deployment (here `0 failure(s)`, with a line each for `unanswered_hold`, `ledger_rollover`, `tool_check`
    and the signed `agents` roster) and the next steps. The bottom line turns to
    `Set up in /home/ubuntu/deploy/billing.`, and two buttons open the next windows on the new folder:
    **Open the constitution editor** and **Open the ledger view**. Ledger rollover is not a page in the setup
    window; it is on at 64 MB by default, and `two-key config set ledger_rollover.*` changes it
    ([HOWTO](HOWTO.md#ledger-rollover)).

    ![Set up done: the config check, the next steps and the buttons for the next windows](images/gui-walkthrough/10-setup-done.png)

## Part 2: Make the rules your own in the constitution editor

The starter allows the tools you named and maps none of their arguments, so Path A cannot see an amount or a
vendor yet. The editor fixes that, lets you try calls against the draft, and signs it with the hybrid key.

1. **Open what setup signed.** Press **Open the constitution editor** in the setup window, or from the
   deployment folder run:

   ```bash
   two-key constitution-editor --signed constitution.signed.json --public-key principal.pub.pem --key principal.pem
   ```

   The editor checks the signature against the folder's `principal.pub.pem` and sets the serial one higher,
   so the new version replaces the old one. The bottom line always says whether the draft signs, here as
   `two-key-constitution-v3`. The tabs are Judges' text, Tools, Rules, Custom fields, Agents, Try a call, and
   Review and sign.

   ![The editor opened on the signed starter constitution](images/gui-walkthrough/11-editor-opened.png)

2. **Judges' text.** Write what the principal wants in plain words. Every judge reads this in full before each
   call. Here a paragraph was added: the agent pays vendor invoices, and the judges should vote no on a payment
   over 1000, on a vendor the operator did not name, or on an odd memo.

   ![The judges' text with the billing paragraph added](images/gui-walkthrough/12-editor-judges-text.png)

3. **Tools: map the arguments.** Pick `pay_vendor`, type its mappings as YAML (`amount` from the `amount`
   argument in US dollars; the counterparty from `vendor`, only `acme-supplies` or `globex`; `memo` a string of
   at most 200 characters), and press **Apply**. The row now lists `amount, counterparties, payload`, and the
   digest at the bottom changes. `read_report` lists `agents`: the agents that may call it, from setup.

   ![pay_vendor applied with its mappings](images/gui-walkthrough/13-editor-tool-applied.png)

   **New tool** clears the form for another tool. Like the setup window, it starts with the stricter defaults:
   **A call cannot be undone** ticked and the lowest data class `classified`. Lower them only for a tool you
   know is safe to undo or reads less sensitive data.

   ![The New tool form with its defaults](images/gui-walkthrough/14-editor-new-tool-defaults.png)

4. **Custom fields and Agents.** Custom fields are the fields your own rules read beyond the five built-in
   ones; this run needs none. The Agents tab is the signed roster as YAML: each agent's id and the account it
   runs as. Setup wrote `billing-agent` on `agent`; add a line here for another agent, then name it in each
   tool it may call.

   ![The Agents tab with the roster setup signed](images/gui-walkthrough/15-editor-agents.png)

5. **Rules: add a hard limit.** On the Rules tab, type an id (`big-payments`) and pick the type
   `deny_if_irreversible_over`.

   ![Picking the rule type](images/gui-walkthrough/16-editor-rule-type.png)

6. Press **Template**, replace its value with `5000`, and press **Apply**. Path A now refuses any call that
   cannot be undone and moves more than 5000, whatever the judges say. Rules run in order; the first one that
   denies is the reason the ledger records.

   ![The big-payments rule applied as rule 2](images/gui-walkthrough/17-editor-rule-applied.png)

7. **Try a call.** Pick `pay_vendor`, type arguments, and press **Run**. The editor signs the draft with a
   throwaway key, uses a temporary ledger and one stand-in judge that votes yes, and shows Path A's result and
   then the full system and user prompt a judge would get, so the output is long. A payment of 2500 to
   `acme-supplies` passes Path A, and the new paragraph is inside `<principal_constitution>`.

   ![A trial call that Path A allows, with the judge's prompt](images/gui-walkthrough/18-editor-try-allowed.png)

8. Try 7500 and Path A denies it with `rule_denied:big-payments`. Nothing real is touched by either run.

   ![A trial call denied by the big-payments rule](images/gui-walkthrough/19-editor-try-denied.png)

9. **Review and sign.** This tab shows the serial (2), the counts (here two tools, two rules, one agent), every
   check (`No warnings or notes`), and the rules file exactly as it will be written. The principal key and
   folder are filled in; give the passphrase file and tick **Replace files that are there**, because setup's
   files are already in the folder.

   ![Review and sign, filled in](images/gui-walkthrough/20-editor-review-and-sign.png)

10. Press **Sign and save**. The editor signs, writes `constitution.md`, `hard_rules.yaml` and
    `constitution.signed.json` owner-only, and says so in green. Close the window. The next start of the proxy
    loads the new constitution and records it as `constitution_loaded`.

    ![Signed and written](images/gui-walkthrough/21-editor-signed.png)

## Part 3: Check the config and let the agent call

1. **Put the agent's credential in the proxy's environment, not in your config.** Here it sits in
   `~/secrets/proxy.env`, readable only by Two-Key's account. Load it and run the check:

   ```bash
   set -a; . ~/secrets/proxy.env; set +a
   two-key config check --config ~/deploy/billing/proxy.yaml
   ```

   The listing above it shows that every file and folder is owner-only although the shell's umask was 022,
   including the three the editor wrote. The check ends with `0 failure(s), 1 warning(s)`: the single-provider
   quorum from Part 1. `ledger_rollover` says when the ledger will seal a segment (64 MB), `tool_check` lists
   each tool's check as on, exempt or off (both off here, which the default profile allows), and `agents`
   names the roster: `billing-agent` on the `agent` account, allowed both tools.

   ![ls -l of the deployment and config check with no failures](images/gui-walkthrough/22-config-check.png)

2. **Give the agent one way in.** The agent's account may start only the proxy wrapper, as Two-Key's account,
   through one exact sudo rule with no arguments ([CONNECTING](CONNECTING.md)). The wrapper sets `umask 077`,
   changes to the deployment folder, loads the secrets file, and starts `two-key mcp-proxy`.

   ![The wrapper script and the agent's only sudo rule](images/gui-walkthrough/23-agent-sudo-wrapper.png)

3. **Point the agent's MCP client at the wrapper** (`sudo -n -u <two-key account> /opt/two-key/run-proxy`) and
   let it work. Here a small client made five calls. The proxy offered only the two signed tools. Reading the
   report and paying 450 to `acme-supplies` went through; 2500 to `globex` was denied by the judges
   (`insufficient_yes:0<2`), 7500 by the hard rule (`rule_denied:big-payments`), and 300 to `initech` because it
   is not on the allow list (`counterparty_not_allowed`). The two `WARNING` lines at start are the proxy asking
   the upstream server to describe its `amount` and `vendor` arguments.

   ![The agent's five calls through the proxy](images/gui-walkthrough/24-agent-calls.png)

## Part 4: Audit what happened in the ledger view

1. **Open the ledger** as Two-Key's account, pinning the witness key (the setup window's **Open the ledger
   view** button opens it with the same pin):

   ```bash
   two-key ledger-view --key principal.pem --key-passphrase-file ~/secrets/principal.pass \
     --ledger ledger --witness-public-key ledger.witness/witness.pub.pem
   ```

   It checks the hash chain, the signed head, the witness pins and every decision's digests before it shows
   anything, and says so in green. It only reads; it writes nothing. The `at` column is UTC time for the kinds
   that record one (decisions, and in Part 5 the seal and continue entries); it is blank for the kinds that
   record no time.

   ![The ledger view on open: 35 verified entries](images/gui-walkthrough/25-ledger-opened.png)

2. **See the hybrid keys.** Select `constitution_loaded`. Key fingerprints start with `hybrid-sha256:`
   (Ed25519 + ML-DSA-65), here the capability key's. A fingerprint that starts with `sha256:` is a key from
   before 0.9.0's key upgrade.

   ![constitution_loaded with a hybrid-sha256 fingerprint](images/gui-walkthrough/26-ledger-hybrid-fingerprint.png)

3. **Filter to decisions.** Press **Add filter**, type `kind` as the field, pick `equals`, and type
   `decision`. Five rows remain, one per call: two allowed, three denied.

   ![Only the decisions](images/gui-walkthrough/27-ledger-decisions.png)

4. **Open one row.** Select the denied 2500 payment to see every field below the table: the reason
   (`insufficient_yes:0<2`), the amount and counterparty, and, above them, the history the judges were shown
   (`history_basis`, `history_digest`) and the digests that tie it to the signed constitution.

   ![The judges' denial, field by field](images/gui-walkthrough/28-ledger-denied-detail.png)

5. **See each judge's vote.** A decision row does not carry the votes: they are on the `path_b` entry just
   before it. Change the filter value to `path_b`, then press **Columns** and pick the fields to show (a plain
   click toggles one). Here everything but `seq`, `kind`, `passed` and the two ballot fields was unticked.

   ![Choosing columns](images/gui-walkthrough/29-ledger-columns.png)

   Each `path_b` row lists both judges and their votes in order. Path B runs alongside Path A, so the judges
   voted on every call, including the two Path A refused: no on 7500, yes on 300 to `initech`, which Path A had
   already stopped for its vendor.

   ![Each judge's vote per call](images/gui-walkthrough/30-ledger-judge-votes.png)

6. **Search everything.** **Clear** removes the filters and empties the search. **Search all fields** finds a
   value anywhere, ignoring case: `big-payments` finds the Path A result and the decision it caused.

   ![Searching for the rule id](images/gui-walkthrough/31-ledger-search.png)

## Part 5: Roll the ledger over and see the archive

A ledger seals its active segment into an encrypted archive by itself when it reaches 64 MB, and you can seal
it at any time ([HOWTO](HOWTO.md#ledger-rollover)). This run sealed it by hand after Part 4, with the proxy
stopped, then let the agent make two more calls.

1. **Roll it.** `two-key ledger roll` takes the same key and pins as `audit`. It prints the archive it wrote
   (`ledger/archive/segment-000001.tkla`, seq 0 to 35) and how much it compressed. Copy `ledger/archive/`
   whenever you copy the ledger directory.

   ```bash
   two-key ledger roll --key principal.pem --key-passphrase-file ~/secrets/principal.pass \
     --ledger ledger --witness-public-key ledger.witness/witness.pub.pem
   ```

   ![ledger roll and the archive it wrote](images/gui-walkthrough/32-ledger-roll.png)

2. **Open the ledger view again.** The banner counts and verifies the whole ledger, 55 entries, archives
   included, but the table lists only the active segment, from seq 36 (`ledger_continued`, the first entry
   after the seal), and the banner says so. An **Include archives** box is shown after **Reload** once a
   ledger has rolled over.

   ![The active segment, with Include archives unticked](images/gui-walkthrough/33a-ledger-archives-off.png)

3. **Tick Include archives.** The view opens and checks each archive and lists every entry from seq 0. The
   search, filters and columns work across all of them. `two-key ledger-view --archives` opens this way, and
   `--print --archives` prints them.

   ![Every entry, archives included](images/gui-walkthrough/33b-ledger-archives-on.png)

## Already set up on 0.9.0? Moving to 0.9.1

Keep your folder and do not run setup again. Constitutions, keys and ledgers load unchanged and nothing is
re-signed, but there is no way back to 0.9.0 once 0.9.1 has written to the ledger: back up first. The full
steps are in [UPGRADING](UPGRADING.md#versions-that-need-more-than-a-reinstall); coming from 0.8.0, follow
[From 0.8.0 to 0.9.0, step by step](UPGRADING.md#from-080-to-090-step-by-step) with 0.9.1 in its place. For
this run a second deployment was set up with 0.9.0 from PyPI (the same answers), the agent made two calls,
and then:

1. Stop the proxy and take a backup with `two-key backup-export`, as in UPGRADING.
2. Install 0.9.1 into the same environment. This run installed the 0.9.1 wheel it was testing; from PyPI it is
   `pip install -U "two-key[yaml,mcp]==0.9.1"`.
3. Run `two-key audit` and `two-key config check`. Both pass with nothing to change, and the check now has the
   `ledger_rollover` line.

   ![backup-export on 0.9.0, the install, then audit and config check on 0.9.1](images/gui-walkthrough/35-upgrade-to-0.9.1.png)

4. Start the proxy as before and back up again. In the ledger view, decisions from before and after the
   upgrade sit in the same verified ledger: here seq 9 and 17 under 0.9.0, and seq 27 and 35 under 0.9.1.

   ![Decisions on both sides of the upgrade](images/gui-walkthrough/36-upgrade-decisions.png)

A new setup on 0.9.1, by window or terminal, starts where this part ends.

## Next steps

To change the rules again, reopen the editor with `--signed` as in Part 2; it bumps the serial each time. To
change one setting with a ledger record and an undo, use `two-key config set` ([SETUP](SETUP.md)). To have the
MCP server check its own calls, follow [TOOL_CHECK](TOOL_CHECK.md). Keep a copy of
`ledger.witness/witness.pub.pem` where Two-Key's account cannot change it.
