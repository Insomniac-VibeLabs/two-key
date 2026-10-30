<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Set up Two-Key with the windows: an illustrated walkthrough (0.9.0)

This walkthrough takes one proxy deployment from nothing to an audited ledger on Two-Key 0.9.0, with a
screenshot of every step. Most of it happens in windows: the setup window writes the deployment, the
constitution editor makes the rules your own and signs them, the agent makes a few calls, and the ledger view
shows what happened. The last part shows what an existing 0.8.0 deployment sees when it moves to 0.9.0.

The reference for each window is in [SETUP](SETUP.md), [CONSTITUTION_EDITOR](CONSTITUTION_EDITOR.md) and
[LEDGER_VIEW](LEDGER_VIEW.md); this page only shows one run through them.

## Contents

<!-- toc -->
- [Before you start](#before-you-start)
- [Part 1: Answer the setup questions in the setup window](#part-1-answer-the-setup-questions-in-the-setup-window)
- [Part 2: Make the rules your own in the constitution editor](#part-2-make-the-rules-your-own-in-the-constitution-editor)
- [Part 3: Check the config and let the agent call](#part-3-check-the-config-and-let-the-agent-call)
- [Part 4: Audit what happened in the ledger view](#part-4-audit-what-happened-in-the-ledger-view)
- [Already set up on 0.8.0? Moving to 0.9.0](#already-set-up-on-080-moving-to-090)
- [Next steps](#next-steps)
<!-- /toc -->

## Before you start

**You need** Two-Key 0.9.0 with the `mcp` extra (`pip install "two-key[yaml,mcp]==0.9.0"`), Python with
tkinter (on Debian and Ubuntu, `apt install python3-tk`), and three accounts: Two-Key's own (here `ubuntu`),
the monitored agent's (here `agent`), and root for the one sudo rule that lets the agent start the proxy.

**How the screenshots were made.** Every picture is a screen capture from one live run on 2026-10-29 at commit
3dabb06 (0.9.0), in a Linux container with a virtual display: the terminal parts in a real xterm, the windows
as they opened, every field typed or clicked in. Nothing is drawn or mocked up. The upstream MCP server is
Two-Key's test billing server (`tests/fixtures/fake_mcp_server.py`), and the two judges are local models
answered by a small stand-in server on loopback, so no real money or API key was involved. The stand-in votes
no when the call's own amount is over 1000, and yes otherwise. The shell ran with the usual umask 022, to show
that setup makes its files owner-only by itself.

The run found two small faults, fixed in 014569f before the release; two pictures show them, and the steps
say what changed.

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
   and the window will not let you change: the tool check on every tool behind the proxy, a yes from a judge on
   this machine, refusing to start on writable paths or agent access, no plaintext SIEM sinks, and checked
   upstream files. Under it, each quorum number can only go up. This run unticked it again and uses the default
   profile.

   ![High assurance switched on, with the settings it locks](images/gui-walkthrough/02-setup-high-assurance.png)

4. **Judges.** For each judge fill in id, type, model, base URL and maker, then press **Add**. The API key is
   named by its environment variable (*auth env*), never typed; leave it blank for a local model with no key.
   Here both judges are local models on the same host, from two makers.

   ![Two judges added](images/gui-walkthrough/03-setup-judges.png)

5. **Quorum.** The profile's five numbers are filled in for these judges. A higher number is stronger and
   needs nothing more; here `min_makers` was raised to 2 with the arrow. A lower number is weaker and needs a
   typed yes on the last page.

   ![The quorum numbers, min_makers raised to 2](images/gui-walkthrough/04-setup-quorum.png)

6. **Agent and history.** Describe the monitored agent and name the variable that holds its credential. Fill in
   *upstream* too (who serves the agent's model) when the address does not say: without it the Review page
   warns `unresolved_identity` and the proxy would refuse to start. Keep the judge-history defaults.

   ![The monitored agent and the judge-history defaults](images/gui-walkthrough/05-setup-agent-history.png)

7. **Rules and prose.** Leave both files blank to get the starter rules and prose. Add each tool to allow with
   its lowest data class and whether a call can be undone. The *tool check* column is new in 0.9.0: put a
   receipt key's `hybrid-sha256:` fingerprint there (from `two-key tool-key new`) when the MCP server checks its
   own calls ([TOOL_CHECK](TOOL_CHECK.md)), `exempt`, or leave it blank for off. It is off here.

   ![pay_vendor and read_report as starter tools](images/gui-walkthrough/06-setup-rules-tools.png)

8. **Proxy.** Give the command that starts the upstream MCP server and leave the schema digest blank so setup
   reads it from the server. The agent-session variable is only needed when a judge runs in the cloud.

   ![The upstream server command](images/gui-walkthrough/07-setup-proxy.png)

9. **Review and set up.** Every answer is shown with its warnings. The one left here is that both judges are
   reached through one provider. Nothing is weaker than the profile, so no typed yes is needed. **Save answers
   file...** writes these answers for `two-key setup --answers` on another machine.

   ![The Review page before Set up](images/gui-walkthrough/08-setup-review.png)

10. Press **Set up**. The bottom line turns to `Set up in /home/ubuntu/deploy/billing.`, and two buttons open
    the next windows on the new folder: **Open the constitution editor** and **Open the ledger view**.

    ![Set up done, with the buttons for the next windows](images/gui-walkthrough/09-setup-done.png)

## Part 2: Make the rules your own in the constitution editor

The starter allows the tools you named and maps none of their arguments, so Path A cannot see an amount or a
vendor yet. The editor fixes that, lets you try calls against the draft, and signs it with the hybrid key.

1. **Open what setup signed.** Press **Open the constitution editor** in the setup window, or from the
   deployment folder run:

   ```bash
   two-key constitution-editor --signed constitution.signed.json --public-key principal.pub.pem --key principal.pem
   ```

   The editor checks the signature and sets the serial one higher, so the new version replaces the old one. The
   bottom line always says whether the draft signs, here as `two-key-constitution-v3` with the hybrid principal
   key setup made. When these pictures were taken the button did not pass `--public-key` yet, so the green
   line on the Review and sign tab (step 8) says the signature was not checked; since 014569f it passes the
   folder's `principal.pub.pem` and the editor checks it.

   ![The editor opened on the signed starter constitution](images/gui-walkthrough/10-editor-opened.png)

2. **Judges' text.** Write what the principal wants in plain words. Every judge reads this in full before each
   call. Here a paragraph was added: the agent pays vendor invoices, and the judges should vote no on a payment
   over 1000, on a vendor the operator did not name, or on an odd memo.

   ![The judges' text with the billing paragraph added](images/gui-walkthrough/11-editor-judges-text.png)

3. **Tools: map the arguments.** Pick `pay_vendor`, type its mappings as YAML (`amount` from the `amount`
   argument in US dollars; the counterparty from `vendor`, only `acme-supplies` or `globex`; `memo` a string of
   at most 200 characters), and press **Apply**. The row now lists `amount, counterparties, payload`, and the
   digest at the bottom changes.

   ![pay_vendor applied with its mappings](images/gui-walkthrough/12-editor-tool-applied.png)

4. **Rules: add a hard limit.** On the Rules tab, type an id (`big-payments`) and pick the type
   `deny_if_irreversible_over`.

   ![Picking the rule type](images/gui-walkthrough/13-editor-rule-type.png)

5. Press **Template**, replace its value with `5000`, and press **Apply**. Path A now refuses any call that
   cannot be undone and moves more than 5000, whatever the judges say. Rules run in order; the first one that
   denies is the reason the ledger records.

   ![The big-payments rule applied as rule 2](images/gui-walkthrough/14-editor-rule-applied.png)

6. **Try a call.** Pick `pay_vendor`, type arguments, and press **Run**. The editor signs the draft with a
   throwaway key, uses a temporary ledger and one stand-in judge that votes yes, and shows Path A's result plus
   the exact system and user prompt a judge would get. A payment of 2500 to `acme-supplies` passes Path A, and
   the new paragraph is inside `<principal_constitution>`.

   ![A trial call that Path A allows, with the judge's prompt](images/gui-walkthrough/15-editor-try-allowed.png)

7. Try 7500 and Path A denies it with `rule_denied:big-payments`. Nothing real is touched by either run.

   ![A trial call denied by the big-payments rule](images/gui-walkthrough/16-editor-try-denied.png)

8. **Review and sign.** This tab shows the serial (2), every check (`No warnings or notes`), and the rules file
   exactly as it will be written. The principal key and folder are filled in; give the passphrase file and tick
   **Replace files that are there**, because setup's files are already in the folder.

   ![Review and sign, filled in](images/gui-walkthrough/17-editor-review-and-sign.png)

9. Press **Sign and save**. The editor signs, writes `constitution.md`, `hard_rules.yaml` and
   `constitution.signed.json`, and says so in green. Close the window. The next start of the proxy loads the
   new constitution and records it as `constitution_loaded`.

   ![Signed and written](images/gui-walkthrough/18-editor-signed.png)

## Part 3: Check the config and let the agent call

1. **Put the agent's credential in the proxy's environment, not in your config.** Here it sits in
   `~/secrets/proxy.env`, readable only by Two-Key's account. Load it and run the check:

   ```bash
   set -a; . ~/secrets/proxy.env; set +a
   two-key config check --config ~/deploy/billing/proxy.yaml
   ```

   It should end with `0 failure(s)`. The one warning left is the single-provider quorum from Part 1. The last
   check is new in 0.9.0: `tool_check` lists each tool's check as on, exempt or off. Both tools are off here,
   which the default profile allows; under `high_assurance` an off tool is a `tool_check_required` failure.

   The listing above it shows that setup made every file and folder owner-only although the shell's umask was
   022. In this picture `constitution.signed.json`, which the editor wrote, is still readable by others; since
   014569f the editor writes it owner-only too.

   ![ls -l of the deployment and config check with no failures](images/gui-walkthrough/19-config-check.png)

2. **Give the agent one way in.** The agent's account may start only the proxy wrapper, as Two-Key's account,
   through one exact sudo rule with no arguments ([CONNECTING](CONNECTING.md)). The wrapper sets `umask 077`,
   changes to the deployment folder, loads the secrets file, and starts `two-key mcp-proxy`.

   ![The wrapper script and the agent's only sudo rule](images/gui-walkthrough/20-agent-sudo-wrapper.png)

3. **Point the agent's MCP client at the wrapper** (`sudo -n -u <two-key account> /opt/two-key/run-proxy`) and
   let it work. Here a small client made five calls. The proxy offered only the two signed tools. Reading the
   report and paying 450 to `acme-supplies` went through; 2500 to `globex` was denied by the judges
   (`insufficient_yes:0<2`), 7500 by the hard rule (`rule_denied:big-payments`), and 300 to `initech` because it
   is not on the allow list (`counterparty_not_allowed`). The two `WARNING` lines at start are the proxy asking
   the upstream server to describe its `amount` and `vendor` arguments.

   ![The agent's five calls through the proxy](images/gui-walkthrough/21-agent-calls.png)

## Part 4: Audit what happened in the ledger view

1. **Open the ledger** as Two-Key's account, pinning the witness key (the setup window's **Open the ledger
   view** button opens it with the same pin):

   ```bash
   two-key ledger-view --key principal.pem --key-passphrase-file ~/secrets/principal.pass \
     --ledger ledger --witness-public-key ledger.witness/witness.pub.pem
   ```

   It checks the hash chain, the signed head, the witness pins and every decision's digests before it shows
   anything, and says so in green. It only reads; it writes nothing.

   ![The ledger view on open: 35 verified entries](images/gui-walkthrough/22-ledger-opened.png)

2. **See the hybrid keys.** Select `constitution_loaded`. Key fingerprints in 0.9.0 start with
   `hybrid-sha256:` (Ed25519 + ML-DSA-65), here the capability key's. A fingerprint that starts with `sha256:`
   is a key from before the upgrade.

   ![constitution_loaded with a hybrid-sha256 fingerprint](images/gui-walkthrough/23-ledger-hybrid-fingerprint.png)

3. **Filter to decisions.** Press **Add filter**, type `kind` as the field, pick `equals`, and type
   `decision`. Five rows remain, one per call: two allowed, three denied.

   ![Only the decisions](images/gui-walkthrough/24-ledger-decisions.png)

4. **Open one row.** Select the denied 2500 payment to see every field below the table: the reason
   (`insufficient_yes:0<2`), the amount and counterparty, the history the judges were shown (`history_basis`,
   `history_digest`), and the digests that tie it to the signed constitution.

   ![The judges' denial, field by field](images/gui-walkthrough/25-ledger-denied-detail.png)

5. **See each judge's vote.** Change the filter value to `path_b`, then press **Columns** and pick the fields
   to show (a plain click toggles one); the columns already shown keep their place.

   ![Choosing columns](images/gui-walkthrough/26-ledger-columns.png)

   Each `path_b` row lists both judges and their votes in order. Path B runs alongside Path A, so the judges
   voted on every call, including the two Path A refused: no on 7500, yes on 300 to `initech`, which Path A had
   already stopped for its vendor.

   ![Each judge's vote per call](images/gui-walkthrough/27-ledger-judge-votes.png)

6. **Search everything.** **Clear** removes the filters. **Search all fields** finds a value anywhere,
   ignoring case: `big-payments` finds the Path A result and the decision it caused.

   ![Searching for the rule id](images/gui-walkthrough/28-ledger-search.png)

## Already set up on 0.8.0? Moving to 0.9.0

Keep your folder and do not run setup again: 0.9.0 upgrades the keys to hybrid Ed25519 + ML-DSA-65 once, and
there is no way back to 0.8.0 except a copy taken before. The full steps are in
[UPGRADING, "From 0.8.0 to 0.9.0, step by step"](UPGRADING.md#from-080-to-090-step-by-step). For this run a
second deployment was made with 0.8.0 from PyPI (same answers, two allowed calls), then moved to 0.9.0:

1. Before upgrading, stop the proxy, take a backup (`two-key backup-export`) and copy the folder, as in
   UPGRADING.
2. Install 0.9.0 and run `two-key config check`. It warns `principal_key: a 0.8.0 Ed25519 key`, which is
   expected.
3. Upgrade the keys. The proxy's first start does it by itself; this run did it by hand with
   `two-key keys upgrade --config proxy.yaml`, which you need anyway when the witness key is pinned outside the
   ledger. It prints `keys upgraded to hybrid ed25519+ml-dsa-65`, the new `hybrid-sha256:` fingerprints and
   every file it replaced, then `back up now`.

   ![config check warning about the 0.8.0 key, then keys upgrade](images/gui-walkthrough/29-upgrade-keys.png)

4. Back up again right away with `two-key backup-export`. The `back up now` reminder stops once it succeeds;
   the agent's next calls through the proxy started with no reminder.
5. In the ledger view (Part 4), type `keys_upgraded` in the search box. The one entry records
   `from_alg = ed25519`, `to_alg = ed25519+ml-dsa-65`, the old and new public keys with signatures by both, and
   the capability key's new `hybrid-sha256:` fingerprint. `two-key audit` lists the same entry with the old
   `sha256:` and new `hybrid-sha256:` fingerprints.

   ![The keys_upgraded entry](images/gui-walkthrough/30-upgrade-ledger-entry.png)

6. Decisions from before and after the upgrade sit in the same verified ledger: here seq 9 and 17 under 0.8.0,
   the upgrade at seq 20, and seq 28 and 36 under 0.9.0.

   ![Decisions on both sides of the upgrade](images/gui-walkthrough/31-upgrade-decisions.png)

7. Change rules in the constitution editor (Part 2) only after the upgrade, so it signs with the new key. The
   upgrade signs the constitution in use again; a signed copy you saved earlier, other than that one, must be
   signed again.

A new setup on 0.9.0, by window or terminal, is hybrid from the start and skips all of this.

## Next steps

To change the rules again, reopen the editor with `--signed` as in Part 2; it bumps the serial each time. To
change one setting with a ledger record and an undo, use `two-key config set` ([SETUP](SETUP.md)). To have the
MCP server check its own calls, follow [TOOL_CHECK](TOOL_CHECK.md). Keep a copy of
`ledger.witness/witness.pub.pem` where Two-Key's account cannot change it.
