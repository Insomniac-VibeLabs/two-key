<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Write and sign a constitution in a window (0.8.0)

A constitution is everything the principal signs in one go: the prose every judge reads, the hard rules
Path A runs, a spec for each allowed tool, the custom fields, and the serial. `two-key constitution-editor`
puts all of it in one window. It checks the draft as you type, runs a trial call through it so you can see
what Path A decides and the exact prompt a judge is sent, and signs it with the principal key.

It signs the same way `two-key sign-constitution` does, with the same code, and writes the same three files.
Nothing it writes needs the editor to read again.

## Contents

<!-- toc -->
- [Open the window](#open-the-window)
- [What it signs](#what-it-signs)
- [The tabs](#the-tabs)
- [Try a call](#try-a-call)
- [Sign and save](#sign-and-save)
- [Edit a constitution that is already signed](#edit-a-constitution-that-is-already-signed)
- [Without a window: --check](#without-a-window---check)
- [What it does not do](#what-it-does-not-do)
<!-- /toc -->

## Open the window

```bash
two-key constitution-editor                                     # a new constitution
two-key constitution-editor --prose constitution.md --rules hard_rules.yaml --key keys/principal.pem
two-key constitution-editor --signed constitution.signed.json --public-key keys/principal.pub.pem
```

`--key` only fills in the key box; the key is read when you press **Sign and save**, not before. `--dir`
chooses the folder the files are written to (by default the folder of `--rules` or `--signed`, else the
current one).

The window is built with tkinter, which comes with Python on Windows and macOS. On Debian and Ubuntu it is a
separate package (`apt install python3-tk`); without it, the command says so, and `--check` and
`two-key sign-constitution` still work.

## What it signs

| Part | Where it is edited | Who reads it |
| --- | --- | --- |
| Prose | **Judges' text** | Every judge, in full, inside `<principal_constitution>` in its prompt |
| Hard rules | **Rules** (the allow list comes from **Tools**) | Path A, in order; the first rule that denies is the reason |
| Tool specs | **Tools** | Path A: whether a call can be undone, the lowest data class, and the argument paths it reads |
| Custom fields | **Custom fields** | Path A, through the specs that map them and the `deny_if_fields` rules that test them |
| Serial | **Review and sign** | The ledger: a constitution with a lower serial than one it has run is refused |

One signature covers all five. The judges' system prompt (the instructions before the constitution) is
Two-Key's own and is not part of the constitution; **Try a call** shows it.

## The tabs

- **Judges' text.** The prose. **Use the starter text** puts back the use-case-agnostic text `two-key setup`
  writes. Write what the principal wants and does not want in plain words; the judges have nothing else to
  go on.
- **Tools.** One row per allowed tool. Pick a row to edit it, or **New tool**. The controls set
  `irreversible` ("A call cannot be undone"), `data_class_floor` ("Lowest data class") and `deny_unmapped`;
  the box below takes the rest of the spec as YAML: `amount`, `counterparties`, `payload` and `fields`
  ([HOWTO, Create a principal key and sign a constitution](HOWTO.md#create-a-principal-key-and-sign-a-constitution)).
  **Apply** adds the tool to the allow list (`allow_only_tools`) and saves its spec; **Remove** takes it out
  of every allow list. Renaming a tool renames it in the allow list too.
- **Rules.** Path A's hard rules, in the order they run. Pick a type (`allow_only_tools`, `deny_if`,
  `deny_if_irreversible_over`, `deny_counterparties`, `deny_if_fields`), press **Template** for a starting
  body, edit it as YAML, and **Apply**. **Up** and **Down** change the order; the first rule that denies is
  the one the ledger names.
- **Custom fields.** The field registry as YAML ([HOWTO, Custom Path A fields](HOWTO.md#custom-path-a-fields)).
  **Insert an example** adds one enum field to change.
- **Try a call.** See below.
- **Review and sign.** The serial, the envelope format (`auto` unless you need an older one), every check
  and note `sign-constitution` would print, the rules file exactly as it will be written, and the key and
  file boxes.

A value typed into a box is read strictly, as Two-Key reads its files: a key given twice is refused. A
problem shows next to the button you pressed. The line at the bottom of the window always says whether the
draft signs, and if not, why not.

## Try a call

Pick a tool, type its arguments (JSON or YAML), and press **Run**. The editor signs the draft with a
throwaway key, opens a temporary ledger, and sends the call through `TwoKey.authorize` with one stand-in
judge that votes yes. It shows:

- what Path A decided and why (`pass`, `rule_denied:<rule id>`, a `derive_failed:` reason),
- Two-Key's decision with that one yes vote,
- the system prompt and the user prompt the stand-in judge was sent: the prose, the judge history summary,
  and the action record, escaped as a real judge receives them.

**Claimed data class** is the claim the proxy or guard sends for the tool: `none` (the default, read as
`classified`), `floor` (the tool's signed lowest data class), or a class, as `tools.<id>.claim` in
[SETTINGS.md](SETTINGS.md). **Proposal** reaches only a judge set to receive it, so by default it
is not in the prompt. **Caller facts** fill `source: caller` fields. Nothing real is touched: no key, ledger,
or judge of the deployment, and nothing is sent anywhere. A real judge's prompt can differ in one way: a
judge with `echo_binding` also gets a `<ballot_binding>` section.

## Sign and save

Fill in the principal key (`principal.pem`), its passphrase if the key is encrypted (typed, or a passphrase
file only you can read), and the folder. **Sign and save** then:

1. checks the draft again and signs it with `sign_constitution`,
2. verifies the signed envelope with the key's public half,
3. writes the prose (`constitution.md`) and the rules file (`hard_rules.yaml`, or JSON for a `.json` name),
   each owner-only, beside its target and then renamed into place,
4. reads those two files back the way `two-key sign-constitution` reads them, and refuses if they would not
   sign to the same body,
5. writes the signed constitution (`constitution.signed.json`) last.

It refuses, with nothing written, when a file is already there and **Replace files that are there** is not
ticked (`sign-constitution`'s `--force`). A folder or file it cannot write is reported under the buttons, as
every refusal is, and `constitution.signed.json` is written only after both sources were. The passphrase box
is emptied after every try, and the key is not kept once the files are written. **Save prose and rules only
(unsigned)** writes the first two files, to review or sign later.

The rules file is what `two-key config set --rules` needs to change a signed setting later, and it signs to
the same digest with `two-key sign-constitution`.

## Edit a constitution that is already signed

Open it with **File, Open a signed constitution** (or `--signed`). Give its public key to check the
signature first; without one the editor says it did not check. The editor shows the signed body without the
defaults signing fills in (`amount: null`, `payload: []`), and sets the serial one higher, so the new
version replaces the old one in the ledger's order. **File, Open prose and rules** opens the source files
instead.

A proxy deployment made by `two-key setup` keeps its files in one folder. Writing a new
`constitution.signed.json` there is what `two-key sign-constitution --force` does: the next start of the
proxy loads it, and the ledger records it as `constitution_loaded`. To change one signed setting with a
`config_changed` ledger entry and `config undo`, use `two-key config set` instead
([SETUP.md](SETUP.md)).

## Without a window: --check

```bash
two-key constitution-editor --check --prose constitution.md --rules hard_rules.yaml
```

prints every warning and note, then `signs as <format>, digest <digest>`, and exits 0; or `does not sign:
<reason>` and exits 1. It reads the files and writes nothing.

## What it does not do

- It does not choose judges, the quorum, or the monitored agent. Those are in `judges.yaml`, which is not
  signed: `two-key setup` writes it and `two-key config set` changes it.
- It does not change the judges' system prompt or what Two-Key sends them besides the prose.
- It opens no network port and sends nothing anywhere; a trial call stays in a temporary folder that is
  removed afterwards.
- It does not record a ledger entry when it signs, as `two-key sign-constitution` does not.
