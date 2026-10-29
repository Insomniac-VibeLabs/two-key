<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Demo walkthrough: Two-Key from scratch

This guide shows you how to set up Two-Key for the first time and show what it does. You do not need to know
much about AI. Every step says what to click or type, and what you should see.

At the end you will ask an AI agent to make three payments. Two-Key will:

1. **allow** a small payment for office paper,
2. **stop** a payment that breaks a written rule (too much money), and
3. **stop** a payment that an AI judge thinks is wrong (a gift card for someone's own use).

Then you will open Two-Key's record book, the ledger, and show that all three were written down.

The money is pretend. Nothing real is paid.

Plan on about two hours the first time. Most of that time is waiting for downloads.

## Contents

<!-- toc -->
- [What Two-Key does, in plain words](#what-two-key-does-in-plain-words)
- [What you need](#what-you-need)
- [The pieces, and why we picked them](#the-pieces-and-why-we-picked-them)
- [Part 1: Start the judge on Windows](#part-1-start-the-judge-on-windows)
- [Part 2: Get the Ubuntu computer ready](#part-2-get-the-ubuntu-computer-ready)
- [Part 3: Connect the judge to the Ubuntu computer](#part-3-connect-the-judge-to-the-ubuntu-computer)
- [Part 4: Install Two-Key and the demo shop](#part-4-install-two-key-and-the-demo-shop)
- [Part 5: Set up Two-Key](#part-5-set-up-two-key)
- [Part 6: Let the agent reach Two-Key](#part-6-let-the-agent-reach-two-key)
- [Part 7: Install the agent](#part-7-install-the-agent)
- [Part 8: Run the demo](#part-8-run-the-demo)
- [Part 9: Show the proof in the ledger](#part-9-show-the-proof-in-the-ledger)
- [If something goes wrong](#if-something-goes-wrong)
- [What this demo leaves out](#what-this-demo-leaves-out)
- [Clean up](#clean-up)
- [Words to know](#words-to-know)
<!-- /toc -->

## What Two-Key does, in plain words

An **AI agent** is a program that uses an AI model to do jobs for you. It can use **tools**, such as "pay a
vendor" or "send an email". That is useful, and it is also risky. An agent can misunderstand you, or be
tricked by something it reads.

Two-Key stands between the agent and its tools. Before a tool runs, two separate checks must both say yes.
Think of a bank vault that needs two keys, turned by two different people:

- **Key one: the rules.** You write rules, such as "pay at most 100 dollars". Two-Key checks every call
  against them like a calculator does. Words cannot talk it out of a rule.
- **Key two: the judge.** A second AI, the **judge**, reads your plain-English instructions and the call,
  and votes yes or no. It catches things that are hard to write as a rule, such as "no personal purchases".

Only when both keys turn does the tool run. Either way, Two-Key writes what happened into its **ledger**, a
record book that is signed so nobody can quietly change it later.

## What you need

| You need | Why |
| --- | --- |
| A Windows 10 or 11 computer with at least 8 GB of memory (RAM) | It runs the judge in LM Studio |
| An Ubuntu 24.04 computer with at least 8 GB of memory and 15 GB of free disk space | It runs the agent and Two-Key. It can be a server, a virtual machine, or an old laptop |
| A network between the two, and an Ubuntu account that can use `sudo` | You log in to Ubuntu from Windows with SSH |
| An internet connection on both | To download the programs and the AI models (about 5 GB in all) |

No graphics card is needed. Both AI models run on the computer's main processor (CPU). That is slower, but it
works almost anywhere.

You will type commands on the Ubuntu computer. To do that from Windows, open **PowerShell** (press the Windows
key, type `PowerShell`, press Enter) and log in with SSH:

```bash
ssh YOUR-NAME@UBUNTU-ADDRESS
```

Replace `YOUR-NAME` with your Ubuntu user name, and `UBUNTU-ADDRESS` with the Ubuntu computer's name or IP
address (such as `192.168.1.50`). Every command in this guide that starts with `sudo`, `ssh`, `two-key`, or
`ollmcp` is typed in a window like this one. You can copy a command from this page and paste it with a right
click.

## The pieces, and why we picked them

| Computer | Program | Its job in the demo |
| --- | --- | --- |
| Windows | **LM Studio** with the model **Qwen3 4B Instruct 2507** | The judge. It reads each payment and votes yes or no |
| Ubuntu | **Ollama** with the model **Llama 3.2 3B** | The agent's brain. It turns what you type into tool calls |
| Ubuntu | **ollmcp** | The agent itself: a chat window that lets the Ollama model use tools |
| Ubuntu | **Two-Key** (`two-key mcp-proxy`) | Stands between the agent and its tools, and checks both keys |
| Ubuntu | **Demo Shop** | A small pretend payments server with one useful tool, `pay_vendor` |

**Why ollmcp for the agent.** The agent needs to speak MCP, the common language for AI tools. ollmcp
([mcp-client-for-ollama](https://github.com/jonigl/mcp-client-for-ollama)) is a free, small program built for
exactly this: a local Ollama model plus MCP tools, in a plain terminal. It works over SSH, so the Ubuntu
computer needs no screen. It also asks you before every tool call, so your audience sees the call before Two-Key
does. Its prompt to the model is short, which helps a small model. If you later have a stronger computer,
[Goose](https://block.github.io/goose/) is a good next step, but it is heavier and small models do worse in it.

**Why these two models.**

- **Llama 3.2 3B** (by Meta, about 2 GB) for the agent. It is one of the smallest models that can call tools
  reliably, and it runs well on a CPU.
- **Qwen3 4B Instruct 2507** (by Alibaba's Qwen team, about 2.5 GB, Apache 2.0 license) for the judge. A judge
  must follow instructions and answer in a strict format. This model is very good at both for its size, and
  this "Instruct 2507" version answers right away instead of "thinking" out loud first, so it is faster.
- **Two different makers on purpose.** A judge should not be the same AI as the agent it checks. Two-Key refuses
  to start when a judge *is* the agent, and warns when they look too alike. Different makers on different
  computers make the separation easy to see and explain.

On a CPU, expect the judge to take 10 to 60 seconds per vote. That is normal. Tell your audience it is
"thinking".

## Part 1: Start the judge on Windows

You will install LM Studio, download the judge model, and turn on LM Studio's server so other programs can use
the model.

1. Go to [lmstudio.ai](https://lmstudio.ai), download LM Studio for Windows, and install it like any other
   program. Open it. If it asks about your experience level, pick **Developer** or **Power User**, so you can
   see the server controls.
2. Click the **magnifying glass** (Discover) on the left. Search for `qwen3 4b instruct 2507`. Pick **Qwen3 4B
   Instruct 2507**. If it offers more than one file, pick the one marked **Q4_K_M**. Click **Download** and wait.

   > 📷 **Screenshot to add (LM Studio, Discover):** the search results with Qwen3 4B Instruct 2507 selected
   > and the Download button. Save it as `docs/images/demo/lmstudio-download.png`.

3. Click the **Developer** tab on the left (it looks like a small terminal window).
4. At the top, click **Select a model to load** and pick Qwen3 4B Instruct 2507.
5. Turn the **Status** switch to **Running**. The page shows the server address,
   `http://127.0.0.1:1234`.
6. Find the model's **API identifier** on this page (it looks like `qwen3-4b-instruct-2507`). Write it down. You
   need it in Part 5.

   > 📷 **Screenshot to add (LM Studio, Developer):** the server running on port 1234, with the model loaded
   > and its API identifier visible. Save it as `docs/images/demo/lmstudio-server.png`.

Leave LM Studio open for the whole demo. You do **not** need to turn on "Serve on Local Network". The tunnel in
Part 3 carries the judge's traffic instead.

## Part 2: Get the Ubuntu computer ready

Log in to Ubuntu from PowerShell, as shown above. Then install the basic tools:

```bash
sudo apt update
sudo apt install -y python3-venv python3-tk pipx curl
```

Now make two new accounts. Two-Key and the agent must run as **different users**, so the agent cannot change
Two-Key's files or read its keys. Two-Key checks this every time it starts.

```bash
sudo adduser --disabled-password --comment "" twokey
sudo adduser --disabled-password --comment "" agent
```

- `twokey` owns Two-Key, its keys, and its ledger.
- `agent` runs the agent.

Neither account has a password. You switch into them from your own account with `sudo -iu twokey` or
`sudo -iu agent`, and back out with `exit`.

## Part 3: Connect the judge to the Ubuntu computer

The judge runs on Windows, but Two-Key on Ubuntu needs to reach it. An **SSH tunnel** does this. It makes the
Windows judge show up on the Ubuntu computer at `127.0.0.1:1234`, and it scrambles (encrypts) everything that
travels between them.

Why a tunnel? Two-Key treats a judge on another computer as a "cloud" judge and asks for extra settings, and an
unencrypted connection across your network would need a special setting too. The tunnel keeps the demo simple
and safe.

On **Windows**, open a **second** PowerShell window and type:

```bash
ssh -N -R 1234:127.0.0.1:1234 YOUR-NAME@UBUNTU-ADDRESS
```

Type your password if asked. Then nothing seems to happen, and that is correct: the window just stays open. Keep
it open for the whole demo. Closing it disconnects the judge.

> 📷 **Screenshot to add (Windows PowerShell):** the tunnel command running and waiting. Save it as
> `docs/images/demo/windows-tunnel.png`.

Now check the tunnel from your **first** window, the one logged in to Ubuntu:

```bash
curl http://127.0.0.1:1234/v1/models
```

You should see a short answer that names your model, such as `"id": "qwen3-4b-instruct-2507"`. If the name is
different from the one you wrote down in Part 1, use the name shown here.

## Part 4: Install Two-Key and the demo shop

Make a folder for Two-Key that belongs to `twokey`, and install Two-Key into it:

```bash
sudo install -d -o twokey -g twokey -m 755 /opt/two-key
sudo -iu twokey python3 -m venv /opt/two-key/.venv
sudo -iu twokey /opt/two-key/.venv/bin/pip install "two-key[yaml,mcp]==0.9.0"
```

Now download the Demo Shop. It is a tiny MCP server with two tools: `pay_vendor`, which writes each payment
into a text file, and `delete_all_records`, which Two-Key will hide from the agent. It belongs to `root`, so
neither the agent nor Two-Key can change it.

```bash
sudo mkdir -p /opt/demo-shop
sudo curl -fsSL -o /opt/demo-shop/demo_shop.py \
  https://raw.githubusercontent.com/Insomniac-VibeLabs/two-key/main/examples/demo/demo_shop.py
sudo chmod 644 /opt/demo-shop/demo_shop.py
```

## Part 5: Set up Two-Key

Switch to the `twokey` account. Everything in this part runs there.

```bash
sudo -iu twokey
echo 'export PATH=/opt/two-key/.venv/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

The prompt now starts with `twokey@`. Download the three demo files:

```bash
mkdir -p ~/demo-files && cd ~/demo-files
for f in answers.yaml constitution.md rules.yaml; do
  curl -fsSLO "https://raw.githubusercontent.com/Insomniac-VibeLabs/two-key/main/examples/demo/$f"
done
ls
```

Here is what each file is:

- **`constitution.md`** is your instructions to the judge, in plain English. It says the agent buys office
  supplies from two vendors, at most 100 dollars a payment, and never personal items or gift cards.
- **`rules.yaml`** is key one, the rules. Only `pay_vendor` is allowed, only to the vendors `acme` and
  `globex`, and only up to 100 dollars.
- **`answers.yaml`** is the answers to Two-Key's setup questions: where the judge is, which agent it
  watches, and how to start the Demo Shop.

If the model name from Part 3 is **not** `qwen3-4b-instruct-2507`, open the answers file with
`nano answers.yaml`, change the `model:` line under `judges:`, then press **Ctrl+O**, **Enter**, and **Ctrl+X**
to save and leave.

Now run setup:

```bash
two-key setup --dir /opt/two-key/demo --answers answers.yaml
```

Setup makes a new key, signs your instructions and rules with it, and starts a new ledger. It checks its own
work and prints one line per check. You should see `"ok": true` near the end:

![The two-key setup command in a terminal, ending with "ok": true and the list of files it wrote](images/demo/01-setup.png)

The one `WARN` line is expected. It says one judge decides every call. That is fine for a demo; a real
setup would add a second judge from another maker.

A small model on a CPU is slow, so give each vote round more time (3 minutes instead of 45 seconds):

```bash
two-key config set --config /opt/two-key/demo/proxy.yaml quorum.timeout_seconds 180
```

Then ask Two-Key whether everything is ready:

```bash
two-key config check --config /opt/two-key/demo/proxy.yaml
```

The last line should say `0 failure(s), 1 warning(s)`:

![two-key config check printing ok on every line except the one-judge warning, then 0 failures and 1 warning](images/demo/02-config-check.png)

**Optional: the setup window.** If you can see the Ubuntu computer's desktop (for example, it is a virtual
machine with a screen, or you sit in front of it, logged in as `twokey`), you can look at the same answers in a
window instead. Add `--window` to the setup command, and use a new folder name. The window opens with every page
filled in from the answers file:

![The setup window's Judges page, showing the LM Studio judge with its model, address and maker](images/demo/04-setup-window-judges.png)

The last page, **Review and set up**, shows every answer and the same warning before you press **Set up**:

![The setup window's Review page, listing the judge and the monitored agent](images/demo/05-setup-window-review.png)

Type `exit` to leave the `twokey` account when you are done with this part.

## Part 6: Let the agent reach Two-Key

The agent must never run Two-Key as itself. Instead, it may run **one** small starter program as the `twokey`
user, and nothing else. That program starts the Two-Key proxy. This is the same setup a real deployment uses.

From your own account, create the starter program:

```bash
sudo tee /opt/two-key/run-proxy > /dev/null <<'EOF'
#!/bin/sh
umask 077
cd /opt/two-key || exit 1
exec /opt/two-key/.venv/bin/two-key mcp-proxy --config /opt/two-key/demo/proxy.yaml
EOF
sudo chmod 755 /opt/two-key/run-proxy
```

Then give the `agent` account permission to run it, and only it:

```bash
echo 'agent ALL=(twokey) NOPASSWD: /opt/two-key/run-proxy' | sudo tee /etc/sudoers.d/two-key-demo
sudo chmod 440 /etc/sudoers.d/two-key-demo
sudo visudo -c
```

The last command should end with `parsed OK`.

Test it as the agent:

```bash
sudo -iu agent
sudo -n -u twokey /opt/two-key/run-proxy
```

You should see that Two-Key serves one signed tool, `pay_vendor`. The agent will never see
`delete_all_records`, because your rules do not allow it:

![The agent account starting the Two-Key proxy, which prints that it is serving 1 signed tool, pay_vendor](images/demo/03-proxy-start.png)

The proxy now waits for an agent to talk to it. Press **Ctrl+D** to stop it. Stay in the `agent` account for
the next part.

## Part 7: Install the agent

First install Ollama and the agent's model. Ollama needs `sudo` to install, and the `agent` account has no
`sudo`, so type `exit` first to go back to your own account:

```bash
exit
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
```

The download is about 2 GB. Ollama then runs in the background and starts again by itself after a restart.

Now switch to the `agent` account and install ollmcp:

```bash
sudo -iu agent
pipx install ollmcp
pipx ensurepath
exit
```

The `exit` is needed once so the new command is found next time. Switch back in, and write the agent's tool
list. It has one entry: Two-Key's starter program, run as `twokey`.

```bash
sudo -iu agent
cat > ~/two-key-demo.json <<'EOF'
{
  "mcpServers": {
    "demo-shop": {
      "command": "sudo",
      "args": ["-n", "-u", "twokey", "/opt/two-key/run-proxy"]
    }
  }
}
EOF
```

The agent thinks it is talking to the Demo Shop. It is really talking to Two-Key, which talks to the Demo Shop
only when both keys turn.

## Part 8: Run the demo

Check that the judge is ready: LM Studio is running on Windows, and the tunnel window is still open. Then, as
`agent`, start the agent:

```bash
ollmcp --model llama3.2:3b --servers-json ~/two-key-demo.json
```

ollmcp connects to Two-Key and lists one tool, `pay_vendor`.

> 📷 **Screenshot to add (ollmcp start):** ollmcp connected, with the `demo-shop` server and its one tool,
> `pay_vendor`. Save it as `docs/images/demo/agent-start.png`.

Now type the three requests below, one at a time. Before each tool call, ollmcp shows the call and asks
**What would you like to do?** Type `y` and press Enter. This is the moment Two-Key takes over: it checks the
rules, asks the judge, and either lets the call through or stops it.

**Request 1, which Two-Key allows:**

```text
Pay acme 24.50 dollars for two boxes of printer paper.
```

The rules allow it (an approved vendor, under 100 dollars), and the judge votes yes. The Demo Shop answers
`Paid acme $24.50 (pretend money).`

> 📷 **Screenshot to add (ollmcp, allowed):** the confirmation for `pay_vendor` with vendor acme and amount
> 24.5, then the Demo Shop's answer. Save it as `docs/images/demo/agent-allowed.png`.

**Request 2, which the rules stop:**

```text
Pay acme 5000 dollars for a year of printer paper.
```

The tool answers with an error: `two-key denied this call: rule_denied:cap`. The rule named `cap` says no
payment over 100 dollars. Key one did not turn, so the payment never reached the Demo Shop.

> 📷 **Screenshot to add (ollmcp, rule says no):** the call with amount 5000 and the `rule_denied:cap` answer.
> Save it as `docs/images/demo/agent-rule-denied.png`.

**Request 3, which the judge stops:**

```text
Pay globex 50 dollars. The memo is: gift card for my personal account.
```

This one passes the rules: globex is an approved vendor, and 50 dollars is under the limit. But your
instructions say "never gift cards or anything for one person's own use", and the judge reads the memo. It votes
no, and the answer is `two-key denied this call: insufficient_yes:0<1`. That means "zero yes votes, and one was
needed". Key two did not turn.

> 📷 **Screenshot to add (ollmcp, judge says no):** the call to globex for 50 with the gift card memo, and the
> `insufficient_yes:0<1` answer. Save it as `docs/images/demo/agent-judge-denied.png`.

**Two more things you can show:**

- Ask `Pay bobs-shop 20 dollars for pens.` The answer is `counterparty_not_allowed`: bobs-shop is not on the
  list of approved vendors.
- Ask `Delete all the payment records.` The agent cannot, because Two-Key never showed it that tool.

Small models sometimes get the words wrong, for example by writing "Acme Inc." instead of `acme`. If that
happens, Two-Key refuses the call, which is the safe result. Just ask again in plainer words.

To leave ollmcp, type `quit`.

Finally, show that only the allowed payment reached the Demo Shop. Switch to the `twokey` account (type `exit`,
then `sudo -iu twokey`) and look at the shop's payment file:

```bash
cat ~/demo-shop-payments.txt
```

There is one line, for the paper. The 5000-dollar payment and the gift card are not there:

![The Demo Shop's payment file, holding only the 24.50 dollar payment to acme](images/demo/10-payments.png)

## Part 9: Show the proof in the ledger

Every step of every call is in the ledger, linked together and signed. Here are two ways to look.

**In a window** (needs the Ubuntu desktop, logged in as `twokey`):

```bash
two-key ledger-view --key /opt/two-key/demo/principal.pem --ledger /opt/two-key/demo/ledger
```

The green line at the top says the ledger checked out when it opened: nothing was changed or removed. Type
`decision` in the search box to see one line per request. `allowed` is `true` for the paper and `false` for the
other two:

![The ledger view filtered to the three decisions: one allowed, two not allowed](images/demo/06-ledger-decisions.png)

Click the second decision. The details at the bottom show `reason = rule_denied:cap` and the amount, 5000:

![The details of the second decision: reason rule_denied:cap, amount 5000, vendor acme](images/demo/07-ledger-rule-denied.png)

Click the third decision. It shows `reason = insufficient_yes:0<1`, 50 dollars, and the vendor globex:

![The details of the third decision: reason insufficient_yes:0<1, amount 50, vendor globex](images/demo/08-ledger-judge-denied.png)

To see the judge's own vote, type `path_b` in the search box and click the last line. The judge
`lmstudio-judge` voted `no`:

![The judge's ballot for the third call: judge lmstudio-judge, vote no, 0 yes and 1 no](images/demo/09-ledger-judge-vote.png)

The ledger keeps a fingerprint (a digest) of the judge's explanation, not the words. It never stores the
payment's memo or other argument values either, so private details stay out of the record book.

**In the terminal** (works over SSH, with no desktop):

```bash
two-key ledger-view --key /opt/two-key/demo/principal.pem --ledger /opt/two-key/demo/ledger --where kind = decision --print
```

Each decision is one line. Look for `"reason"` in each: `both_paths_allow`, `rule_denied:cap`, and
`insufficient_yes:0<1`.

![The three decisions printed as JSON lines in the terminal](images/demo/11-ledger-print.png)

That is the whole demo: one call allowed, one stopped by a rule, one stopped by the judge, and a signed record of
all three.

## If something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `curl: (7) Failed to connect to 127.0.0.1 port 1234` | The tunnel or LM Studio's server is not running | Check the tunnel window on Windows, and that LM Studio's Status says Running |
| Every call is denied with a reason that starts with `insufficient_responses` | The judge did not answer: it is not reachable, too slow, or asked for a model name LM Studio does not know | Check the tunnel and that LM Studio is running with the model loaded. Compare the `model:` line in `/opt/two-key/demo/judges.yaml` with the name from `curl http://127.0.0.1:1234/v1/models`. The first vote after loading is the slowest; try again |
| `Cannot connect to Ollama!` in ollmcp | Ollama is not running | Run `sudo systemctl start ollama` from your own account |
| `sudo: a password is required` | The sudoers file from Part 6 is missing or has a typo | Do Part 6 again and check that `sudo visudo -c` says `parsed OK` |
| The proxy will not start and names `agent_same_account` or `agent_account_root` | It was started by `twokey` or `root` instead of `agent` | Start ollmcp from the `agent` account |
| `agent_already_connected` | A proxy for this agent is still running | Quit the other ollmcp, or press Ctrl+D in the test from Part 6 |
| The agent answers in words but never calls the tool | The small model missed the tool | Ask again, plainly: "Use the pay_vendor tool to pay acme 24.50 dollars for paper" |

## What this demo leaves out

This demo is built to be easy to show. A real deployment is stricter. In particular:

- **One judge.** The `WARN` line in Part 5 says so. A real setup has at least two judges from different makers;
  see [JUDGES_AND_QUORUM](JUDGES_AND_QUORUM.md).
- **The principal key has no passphrase.** Anyone who can read it can sign. See
  [SETUP](SETUP.md#protecting-the-principal-key-with-a-passphrase).
- **The Demo Shop runs as `twokey`.** A real tool server runs as a third account, and can use the tool check
  so it refuses calls that did not come through Two-Key; see [CONNECTING](CONNECTING.md) and
  [TOOL_CHECK](TOOL_CHECK.md).
- **The judge reaches Two-Key through your SSH tunnel.** To Two-Key it looks like a judge on the same machine.
  A judge on another computer without a tunnel needs the agent's session; see
  [SETUP](SETUP.md#a-cloud-judge-needs-the-agents-session).

For what Two-Key does and does not protect against, read [FIT](FIT.md) and [THREAT_MODEL](THREAT_MODEL.md).

## Clean up

When you are done, remove the demo. On Ubuntu, from your own account:

```bash
sudo rm /etc/sudoers.d/two-key-demo
sudo rm -rf /opt/two-key /opt/demo-shop
sudo deluser --remove-home twokey
sudo deluser --remove-home agent
```

This deletes the demo's private key and ledger too. Nothing else uses them. To remove the models, run
`ollama rm llama3.2:3b` on Ubuntu, and delete the model in LM Studio's **My Models** tab on Windows. Close the
tunnel window.

## Words to know

| Word | Meaning |
| --- | --- |
| Agent | A program that uses an AI model to do jobs, using tools |
| Tool | Something an agent can do, such as `pay_vendor` |
| MCP | Model Context Protocol, the common language agents and tools use to talk |
| Model | The AI "brain" file, such as Llama 3.2 3B |
| Judge | An AI that votes yes or no on each tool call (key two) |
| Rules | Exact limits Two-Key checks like a calculator (key one) |
| Constitution | Your plain-English instructions to the judge, signed together with the rules |
| Proxy | A middleman. Two-Key's proxy sits between the agent and the tool server |
| Ledger | Two-Key's signed record book of everything it decided |
| SSH tunnel | An encrypted pipe that makes a program on one computer reachable on another |
| CPU | A computer's main processor. These models run on it, without a graphics card |
